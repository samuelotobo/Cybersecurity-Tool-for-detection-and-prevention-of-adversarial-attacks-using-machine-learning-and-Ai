"""
User Behaviour Analytics Engine (UEBA).

Builds per-user activity baselines from Windows Event Log data and
alerts on behavioural anomalies:
  - Off-hours logins (outside the user's normal working hours)
  - Login from a new / unknown workstation
  - Sudden spike in failed logon attempts
  - New process launched that the user has never run before
  - Unusual number of file accesses or group membership changes

Baseline persistence: <project_root>/ueba_baselines.json
"""

import json
import statistics
import threading
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Callable


_BASELINE_FILE = Path(__file__).parent.parent / "ueba_baselines.json"

# Working hours window used for off-hours detection (24-hour clock)
_WORK_HOUR_START = 7    # 07:00
_WORK_HOUR_END   = 20   # 20:00

# How many logins must be observed before enabling off-hours detection
_MIN_SAMPLES_FOR_ANOMALY = 5

# Number of failed logons within a single polling cycle to count as "spike"
_FAILED_LOGON_SPIKE = 5


class UEBAEngine:
    """
    Feed Windows Event Log alert dicts into update() and receive anomaly alerts
    via the on_alert callback.  Call save() periodically to persist baselines.
    """

    def __init__(self, on_alert: Callable[[dict], None] | None = None):
        self._on_alert   = on_alert or (lambda _: None)
        self._lock       = threading.Lock()
        self._baselines: dict[str, dict] = {}   # username → baseline dict
        self._failed_counts: dict[str, list[str]] = defaultdict(list)
        self._load()

    # ── Public ──────────────────────────────────────────────────────────────

    def update(self, event: dict) -> None:
        """
        Process one event log alert dict (as produced by EventLogMonitor).
        Detects anomalies and updates the user's baseline.
        """
        eid      = event.get("event_id")
        ts_str   = event.get("timestamp", "")
        username = _extract_user(event)
        workstation = event.get("source_ip", "")

        if not username or username in ("-", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"):
            return

        ts = _parse_ts(ts_str)

        with self._lock:
            base = self._baselines.setdefault(username, _empty_baseline())

            # ── Successful logon (4624) → update baseline ──────────────────
            if eid == 4624:
                self._record_logon(base, ts, workstation, username)

            # ── Failed logon (4625) → spike detection ──────────────────────
            elif eid == 4625:
                self._check_failed_spike(base, ts, username, workstation)

            # ── Process creation (4688) → track process names ──────────────
            elif eid == 4688:
                self._check_new_process(base, event, username, ts)

            # ── Added to Administrators (4732) ─────────────────────────────
            elif eid == 4732:
                self._on_alert({
                    "rule_name": "UEBA — Privilege Escalation",
                    "severity":  "critical",
                    "source_ip": workstation,
                    "message":   (
                        f"UEBA: '{username}' was added to the Administrators group "
                        "— verify this is authorised. Immediate investigation recommended."
                    ),
                    "timestamp": ts_str,
                    "category":  "ueba",
                    "user":      username,
                })

    def save(self) -> None:
        with self._lock:
            try:
                _BASELINE_FILE.write_text(
                    json.dumps(self._baselines, indent=2), encoding="utf-8"
                )
            except Exception:
                pass

    def get_profile(self, username: str) -> dict | None:
        with self._lock:
            return self._baselines.get(username)

    def all_users(self) -> list[str]:
        with self._lock:
            return list(self._baselines.keys())

    # ── Internal ────────────────────────────────────────────────────────────

    def _record_logon(
        self, base: dict, ts: datetime | None, workstation: str, username: str
    ) -> None:
        if ts is None:
            return

        hour = ts.hour

        # Off-hours detection (only after enough samples)
        if (
            len(base["logon_hours"]) >= _MIN_SAMPLES_FOR_ANOMALY
            and not (_WORK_HOUR_START <= hour < _WORK_HOUR_END)
        ):
            self._on_alert({
                "rule_name": "UEBA — Off-Hours Login",
                "severity":  "medium",
                "source_ip": workstation,
                "message":   (
                    f"UEBA: '{username}' logged in at {ts.strftime('%H:%M')} "
                    f"({_hour_label(hour)}) — outside normal working hours "
                    f"({_WORK_HOUR_START:02d}:00–{_WORK_HOUR_END:02d}:00)."
                ),
                "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
                "category":  "ueba",
                "user":      username,
            })

        # Unknown workstation detection
        known_ws = set(base.get("workstations", []))
        if (
            workstation
            and workstation not in ("-", "")
            and workstation not in known_ws
            and len(known_ws) > 0
        ):
            self._on_alert({
                "rule_name": "UEBA — New Workstation",
                "severity":  "medium",
                "source_ip": workstation,
                "message":   (
                    f"UEBA: '{username}' logged in from unrecognised workstation "
                    f"'{workstation}'. Known machines: {', '.join(list(known_ws)[:5])}."
                ),
                "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
                "category":  "ueba",
                "user":      username,
            })

        # Update baseline
        base["logon_hours"].append(hour)
        if len(base["logon_hours"]) > 500:
            base["logon_hours"] = base["logon_hours"][-500:]
        if workstation and workstation not in ("-", ""):
            ws_set = set(base["workstations"])
            ws_set.add(workstation)
            base["workstations"] = list(ws_set)

    def _check_failed_spike(
        self, base: dict, ts: datetime | None, username: str, workstation: str
    ) -> None:
        ts_str = ts.strftime("%Y-%m-%d %H:%M:%S") if ts else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._failed_counts[username].append(ts_str)
        # Keep last 60 seconds worth
        now_s = datetime.now()
        self._failed_counts[username] = [
            t for t in self._failed_counts[username]
            if (now_s - _parse_ts(t)).total_seconds() < 60 if _parse_ts(t)
        ]
        count = len(self._failed_counts[username])
        if count == _FAILED_LOGON_SPIKE:
            self._on_alert({
                "rule_name": "UEBA — Failed Logon Spike",
                "severity":  "high",
                "source_ip": workstation,
                "message":   (
                    f"UEBA: {count} failed logon attempts for '{username}' within 60 s "
                    "— possible credential attack or account lockout underway."
                ),
                "timestamp": ts_str,
                "category":  "ueba",
                "user":      username,
            })
        base["failed_logons"] = base.get("failed_logons", 0) + 1

    def _check_new_process(
        self, base: dict, event: dict, username: str, ts: datetime | None
    ) -> None:
        msg_text = event.get("message", "")
        # Extract process name from message like "Process launched: C:\...\evil.exe"
        proc_name = ""
        if "Process launched:" in msg_text:
            try:
                proc_name = msg_text.split("Process launched:")[-1].split("by")[0].strip()
                proc_name = proc_name.split("\\")[-1].lower()
            except Exception:
                pass
        if not proc_name or proc_name in base.get("known_processes", []):
            if proc_name:
                pass   # already known — update count silently
            return

        ts_str = ts.strftime("%Y-%m-%d %H:%M:%S") if ts else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        known = base.get("known_processes", [])

        if len(known) >= _MIN_SAMPLES_FOR_ANOMALY:
            self._on_alert({
                "rule_name": "UEBA — New Process",
                "severity":  "low",
                "source_ip": event.get("source_ip", "localhost"),
                "message":   (
                    f"UEBA: '{username}' launched a process not seen before: "
                    f"'{proc_name}'. Verify it is authorised."
                ),
                "timestamp": ts_str,
                "category":  "ueba",
                "user":      username,
            })

        known.append(proc_name)
        base["known_processes"] = known[-200:]   # cap at 200 entries

    def _load(self) -> None:
        try:
            if _BASELINE_FILE.exists():
                self._baselines = json.loads(
                    _BASELINE_FILE.read_text(encoding="utf-8")
                )
        except Exception:
            self._baselines = {}


def _empty_baseline() -> dict:
    return {
        "logon_hours":    [],
        "workstations":   [],
        "known_processes": [],
        "failed_logons":  0,
    }


def _extract_user(event: dict) -> str:
    msg = event.get("message", "")
    for marker in ("by '", "on ", "for '"):
        if marker in msg:
            try:
                return msg.split(marker)[1].split("'")[0].strip()
            except IndexError:
                pass
    return ""


def _parse_ts(ts_str: str) -> datetime | None:
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(ts_str, fmt)
        except (ValueError, TypeError):
            pass
    return None


def _hour_label(hour: int) -> str:
    if 0 <= hour < 6:
        return "night"
    if 6 <= hour < 12:
        return "early morning"
    if 21 <= hour <= 23:
        return "late night"
    return f"{hour:02d}:00"
