"""
Windows Security / System Event Log Monitor.
Polls event logs via wevtutil (built into Windows, no extra deps needed).
Alerts on key threat-indicator event IDs.
"""
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from typing import Callable


# Event IDs to watch and their default severity.
# Severities are calibrated to minimise false positives on normal workstations:
#   - 4698 is "medium" because software installers routinely create scheduled tasks
#   - 4724 is "low"    because users legitimately reset their own passwords
#   - 4648 is "medium" because service accounts use explicit credentials normally
_WATCHED: dict[int, tuple[str, str]] = {
    1102: ("Audit Log Cleared",        "critical"),   # log tampering — always suspicious
    4625: ("Failed Logon",             "high"),       # credential attack
    4648: ("Explicit Credential Use",  "medium"),     # pass-the-hash / runas (common FP)
    4688: ("Process Created",          "medium"),     # new process (filtered below)
    4698: ("Scheduled Task Created",   "medium"),     # persistence — but installers do this too
    4720: ("New Local Account",        "high"),       # account creation
    4724: ("Password Reset Attempt",   "low"),        # users reset own passwords legitimately
    4732: ("Added to Administrators",  "critical"),   # privilege escalation
    4756: ("Universal Group Modified", "high"),
    7045: ("New Service Installed",    "critical"),   # persistence / rootkit
}

# 4688 is only interesting for these process names
_SUSPICIOUS_PROCS = {
    "mimikatz", "procdump", "psexec", "wce", "fgdump", "pwdump",
    "mshta.exe", "wscript.exe", "cscript.exe", "regsvr32.exe",
    "certutil.exe", "bitsadmin.exe", "rundll32.exe",
}

_POLL_SECONDS   = 10    # how often to query the log
_LOOK_BACK_SECS = 25    # query events newer than this (>_POLL_SECONDS to handle overlap)
_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


class EventLogMonitor:
    """
    Background thread that polls Windows Security and System event logs
    every _POLL_SECONDS seconds and calls on_alert() for each notable event.
    Requires Windows with wevtutil in PATH (all editions since Vista).
    """

    def __init__(self, on_alert: Callable[[dict], None] | None = None):
        self._alert_cb  = on_alert or (lambda _: None)
        self._running   = False
        self._thread:   threading.Thread | None = None
        self._seen_ids: set[str] = set()   # EventRecordID deduplication

    # ── Public ──────────────────────────────────────────────────────────────

    def start(self) -> None:
        self._running = True
        self._thread  = threading.Thread(
            target=self._run, daemon=True, name="EventLogMonitor"
        )
        self._thread.start()

    def stop(self) -> None:
        self._running = False

    def is_available(self) -> bool:
        """Return True if wevtutil is accessible."""
        try:
            r = subprocess.run(
                ["wevtutil", "el"],
                capture_output=True, timeout=3,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            return r.returncode == 0
        except Exception:
            return False

    # ── Internal ────────────────────────────────────────────────────────────

    def _run(self) -> None:
        while self._running:
            for channel in ("Security", "System"):
                try:
                    self._poll(channel)
                except Exception:
                    pass
            time.sleep(_POLL_SECONDS)

    def _poll(self, channel: str) -> None:
        since = (
            datetime.now(timezone.utc) - timedelta(seconds=_LOOK_BACK_SECS)
        ).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        ids_clause = " or ".join(f"EventID={eid}" for eid in _WATCHED)
        query = (
            f"*[System[({ids_clause}) "
            f"and TimeCreated[@SystemTime>='{since}']]]"
        )

        try:
            result = subprocess.run(
                ["wevtutil", "qe", channel,
                 f"/q:{query}", "/f:xml", "/rd:true", "/c:100"],
                capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return

        raw = (result.stdout or "").strip()
        if not raw:
            return

        try:
            root = ET.fromstring(f"<Events>{raw}</Events>")
        except ET.ParseError:
            return

        for event in root.findall("Event"):
            self._process(event)

    def _process(self, event: ET.Element) -> None:
        try:
            sys_el = event.find("e:System", _NS)
            eid    = int(sys_el.find("e:EventID", _NS).text)
            rec_id = (sys_el.find("e:EventRecordID", _NS).text or "").strip()
            ts_raw = sys_el.find("e:TimeCreated", _NS).get("SystemTime", "")
            host   = (sys_el.find("e:Computer", _NS).text or "local")
        except (AttributeError, TypeError, ValueError):
            return

        uid = f"{eid}:{rec_id}"
        if uid in self._seen_ids:
            return
        self._seen_ids.add(uid)
        if len(self._seen_ids) > 5000:
            # prevent unbounded growth — keep newest half
            self._seen_ids = set(list(self._seen_ids)[-2500:])

        if eid not in _WATCHED:
            return

        rule, severity = _WATCHED[eid]

        # Extract EventData fields into a flat dict
        data: dict[str, str] = {}
        ed = event.find("e:EventData", _NS)
        if ed is not None:
            for d in ed.findall("e:Data", _NS):
                name = d.get("Name", "")
                if name:
                    data[name] = (d.text or "").strip()

        # 4688 — only alert on suspicious process names
        if eid == 4688:
            proc = data.get("NewProcessName", "").lower()
            exe  = proc.split("\\")[-1]
            if not any(s in exe for s in _SUSPICIOUS_PROCS):
                return
            rule     = f"Suspicious Process: {exe}"
            severity = "high"

        # Parse timestamp
        try:
            ts = datetime.fromisoformat(
                ts_raw.replace("Z", "+00:00")
            ).astimezone().strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, TypeError):
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        subject     = data.get("SubjectUserName") or data.get("TargetUserName", "")
        workstation = data.get("WorkstationName") or data.get("IpAddress", "") or host

        self._alert_cb({
            "rule_name":  rule,
            "severity":   severity,
            "source_ip":  workstation,
            "message":    self._describe(eid, data, subject, workstation),
            "timestamp":  ts,
            "category":   "event_log",
            "event_id":   eid,
        })

    @staticmethod
    def _describe(eid: int, data: dict, subject: str, where: str) -> str:
        who   = f" by '{subject}'"   if subject else ""
        where = f" from {where}"     if where   else ""
        msgs = {
            4625: lambda: f"Failed logon{who}{where} (type {data.get('LogonType', '?')})",
            4648: lambda: f"Explicit credentials used{who} targeting {data.get('TargetServerName', '?')}",
            4688: lambda: f"Process launched: {data.get('NewProcessName', '?')}{who}",
            4698: lambda: f"Scheduled task created: {data.get('TaskName', '?')}{who}",
            4720: lambda: f"New local account created: {data.get('TargetUserName', '?')}{who}",
            4724: lambda: f"Password reset attempted on {data.get('TargetUserName', '?')}{who}",
            4732: lambda: f"User {data.get('MemberName', '?')} added to Administrators{who}",
            4756: lambda: f"Group membership changed: {data.get('GroupName', '?')}{who}",
            7045: lambda: f"New service installed: {data.get('ServiceName', '?')}{who}",
            1102: lambda: f"Security audit log CLEARED{who}",
        }
        fn = msgs.get(eid)
        return fn() if fn else f"Security event {eid}{who}{where}"
