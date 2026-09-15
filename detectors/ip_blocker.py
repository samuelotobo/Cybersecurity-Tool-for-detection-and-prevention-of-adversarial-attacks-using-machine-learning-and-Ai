"""
Auto IP Blocker with rollback timer.
Wraps Windows Firewall (netsh advfirewall) and stores timed blocks
so they are automatically removed after a configurable duration.
"""

import json
import subprocess
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable


_RULE_PREFIX = "SecurityMonitor_Block_"
_STORE_FILE  = Path(__file__).parent.parent / "blocked_ips.json"


class IPBlocker:
    """
    Manages automatic Windows Firewall blocks with optional rollback.

    Usage:
        blocker = IPBlocker(on_event=print)
        blocker.start()
        blocker.block("1.2.3.4", reason="ARP spoof", ttl_minutes=30)
        # 30 minutes later the rule is automatically removed
    """

    def __init__(
        self,
        on_event: Callable[[dict], None] | None = None,
        check_interval: int = 30,
    ):
        self._on_event       = on_event or (lambda _: None)
        self._check_interval = check_interval
        self._lock           = threading.Lock()
        self._blocks: dict[str, dict] = {}   # ip → {blocked_at, expires_at, reason, ttl_minutes}
        self._running        = False
        self._thread: threading.Thread | None = None
        self._load()

    # ── Public ──────────────────────────────────────────────────────────────

    def start(self) -> None:
        self._running = True
        self._thread  = threading.Thread(
            target=self._run, daemon=True, name="IPBlockerTimer"
        )
        self._thread.start()

    def stop(self) -> None:
        self._running = False

    def block(
        self,
        ip: str,
        reason: str = "Manual block",
        ttl_minutes: int = 60,
    ) -> tuple[bool, str]:
        """Add a firewall block rule and schedule auto-unblock after ttl_minutes."""
        ok, msg = _fw_block(ip)
        if not ok:
            return False, msg

        now     = datetime.now()
        expires = now + timedelta(minutes=ttl_minutes) if ttl_minutes > 0 else None
        entry   = {
            "blocked_at":  now.strftime("%Y-%m-%d %H:%M:%S"),
            "expires_at":  expires.strftime("%Y-%m-%d %H:%M:%S") if expires else "never",
            "reason":      reason,
            "ttl_minutes": ttl_minutes,
            "auto":        True,
        }
        with self._lock:
            self._blocks[ip] = entry
        self._save()
        self._on_event({
            "rule_name": "IP Auto-Blocked",
            "severity":  "high",
            "source_ip": ip,
            "message":   f"{ip} blocked via firewall — auto-unblock in {ttl_minutes} min. Reason: {reason}",
            "timestamp": entry["blocked_at"],
            "category":  "firewall",
        })
        return True, f"Blocked {ip} for {ttl_minutes} minutes."

    def unblock(self, ip: str) -> tuple[bool, str]:
        ok, msg = _fw_unblock(ip)
        with self._lock:
            self._blocks.pop(ip, None)
        self._save()
        return ok, msg

    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            return ip in self._blocks

    def list_blocks(self) -> list[dict]:
        with self._lock:
            return [{"ip": ip, **info} for ip, info in self._blocks.items()]

    # ── Internal ────────────────────────────────────────────────────────────

    def _run(self) -> None:
        while self._running:
            self._expire_check()
            time.sleep(self._check_interval)

    def _expire_check(self) -> None:
        now     = datetime.now()
        expired = []
        with self._lock:
            for ip, info in self._blocks.items():
                exp = info.get("expires_at", "never")
                if exp == "never":
                    continue
                try:
                    if datetime.strptime(exp, "%Y-%m-%d %H:%M:%S") <= now:
                        expired.append(ip)
                except ValueError:
                    pass

        for ip in expired:
            ok, msg = _fw_unblock(ip)
            with self._lock:
                self._blocks.pop(ip, None)
            self._save()
            self._on_event({
                "rule_name": "IP Block Expired",
                "severity":  "low",
                "source_ip": ip,
                "message":   f"Auto-unblocked {ip} — TTL expired. Firewall: {msg}",
                "timestamp": now.strftime("%Y-%m-%d %H:%M:%S"),
                "category":  "firewall",
            })

    def _load(self) -> None:
        try:
            if _STORE_FILE.exists():
                raw = json.loads(_STORE_FILE.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    # Merge any ip → {auto:True} entries that have expires_at
                    for ip, info in raw.items():
                        if isinstance(info, dict) and info.get("auto"):
                            self._blocks[ip] = info
        except Exception:
            pass

    def _save(self) -> None:
        try:
            existing: dict = {}
            if _STORE_FILE.exists():
                raw = json.loads(_STORE_FILE.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    existing = raw
            existing.update(self._blocks)
            _STORE_FILE.write_text(json.dumps(existing, indent=2), encoding="utf-8")
        except Exception:
            pass


# ── Low-level firewall helpers ──────────────────────────────────────────────

def _fw_block(ip: str) -> tuple[bool, str]:
    try:
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name={_RULE_PREFIX}{ip}",
             "dir=in", "action=block", f"remoteip={ip}",
             "protocol=any", "enable=yes"],
            check=True, capture_output=True, timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        # Also block outbound
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name={_RULE_PREFIX}{ip}_out",
             "dir=out", "action=block", f"remoteip={ip}",
             "protocol=any", "enable=yes"],
            check=True, capture_output=True, timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        return True, f"Firewall rules added for {ip}."
    except FileNotFoundError:
        return False, "netsh not found — Windows Firewall unavailable."
    except subprocess.CalledProcessError as e:
        return False, f"netsh error: {e}"
    except Exception as e:
        return False, str(e)


def _fw_unblock(ip: str) -> tuple[bool, str]:
    for direction in ("", "_out"):
        try:
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule",
                 f"name={_RULE_PREFIX}{ip}{direction}"],
                capture_output=True, timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        except Exception:
            pass
    return True, f"Firewall rules removed for {ip}."
