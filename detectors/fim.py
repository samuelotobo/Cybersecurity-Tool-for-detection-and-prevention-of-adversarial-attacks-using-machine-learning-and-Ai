"""
File Integrity Monitor (FIM).
Builds a SHA-256 baseline of watched directories and alerts whenever
files are created, modified, or deleted between scans.
"""
import hashlib
import json
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Callable


_POLL_SECONDS   = 60              # seconds between full directory scans
_MAX_FILE_BYTES = 50 * 1024 * 1024   # skip files larger than 50 MB

# Files / directories to always skip — prevents self-referential and transient false positives.
_EXCLUDE_NAMES = {
    "fim_baseline.json",   # FIM writes this itself every scan — would always alert
    "blocked_ips.json",    # changes when IPs are blocked/unblocked
    "security_alerts.log",
    "system_monitor.log",
}
_EXCLUDE_SUFFIXES = {".pyc", ".log", ".tmp", ".bak", ".lock", ".swp", ".db-journal"}
_EXCLUDE_DIRS    = {"__pycache__", ".git", ".venv", "venv", "node_modules", "logs", ".pytest_cache"}


class FIMMonitor:
    """
    Background thread that periodically scans watched directories,
    compares SHA-256 hashes to the saved baseline, and calls on_alert()
    for any changes detected.

    The baseline is persisted to `baseline_path` as JSON so it survives
    restarts.  The very first scan creates the baseline without alerting.
    """

    def __init__(
        self,
        watch_dirs: list[str],
        baseline_path: Path,
        on_alert: Callable[[dict], None] | None = None,
    ):
        self._dirs        = [Path(d) for d in watch_dirs]
        self._baseline_p  = Path(baseline_path)
        self._alert_cb    = on_alert or (lambda _: None)
        self._baseline: dict[str, str] = {}   # abs_path → sha256
        self._running     = False
        self._thread: threading.Thread | None = None
        self._load_baseline()

    # ── Public ──────────────────────────────────────────────────────────────

    def start(self) -> None:
        self._running = True
        self._thread  = threading.Thread(
            target=self._run, daemon=True, name="FIMMonitor"
        )
        self._thread.start()

    def stop(self) -> None:
        self._running = False

    def file_count(self) -> int:
        """Number of files currently in the baseline."""
        return len(self._baseline)

    def rescan_now(self) -> dict:
        """Synchronous rescan — returns {"added": N, "modified": N, "deleted": N}."""
        current = self._scan_all()
        counts  = self._diff(current, silent=False)
        self._baseline = current
        self._save_baseline()
        return counts

    # ── Internal ────────────────────────────────────────────────────────────

    def _load_baseline(self) -> None:
        if self._baseline_p.exists():
            try:
                self._baseline = json.loads(
                    self._baseline_p.read_text(encoding="utf-8")
                )
                return
            except Exception:
                pass
        self._baseline = {}

    def _save_baseline(self) -> None:
        try:
            self._baseline_p.parent.mkdir(parents=True, exist_ok=True)
            self._baseline_p.write_text(
                json.dumps(self._baseline, indent=2), encoding="utf-8"
            )
        except Exception:
            pass

    def _run(self) -> None:
        if not self._baseline:
            # First run — establish baseline silently
            self._baseline = self._scan_all()
            self._save_baseline()
            time.sleep(_POLL_SECONDS)

        while self._running:
            try:
                current = self._scan_all()
                self._diff(current, silent=False)
                self._baseline = current
                self._save_baseline()
            except Exception:
                pass
            time.sleep(_POLL_SECONDS)

    def _scan_all(self) -> dict[str, str]:
        hashes: dict[str, str] = {}
        for d in self._dirs:
            if not d.exists():
                continue
            try:
                for f in d.rglob("*"):
                    try:
                        if not f.is_file():
                            continue
                        # Skip excluded directories anywhere in the path
                        if any(part in _EXCLUDE_DIRS for part in f.parts):
                            continue
                        # Skip excluded filenames and suffixes
                        if f.name in _EXCLUDE_NAMES:
                            continue
                        if f.suffix.lower() in _EXCLUDE_SUFFIXES:
                            continue
                        if f.stat().st_size > _MAX_FILE_BYTES:
                            continue
                        h = self._hash_file(f)
                        if h:
                            hashes[str(f)] = h
                    except (PermissionError, OSError):
                        pass
            except (PermissionError, OSError):
                pass
        return hashes

    @staticmethod
    def _hash_file(path: Path) -> str:
        try:
            sha = hashlib.sha256()
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(65536), b""):
                    sha.update(chunk)
            return sha.hexdigest()
        except (PermissionError, OSError):
            return ""

    def _diff(self, current: dict[str, str], silent: bool) -> dict:
        ts  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        old = set(self._baseline)
        new = set(current)
        counts = {"added": 0, "modified": 0, "deleted": 0}

        for path in new - old:
            counts["added"] += 1
            if not silent:
                self._alert_cb({
                    "rule_name": "FIM — File Created",
                    "severity":  "medium",
                    "source_ip": "localhost",
                    "message":   f"New file appeared in monitored directory: {path}",
                    "timestamp": ts,
                    "category":  "fim",
                    "path":      path,
                })

        for path in old - new:
            counts["deleted"] += 1
            if not silent:
                self._alert_cb({
                    "rule_name": "FIM — File Deleted",
                    "severity":  "medium",
                    "source_ip": "localhost",
                    "message":   f"Monitored file was deleted: {path}",
                    "timestamp": ts,
                    "category":  "fim",
                    "path":      path,
                })

        for path in old & new:
            if self._baseline[path] != current[path]:
                counts["modified"] += 1
                if not silent:
                    self._alert_cb({
                        "rule_name": "FIM — File Modified",
                        "severity":  "high",
                        "source_ip": "localhost",
                        "message":   f"Monitored file hash changed (possible tampering): {path}",
                        "timestamp": ts,
                        "category":  "fim",
                        "path":      path,
                    })

        return counts
