"""
File Scanner — USB drive detection, download folder watching, and malware analysis.

Components
----------
FileScanner     — heuristic analysis + MalwareBazaar cloud hash lookup (free, no key)
USBMonitor      — polls for newly inserted external/removable drives every 3 s
DownloadWatcher — polls Downloads / Desktop / Temp for new files every 5 s
"""
from __future__ import annotations

import ctypes
import hashlib
import math
import os
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

# ── Drive type constants (Windows) ───────────────────────────────────────────
_DRIVE_REMOVABLE = 2
_DRIVE_CDROM     = 5

# ── File extensions worth scanning ───────────────────────────────────────────
SCAN_EXTENSIONS = frozenset({
    # Executables
    ".exe", ".dll", ".scr", ".pif", ".com", ".sys", ".drv", ".ocx", ".cpl",
    # Scripts
    ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".wsf", ".vbe",
    # Installers / archives
    ".msi", ".jar", ".zip", ".rar", ".7z", ".iso", ".img", ".cab",
    # Macro-enabled Office
    ".docm", ".xlsm", ".pptm", ".xltm", ".dotm", ".xlam",
    # Common lure types (can be weaponised)
    ".pdf", ".doc", ".xls", ".ppt",
    # Registry / shortcuts
    ".reg", ".lnk",
})

_LURE_EXTENSIONS = frozenset({
    ".pdf", ".jpg", ".jpeg", ".png", ".docx", ".xlsx",
    ".txt", ".mp4", ".mp3", ".gif", ".svg",
})

_SUSPICIOUS_WORDS = frozenset({
    "invoice", "receipt", "payment", "order", "delivery", "shipment",
    "urgent", "password", "credentials", "crack", "keygen", "patch",
    "loader", "injector", "exploit", "hack", "bypass", "cheat",
    "activate", "serial", "license", "setup", "install",
})

# Files that Windows / system tools create legitimately — always skip
_SYSTEM_NAME_PREFIXES = (
    "__PSScriptPolicyTest_",   # PowerShell execution policy test
    "__PSWorkflowJob_",        # PowerShell workflow
    "~$",                      # Office temp lock files
    "thumbs",                  # Thumbs.db
)
_SYSTEM_NAME_EXACT = frozenset({
    "desktop.ini", "thumbs.db", "ntuser.dat", "ntuser.ini",
    "hiberfil.sys", "pagefile.sys", "swapfile.sys",
})
_SYSTEM_SUFFIXES = frozenset({".tmp", ".temp", ".~tmp", ".part", ".crdownload"})


# ══════════════════════════════════════════════════════════════════════════════
# ── Scan result ───────────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ScanResult:
    path:        str
    sha256:      str
    md5:         str
    size:        int
    verdict:     str              # CLEAN | SUSPICIOUS | MALWARE | ERROR | SKIPPED
    risk_score:  int              # 0–100
    indicators:  list[str] = field(default_factory=list)
    cloud_match: Optional[dict] = None   # MalwareBazaar hit, if any
    error:       Optional[str]  = None
    scanned_at:  str = field(default_factory=lambda: datetime.now().strftime("%H:%M:%S"))

    @property
    def verdict_color(self) -> str:
        return {
            "MALWARE":    "#f47070",
            "SUSPICIOUS": "#f5c542",
            "CLEAN":      "#34d399",
            "SKIPPED":    "#8fa3c0",
            "ERROR":      "#f59e0b",
        }.get(self.verdict, "#8fa3c0")

    @property
    def filename(self) -> str:
        return Path(self.path).name


# ══════════════════════════════════════════════════════════════════════════════
# ── File Scanner ──────────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

class FileScanner:
    """Heuristic analyser + MalwareBazaar cloud hash lookup (free, no API key)."""

    MAX_FILE_BYTES = 100 * 1024 * 1024  # skip files > 100 MB

    def __init__(self, use_cloud: bool = True):
        self._use_cloud = use_cloud

    # ── Public ────────────────────────────────────────────────────────────────

    @staticmethod
    def _is_system_file(path: Path) -> bool:
        """Return True for Windows/system-generated files that are always benign."""
        name  = path.name.lower()
        stem  = path.stem.lower()
        if name in _SYSTEM_NAME_EXACT:
            return True
        if any(path.name.startswith(p) for p in _SYSTEM_NAME_PREFIXES):
            return True
        if path.suffix.lower() in _SYSTEM_SUFFIXES:
            return True
        return False

    def scan_file(self, path: str | Path) -> ScanResult:
        path = Path(path)
        if self._is_system_file(path):
            return ScanResult(str(path), "", "", 0, "SKIPPED", 0,
                              error="System-generated file — skipped")
        try:
            size = path.stat().st_size
            if size > self.MAX_FILE_BYTES:
                return ScanResult(
                    str(path), "", "", size, "SKIPPED", 0,
                    error=f"File too large ({size // (1024*1024)} MB) — skipped to avoid slowdown",
                )
            data = path.read_bytes()
        except PermissionError:
            return ScanResult(str(path), "", "", 0, "ERROR", 0,
                              error="Permission denied — try running as Administrator")
        except OSError as e:
            return ScanResult(str(path), "", "", 0, "ERROR", 0, error=str(e))

        sha256 = hashlib.sha256(data).hexdigest()
        md5    = hashlib.md5(data).hexdigest()
        indicators: list[str] = []
        cloud_match = None

        # 1. Cloud hash check — definitive answer
        if self._use_cloud:
            cloud_match = self._check_malwarebazaar(sha256)
            if cloud_match:
                sig  = cloud_match.get("signature") or cloud_match.get("file_type", "Unknown")
                tags = cloud_match.get("tags") or []
                tag_str = ", ".join(tags[:4]) if tags else ""
                indicators.insert(0,
                    f"CONFIRMED MALWARE: {sig}"
                    + (f" [{tag_str}]" if tag_str else "")
                    + " — found in MalwareBazaar threat database"
                )

        # 2. Local heuristics
        indicators += self._heuristics(path, data)

        risk    = 100 if cloud_match else min(100, len(indicators) * 22)
        verdict = (
            "MALWARE"     if cloud_match or risk >= 80
            else "SUSPICIOUS" if risk >= 22
            else "CLEAN"
        )
        return ScanResult(str(path), sha256, md5, len(data),
                          verdict, risk, indicators, cloud_match)

    def scan_directory(
        self,
        directory:   str | Path,
        recursive:   bool = False,
        on_progress: Optional[Callable[[str], None]] = None,
        stop_event:  Optional[threading.Event] = None,
    ) -> list[ScanResult]:
        directory = Path(directory)
        pattern   = "**/*" if recursive else "*"
        results:  list[ScanResult] = []
        for f in directory.glob(pattern):
            if stop_event and stop_event.is_set():
                break
            if f.is_file() and f.suffix.lower() in SCAN_EXTENSIONS:
                if on_progress:
                    on_progress(f.name)
                results.append(self.scan_file(f))
        return results

    # ── Heuristics ────────────────────────────────────────────────────────────

    def _heuristics(self, path: Path, data: bytes) -> list[str]:
        findings: list[str] = []
        stem  = path.stem.lower()
        ext   = path.suffix.lower()
        is_pe = len(data) >= 2 and data[:2] == b"MZ"

        # Double extension (e.g. invoice.pdf.exe)
        if any(stem.endswith(le) for le in _LURE_EXTENSIONS):
            findings.append(
                f"Double extension: '{path.name}' is disguised as a harmless file "
                "(real extension suggests it is executable)"
            )

        # PE binary in non-executable container
        if is_pe and ext not in {".exe", ".dll", ".scr", ".pif", ".com",
                                  ".sys", ".drv", ".ocx", ".cpl"}:
            findings.append(
                f"Windows executable (PE) hidden inside a '{ext or 'no extension'}' file — "
                "attacker disguised malware as a document or media file"
            )

        # Entropy — packed / encrypted executables
        entropy = self._entropy(data)
        if is_pe and entropy > 7.1:
            findings.append(
                f"Very high entropy ({entropy:.2f}/8.0) in executable — "
                "file is likely packed or encrypted, common technique to hide malware from antivirus"
            )
        elif not is_pe and entropy > 7.6 and len(data) > 4096:
            findings.append(
                f"High entropy ({entropy:.2f}/8.0) in non-executable — "
                "may contain an encrypted payload or heavily obfuscated script"
            )

        # UPX packer
        if b"UPX0" in data[:512] or b"UPX1" in data[:512]:
            findings.append(
                "UPX packer signature detected — "
                "commonly used to compress and conceal malware from antivirus scanners"
            )

        # Very small executable (dropper / shellcode)
        if is_pe and len(data) < 8192:
            findings.append(
                f"Tiny executable ({len(data):,} bytes) — "
                "may be a dropper that downloads and executes additional malware after running"
            )

        # Script files (always risky from external sources)
        if ext in {".ps1", ".vbs", ".js", ".hta", ".wsf", ".bat", ".cmd", ".vbe"}:
            findings.append(
                f"Script file ({ext}) from external source — "
                "scripts can silently execute system commands, download malware, or disable defences"
            )

        # Macro-enabled Office documents
        if ext in {".docm", ".xlsm", ".pptm", ".xltm", ".dotm", ".xlam"}:
            findings.append(
                "Macro-enabled Office document — "
                "malicious macros run on open, can download payloads and establish persistence"
            )

        # Suspicious filename keywords (phishing lures)
        for word in _SUSPICIOUS_WORDS:
            if word in stem:
                findings.append(
                    f"Suspicious filename keyword '{word}' — "
                    "commonly used in phishing lures and trojanised cracked software"
                )
                break

        # Suspicious LNK shortcut
        if ext == ".lnk" and len(data) < 1024:
            findings.append(
                "Small shortcut file (.lnk) — "
                "LNK files can silently execute commands on open; popular malware delivery method"
            )

        return findings

    # ── Cloud lookup ──────────────────────────────────────────────────────────

    @staticmethod
    def _check_malwarebazaar(sha256: str) -> Optional[dict]:
        try:
            import requests
            r = requests.post(
                "https://mb-api.abuse.ch/api/v1/",
                data={"query": "get_info", "hash": sha256},
                timeout=12,
                headers={"User-Agent": "SecurityMonitor/1.0"},
            )
            d = r.json()
            if d.get("query_status") == "hash_not_found":
                return None
            hits = d.get("data", [])
            return hits[0] if hits else None
        except Exception:
            return None

    @staticmethod
    def _entropy(data: bytes) -> float:
        if not data:
            return 0.0
        counts = Counter(data)
        total  = len(data)
        return -sum((c / total) * math.log2(c / total) for c in counts.values())


# ══════════════════════════════════════════════════════════════════════════════
# ── USB / External Drive Monitor ─────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

class USBMonitor(threading.Thread):
    """Polls for newly inserted removable / CD-ROM drives every 3 seconds."""

    def __init__(
        self,
        on_device: Callable[[str, str], None],      # (mountpoint, label)
        on_alert:  Optional[Callable[[dict], None]] = None,
    ):
        super().__init__(daemon=True, name="USBMonitor")
        self._on_device = on_device
        self._on_alert  = on_alert
        self._known:    set[str] = set()
        self._stop      = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        try:
            import psutil
            for p in psutil.disk_partitions(all=False):
                self._known.add(p.mountpoint)
        except Exception:
            pass

        while not self._stop.wait(3.0):
            try:
                import psutil as _ps
                current = {p.mountpoint: p for p in _ps.disk_partitions(all=False)}
                for mp in set(current) - self._known:
                    part = current[mp]
                    if _is_removable(mp):
                        label = _volume_label(mp)
                        self._on_device(mp, label)
                        if self._on_alert:
                            self._on_alert({
                                "rule_name": "External Drive Inserted",
                                "severity":  "high",
                                "category":  "file_scan",
                                "source_ip": "local",
                                "message": (
                                    f"External drive inserted: {label or mp}  "
                                    f"({part.fstype or 'unknown FS'}, {mp}) — scan recommended"
                                ),
                                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            })
                self._known = set(current)
            except Exception:
                pass


# ══════════════════════════════════════════════════════════════════════════════
# ── Download / Transfer Watcher ───────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

class DownloadWatcher(threading.Thread):
    """Polls common download locations for newly created files every 5 seconds."""

    def __init__(
        self,
        on_new_file: Callable[[Path], None],
        watch_dirs:  Optional[list[Path]] = None,
    ):
        super().__init__(daemon=True, name="DownloadWatcher")
        self._on_new = on_new_file
        self._dirs   = watch_dirs or _default_watch_dirs()
        self._seen:  dict[Path, set[Path]] = {}
        self._stop   = threading.Event()

    @property
    def watch_dirs(self) -> list[Path]:
        return list(self._dirs)

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        for d in self._dirs:
            try:
                self._seen[d] = set(d.iterdir()) if d.exists() else set()
            except Exception:
                self._seen[d] = set()

        while not self._stop.wait(5.0):
            for d in self._dirs:
                try:
                    if not d.exists():
                        continue
                    current = set(d.iterdir())
                    prev    = self._seen.get(d, set())
                    for f in current - prev:
                        if f.is_file():
                            time.sleep(0.3)  # let write finish
                            self._on_new(f)
                    self._seen[d] = current
                except Exception:
                    pass


# ══════════════════════════════════════════════════════════════════════════════
# ── Utilities ─────────────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

def _is_removable(mountpoint: str) -> bool:
    try:
        drive_type = ctypes.windll.kernel32.GetDriveTypeW(mountpoint)
        return int(drive_type) in (_DRIVE_REMOVABLE, _DRIVE_CDROM)
    except Exception:
        return False


def _volume_label(mountpoint: str) -> str:
    try:
        buf = ctypes.create_unicode_buffer(1024)
        ctypes.windll.kernel32.GetVolumeInformationW(
            mountpoint, buf, len(buf), None, None, None, None, 0
        )
        return buf.value or ""
    except Exception:
        return ""


def _default_watch_dirs() -> list[Path]:
    dirs = [Path.home() / "Downloads", Path.home() / "Desktop"]
    for env in ("TEMP", "TMP"):
        tmp = os.environ.get(env)
        if tmp:
            dirs.append(Path(tmp))
            break
    return [d for d in dirs if d.exists()]


def get_all_drives() -> list[dict]:
    """Return list of drive dicts for the current system."""
    drives = []
    try:
        import psutil
        for p in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(p.mountpoint)
                total_gb = usage.total / (1024 ** 3)
                free_gb  = usage.free  / (1024 ** 3)
            except Exception:
                total_gb = free_gb = 0.0
            drives.append({
                "mountpoint": p.mountpoint,
                "device":     p.device,
                "fstype":     p.fstype,
                "removable":  _is_removable(p.mountpoint),
                "label":      _volume_label(p.mountpoint),
                "total_gb":   total_gb,
                "free_gb":    free_gb,
            })
    except Exception:
        pass
    return drives
