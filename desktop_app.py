#!/usr/bin/env python3
"""
Security Monitor Desktop Application
=====================================
Real-time background threat detection with system tray,
Windows Firewall IP blocking, and threat notifications.

Run:    python desktop_app.py
Build:  pyinstaller desktop_app.spec
Needs:  pip install PyQt6
"""

import ctypes
import ipaddress
import json
import subprocess
import sys
import threading
import time
import warnings
from collections import deque
from datetime import datetime
from pathlib import Path

# Suppress sklearn warning about feature names when predicting with raw numpy arrays
warnings.filterwarnings("ignore", message="X does not have valid feature names")

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

try:
    from PyQt6.QtCore import (
        QEasingCurve, QEvent, QPointF, QRectF, QSize, Qt, QThread, QTimer,
        pyqtSignal,
    )
    from PyQt6.QtGui import (
        QAction, QBrush, QColor, QFont, QIcon, QLinearGradient, QPainter,
        QPainterPath, QPen, QPixmap,
    )
    from PyQt6.QtWidgets import (
        QAbstractItemView, QApplication, QCheckBox, QComboBox, QDialog,
        QFileDialog, QFormLayout, QFrame, QGridLayout, QGroupBox, QHBoxLayout, QHeaderView,
        QLabel, QLineEdit, QMainWindow, QMenu, QMessageBox, QPushButton,
        QScrollArea, QSizePolicy, QSpacerItem, QSpinBox, QStackedWidget,
        QSlider, QSplitter, QStatusBar, QSystemTrayIcon, QTabWidget, QTableWidget,
        QTableWidgetItem, QTextEdit, QProgressBar, QVBoxLayout, QWidget,
    )
except ImportError:
    print("PyQt6 is required.  Install with:  pip install PyQt6")
    sys.exit(1)

try:
    from PyQt6.QtWebEngineWidgets import QWebEngineView
    from PyQt6.QtCore import QUrl
    _HAS_WEBENGINE = True
except ImportError:
    _HAS_WEBENGINE = False

import webbrowser

try:
    from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as _MplCanvas
    from matplotlib.figure import Figure as _MplFigure
    # NOTE: do NOT import matplotlib.pyplot here — importing pyplot before
    # QApplication exists can create a conflicting Qt event loop.
    _HAS_MPL = True
except ImportError:
    _HAS_MPL = False

try:
    from detectors.adversarial import (
        ModelAnalyzer, FeatureExplainer, AdversarialEngine,
        SecurityScorer, ATTACK_PROFILES, BENIGN_PROFILE, FEATURE_DISPLAY,
        _ModelWrapper,
    )
    _HAS_ADV = True
except ImportError:
    _HAS_ADV = False

try:
    from detectors.adaptive_trainer import (
        get_feedback_buffer, get_corrective_layer, get_trainer,
        FEATURE_NAMES as _AT_FEATURES,
    )
    _HAS_ADAPTIVE = True
except ImportError:
    _HAS_ADAPTIVE = False


# ══════════════════════════════════════════════════════════════════════════════
# ── OS / Firewall helpers ──────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

BLOCKED_FILE  = ROOT / "blocked_ips.json"
SETTINGS_FILE = ROOT / "settings.json"


def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


IS_ADMIN = _is_admin()


def _apply_dark_titlebar(hwnd: int) -> None:
    """Make the native Windows title bar dark (Windows 11 / 10 v20H1+)."""
    try:
        ctypes.windll.dwmapi.DwmSetWindowAttribute(
            hwnd, 20, ctypes.byref(ctypes.c_int(1)), 4
        )
    except Exception:
        pass


def _load_blocked() -> dict:
    """Return {ip: {blocked_at, reason, auto}} — handles legacy list format too."""
    try:
        if BLOCKED_FILE.exists():
            raw = json.loads(BLOCKED_FILE.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                # Legacy format: {"blocked_ips": ["1.2.3.4", ...]}
                if "blocked_ips" in raw and isinstance(raw.get("blocked_ips"), list):
                    return {ip: {"blocked_at": "—", "reason": "Legacy entry", "auto": False}
                            for ip in raw["blocked_ips"] if isinstance(ip, str)}
                # New format: {"1.2.3.4": {blocked_at, reason, auto}, ...}
                return raw
            # Bare list format: ["1.2.3.4", ...]
            if isinstance(raw, list):
                return {ip: {"blocked_at": "—", "reason": "Legacy entry", "auto": False}
                        for ip in raw if isinstance(ip, str)}
    except Exception:
        pass
    return {}


def _save_blocked(data: dict) -> None:
    try:
        BLOCKED_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except Exception:
        pass


class AppSettings:
    """Persistent app settings stored in settings.json."""

    def __init__(self):
        self._path = SETTINGS_FILE
        self._data = self._defaults()
        self._load()

    def _defaults(self):
        return {
            "notifications": {"enabled": True, "min_severity": "high",
                               "network": True, "system": True, "file_scan": True, "sound": False},
            "appearance": {"accent": "#4f8ef7"},
            "detection": {"arp": True, "dns": True, "brute_force": True,
                          "threat_intel": True, "tls": True, "auto_block": False,
                          "attack_threshold": 75},
            "file_protection": {"usb_monitor": True, "download_watcher": True,
                                "auto_scan": True, "cloud_lookup": True},
            "performance": {"max_alerts": 150, "packet_rate": 20, "max_rows": 300},
            "whitelist": [],
        }

    def get(self, *keys, default=None):
        d = self._data
        for k in keys:
            if not isinstance(d, dict) or k not in d:
                return default
            d = d[k]
        return d

    def set(self, *args):
        keys, value = args[:-1], args[-1]
        d = self._data
        for k in keys[:-1]:
            d = d.setdefault(k, {})
        d[keys[-1]] = value
        self._save()

    def _load(self):
        try:
            if self._path.exists():
                loaded = json.loads(self._path.read_text(encoding="utf-8"))
                self._deep_merge(self._data, loaded)
        except Exception:
            pass

    def _save(self):
        try:
            self._path.write_text(json.dumps(self._data, indent=2), encoding="utf-8")
        except Exception:
            pass

    def _deep_merge(self, base, override):
        for k, v in override.items():
            if k in base and isinstance(base[k], dict) and isinstance(v, dict):
                self._deep_merge(base[k], v)
            else:
                base[k] = v


def _validate_ip(ip: str) -> bool:
    """Return True only for syntactically valid IPv4/IPv6 addresses."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _firewall_block(ip: str) -> tuple[bool, str]:
    if not IS_ADMIN:
        return False, "Administrator rights required.  Right-click the app → Run as administrator."
    if not _validate_ip(ip):
        return False, f"Invalid IP address: {ip!r}"
    try:
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name=SecurityMonitor_Block_{ip}",
             "dir=in", "action=block", f"remoteip={ip}",
             "protocol=any", "enable=yes"],
            check=True, capture_output=True, timeout=10,
        )
        return True, f"Blocked {ip} via Windows Firewall."
    except Exception as e:
        return False, f"Firewall rule failed: {e}"


def _firewall_unblock(ip: str) -> tuple[bool, str]:
    if not IS_ADMIN:
        return False, "Administrator rights required."
    if not _validate_ip(ip):
        return False, f"Invalid IP address: {ip!r}"
    try:
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "delete", "rule",
             f"name=SecurityMonitor_Block_{ip}"],
            check=True, capture_output=True, timeout=10,
        )
        return True, f"Unblocked {ip}."
    except Exception as e:
        return False, f"Unblock failed: {e}"


def _humanize(a: dict) -> str:
    rule = a.get("rule_name", "")
    ip   = a.get("source_ip", "Unknown")
    msgs = {
        # DDoS / network
        "SYN Flood":               f"{ip} flooding with SYN packets — likely a SYN flood attack",
        "Port Scan":               f"{ip} probing multiple ports — pre-attack reconnaissance",
        "Connection Flood":        f"{ip} opening too many connections per second",
        "IP Reputation":           f"Known malicious address {ip} detected on your network",
        "Sustained Attack":        f"{ip} flagged as attacker multiple times in quick succession",
        "Oversized Packets":       f"Abnormally large packets from {ip} — possible data exfiltration",
        # ARP
        "ARP Flood":               f"ARP flood from {ip} — possible network scanning or DoS",
        "ARP Spoofing":            f"{ip} claims a different MAC — possible MitM / ARP poisoning",
        "ARP Spoofing — Gateway!": f"Gateway ARP hijack from {ip} — all traffic may be intercepted",
        # DNS
        "DNS Tunneling":           f"DNS tunneling suspected — data may be exfiltrated via DNS queries",
        "Fast-Flux DNS":           f"Fast-flux DNS detected — possible bulletproof hosting or botnet C2",
        "DNS C2 Beacon":           f"High DNS query rate from {ip} — possible C2 beaconing",
        "Suspicious TLD":          f"Query to high-risk TLD from {ip} — possible phishing or malware",
        # Brute force
        "SSH Brute Force":         f"{ip} brute-forcing SSH — repeated login attempts detected",
        "RDP Brute Force":         f"{ip} brute-forcing RDP — repeated Remote Desktop attempts",
        "FTP Brute Force":         f"{ip} brute-forcing FTP — repeated file-transfer login attempts",
        "SMB Brute Force":         f"{ip} brute-forcing SMB — possible lateral movement attempt",
        "Credential Stuffing":     f"{ip} credential stuffing via HTTP — possible account takeover",
        "Password Spray":          f"{ip} password-spraying multiple services simultaneously",
        # Threat intel
        "Threat Intelligence Hit": f"{ip} is a known malicious host according to AbuseIPDB",
        # Event log
        "Failed Logon":            f"Failed login attempt from {ip} — possible credential attack",
        "New Local Account":       f"New local user account created — verify this is authorized",
        "Added to Administrators": f"User added to Administrators group — possible privilege escalation",
        "New Service Installed":   f"New Windows service installed — possible persistence mechanism",
        "Audit Log Cleared":       "Windows Security audit log was cleared — sign of log tampering",
        "Scheduled Task Created":  "Scheduled task created — verify this is an authorized automation",
        "Explicit Credential Use": "Explicit credentials used — possible pass-the-hash / runas attack",
        # FIM
        "FIM — File Modified":     "Monitored file hash changed — possible tampering or malware",
        "FIM — File Created":      "New file appeared in a monitored directory",
        "FIM — File Deleted":      "A monitored file was deleted unexpectedly",
        # File scanner
        "External Drive Inserted": f"External USB/removable drive inserted — automatic scan recommended",
        "Malware Detected":        f"MALWARE confirmed on local disk — immediate action required",
        "Suspicious File":         f"Suspicious file detected — heuristic indicators triggered",
    }
    # Partial match for dynamically-named rules (e.g. "SSH Brute Force", "Telnet Brute Force")
    for key, val in msgs.items():
        if rule.startswith(key.split()[0]) and "Brute Force" in rule and "Brute Force" in key:
            return val
    return msgs.get(rule, a.get("message", rule or "Unclassified threat"))


# ══════════════════════════════════════════════════════════════════════════════
# ── Theme ──────────────────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

_QSS_BASE = """
/* ══════════════════════════════════════════════════════════
   Security Monitor  –  Design System v4
   ══════════════════════════════════════════════════════════ */

/* BASE */
QMainWindow, QDialog        { background: #0b0d1e; }
QWidget {
    background: transparent;
    color: #bcd0e8;
    font-family: 'Segoe UI', sans-serif;
    font-size: 13px;
}
QStackedWidget              { background: #0b0d1e; }
QScrollArea                 { background: transparent; border: none; }

/* SIDEBAR */
QWidget#sidebar {
    background: #080a18;
    border-right: 1px solid #141a2e;
    min-width: 226px;
    max-width: 226px;
}

/* NAV BUTTONS */
QPushButton#navBtn {
    background: transparent;
    border: none;
    border-radius: 8px;
    color: #36506e;
    text-align: left;
    padding: 0px 10px 0px 10px;
    min-height: 38px;
    max-height: 38px;
    font-size: 13px;
    font-weight: 500;
}
QPushButton#navBtn:hover {
    background: rgba(255, 255, 255, 0.05);
    color: #6a8aaa;
}
QPushButton#navBtn[active="1"] {
    background: rgba(79, 142, 247, 0.13);
    color: #aaccf8;
    font-weight: 600;
    border: 1px solid rgba(79, 142, 247, 0.20);
    border-left: 3px solid #4f8ef7;
    padding-left: 8px;
}
QPushButton#navBtn[active="1"]:hover {
    background: rgba(79, 142, 247, 0.20);
    color: #c8e0ff;
}

/* CARDS */
QFrame#card {
    background: #141828;
    border: 1px solid #1e2848;
    border-radius: 14px;
}
QFrame#card2 {
    background: #10131f;
    border: 1px solid #192038;
    border-radius: 10px;
}

/* ── Alert severity cards ───────────────────────────────── */
QFrame#cCrit {
    background: rgba(239, 68, 68, 0.08);
    border: 1px solid rgba(239, 68, 68, 0.30);
    border-left: 3px solid #ef4444;
    border-radius: 12px;
}
QFrame#cCrit:hover { border-color: rgba(239,68,68,0.50); border-left-color: #ef4444; }
QFrame#cHigh {
    background: rgba(251, 146, 60, 0.07);
    border: 1px solid rgba(251, 146, 60, 0.26);
    border-left: 3px solid #fb923c;
    border-radius: 12px;
}
QFrame#cHigh:hover { border-color: rgba(251,146,60,0.44); border-left-color: #fb923c; }
QFrame#cMed {
    background: rgba(245, 197, 66, 0.06);
    border: 1px solid rgba(245, 197, 66, 0.22);
    border-left: 3px solid #f5c542;
    border-radius: 12px;
}
QFrame#cMed:hover { border-color: rgba(245,197,66,0.38); border-left-color: #f5c542; }
QFrame#cLow {
    background: rgba(79, 142, 247, 0.05);
    border: 1px solid rgba(79, 142, 247, 0.16);
    border-left: 3px solid rgba(79,142,247,0.6);
    border-radius: 12px;
}
QFrame#cLow:hover { border-color: rgba(79,142,247,0.28); }

/* ── Tables ─────────────────────────────────────────────── */
QTableWidget {
    background: #0a0c1a;
    border: none;
    color: #b8cce4;
    gridline-color: #131828;
    font-size: 12px;
    font-family: 'Cascadia Code', 'Consolas', 'Courier New', monospace;
    selection-background-color: rgba(79, 142, 247, 0.18);
    selection-color: #e0eeff;
    alternate-background-color: #0c0f1e;
}
QTableWidget::item {
    padding: 8px 12px;
    border-bottom: 1px solid #131828;
}
QTableWidget::item:hover    { background: rgba(79, 142, 247, 0.08); }
QTableWidget::item:selected { background: rgba(79, 142, 247, 0.18); color: #e2eeff; }
QHeaderView::section {
    background: #0a0c1a;
    color: #2e4060;
    font-size: 10px;
    font-weight: 700;
    font-family: 'Segoe UI', sans-serif;
    padding: 10px 12px;
    border: none;
    border-bottom: 2px solid #161e34;
    border-right: 1px solid #141828;
    letter-spacing: 1px;
    text-transform: uppercase;
}
QHeaderView::section:hover { color: #5a7898; background: #0c0e1c; }
QHeaderView { background: #090b18; }

/* FORM CONTROLS */
QLineEdit, QTextEdit, QSpinBox {
    background: #0c0e1e;
    border: 1px solid #1c2240;
    border-radius: 8px;
    color: #b0c8e4;
    padding: 8px 12px;
    font-size: 13px;
    selection-background-color: rgba(79, 142, 247, 0.22);
}
QLineEdit:focus, QTextEdit:focus, QSpinBox:focus {
    border-color: #4f8ef7;
    background: #0e1126;
}
QLineEdit:hover:!focus, QSpinBox:hover:!focus { border-color: #253060; }
QComboBox {
    background: #0c0e1e;
    border: 1px solid #1c2240;
    border-radius: 8px;
    color: #b0c8e4;
    padding: 8px 32px 8px 12px;
    font-size: 13px;
}
QComboBox:focus, QComboBox:on { border-color: #4f8ef7; background: #0e1126; }
QComboBox:hover:!on { border-color: #253060; }
QComboBox::drop-down { border: none; width: 28px; }
QComboBox::down-arrow { image: none; }
QComboBox QAbstractItemView {
    background: #101428;
    border: 1px solid #1e2848;
    border-radius: 8px;
    color: #b0c8e4;
    selection-background-color: rgba(79, 142, 247, 0.16);
    padding: 4px;
    outline: none;
}
QComboBox QAbstractItemView::item { padding: 8px 12px; border-radius: 6px; min-height: 28px; }
QComboBox QAbstractItemView::item:hover { background: rgba(79, 142, 247, 0.10); }
QSpinBox::up-button, QSpinBox::down-button {
    background: #182030;
    border: none;
    width: 20px;
    border-radius: 4px;
}
QSpinBox::up-button:hover, QSpinBox::down-button:hover { background: #1e2a40; }

/* ── Slider ─────────────────────────────────────────────── */
QSlider::groove:horizontal {
    background: #1a2038;
    height: 4px;
    border-radius: 2px;
}
QSlider::handle:horizontal {
    background: #4f8ef7;
    border: 2px solid #3070d0;
    width: 16px;
    height: 16px;
    margin: -6px 0;
    border-radius: 8px;
}
QSlider::handle:horizontal:hover { background: #6ba4ff; }
QSlider::sub-page:horizontal { background: #4f8ef7; border-radius: 2px; }

/* ── Primary button ─────────────────────────────────────── */
QPushButton#primaryBtn {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
        stop:0 #2a5ee0, stop:1 #4f8ef7);
    color: #ffffff;
    border: none;
    border-radius: 10px;
    font-size: 13px;
    font-weight: 600;
    padding: 10px 24px;
    min-height: 38px;
    letter-spacing: 0.2px;
}
QPushButton#primaryBtn:hover {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
        stop:0 #3068ee, stop:1 #5f9eff);
}
QPushButton#primaryBtn:pressed {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
        stop:0 #2050c8, stop:1 #4280e0);
    padding-top: 11px;
}
QPushButton#primaryBtn:disabled { background: #182038; color: #303a54; }

/* ── Secondary button ───────────────────────────────────── */
QPushButton#secondaryBtn {
    background: rgba(79, 142, 247, 0.07);
    color: #6090e8;
    border: 1px solid rgba(79, 142, 247, 0.22);
    border-radius: 9px;
    font-size: 12px;
    font-weight: 500;
    padding: 6px 16px;
    min-height: 30px;
}
QPushButton#secondaryBtn:hover {
    background: rgba(79, 142, 247, 0.14);
    border-color: rgba(79, 142, 247, 0.45);
    color: #90b8ff;
}
QPushButton#secondaryBtn:pressed { background: rgba(79, 142, 247, 0.20); }
QPushButton#secondaryBtn:disabled { color: #283448; border-color: #1a2038; background: transparent; }

/* ── Danger button ──────────────────────────────────────── */
QPushButton#dangerBtn {
    background: rgba(239, 68, 68, 0.07);
    color: #e06060;
    border: 1px solid rgba(239, 68, 68, 0.24);
    border-radius: 9px;
    font-size: 12px;
    font-weight: 600;
    padding: 5px 14px;
}
QPushButton#dangerBtn:hover {
    background: rgba(239, 68, 68, 0.14);
    border-color: rgba(239, 68, 68, 0.50);
    color: #f47070;
}
QPushButton#dangerBtn:disabled { color: #3a4458; border-color: #1a2038; background: transparent; }

/* ── Success button ─────────────────────────────────────── */
QPushButton#successBtn {
    background: rgba(52, 211, 153, 0.07);
    color: #30c088;
    border: 1px solid rgba(52, 211, 153, 0.24);
    border-radius: 9px;
    font-size: 12px;
    font-weight: 600;
    padding: 5px 14px;
}
QPushButton#successBtn:hover {
    background: rgba(52, 211, 153, 0.14);
    border-color: rgba(52, 211, 153, 0.50);
    color: #34d399;
}

/* ── Inner sub-tabs ─────────────────────────────────────── */
QTabWidget#innerTabs::pane { border: none; background: transparent; }
QTabWidget#innerTabs > QWidget > QTabBar { background: transparent; }
QTabBar::tab {
    background: transparent;
    color: #2e4860;
    border: none;
    border-bottom: 2px solid transparent;
    padding: 10px 20px;
    font-size: 12px;
    font-weight: 500;
    margin-right: 2px;
}
QTabBar::tab:selected {
    color: #c8e0ff;
    border-bottom: 2px solid #4f8ef7;
    font-weight: 600;
}
QTabBar::tab:hover:!selected { color: #7090b8; background: rgba(255,255,255,0.025); }
QTabBar { background: #0a0c1a; border-bottom: 1px solid #161c30; }

/* ── Scrollbars ─────────────────────────────────────────── */
QScrollBar:vertical {
    background: transparent;
    width: 6px;
    margin: 0;
}
QScrollBar::handle:vertical {
    background: rgba(255, 255, 255, 0.08);
    border-radius: 3px;
    min-height: 32px;
}
QScrollBar::handle:vertical:hover { background: rgba(79, 142, 247, 0.40); }
QScrollBar::handle:vertical:pressed { background: rgba(79, 142, 247, 0.60); }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: none; }
QScrollBar:horizontal {
    background: transparent;
    height: 6px;
    margin: 0;
}
QScrollBar::handle:horizontal {
    background: rgba(255, 255, 255, 0.08);
    border-radius: 3px;
    min-width: 32px;
}
QScrollBar::handle:horizontal:hover { background: rgba(79, 142, 247, 0.40); }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }

/* STATUS BAR */
QStatusBar {
    background: #07091a;
    border-top: 1px solid #101828;
    color: #2e4060;
    font-size: 12px;
    padding: 2px 10px;
}
QStatusBar::item { border: none; }

/* ── Tooltips ───────────────────────────────────────────── */
QToolTip {
    background: #141828;
    border: 1px solid #2a3458;
    color: #c8d8f0;
    padding: 8px 12px;
    border-radius: 10px;
    font-size: 12px;
}

/* GROUP BOX */
QGroupBox {
    background: transparent;
    border: 1px solid #1c2540;
    border-radius: 12px;
    font-weight: 600;
    font-size: 12px;
    color: #7890b0;
    margin-top: 14px;
    padding-top: 10px;
}
QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 10px;
    color: #4a6888;
    left: 16px;
}

/* ── Message / dialogs ──────────────────────────────────── */
QMessageBox { background: #0d0f1c; }
QMessageBox QLabel { color: #c8d8ee; font-size: 13px; }
QMessageBox QPushButton { min-width: 90px; min-height: 34px; }

/* ── Splitter ───────────────────────────────────────────── */
QSplitter::handle { background: #151a2a; }
QSplitter::handle:hover { background: rgba(79,142,247,0.20); }
QSplitter::handle:horizontal { width: 3px; }
QSplitter::handle:vertical { height: 3px; }

/* CHECKBOX */
QCheckBox {
    color: #7090b0;
    font-size: 13px;
    spacing: 8px;
}
QCheckBox::indicator {
    width: 18px;
    height: 18px;
    border-radius: 5px;
    border: 1px solid #1e2e50;
    background: #0c0e1e;
}
QCheckBox::indicator:hover { border-color: #4f8ef7; }
QCheckBox::indicator:checked {
    background: #4f8ef7;
    border-color: #4f8ef7;
}

/* ── Settings category buttons ──────────────────────────── */
QPushButton#catBtn {
    background: transparent;
    border: none;
    border-radius: 9px;
    color: #3a5070;
    text-align: left;
    padding: 7px 12px;
    font-size: 12px;
    font-weight: 500;
    min-height: 36px;
}
QPushButton#catBtn:hover {
    background: rgba(255, 255, 255, 0.04);
    color: #8fa8c8;
}
QPushButton#catBtn[active="1"] {
    background: rgba(79, 142, 247, 0.10);
    color: #7aaeff;
    font-weight: 600;
    border-left: 2px solid #4f8ef7;
    padding-left: 10px;
}
QPushButton#catBtn[active="1"]:hover {
    background: rgba(79, 142, 247, 0.18);
}

/* SETTINGS */
QWidget#settingsPanel            { background: transparent; }
QWidget#settingsCatSidebar       { background: #080a18; border-right: 1px solid #141a2e; }
"""


def _build_qss(accent: str = "#4f8ef7") -> str:
    h = accent.lstrip("#")
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return (
        _QSS_BASE
        .replace("#4f8ef7", accent)
        .replace("79, 142, 247", f"{r}, {g}, {b}")
    )


SEV_FRAME = {"critical": "cCrit", "high": "cHigh", "medium": "cMed", "low": "cLow"}
SEV_COLOR  = {"critical": "#f47070", "high": "#fb923c", "medium": "#f5c542", "low": "#60a8fa"}
STATUS_COLOR = {"SAFE": "#34d399", "ATTACK": "#f47070", "SUSPICIOUS": "#a78bfa"}


# ══════════════════════════════════════════════════════════════════════════════
# ── Background sniffer thread ─────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

class SnifferThread(QThread):
    packet_signal = pyqtSignal(dict)
    alert_signal  = pyqtSignal(dict)
    status_signal = pyqtSignal(str)

    def __init__(self, auto_block: bool = False, parent=None):
        super().__init__(parent)
        self.auto_block      = auto_block
        self._stop_event     = threading.Event()
        self._blocked_ips    = set(_load_blocked().keys())
        self._stats          = dict(total=0, safe=0, attacks=0, suspicious=0,
                                    rule_alerts=0, heuristic_alerts=0, active_flows=0)
        self._last_pkt_emit  = 0.0   # throttle UI updates to ≤20/s

    def stop(self):
        self._stop_event.set()

    def refresh_blocked(self):
        self._blocked_ips = set(_load_blocked().keys())

    def run(self):
        self.status_signal.emit("starting")

        try:
            import config
            from detectors.anomaly import AnomalyDetector
            from detectors.ddos import DDosDetector
            from detectors.flow_tracker import FlowTracker
            from detectors.ip_tracker import IPTracker
        except Exception as e:
            self.status_signal.emit(f"error:Detectors failed to load — {e}")
            return

        try:
            from scapy.all import IP, TCP, UDP, sniff
        except ImportError:
            self.status_signal.emit("error:Scapy not found — run: pip install scapy")
            return

        ddos_d = DDosDetector(config.MODEL_FILENAME, config.RULES_CONFIG,
                               config.ATTACK_CONFIDENCE_THRESHOLD)
        anm_d  = AnomalyDetector(config.ANOMALY_MODEL_FILENAME)
        flow_t = FlowTracker(min_packets=config.FLOW_MIN_PACKETS,
                              timeout_s=config.FLOW_TIMEOUT_S)
        _ml_alert_cooldown: dict[str, float] = {}  # src_ip → last alert time
        _ML_ALERT_COOLDOWN_S = 30.0                # max 1 ML alert per IP per 30 s
        ip_t   = IPTracker(window_s=config.IP_WINDOW_S,
                            syn_ack_ratio_threshold=config.SYN_ACK_RATIO_THRESHOLD,
                            conn_rate_threshold=config.CONN_RATE_THRESHOLD,
                            port_spread_threshold=config.PORT_SPREAD_THRESHOLD,
                            sustained_n=config.SUSTAINED_ATTACK_N)

        # ── New network-layer detectors ──────────────────────────────────────
        try:
            from detectors.arp_monitor import ARPMonitor
            from detectors.dns_monitor import DNSMonitor
            from detectors.brute_force import BruteForceDetector
            from detectors.threat_intel import ThreatIntel
            arp_m = ARPMonitor(on_alert=self.alert_signal.emit,
                               gateway_ip=getattr(config, "GATEWAY_IP", ""))
            dns_m = DNSMonitor(on_alert=self.alert_signal.emit)
            bf_d  = BruteForceDetector(on_alert=self.alert_signal.emit)
            ti    = ThreatIntel(api_key=getattr(config, "ABUSEIPDB_API_KEY", ""),
                                on_alert=self.alert_signal.emit)
        except Exception:
            arp_m = dns_m = bf_d = ti = None

        # ── New feature detectors ─────────────────────────────────────────────
        try:
            from detectors.tls_inspector import TLSInspector
            tls_d = TLSInspector(on_alert=self.alert_signal.emit)
        except Exception:
            tls_d = None

        try:
            from detectors.geo_mapper import GeoMapper
            geo_m = GeoMapper(on_alert=self.alert_signal.emit)
        except Exception:
            geo_m = None

        try:
            from detectors.ip_blocker import IPBlocker
            auto_blocker = IPBlocker(on_event=self.alert_signal.emit)
            auto_blocker.start()
        except Exception:
            auto_blocker = None

        from detectors.fusion import MLCorroborator, fuse_verdict as _fuse
        ml_gate = MLCorroborator(config.ML_ALERT_MIN_FLOWS, config.IP_WINDOW_S)

        _EMIT_INTERVAL = 0.05   # emit packet_signal at most 20×/s

        def _process(pkt):
            if self._stop_event.is_set():
                return

            # Layer-2 / application detectors — each self-filters; guard individually
            # so a malformed packet crashing one detector doesn't kill the others.
            if arp_m:
                try: arp_m.process_packet(pkt)
                except Exception: pass
            if dns_m:
                try: dns_m.process_packet(pkt)
                except Exception: pass
            if bf_d:
                try: bf_d.process_packet(pkt)
                except Exception: pass
            if tls_d:
                try: tls_d.process_packet(pkt)
                except Exception: pass

            if not pkt.haslayer(IP):
                return
            ip_l = pkt[IP]
            if ip_l.src in self._blocked_ips:
                return

            try:
                tcp  = pkt[TCP] if pkt.haslayer(TCP) else None
                udp  = pkt[UDP] if pkt.haslayer(UDP) else None
                proto = "TCP" if tcp else "UDP" if udp else str(ip_l.proto)
                length = len(pkt)
                tl   = tcp or udp
                sport = tl.sport if tl else 0
                dport = tl.dport if tl else 0
                pnum  = 6 if tcp else 17 if udp else int(ip_l.proto)
                flags = int(tcp.flags) if tcp else 0
                win   = int(tcp.window) if tcp else 0
                syn   = bool(flags & 0x02) and not bool(flags & 0x10)
                ack   = bool(flags & 0x10)

                pkt_info = {"src_ip": ip_l.src, "dst_ip": ip_l.dst,
                            "protocol": proto, "Length": length, "TTL": ip_l.ttl}
                rule_a = ddos_d.check_rules(pkt_info)

                ml_r = {}
                anm_r = {}
                fr = flow_t.update(src_ip=ip_l.src, dst_ip=ip_l.dst,
                                    src_port=sport, dst_port=dport,
                                    proto_num=pnum, pkt_len=length,
                                    tcp_flags=flags, win=win)
                if fr:
                    ff, _ = fr
                    if ddos_d.model_ready:
                        ml_r = ddos_d.predict(ff)
                    if anm_d.ready:
                        anm_r = anm_d.score(ff)
                    if (ml_r.get("verdict") in ("ATTACK", "SUSPICIOUS")
                            or anm_r.get("anomaly")):
                        ml_gate.record(ip_l.src, ip_l.dst)
                corroborated = ml_gate.is_active(ip_l.src, ip_l.dst)

                heur_a = ip_t.update(src_ip=ip_l.src, dst_port=dport,
                                       is_syn=syn, is_ack=ack, is_new_connection=syn,
                                       ml_verdict=ml_r.get("verdict") if ml_r else None)

                status = _fuse(ml_r, anm_r, rule_a, heur_a, corroborated)

                self._stats["total"] += 1
                if status == "ATTACK":
                    self._stats["attacks"] += 1
                elif status == "SUSPICIOUS":
                    self._stats["suspicious"] += 1
                else:
                    self._stats["safe"] += 1
                self._stats["active_flows"] = flow_t.active_flows

                # Throttle UI packet updates to ≤20/s to keep the UI responsive
                now = time.monotonic()
                if now - self._last_pkt_emit >= _EMIT_INTERVAL:
                    self._last_pkt_emit = now
                    ts = datetime.now().strftime("%H:%M:%S")
                    self.packet_signal.emit({
                        "timestamp": ts, "src_ip": ip_l.src, "dst_ip": ip_l.dst,
                        "protocol": proto, "length": length, "status": status,
                        "confidence": ml_r.get("confidence"),
                        "anomaly_score": anm_r.get("score"),
                        "model_ready": ddos_d.model_ready, "anomaly_ready": anm_d.ready,
                        "threshold": round(ddos_d.threshold * 100, 1),
                        **self._stats,
                    })

                ts_full = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                for a in rule_a:
                    self._stats["rule_alerts"] += 1
                    alert = {**a.to_dict(), "source_ip": ip_l.src, "timestamp": ts_full,
                             "ml_features": ff if fr else {}}
                    self.alert_signal.emit(alert)
                    if self.auto_block and a.severity == "critical":
                        self._auto_block(ip_l.src, a.rule_name)

                for h in heur_a:
                    self._stats["heuristic_alerts"] += 1
                    alert = {**h, "source_ip": ip_l.src, "timestamp": ts_full,
                             "ml_features": ff if fr else {}}
                    self.alert_signal.emit(alert)
                    if self.auto_block and h["severity"] == "critical":
                        self._auto_block(ip_l.src, h["rule_name"])

                # Emit ML attack alert — rate-limited per source IP (max 1 per 30 s)
                if (ml_r and ml_r.get("verdict") in ("ATTACK", "SUSPICIOUS") and ff
                        and corroborated):
                    _now = time.monotonic()
                    _src = ip_l.src
                    if _now - _ml_alert_cooldown.get(_src, 0.0) >= _ML_ALERT_COOLDOWN_S:
                        _ml_alert_cooldown[_src] = _now
                        self._stats["rule_alerts"] += 1
                        self.alert_signal.emit({
                            "rule_name":  f"ML: {ml_r['verdict']} ({ml_r.get('confidence',0):.0f}%)",
                            "severity":   "high" if ml_r["verdict"] == "ATTACK" else "medium",
                            "source_ip":  _src,
                            "message":    (f"ML classifier: {ml_r['verdict']} — "
                                           f"confidence {ml_r.get('confidence',0):.1f}% "
                                           f"(threshold {ml_r.get('threshold',0):.1f}%)"),
                            "timestamp":  ts_full,
                            "category":   "ddos",
                            "ml_features": ff,
                            "confidence":  ml_r.get("confidence", 0),
                        })

                # Async threat intel check for flagged source IPs
                if ti and status in ("ATTACK", "SUSPICIOUS"):
                    ti.check_ip_async(ip_l.src)

            except Exception:
                pass

        self.status_signal.emit("running")
        try:
            sniffer_filter = "ip or arp"   # include ARP for MitM detection
            try:
                import config
                sniffer_filter = getattr(config, "SNIFFER_FILTER", "ip or arp")
            except Exception:
                pass
            while not self._stop_event.is_set():
                sniff(filter=sniffer_filter, prn=_process, store=False, timeout=1)
        except Exception as e:
            self.status_signal.emit(f"error:{e}")
        finally:
            self.status_signal.emit("stopped")

    def _auto_block(self, ip: str, reason: str):
        if ip in self._blocked_ips or not IS_ADMIN:
            return
        ok, _ = _firewall_block(ip)
        if ok:
            self._blocked_ips.add(ip)
            data = _load_blocked()
            data[ip] = {
                "blocked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "reason": reason, "auto": True,
            }
            _save_blocked(data)


# ══════════════════════════════════════════════════════════════════════════════
# ── Custom paint widgets ───────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

class DonutGauge(QWidget):
    """Animated SVG-style donut gauge for the health score."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(130, 130)
        self._pct    = 100.0
        self._target = 100.0
        self._color  = QColor("#34d399")
        self._timer  = QTimer(self)
        self._timer.timeout.connect(self._step)

    def set_value(self, v: float):
        self._target = max(0.0, min(100.0, v))
        self._timer.start(16)

    def _step(self):
        diff = self._target - self._pct
        if abs(diff) < 0.3:
            self._pct = self._target
            self._timer.stop()
        else:
            self._pct += diff * 0.12
        pct = self._pct
        self._color = (
            QColor("#34d399") if pct >= 85 else
            QColor("#fbbf24") if pct >= 60 else
            QColor("#fb923c") if pct >= 35 else
            QColor("#f87171")
        )
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        m = 12
        rect = QRectF(m, m, w - 2 * m, h - 2 * m)

        # Track ring
        p.setPen(QPen(QColor("#161c30"), 11, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawEllipse(rect)

        # Soft glow behind arc (wider, lower opacity)
        if self._pct > 0:
            glow_col = QColor(self._color); glow_col.setAlpha(40)
            p.setPen(QPen(glow_col, 18, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
            span = int(-360 * 16 * self._pct / 100)
            p.drawArc(rect, 90 * 16, span)
            # Crisp arc on top
            p.setPen(QPen(self._color, 11, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
            p.drawArc(rect, 90 * 16, span)

        # Center text
        p.setPen(QPen(self._color))
        f = QFont("Segoe UI", 17)
        f.setWeight(QFont.Weight.Bold)
        p.setFont(f)
        p.drawText(rect.adjusted(0, 2, 0, 2), Qt.AlignmentFlag.AlignCenter,
                   f"{int(self._pct)}%")
        p.end()


class MiniChart(QWidget):
    """Smooth multi-line traffic chart, ticks every second via QTimer."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(150)
        self._safe = deque(maxlen=60)
        self._susp = deque(maxlen=60)
        self._atk  = deque(maxlen=60)
        self._cs = self._cu = self._ca = 0
        self._tick_timer = QTimer(self)
        self._tick_timer.timeout.connect(self._tick)
        self._tick_timer.start(1000)

    def feed(self, status: str):
        if status == "SAFE":       self._cs += 1
        elif status == "SUSPICIOUS": self._cu += 1
        elif status == "ATTACK":   self._ca += 1

    def _tick(self):
        self._safe.append(self._cs)
        self._susp.append(self._cu)
        self._atk.append(self._ca)
        self._cs = self._cu = self._ca = 0
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        pl, pr, pt, pb = 8, 8, 8, 22

        # Grid
        p.setPen(QPen(QColor("#1c2138"), 1))
        for i in range(1, 4):
            y = pt + (h - pt - pb) * i // 4
            p.drawLine(pl, y, w - pr, y)

        n = len(self._safe)
        if n < 2:
            p.setPen(QPen(QColor("#374166")))
            p.setFont(QFont("Segoe UI", 11))
            p.drawText(QRectF(0, 0, w, h), Qt.AlignmentFlag.AlignCenter,
                       "Waiting for traffic…")
            p.end()
            return

        all_v = list(self._safe) + list(self._susp) + list(self._atk)
        mx = max(all_v) if max(all_v) > 0 else 1
        cw = w - pl - pr
        ch = h - pt - pb
        step = cw / (n - 1)

        def _pts(data):
            return [QPointF(pl + i * step, pt + ch - (v / mx) * ch)
                    for i, v in enumerate(data)]

        def _draw(data, hex_color):
            pts = _pts(data)
            if len(pts) < 2:
                return
            path = QPainterPath()
            path.moveTo(pts[0])
            for i in range(1, len(pts)):
                p0, p1 = pts[i - 1], pts[i]
                cx = (p0.x() + p1.x()) / 2
                path.cubicTo(QPointF(cx, p0.y()), QPointF(cx, p1.y()), p1)

            # Filled area beneath the line
            fill = QPainterPath(path)
            fill.lineTo(pts[-1].x(), pt + ch)
            fill.lineTo(pts[0].x(),  pt + ch)
            fill.closeSubpath()
            col = QColor(hex_color); col.setAlpha(28)
            p.setBrush(col); p.setPen(Qt.PenStyle.NoPen)
            p.drawPath(fill)

            # Line on top
            pen = QPen(QColor(hex_color), 2)
            pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            p.setPen(pen); p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawPath(path)

        _draw(self._safe, "#34d399")
        _draw(self._susp, "#a78bfa")
        _draw(self._atk,  "#f87171")

        # Legend
        p.setFont(QFont("Segoe UI", 10))
        for i, (label, color) in enumerate([
            ("Safe", "#34d399"), ("Suspicious", "#a78bfa"), ("Attack", "#f87171")
        ]):
            x = pl + i * (w - 2 * pl) // 3
            p.setPen(QPen(QColor(color), 2))
            p.drawLine(x, h - 9, x + 14, h - 9)
            p.setPen(QPen(QColor("#8fa3c0")))
            p.drawText(x + 18, h - 3, label)
        p.end()


# ══════════════════════════════════════════════════════════════════════════════
# ── Shared UI helpers ──────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

def _sep():
    """Horizontal separator line."""
    f = QFrame()
    f.setFrameShape(QFrame.Shape.HLine)
    f.setStyleSheet("background:rgba(255,255,255,0.06); max-height:1px; border:none;")
    return f


def _lbl(text, style=""):
    l = QLabel(text)
    if style:
        l.setStyleSheet(style)
    return l


def _page_header(icon: str, title: str, subtitle: str = "",
                 actions: "list[QWidget] | None" = None) -> QFrame:
    """Full-width page identity header for every tab."""
    frame = QFrame()
    frame.setStyleSheet(
        "QFrame { background: #0f1222; border: none; border-bottom: 1px solid #1a2240; }"
    )
    frame.setFixedHeight(72 if subtitle else 58)
    lay = QHBoxLayout(frame)
    lay.setContentsMargins(24, 0, 20, 0)
    lay.setSpacing(14)

    if icon:
        ic = QLabel(icon)
        ic.setFixedSize(36, 36)
        ic.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ic.setStyleSheet("font-size: 20px; background: transparent;")
        lay.addWidget(ic)

    txt = QVBoxLayout(); txt.setSpacing(1)
    txt.addWidget(_lbl(title,
        "font-size: 17px; font-weight: 700; color: #d8e8f8; background: transparent;"))
    if subtitle:
        txt.addWidget(_lbl(subtitle,
            "font-size: 11px; color: #3a5070; background: transparent;"))
    lay.addLayout(txt)
    lay.addStretch()

    if actions:
        for w in actions:
            lay.addWidget(w)

    return frame


def _make_stat_card(icon: str, title: str, color: str) -> tuple[QFrame, QLabel]:
    card = QFrame()
    card.setObjectName("card")
    # Top accent line painted via a nested widget approach using stylesheet
    c_accent = QColor(color)
    c_bg = QColor(color); c_bg.setAlpha(18)
    card.setStyleSheet(
        f"QFrame#card {{"
        f"  border-top: 2px solid {color};"
        f"  border-radius: 14px;"
        f"}}"
    )

    lay = QHBoxLayout(card)
    lay.setContentsMargins(16, 16, 16, 16)
    lay.setSpacing(14)

    # Colored icon circle — 44x44
    ic = QLabel(icon)
    ic.setFixedSize(44, 44)
    ic.setAlignment(Qt.AlignmentFlag.AlignCenter)
    c_icon = QColor(color); c_icon.setAlpha(30)
    ic.setStyleSheet(
        f"background:{c_icon.name(QColor.NameFormat.HexArgb)};"
        "border-radius:12px; font-size:20px;"
    )
    lay.addWidget(ic)

    info = QVBoxLayout(); info.setSpacing(3)
    val = QLabel("0")
    val.setStyleSheet(
        f"font-size:24px; font-weight:700; font-family:'Consolas','Cascadia Code';"
        f"color:{color}; background:transparent;"
    )
    info.addWidget(val)
    lbl_title = _lbl(title, "font-size:11px; color:#4a6080; letter-spacing:0.4px; background:transparent;")
    info.addWidget(lbl_title)
    lay.addLayout(info, 1)
    return card, val


def _make_badge(text: str, color: str) -> QLabel:
    lbl = QLabel(f"  {text}  ")
    lbl.setStyleSheet(
        f"color:{color}; background:rgba(0,0,0,0.25); border:1px solid {color};"
        "border-radius:99px; font-size:10px; font-weight:700; padding:2px 2px;"
        "letter-spacing:0.5px;"
    )
    lbl.setFixedHeight(20)
    return lbl


def _make_badge_icon(emoji: str, hex_color: str) -> QIcon:
    """32×32 sidebar nav icon — colored rounded square with centred emoji."""
    sz = 32
    px = QPixmap(sz, sz)
    px.fill(Qt.GlobalColor.transparent)
    p  = QPainter(px)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    bg = QColor(hex_color); bg.setAlpha(40)
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QBrush(bg))
    p.drawRoundedRect(2, 2, sz - 4, sz - 4, 8, 8)
    p.setFont(QFont("Segoe UI Emoji", 13))
    p.drawText(QRectF(0, 0, sz, sz), Qt.AlignmentFlag.AlignCenter, emoji)
    p.end()
    return QIcon(px)


def _make_shield_logo(size: int = 40) -> QPixmap:
    """Custom shield logo with gradient fill and 'SM' monogram."""
    px = QPixmap(size, size)
    px.fill(Qt.GlobalColor.transparent)
    p  = QPainter(px)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    s  = float(size)

    grad = QLinearGradient(QPointF(0, 0), QPointF(0, s))
    grad.setColorAt(0.0, QColor("#5b9cf6"))
    grad.setColorAt(1.0, QColor("#2d5bc4"))

    shield = QPainterPath()
    shield.moveTo(s / 2, 1)
    shield.lineTo(s - 2, s * 0.22)
    shield.lineTo(s - 2, s * 0.56)
    shield.cubicTo(QPointF(s - 2, s * 0.82),
                   QPointF(s / 2 + 1, s - 2), QPointF(s / 2, s - 1))
    shield.cubicTo(QPointF(s / 2 - 1, s - 2),
                   QPointF(2, s * 0.82), QPointF(2, s * 0.56))
    shield.lineTo(2, s * 0.22)
    shield.closeSubpath()

    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QBrush(grad))
    p.drawPath(shield)

    # Highlight sheen
    sheen = QLinearGradient(QPointF(0, 0), QPointF(0, s * 0.35))
    sheen.setColorAt(0, QColor(255, 255, 255, 55))
    sheen.setColorAt(1, QColor(255, 255, 255, 0))
    p.setBrush(QBrush(sheen))
    p.drawPath(shield)

    # "SM" monogram
    f = QFont("Segoe UI", max(8, int(s * 0.28)), QFont.Weight.Bold)
    p.setFont(f)
    p.setPen(QPen(QColor(255, 255, 255, 230)))
    p.drawText(QRectF(0, s * 0.22, s, s * 0.55), Qt.AlignmentFlag.AlignCenter, "SM")
    p.end()
    return px


def _icon_circle(emoji: str, bg_hex: str, circle_size: int = 40) -> QLabel:
    """A label that renders as a solid colored circle with an emoji inside."""
    lbl = QLabel(emoji)
    lbl.setFixedSize(circle_size, circle_size)
    lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
    lbl.setStyleSheet(
        f"background:{bg_hex}; border-radius:{circle_size // 2}px;"
        "font-size:18px;"
    )
    return lbl


class ToggleSwitch(QWidget):
    """Animated pill-style on/off toggle."""
    toggled = pyqtSignal(bool)

    def __init__(self, checked: bool = True, parent=None):
        super().__init__(parent)
        self._checked  = checked
        self._pos      = 1.0 if checked else 0.0
        self._timer    = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self.setFixedSize(46, 26)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

    def isChecked(self) -> bool:
        return self._checked

    def setChecked(self, v: bool):
        if v != self._checked:
            self._checked = v
            self._timer.start(14)

    def mousePressEvent(self, _):
        self._checked = not self._checked
        self._timer.start(14)
        self.toggled.emit(self._checked)

    def _tick(self):
        target = 1.0 if self._checked else 0.0
        diff   = target - self._pos
        if abs(diff) < 0.04:
            self._pos = target
            self._timer.stop()
        else:
            self._pos += diff * 0.22
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        # Track
        col = QColor("#4f8ef7") if self._checked else QColor("#1e2440")
        alpha = int(180 + 75 * self._pos) if self._checked else int(160 + 40 * (1 - self._pos))
        col.setAlpha(alpha)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QBrush(col))
        p.drawRoundedRect(0, 0, w, h, h // 2, h // 2)
        # Thumb
        margin  = 3
        thumb_d = h - margin * 2
        thumb_x = int(margin + self._pos * (w - thumb_d - margin * 2))
        p.setBrush(QBrush(QColor("#ffffff")))
        p.drawEllipse(thumb_x, margin, thumb_d, thumb_d)
        p.end()


# ══════════════════════════════════════════════════════════════════════════════
# ── Dashboard tab ──────────────────────────────────────────════════════════════
# ══════════════════════════════════════════════════════════════════════════════

class DashboardTab(QWidget):
    navigate_to = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._health   = 100.0
        self._last_thr = 0.0
        self._activity_count = 0
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 20, 20, 20)
        root.setSpacing(14)

        # ── Health banner
        _hour = datetime.now().hour
        _greeting = "Good morning" if _hour < 12 else ("Good afternoon" if _hour < 17 else "Good evening")
        banner = QFrame(); banner.setObjectName("card")
        banner.setStyleSheet(
            "QFrame#card { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            "stop:0 #12152c, stop:0.6 #0f1228, stop:1 #0a0c1e);"
            "border: 1px solid #1e2448; border-top: 1px solid #263060; border-radius: 16px; }"
        )
        bl = QHBoxLayout(banner); bl.setContentsMargins(28, 24, 28, 24); bl.setSpacing(24)
        self.gauge = DonutGauge()
        bl.addWidget(self.gauge)
        info = QVBoxLayout(); info.setSpacing(4)
        greet_lbl = _lbl(f"{_greeting}.", "font-size:12px; color:#3a5880; letter-spacing:0.3px;")
        self.h_title = _lbl("Your network is healthy",
                             "font-size:22px; font-weight:700; color:#e6eeff; letter-spacing:-0.3px;")
        self.h_sub   = _lbl("Everything looks clear — monitoring your traffic in real time.",
                             "color:#556680; font-size:13px;")
        self.h_sub.setWordWrap(True)
        self.h_meta  = _lbl("Packets: 0  ·  Flows: 0",
                             "color:#273650; font-size:11.5px; font-family:Consolas;")
        info.addWidget(greet_lbl)
        info.addSpacing(2)
        info.addWidget(self.h_title)
        info.addWidget(self.h_sub)
        info.addSpacing(6)
        info.addWidget(self.h_meta)
        bl.addLayout(info, 1)
        # Live clock
        self._clock_lbl = _lbl("", "font-size:11px; color:#2a3a5a; font-family:Consolas;")
        self._clock_lbl.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignTop)
        bl.addWidget(self._clock_lbl)
        self._clock_timer = QTimer(self)
        self._clock_timer.timeout.connect(self._tick_clock)
        self._clock_timer.start(1000)
        self._tick_clock()
        root.addWidget(banner)

        # ── Stats row
        stats_row = QHBoxLayout(); stats_row.setSpacing(10)
        self._stat_vals = {}
        for key, icon, title, color in [
            ("total",      "📡", "Packets analysed",    "#5b9cf6"),
            ("safe",       "✅", "Confirmed safe",       "#34d399"),
            ("attacks",    "🚨", "Confirmed attacks",    "#f87171"),
            ("suspicious", "⚡", "Suspicious flows",     "#a78bfa"),
            ("alerts",     "⚠️", "Rule / heuristic",     "#fbbf24"),
        ]:
            card, val = _make_stat_card(icon, title, color)
            stats_row.addWidget(card, 1)
            self._stat_vals[key] = val
        root.addLayout(stats_row)

        # ── AI Security Score banner
        self._ai_score_card = QFrame(); self._ai_score_card.setObjectName("card")
        self._ai_score_card.setStyleSheet(
            "QFrame#card { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            "stop:0 #0e1220, stop:1 #111828); border:1px solid #1e2240; border-radius:14px; }"
        )
        asl = QHBoxLayout(self._ai_score_card)
        asl.setContentsMargins(22, 14, 22, 14); asl.setSpacing(20)

        # Score circle
        self._ai_score_circle = QLabel("—")
        self._ai_score_circle.setFixedSize(58, 58)
        self._ai_score_circle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._ai_score_circle.setStyleSheet(
            "background: rgba(79,142,247,0.12); border-radius: 29px;"
            "font-size: 20px; font-weight: 800; color: #4f8ef7; border: 2px solid rgba(79,142,247,0.3);"
        )
        asl.addWidget(self._ai_score_circle)

        # Text block
        score_info = QVBoxLayout(); score_info.setSpacing(3)
        score_hdr  = QHBoxLayout(); score_hdr.setSpacing(10)
        score_hdr.addWidget(_lbl("AI Security Score", "font-size:13px; font-weight:700; color:#dde6f0;"))
        self._ai_grade_lbl = _lbl("", "font-size:11px; font-weight:700; padding:2px 8px;"
                                      "border-radius:5px; background:#1a2a10; color:#34d399;")
        score_hdr.addWidget(self._ai_grade_lbl); score_hdr.addStretch()
        score_info.addLayout(score_hdr)
        self._ai_desc_lbl = _lbl(
            "Click 'Compute Metrics' in ML Analysis to evaluate model robustness.",
            "font-size:11px; color:#445068;"
        )
        self._ai_desc_lbl.setWordWrap(True)
        score_info.addWidget(self._ai_desc_lbl)

        # Component pills
        self._ai_comp_row = QHBoxLayout(); self._ai_comp_row.setSpacing(8)
        self._ai_comp_labels: dict[str, QLabel] = {}
        for key, label in [("detection_rate","Detection"),
                            ("false_positive_rate","Low FP"),
                            ("model_confidence","Confidence"),
                            ("adversarial_robustness","Robustness")]:
            pill = _lbl(f"{label}: —", "font-size:10px; color:#556077; padding:2px 7px;"
                                        "border-radius:5px; background:#0d1020;")
            self._ai_comp_row.addWidget(pill)
            self._ai_comp_labels[key] = pill
        self._ai_comp_row.addStretch()
        score_info.addLayout(self._ai_comp_row)

        asl.addLayout(score_info, 1)

        # Go-to button
        ai_btn = QPushButton("📊  Open ML Analysis")
        ai_btn.setObjectName("secondaryBtn"); ai_btn.setFixedHeight(32)
        ai_btn.clicked.connect(lambda: self.navigate_to.emit("mlanalysis"))
        asl.addWidget(ai_btn)

        root.addWidget(self._ai_score_card)

        # ── Bottom row: activity + quick actions
        bot = QHBoxLayout(); bot.setSpacing(12)

        # Activity list
        act = QFrame(); act.setObjectName("card")
        al  = QVBoxLayout(act); al.setContentsMargins(0, 0, 0, 0); al.setSpacing(0)
        head = QHBoxLayout(); head.setContentsMargins(16, 14, 16, 10)
        head.addWidget(_lbl("Recent Activity", "font-size:13px; font-weight:700; color:#dde6f0;"))
        al.addLayout(head)
        al.addWidget(_sep())
        self._act_scroll = QScrollArea()
        self._act_scroll.setWidgetResizable(True)
        self._act_scroll.setFrameShape(QFrame.Shape.NoFrame)
        self._act_inner  = QWidget()
        self._act_vlay   = QVBoxLayout(self._act_inner)
        self._act_vlay.setContentsMargins(0, 0, 0, 0)
        self._act_vlay.setSpacing(0)
        self._act_empty  = _lbl("All quiet right now — no recent events.\nYour network looks calm.",
                                 "color:#2a3a5a; font-size:13px; padding:36px;")
        self._act_empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._act_vlay.addWidget(self._act_empty)
        self._act_vlay.addStretch()
        self._act_scroll.setWidget(self._act_inner)
        al.addWidget(self._act_scroll)
        bot.addWidget(act, 3)

        # Quick actions
        qa = QFrame(); qa.setObjectName("card")
        ql = QVBoxLayout(qa); ql.setContentsMargins(14, 14, 14, 14); ql.setSpacing(10)
        ql.addWidget(_lbl("Quick Actions",
                          "font-size:13px; font-weight:700; color:#c8d8ee; background:transparent;"))
        ql.addWidget(_lbl("Navigate to any section instantly",
                          "font-size:11px; color:#3a5070; background:transparent;"))
        ql.addSpacing(2)

        self._qa_btns = {}
        _qa_items = [
            ("traffic",     "📡", "Live Traffic",    "#34d399"),
            ("threats",     "🚨", "Threats",         "#f47070"),
            ("system",      "🖥", "System Monitor",  "#a78bfa"),
            ("geomap",      "🗺", "Geo Map",         "#2dd4bf"),
            ("filescanner", "🔍", "File Scanner",    "#fbbf24"),
            ("blocked",     "🔒", "Blocked IPs",     "#fb923c"),
            ("tools",       "🧪", "Test & Analyse",  "#8fa3c0"),
            ("mlanalysis",  "📊", "ML Analysis",     "#2dd4bf"),
            ("advlab",      "⚡", "Adversarial Lab", "#f5c542"),
        ]
        grid = QGridLayout(); grid.setSpacing(6)
        for idx, (tab, icon, label, color) in enumerate(_qa_items):
            btn = QPushButton(f" {icon}  {label}")
            btn.setMinimumHeight(36)
            btn.setStyleSheet(
                f"QPushButton {{"
                f"  background: rgba(255,255,255,0.03);"
                f"  color: #a8c0de;"
                f"  border: 1px solid #1e2848;"
                f"  border-left: 3px solid {color};"
                f"  border-radius: 8px;"
                f"  text-align: left;"
                f"  font-size: 12px;"
                f"  font-weight: 500;"
                f"  padding: 0 10px 0 8px;"
                f"}}"
                f"QPushButton:hover {{"
                f"  background: rgba(255,255,255,0.07);"
                f"  color: #dce8f8;"
                f"  border-color: #2a3860;"
                f"  border-left-color: {color};"
                f"}}"
                f"QPushButton:pressed {{"
                f"  background: rgba(255,255,255,0.10);"
                f"}}"
            )
            btn.clicked.connect(lambda _, t=tab: self.navigate_to.emit(t))
            grid.addWidget(btn, idx // 2, idx % 2)
            self._qa_btns[tab] = btn

        ql.addLayout(grid)
        ql.addSpacing(4)

        exp = QPushButton("💾  Export Alert Log")
        exp.setMinimumHeight(34)
        exp.setStyleSheet(
            "QPushButton {"
            "  background: rgba(79,142,247,0.06);"
            "  color: #7090c8;"
            "  border: 1px solid rgba(79,142,247,0.18);"
            "  border-radius: 8px;"
            "  font-size: 12px; font-weight: 500;"
            "  text-align: left; padding-left: 12px;"
            "}"
            "QPushButton:hover {"
            "  background: rgba(79,142,247,0.12);"
            "  color: #a0c0f0;"
            "  border-color: rgba(79,142,247,0.35);"
            "}"
        )
        exp.clicked.connect(self._export)
        ql.addWidget(exp)
        ql.addStretch()
        bot.addWidget(qa, 1)
        root.addLayout(bot, 1)

        # Recovery timer stored as child
        t = QTimer(self); t.timeout.connect(self._recover); t.start(10_000)

    # ── Updates from sniffer ────────────────────────────────────────────────

    def on_packet(self, d: dict):
        status = d.get("status", "SAFE")
        if status == "ATTACK":
            self._health = max(0.0, self._health - 14.0)
            self._last_thr = time.time()
            self._add_activity("🚨", f"Possible attack from {d.get('src_ip','?')}",
                               f"{d.get('protocol','?')} · {d.get('length',0)} B → {d.get('dst_ip','?')}",
                               d.get("timestamp", ""), "#f87171")
        elif status == "SUSPICIOUS":
            self._health = max(0.0, self._health - 3.0)
            self._last_thr = time.time()
            self._add_activity("⚡", f"Suspicious flow from {d.get('src_ip','?')}",
                               f"{d.get('protocol','?')} · {d.get('length',0)} B",
                               d.get("timestamp", ""), "#a78bfa")

        total = d.get("total", 0)
        self._stat_vals["total"].setText(f"{total:,}")
        self._stat_vals["safe"].setText(f"{d.get('safe', 0):,}")
        self._stat_vals["attacks"].setText(f"{d.get('attacks', 0):,}")
        self._stat_vals["suspicious"].setText(f"{d.get('suspicious', 0):,}")
        alerts = d.get("rule_alerts", 0) + d.get("heuristic_alerts", 0)
        self._stat_vals["alerts"].setText(f"{alerts:,}")
        self.h_meta.setText(
            f"Packets: {total:,}  ·  Flows: {d.get('active_flows', 0):,}"
        )
        self._update_health()

    def on_alert(self, a: dict):
        self._add_activity("⚠️", _humanize(a)[:70],
                           f"{a.get('rule_name','?')} · {a.get('source_ip','?')}",
                           (a.get("timestamp", ""))[-8:], "#fbbf24")

    def _recover(self):
        if time.time() - self._last_thr > 30 and self._health < 100:
            self._health = min(100.0, self._health + 1.0)
            self._update_health()

    def _update_health(self):
        h = self._health
        self.gauge.set_value(h)
        if h >= 85:
            t = "Your network is healthy"
            s = "Everything looks clear — we're watching your traffic in real time."
            c = "#e2eeff"
        elif h >= 65:
            t = "Some unusual activity detected"
            s = "A few suspicious flows were spotted. Worth keeping an eye on."
            c = "#fbbf24"
        elif h >= 40:
            t = "Suspicious patterns detected"
            s = "Multiple suspicious events observed recently. Check the Threats tab."
            c = "#fb923c"
        elif h >= 20:
            t = "Potential attack in progress"
            s = "Signs of an active attack detected. Check Threats immediately."
            c = "#f87171"
        else:
            t = "⚠  Active attack detected!"
            s = "Your network appears to be under attack. Immediate attention recommended."
            c = "#f87171"
        self.h_title.setText(t)
        self.h_title.setStyleSheet(f"font-size:22px; font-weight:700; color:{c}; letter-spacing:-0.3px;")
        self.h_sub.setText(s)

    def _tick_clock(self):
        self._clock_lbl.setText(datetime.now().strftime("%H:%M:%S\n%d %b %Y"))

    def _add_activity(self, icon, title, sub, ts, color):
        if self._act_empty.isVisible():
            self._act_empty.hide()
        item = QFrame()
        item.setStyleSheet(
            f"QFrame {{ border-left: 3px solid {color}; background: rgba(255,255,255,0.015);"
            f"border-top-right-radius:8px; border-bottom-right-radius:8px; }}"
            f"QFrame:hover {{ background: rgba(255,255,255,0.03); }}"
        )
        il = QHBoxLayout(item); il.setContentsMargins(14, 10, 16, 10); il.setSpacing(12)
        icon_lbl = _lbl(icon, f"font-size:16px; background:transparent;")
        icon_lbl.setFixedWidth(22)
        il.addWidget(icon_lbl)
        tl = QVBoxLayout(); tl.setSpacing(2)
        tl.addWidget(_lbl(title, "font-size:12.5px; font-weight:600; color:#c8d8ee; background:transparent;"))
        tl.addWidget(_lbl(sub,   "font-size:11px; color:#4a6080; background:transparent;"))
        il.addLayout(tl, 1)
        time_lbl = _lbl(ts, "font-size:10.5px; color:#2a3a54; font-family:Consolas; background:transparent;")
        time_lbl.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        il.addWidget(time_lbl)
        self._act_vlay.insertWidget(0, item)
        self._activity_count += 1
        if self._activity_count > 15:
            # Layout: [item_N, ..., item_1, _act_empty, stretch]
            # The oldest item is at index count-3 (before _act_empty at count-2, stretch at count-1)
            c = self._act_vlay.count()
            it = self._act_vlay.takeAt(c - 3)
            if it and it.widget():
                it.widget().deleteLater()

    def _export(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Alert Log", str(ROOT / "alerts_export.json"),
            "JSON files (*.json)"
        )
        if path:
            data = _load_blocked()
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"exported": datetime.now().isoformat(),
                           "blocked_ips": data}, f, indent=2)
            QMessageBox.information(self, "Exported", f"Saved to {path}")

    def update_ai_score(self, result: dict) -> None:
        """Update the AI Security Score banner with fresh computed results."""
        score = result.get("score", 0)
        grade = result.get("grade", "?")
        desc  = result.get("description", "")
        comps = result.get("components", {})

        # Score circle
        colors = {"A+": "#34d399", "A": "#4ade80", "B": "#facc15",
                  "C": "#fb923c", "D": "#f87171"}
        col = colors.get(grade, "#4f8ef7")
        self._ai_score_circle.setText(str(score))
        self._ai_score_circle.setStyleSheet(
            f"background: rgba(79,142,247,0.10); border-radius:29px;"
            f"font-size:20px; font-weight:800; color:{col};"
            f"border: 2px solid {col}40;"
        )

        # Grade badge
        bg_map = {"A+": "#0a2010", "A": "#0a2010", "B": "#1a1a08",
                  "C": "#1a1008", "D": "#1a0808"}
        self._ai_grade_lbl.setText(f"  Grade {grade}  ")
        self._ai_grade_lbl.setStyleSheet(
            f"font-size:11px; font-weight:700; padding:2px 8px; border-radius:5px;"
            f"background:{bg_map.get(grade,'#111')}; color:{col};"
        )

        # Description
        self._ai_desc_lbl.setText(desc)

        # Component pills
        comp_colors = {"A+": "#34d399", "A": "#4ade80", "B": "#facc15"}
        labels = {"detection_rate": "Detection", "false_positive_rate": "Low FP",
                  "model_confidence": "Confidence", "adversarial_robustness": "Robustness"}
        for key, lbl_widget in self._ai_comp_labels.items():
            val = comps.get(key, 0)
            pill_col = "#34d399" if val >= 80 else "#facc15" if val >= 60 else "#f87171"
            lbl_widget.setText(f"{labels[key]}: {val:.0f}%")
            lbl_widget.setStyleSheet(
                f"font-size:10px; color:{pill_col}; padding:2px 7px;"
                f"border-radius:5px; background:{pill_col}18;"
            )


# ══════════════════════════════════════════════════════════════════════════════
# ── Traffic tab ────────────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

class TrafficTab(QWidget):
    _MAX_ROWS = 300   # hard cap on in-memory rows

    def __init__(self, parent=None):
        super().__init__(parent)
        self._all_rows: list[dict] = []
        self._filter_status = "all"
        self._filter_ip     = ""
        self._dirty         = False
        self._build()
        # Refresh table at most 4×/s regardless of packet rate
        self._refresh_timer = QTimer(self)
        self._refresh_timer.timeout.connect(self._maybe_apply)
        self._refresh_timer.start(250)

    def _build(self):
        root = QVBoxLayout(self); root.setContentsMargins(0, 0, 0, 0); root.setSpacing(0)
        root.addWidget(_page_header("📡", "Live Traffic",
            "Real-time packet stream — every flow classified as it arrives"))

        inner = QWidget(); inner.setStyleSheet("background: #0b0d1e;")
        il = QVBoxLayout(inner); il.setContentsMargins(20, 16, 20, 16); il.setSpacing(12)

        chart_card = QFrame(); chart_card.setObjectName("card")
        cl = QVBoxLayout(chart_card); cl.setContentsMargins(0, 10, 0, 0); cl.setSpacing(0)
        cl.addWidget(_lbl("  Packets per second — last 60 s",
                           "font-size:13px; font-weight:700; color:#c8d8ee; padding:4px 16px; background:transparent;"))
        self.chart = MiniChart()
        cl.addWidget(self.chart)
        il.addWidget(chart_card)

        # Filter bar
        fb = QHBoxLayout(); fb.setSpacing(8)
        self._filter_btns = {}
        for key, label in [("all","All"),("SAFE","Safe"),("SUSPICIOUS","Suspicious"),("ATTACK","Attack")]:
            b = QPushButton(label); b.setObjectName("secondaryBtn")
            b.setFixedHeight(28)
            b.clicked.connect(lambda _, k=key: self._set_filter(k))
            fb.addWidget(b)
            self._filter_btns[key] = b
        fb.addWidget(_sep_v())
        self._ip_search = QLineEdit(); self._ip_search.setPlaceholderText("Filter by IP…")
        self._ip_search.setFixedHeight(28)
        self._ip_search.textChanged.connect(lambda _: (setattr(self, '_dirty', False), self._apply()))
        fb.addWidget(self._ip_search, 1)
        self._row_count_lbl = _lbl("— rows", "color:#445068; font-size:12px; font-family:Consolas;")
        fb.addWidget(self._row_count_lbl)
        clr = QPushButton("Clear"); clr.setObjectName("secondaryBtn"); clr.setFixedHeight(28)
        clr.clicked.connect(self._clear); fb.addWidget(clr)
        il.addLayout(fb)

        # Table
        cols = ["Time", "Protocol", "Source", "Destination", "Size", "Status", "Confidence", "IF Score"]
        self.tbl = QTableWidget(0, len(cols))
        self.tbl.setHorizontalHeaderLabels(cols)
        self.tbl.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.tbl.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.tbl.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.tbl.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.tbl.verticalHeader().setVisible(False)
        self.tbl.setAlternatingRowColors(False)
        il.addWidget(self.tbl, 1)
        root.addWidget(inner, 1)
        self._set_filter("all")

    def add_row(self, d: dict):
        self._all_rows.insert(0, d)
        if len(self._all_rows) > self._MAX_ROWS:
            del self._all_rows[self._MAX_ROWS:]
        self.chart.feed(d.get("status", "SAFE"))
        self._dirty = True   # table will refresh on next timer tick

    def _maybe_apply(self):
        if self._dirty:
            self._dirty = False
            self._apply()

    def _set_filter(self, key: str):
        self._filter_status = key
        for k, b in self._filter_btns.items():
            b.setStyleSheet(
                "background:rgba(79,142,247,.16);color:#7ab4ff;border:1px solid rgba(79,142,247,.55);"
                "border-radius:9px;font-size:12px;font-weight:600;padding:4px 14px;"
                if k == key else
                "background:transparent;color:#5580b8;border:1px solid rgba(79,142,247,.25);"
                "border-radius:9px;font-size:12px;font-weight:500;padding:4px 14px;"
            )
        self._dirty = False
        self._apply()   # immediate response to user action

    def _apply(self):
        ip_q = self._ip_search.text().strip().lower()
        rows = [r for r in self._all_rows if
                (self._filter_status == "all" or r.get("status") == self._filter_status) and
                (not ip_q or ip_q in r.get("src_ip","").lower() or ip_q in r.get("dst_ip","").lower())]
        self.tbl.setRowCount(0)
        for r in rows[:150]:
            i = self.tbl.rowCount(); self.tbl.insertRow(i)
            status = r.get("status", "SAFE")
            conf   = f"{r['confidence']:.1f}%" if r.get("confidence") is not None else "—"
            ascore = f"{r['anomaly_score']:.3f}" if r.get("anomaly_score") is not None else "—"
            cells  = [r.get("timestamp",""), r.get("protocol",""), r.get("src_ip",""),
                      r.get("dst_ip",""), f"{r.get('length',0)} B", status, conf, ascore]
            for j, text in enumerate(cells):
                it = QTableWidgetItem(text)
                if j == 5:
                    it.setForeground(QColor(STATUS_COLOR.get(status, "#8fa3c0")))
                else:
                    it.setForeground(QColor("#8fa3c0"))
                self.tbl.setItem(i, j, it)
        self._row_count_lbl.setText(f"{len(rows)} rows")

    def _clear(self):
        self._all_rows.clear(); self.tbl.setRowCount(0)
        self._row_count_lbl.setText("0 rows")


def _sep_v() -> QFrame:
    f = QFrame(); f.setFrameShape(QFrame.Shape.VLine)
    f.setStyleSheet("background:rgba(255,255,255,0.06); max-width:1px; border:none;")
    return f


# ══════════════════════════════════════════════════════════════════════════════
# ── Threats tab ────────────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

class AlertsTab(QWidget):
    block_requested = pyqtSignal(str, str)   # ip, reason
    _MAX_CARDS = 150   # keep last N alert cards; prune in batches of 30

    def __init__(self, parent=None):
        super().__init__(parent)
        self._alerts: list[dict] = []
        self._card_widgets: list[QFrame] = []   # parallel list to self._alerts
        self._build()

    def _build(self):
        root = QVBoxLayout(self); root.setContentsMargins(0, 0, 0, 0); root.setSpacing(0)

        clr = QPushButton("Clear All"); clr.setObjectName("secondaryBtn"); clr.setFixedHeight(30)
        clr.clicked.connect(self._clear)
        root.addWidget(_page_header("🚨", "Threats & Alerts",
            "All triggered detections — rule engine, ML classifier and heuristic alerts",
            actions=[clr]))

        inner = QWidget(); inner.setStyleSheet("background: #0b0d1e;")
        il = QVBoxLayout(inner); il.setContentsMargins(16, 12, 16, 12); il.setSpacing(0)

        scroll = QScrollArea(); scroll.setWidgetResizable(True); scroll.setFrameShape(QFrame.Shape.NoFrame)
        self._inner  = QWidget()
        self._vlay   = QVBoxLayout(self._inner)
        self._vlay.setContentsMargins(0, 0, 4, 0); self._vlay.setSpacing(0)
        self._empty  = _lbl("No threats detected — your network looks clean.\n"
                             "Threats will appear here as they are detected.",
                             "color:#28385a; font-size:14px; padding:50px; line-height:1.8;")
        self._empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._vlay.addWidget(self._empty)
        self._vlay.addStretch()
        scroll.setWidget(self._inner)
        il.addWidget(scroll, 1)
        root.addWidget(inner, 1)

    def add_alert(self, a: dict):
        self._alerts.insert(0, a)
        if self._empty.isVisible():
            self._empty.hide()
        card = self._make_card(a)
        self._card_widgets.insert(0, card)
        self._vlay.insertWidget(0, card)
        self._vlay.insertWidget(1, _spacer(6))

        # Prune oldest cards when over the cap to prevent memory/UI bloat
        if len(self._card_widgets) > self._MAX_CARDS:
            drop = len(self._card_widgets) - self._MAX_CARDS + 30
            for _ in range(drop):
                if not self._card_widgets:
                    break
                old = self._card_widgets.pop()
                old.deleteLater()
            if len(self._alerts) > self._MAX_CARDS:
                del self._alerts[self._MAX_CARDS:]

    def _make_card(self, a: dict) -> QFrame:
        try:
            from utils.threat_context import get_context, risk_tags
            ctx = get_context(a.get("rule_name", ""))
        except Exception:
            ctx = {}
            def risk_tags(_): return []

        sev    = (a.get("severity") or "low").lower()
        card   = QFrame(); card.setObjectName(SEV_FRAME.get(sev, "card2"))
        cl     = QVBoxLayout(card); cl.setContentsMargins(14, 12, 14, 12); cl.setSpacing(8)

        # ── Header row: icon circle + rule + severity badge ────────────────
        top = QHBoxLayout(); top.setSpacing(10)
        sev_col  = SEV_COLOR.get(sev, "#8fa3c0")
        icon_txt = ctx.get("icon", "⚠")
        ic = QLabel(icon_txt)
        ic.setFixedSize(38, 38)
        ic.setAlignment(Qt.AlignmentFlag.AlignCenter)
        bg = QColor(sev_col); bg.setAlpha(28)
        ic.setStyleSheet(
            f"background:{bg.name(QColor.NameFormat.HexArgb)};"
            "border-radius:10px; font-size:16px;"
        )
        top.addWidget(ic)
        rule_lbl = _lbl(a.get("rule_name", "Unknown"),
                        "font-size:14px; font-weight:700; color:#e2eeff;")
        top.addWidget(rule_lbl, 1)
        top.addWidget(_make_badge(sev.upper(), sev_col))
        cl.addLayout(top)

        # Category label
        if ctx.get("category_label"):
            cl.addWidget(_lbl(ctx["category_label"],
                              "color:#5577aa; font-size:11px; font-weight:600; "
                              "text-transform:uppercase; letter-spacing:1px;"))

        # Risk tags row (spy / attack / data)
        tags = risk_tags(a.get("rule_name", ""))
        if tags:
            tag_row = QHBoxLayout(); tag_row.setSpacing(6)
            for t in tags:
                tag_lbl = _lbl(t, "font-size:10px; font-weight:700; padding:2px 7px; border-radius:6px;")
                if "Surveillance" in t:
                    tag_lbl.setStyleSheet(tag_lbl.styleSheet() +
                        "color:#a855f7; background:rgba(168,85,247,.12); border:1px solid rgba(168,85,247,.3);")
                elif "Attack" in t:
                    tag_lbl.setStyleSheet(tag_lbl.styleSheet() +
                        "color:#ef4444; background:rgba(239,68,68,.12); border:1px solid rgba(239,68,68,.3);")
                elif "Data" in t:
                    tag_lbl.setStyleSheet(tag_lbl.styleSheet() +
                        "color:#f97316; background:rgba(249,115,22,.12); border:1px solid rgba(249,115,22,.3);")
                tag_row.addWidget(tag_lbl)
            tag_row.addStretch()
            cl.addLayout(tag_row)

        # Divider
        div = QFrame(); div.setFrameShape(QFrame.Shape.HLine)
        div.setStyleSheet("color:#1c2440; margin:2px 0;")
        cl.addWidget(div)

        # ── What is happening ──────────────────────────────────────────────
        if ctx.get("what_is_happening"):
            what_lbl = _lbl("🔍  What is happening", "font-size:10px; color:#445068; font-weight:700; text-transform:uppercase;")
            cl.addWidget(what_lbl)
            what_txt = _lbl(ctx["what_is_happening"], "color:#8fa3c0; font-size:12px; line-height:1.6;")
            what_txt.setWordWrap(True)
            cl.addWidget(what_txt)

        # ── Why dangerous ──────────────────────────────────────────────────
        if ctx.get("why_dangerous"):
            why_lbl = _lbl("⚠  Why this is dangerous", "font-size:10px; color:#445068; font-weight:700; text-transform:uppercase; margin-top:6px;")
            cl.addWidget(why_lbl)
            why_txt = _lbl(ctx["why_dangerous"], "color:#c08060; font-size:12px; line-height:1.6;")
            why_txt.setWordWrap(True)
            cl.addWidget(why_txt)

        # ── What to do ─────────────────────────────────────────────────────
        if ctx.get("what_to_do"):
            todo_lbl = _lbl("✅  What you should do", "font-size:10px; color:#445068; font-weight:700; text-transform:uppercase; margin-top:6px;")
            cl.addWidget(todo_lbl)
            todo_txt = _lbl(ctx["what_to_do"], "color:#6aad8a; font-size:12px; line-height:1.6;")
            todo_txt.setWordWrap(True)
            cl.addWidget(todo_txt)

        # ── MITRE tag ──────────────────────────────────────────────────────
        if ctx.get("mitre_id"):
            mitre = _lbl(f"  🛡  {ctx['mitre_id']}  —  {ctx.get('mitre_name','')}",
                         "color:#3b82f6; font-size:11px; font-family:Consolas; "
                         "background:rgba(59,130,246,.08); border:1px solid rgba(59,130,246,.25); "
                         "border-radius:6px; padding:4px 8px; margin-top:4px;")
            cl.addWidget(mitre)

        # ── Technical packet details ───────────────────────────────────────
        pkt_parts = []
        src_ip    = a.get("source_ip", "—")
        ts        = a.get("timestamp", "")
        if src_ip and src_ip != "—":
            pkt_parts.append(f"Source: {src_ip}")
        if a.get("dst_port"):
            pkt_parts.append(f"Port: {a['dst_port']}")
        if a.get("protocol"):
            pkt_parts.append(f"Proto: {a['protocol']}")
        if a.get("attempts") or a.get("count") or a.get("rate"):
            val = a.get("attempts") or a.get("count") or a.get("rate")
            pkt_parts.append(f"Rate/Count: {val}")
        if a.get("ja3"):
            pkt_parts.append(f"JA3: {a['ja3'][:16]}…")
        if a.get("sni"):
            pkt_parts.append(f"SNI: {a['sni']}")
        if a.get("path"):
            pkt_parts.append(f"Path: ...{a['path'][-40:]}")
        if a.get("user"):
            pkt_parts.append(f"User: {a['user']}")
        if a.get("event_id"):
            pkt_parts.append(f"Event ID: #{a['event_id']}")
        if ts:
            pkt_parts.append(f"Time: {ts}")

        if pkt_parts:
            div2 = QFrame(); div2.setFrameShape(QFrame.Shape.HLine)
            div2.setStyleSheet("color:#1c2440; margin:2px 0;"); cl.addWidget(div2)
            pkt_lbl = _lbl("🔧  Technical Details", "font-size:10px; color:#445068; font-weight:700; text-transform:uppercase;")
            cl.addWidget(pkt_lbl)
            pkt_txt = _lbl("  |  ".join(pkt_parts),
                           "color:#445068; font-size:11px; font-family:Consolas; line-height:1.5;")
            pkt_txt.setWordWrap(True)
            cl.addWidget(pkt_txt)

        # Raw alert message if not already covered
        raw_msg = a.get("message","")
        if raw_msg and raw_msg not in (ctx.get("what_is_happening",""), ""):
            msg_lbl = _lbl(raw_msg, "color:#506070; font-size:11px; font-style:italic;")
            msg_lbl.setWordWrap(True); cl.addWidget(msg_lbl)

        # ── Action buttons ─────────────────────────────────────────────────
        div3 = QFrame(); div3.setFrameShape(QFrame.Shape.HLine)
        div3.setStyleSheet("color:#1c2440; margin:2px 0;"); cl.addWidget(div3)

        meta = QHBoxLayout(); meta.setSpacing(8)

        if src_ip and src_ip not in ("—", "localhost", "local"):
            blk = QPushButton("🔒  Block IP"); blk.setObjectName("dangerBtn")
            blk.setFixedHeight(28)
            if not IS_ADMIN:
                blk.setToolTip("Needs admin — right-click app → Run as administrator")
                blk.setEnabled(False)
            else:
                blk.clicked.connect(lambda _, ip=src_ip, r=a.get("rule_name",""):
                                     self.block_requested.emit(ip, r))
            meta.addWidget(blk)

        qr_btn = QPushButton("📤  Share"); qr_btn.setObjectName("secondaryBtn")
        qr_btn.setFixedHeight(28)
        qr_btn.clicked.connect(lambda _, alert=a: self._show_qr(alert))
        meta.addWidget(qr_btn)

        # ── ML Feedback buttons (improve the model from user judgement) ────
        if _HAS_ADAPTIVE:
            meta.addStretch()
            fb_lbl = _lbl("ML Feedback:", "font-size:10px; color:#2c3858; background:transparent;")
            meta.addWidget(fb_lbl)
            tp_btn = QPushButton("✓ True Positive")
            tp_btn.setFixedHeight(26)
            tp_btn.setStyleSheet(
                "QPushButton{background:rgba(52,211,153,.10);color:#34d399;"
                "border:1px solid rgba(52,211,153,.30);border-radius:7px;"
                "font-size:11px;font-weight:600;padding:0 8px;}"
                "QPushButton:hover{background:rgba(52,211,153,.20);}"
                "QPushButton:disabled{color:#2a4a3a;border-color:#1a3028;}"
            )
            fp_btn = QPushButton("✗ False Positive")
            fp_btn.setFixedHeight(26)
            fp_btn.setStyleSheet(
                "QPushButton{background:rgba(248,113,113,.10);color:#f87171;"
                "border:1px solid rgba(248,113,113,.30);border-radius:7px;"
                "font-size:11px;font-weight:600;padding:0 8px;}"
                "QPushButton:hover{background:rgba(248,113,113,.20);}"
                "QPushButton:disabled{color:#4a2a2a;border-color:#301818;}"
            )
            fb_status = _lbl("", "font-size:10px; color:#34d399; background:transparent;")

            def _send_feedback(label: int, alert=a, tp=tp_btn, fp=fp_btn, st=fb_status):
                try:
                    buf  = get_feedback_buffer()
                    feat = alert.get("ml_features") or alert.get("packet_features") or {}
                    buf.add(
                        features   = feat,
                        label      = label,
                        source     = "user_tp" if label == 1 else "user_fp",
                        verdict    = alert.get("rule_name", ""),
                        confidence = float(alert.get("confidence", 0)),
                    )
                    # Immediately update online corrective layer
                    corr = get_corrective_layer()
                    corr.fit_one(feat, label)
                    tp.setEnabled(False); fp.setEnabled(False)
                    st.setText("Feedback saved — model learning…" if label == 1
                               else "Marked as FP — model adjusting…")
                except Exception as e:
                    st.setText(f"Error: {e}")

            tp_btn.clicked.connect(lambda _, l=1: _send_feedback(l))
            fp_btn.clicked.connect(lambda _, l=0: _send_feedback(l))
            meta.addWidget(tp_btn)
            meta.addWidget(fp_btn)
            cl.addLayout(meta)
            cl.addWidget(fb_status)
        else:
            meta.addStretch()
            cl.addLayout(meta)

        return card

    def _show_qr(self, alert: dict) -> None:
        try:
            from utils.qr_share import AlertQRDialog
            dlg = AlertQRDialog(alert, parent=self)
            dlg.exec()
        except ImportError:
            QMessageBox.information(self, "QR Share",
                "Install qrcode to enable QR sharing:\n  pip install qrcode[pil]")

    def _clear(self):
        self._alerts.clear()
        self._card_widgets.clear()
        for i in reversed(range(self._vlay.count())):
            item = self._vlay.itemAt(i)
            if item and item.widget() and item.widget() is not self._empty:
                item.widget().deleteLater()
        self._empty.show()


def _spacer(h: int) -> QWidget:
    w = QWidget(); w.setFixedHeight(h); return w


# ══════════════════════════════════════════════════════════════════════════════
# ── System Monitor tab (Event Log + FIM alerts) ────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

_CAT_ICON = {
    "event_log":    "🪟",
    "fim":          "📁",
    "threat_intel": "🌐",
    "arp":          "🔗",
    "dns":          "🌍",
    "brute_force":  "🔑",
}


class SystemMonitorTab(QWidget):
    """
    Displays alerts from host-based monitors:
    Windows Event Log, File Integrity Monitor, and Threat Intelligence.
    """

    _MAX_CARDS = 100

    def __init__(self, parent=None):
        super().__init__(parent)
        self._alerts: list[dict] = []
        self._sys_cards: list[QFrame] = []
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0); root.setSpacing(0)

        self._count_lbl = _lbl("0 events", "color:#445068; font-size:12px; font-family:Consolas;")
        clr = QPushButton("Clear"); clr.setObjectName("secondaryBtn")
        clr.setFixedHeight(28); clr.clicked.connect(self._clear)
        root.addWidget(_page_header("🖥", "System Monitor",
            "Windows Event Log · File Integrity · Threat Intel alerts",
            actions=[self._count_lbl, clr]))

        inner = QWidget(); inner.setStyleSheet("background: #0b0d1e;")
        il = QVBoxLayout(inner); il.setContentsMargins(20, 14, 20, 14); il.setSpacing(12)

        # Status cards
        sc = QHBoxLayout(); sc.setSpacing(10)
        self._el_status  = self._status_card("🪟  Event Log", "Initialising…", "#fbbf24")
        self._fim_status = self._status_card("📁  File Integrity", "Initialising…", "#fbbf24")
        self._ti_status  = self._status_card("🌐  Threat Intel", "No API key", "#445068")
        sc.addWidget(self._el_status[0])
        sc.addWidget(self._fim_status[0])
        sc.addWidget(self._ti_status[0])
        sc.addStretch()
        il.addLayout(sc)

        # Alert scroll area
        scroll = QScrollArea(); scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        self._inner = QWidget()
        self._vlay  = QVBoxLayout(self._inner)
        self._vlay.setContentsMargins(0, 0, 4, 0); self._vlay.setSpacing(0)
        self._empty = _lbl(
            "No system events detected yet.\n"
            "Event log and file integrity monitoring will report here.",
            "color:#28385a; font-size:14px; padding:50px; line-height:1.8;"
        )
        self._empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._vlay.addWidget(self._empty)
        self._vlay.addStretch()
        scroll.setWidget(self._inner)
        il.addWidget(scroll, 1)
        root.addWidget(inner, 1)

    @staticmethod
    def _status_card(title: str, status: str, color: str):
        f = QFrame(); f.setObjectName("card2")
        l = QVBoxLayout(f); l.setContentsMargins(14, 10, 14, 10); l.setSpacing(4)
        l.addWidget(_lbl(title, "font-size:11px; font-weight:700; color:#8fa3c0; letter-spacing:0.3px;"))
        lbl = _lbl(status, f"font-size:12px; color:{color}; font-weight:600;")
        l.addWidget(lbl)
        return f, lbl

    def set_eventlog_status(self, text: str, color: str = "#34d399") -> None:
        self._el_status[1].setText(text)
        self._el_status[1].setStyleSheet(f"font-size:12px; color:{color}; font-weight:600;")

    def set_fim_status(self, text: str, color: str = "#34d399") -> None:
        self._fim_status[1].setText(text)
        self._fim_status[1].setStyleSheet(f"font-size:12px; color:{color}; font-weight:600;")

    def set_ti_status(self, text: str, color: str = "#34d399") -> None:
        self._ti_status[1].setText(text)
        self._ti_status[1].setStyleSheet(f"font-size:12px; color:{color}; font-weight:600;")

    def add_alert(self, a: dict) -> None:
        self._alerts.insert(0, a)
        if self._empty.isVisible():
            self._empty.hide()
        sev   = (a.get("severity") or "low").lower()
        cat   = a.get("category", "")
        icon  = _CAT_ICON.get(cat, "⚠")
        frame_name = SEV_FRAME.get(sev, "cLow")
        color      = SEV_COLOR.get(sev, "#5b9cf6")

        card = QFrame(); card.setObjectName(frame_name)
        cl   = QHBoxLayout(card); cl.setContentsMargins(12, 10, 12, 10); cl.setSpacing(10)
        # Colored icon circle
        ic2 = QLabel(icon); ic2.setFixedSize(36, 36)
        ic2.setAlignment(Qt.AlignmentFlag.AlignCenter)
        bg2 = QColor(color); bg2.setAlpha(25)
        ic2.setStyleSheet(
            f"background:{bg2.name(QColor.NameFormat.HexArgb)};"
            "border-radius:9px; font-size:16px;"
        )
        cl.addWidget(ic2)
        info = QVBoxLayout(); info.setSpacing(2)
        info.addWidget(_lbl(a.get("rule_name", "Event"),
                             f"font-size:13px; font-weight:600; color:{color};"))
        msg = _lbl(a.get("message", "")[:140], "font-size:12px; color:#8fa3c0;")
        msg.setWordWrap(True)
        info.addWidget(msg)
        if a.get("path"):
            info.addWidget(_lbl(
                str(a["path"])[-80:], "font-size:11px; color:#445068; font-family:Consolas;"
            ))
        cl.addLayout(info, 1)
        meta = QVBoxLayout(); meta.setSpacing(2); meta.setAlignment(Qt.AlignmentFlag.AlignTop)
        meta.addWidget(_lbl(a.get("timestamp", "")[-8:],
                             "font-size:11px; color:#445068; font-family:Consolas;"))
        sev_lbl = _lbl(sev.upper(), f"font-size:10px; font-weight:700; color:{color};")
        meta.addWidget(sev_lbl)
        cl.addLayout(meta)

        self._sys_cards.insert(0, card)
        self._vlay.insertWidget(0, card)
        self._vlay.insertWidget(1, _spacer(4))

        # Prune oldest cards when over the cap
        if len(self._sys_cards) > self._MAX_CARDS:
            drop = len(self._sys_cards) - self._MAX_CARDS + 20
            for _ in range(drop):
                if not self._sys_cards:
                    break
                old = self._sys_cards.pop()
                old.deleteLater()
            if len(self._alerts) > self._MAX_CARDS:
                del self._alerts[self._MAX_CARDS:]

        self._count_lbl.setText(f"{len(self._alerts)} event(s)")

    def _clear(self) -> None:
        self._alerts.clear()
        self._sys_cards.clear()
        for i in reversed(range(self._vlay.count())):
            it = self._vlay.itemAt(i)
            if it and it.widget() and it.widget() is not self._empty:
                it.widget().deleteLater()
        self._empty.show()
        self._count_lbl.setText("0 events")


# ── QThread wrappers for host-based monitors ───────────────────────────────────

class EventLogThread(QThread):
    """Wraps EventLogMonitor in a QThread, marshalling alerts to the main thread."""
    new_alert  = pyqtSignal(dict)
    status_sig = pyqtSignal(str, str)   # text, colour

    def __init__(self, parent=None):
        super().__init__(parent)
        self._monitor = None

    def run(self):
        try:
            from detectors.event_log import EventLogMonitor
            self._monitor = EventLogMonitor(on_alert=self.new_alert.emit)
            if self._monitor.is_available():
                self.status_sig.emit("Active — polling every 10 s", "#34d399")
                self._monitor.start()
                self._monitor._thread.join()   # block until stop() is called
            else:
                self.status_sig.emit("wevtutil unavailable", "#f87171")
        except Exception as e:
            self.status_sig.emit(f"Error: {e}", "#f87171")

    def stop(self):
        if self._monitor:
            self._monitor.stop()


class FIMThread(QThread):
    """Wraps FIMMonitor in a QThread, marshalling alerts to the main thread."""
    new_alert  = pyqtSignal(dict)
    status_sig = pyqtSignal(str, str)   # text, colour

    def __init__(self, watch_dirs: list[str], baseline_path, parent=None):
        super().__init__(parent)
        self._watch_dirs    = watch_dirs
        self._baseline_path = baseline_path
        self._monitor       = None

    def run(self):
        try:
            from detectors.fim import FIMMonitor
            from pathlib import Path
            self._monitor = FIMMonitor(
                watch_dirs    = self._watch_dirs,
                baseline_path = Path(self._baseline_path),
                on_alert      = self.new_alert.emit,
            )
            self._monitor.start()
            self.status_sig.emit(
                f"Watching {len(self._watch_dirs)} dir(s) — scanning every 60 s",
                "#34d399"
            )
            self._monitor._thread.join()
        except Exception as e:
            self.status_sig.emit(f"Error: {e}", "#f87171")

    def stop(self):
        if self._monitor:
            self._monitor.stop()


# ══════════════════════════════════════════════════════════════════════════════
# ── Blocked IPs tab ────────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

class BlockedIPsTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._build()

    def _build(self):
        root = QVBoxLayout(self); root.setContentsMargins(0, 0, 0, 0); root.setSpacing(0)

        ref = QPushButton("Refresh"); ref.setObjectName("secondaryBtn"); ref.setFixedHeight(30)
        ref.clicked.connect(self.refresh)
        _actions = [ref]
        if not IS_ADMIN:
            _actions.insert(0, _lbl("⚠ Admin required",
                                    "color:#fbbf24; font-size:11px; background:transparent;"))
        root.addWidget(_page_header("🔒", "Blocked IPs",
            "Firewall-blocked addresses — Windows Firewall rules managed by this tool",
            actions=_actions))

        inner = QWidget(); inner.setStyleSheet("background: #0b0d1e;")
        il = QVBoxLayout(inner); il.setContentsMargins(20, 14, 20, 14); il.setSpacing(12)

        # ── Manual block / unblock panel ──────────────────────────────────────
        panel = QFrame(); panel.setObjectName("card2")
        pl = QVBoxLayout(panel); pl.setContentsMargins(16, 14, 16, 14); pl.setSpacing(10)

        pl.addWidget(_lbl("Block / Unblock IP",
                          "font-size:13px; font-weight:700; color:#dde6f0;"))
        pl.addWidget(_lbl(
            "Enter an IP address to add or remove a Windows Firewall block rule.",
            "font-size:11px; color:#6a7fa0;"
        ))

        row = QHBoxLayout(); row.setSpacing(8)
        self._ip_input = QLineEdit()
        self._ip_input.setPlaceholderText("e.g.  203.0.113.42  or  198.51.100.7")
        self._ip_input.setFixedHeight(34)
        self._ip_input.setStyleSheet(
            "QLineEdit { background:#0d1020; border:1px solid #1e2848; border-radius:8px;"
            " color:#dde6f0; padding:0 10px; font-size:12px; }"
            "QLineEdit:focus { border-color:#4f8ef7; }"
        )
        self._reason_input = QLineEdit()
        self._reason_input.setPlaceholderText("Reason (optional)")
        self._reason_input.setFixedHeight(34)
        self._reason_input.setMaximumWidth(200)
        self._reason_input.setStyleSheet(
            "QLineEdit { background:#0d1020; border:1px solid #1e2848; border-radius:8px;"
            " color:#dde6f0; padding:0 10px; font-size:12px; }"
            "QLineEdit:focus { border-color:#4f8ef7; }"
        )
        self._block_btn = QPushButton("🔒  Block IP")
        self._block_btn.setObjectName("dangerBtn")
        self._block_btn.setFixedHeight(34)
        self._block_btn.setFixedWidth(110)
        self._unblock_btn = QPushButton("🔓  Unblock IP")
        self._unblock_btn.setObjectName("successBtn")
        self._unblock_btn.setFixedHeight(34)
        self._unblock_btn.setFixedWidth(115)

        if not IS_ADMIN:
            for b in (self._block_btn, self._unblock_btn):
                b.setEnabled(False)
                b.setToolTip("Needs administrator rights — right-click app → Run as administrator")
        else:
            self._block_btn.clicked.connect(self._manual_block)
            self._unblock_btn.clicked.connect(self._manual_unblock)

        # Allow pressing Enter in the IP field to trigger block
        self._ip_input.returnPressed.connect(self._block_btn.click)

        row.addWidget(self._ip_input, 1)
        row.addWidget(self._reason_input)
        row.addWidget(self._block_btn)
        row.addWidget(self._unblock_btn)
        pl.addLayout(row)

        self._panel_status = _lbl("", "font-size:11px; color:#34d399;")
        pl.addWidget(self._panel_status)
        il.addWidget(panel)

        # ── Summary row ───────────────────────────────────────────────────────
        sum_row = QHBoxLayout(); sum_row.setSpacing(16)
        self._count_lbl = _lbl("0 IPs blocked", "font-size:12px; color:#8fa3c0;")
        self._unblock_all_btn = QPushButton("Unblock All")
        self._unblock_all_btn.setObjectName("secondaryBtn")
        self._unblock_all_btn.setFixedHeight(28)
        self._unblock_all_btn.setFixedWidth(100)
        if not IS_ADMIN:
            self._unblock_all_btn.setEnabled(False)
        else:
            self._unblock_all_btn.clicked.connect(self._unblock_all)
        sum_row.addWidget(self._count_lbl)
        sum_row.addStretch()
        sum_row.addWidget(self._unblock_all_btn)
        il.addLayout(sum_row)

        # ── Blocked IPs table ─────────────────────────────────────────────────
        cols = ["IP Address", "Blocked At", "Reason", "Auto?", "Action"]
        self.tbl = QTableWidget(0, len(cols))
        self.tbl.setHorizontalHeaderLabels(cols)
        self.tbl.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.tbl.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.tbl.verticalHeader().setVisible(False)
        self.tbl.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        # Right-click context menu
        self.tbl.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tbl.customContextMenuRequested.connect(self._table_context_menu)
        # Single-click fills the IP field for quick unblock editing
        self.tbl.cellClicked.connect(self._row_clicked)
        il.addWidget(self.tbl, 1)
        root.addWidget(inner, 1)
        self.refresh()

    # ── Context menu ──────────────────────────────────────────────────────────

    def _table_context_menu(self, pos) -> None:
        row = self.tbl.rowAt(pos.y())
        if row < 0:
            return
        ip_item = self.tbl.item(row, 0)
        if not ip_item:
            return
        ip = ip_item.text()

        menu = QMenu(self)
        menu.setStyleSheet(
            "QMenu { background:#0f1222; border:1px solid #1e2848; color:#c8d8f0;"
            " font-size:12px; padding:4px; }"
            "QMenu::item { padding:6px 18px; border-radius:6px; }"
            "QMenu::item:selected { background:#1a2a4a; }"
        )
        act_unblock = menu.addAction(f"Unblock  {ip}")
        act_copy    = menu.addAction("Copy IP address")

        chosen = menu.exec(self.tbl.viewport().mapToGlobal(pos))
        if chosen == act_unblock:
            self._unblock(ip)
        elif chosen == act_copy:
            QApplication.clipboard().setText(ip)

    def _row_clicked(self, row: int, _col: int) -> None:
        item = self.tbl.item(row, 0)
        if item:
            self._ip_input.setText(item.text())
            self._panel_status.setText("")

    # ── Refresh ───────────────────────────────────────────────────────────────

    def refresh(self):
        data = _load_blocked()
        self.tbl.setRowCount(0)
        count = len(data)
        for ip, meta in data.items():
            i = self.tbl.rowCount(); self.tbl.insertRow(i)
            for j, text in enumerate([
                ip,
                meta.get("blocked_at", "—"),
                meta.get("reason", "Manual"),
                "Yes" if meta.get("auto") else "No",
            ]):
                it = QTableWidgetItem(text)
                it.setForeground(QColor("#f87171" if j == 0 else "#8fa3c0"))
                self.tbl.setItem(i, j, it)
            btn = QPushButton("🔓 Unblock"); btn.setObjectName("successBtn")
            btn.setFixedHeight(26)
            if not IS_ADMIN:
                btn.setEnabled(False)
                btn.setToolTip("Needs administrator rights")
            else:
                btn.clicked.connect(lambda _, _ip=ip: self._unblock(_ip))
            self.tbl.setCellWidget(i, 4, btn)
        n = f"{count} IP{'s' if count != 1 else ''} blocked"
        self._count_lbl.setText(n)

    # ── Actions ───────────────────────────────────────────────────────────────

    def add_entry(self, ip: str, reason: str, auto: bool = False):
        data = _load_blocked()
        data[ip] = {
            "blocked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "reason": reason, "auto": auto,
        }
        _save_blocked(data)
        self.refresh()

    def _manual_block(self) -> None:
        ip = self._ip_input.text().strip()
        if not ip:
            self._set_status("Enter an IP address first.", "#fbbf24")
            return
        if not _validate_ip(ip):
            self._set_status(f"'{ip}' is not a valid IP address.", "#f87171")
            return
        reason = self._reason_input.text().strip() or "Manual block"
        ok, msg = _firewall_block(ip)
        if ok:
            data = _load_blocked()
            data[ip] = {
                "blocked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "reason": reason, "auto": False,
            }
            _save_blocked(data)
            self.refresh()
            self._ip_input.clear()
            self._reason_input.clear()
            self._set_status(f"Blocked {ip} via Windows Firewall.", "#34d399")
        else:
            self._set_status(msg, "#f87171")

    def _manual_unblock(self) -> None:
        ip = self._ip_input.text().strip()
        if not ip:
            self._set_status("Enter an IP address first.", "#fbbf24")
            return
        if not _validate_ip(ip):
            self._set_status(f"'{ip}' is not a valid IP address.", "#f87171")
            return
        self._unblock(ip)

    def _unblock(self, ip: str) -> None:
        ok, msg = _firewall_unblock(ip)
        if ok:
            data = _load_blocked()
            data.pop(ip, None)
            _save_blocked(data)
            self.refresh()
            self._ip_input.clear()
            self._set_status(f"Unblocked {ip} — firewall rule removed.", "#34d399")
        else:
            self._set_status(msg, "#f87171")

    def _unblock_all(self) -> None:
        data = _load_blocked()
        if not data:
            self._set_status("No blocked IPs to remove.", "#fbbf24")
            return
        count = len(data)
        reply = QMessageBox.question(
            self, "Unblock All",
            f"Remove Windows Firewall blocks for all {count} IP(s)?\nThis cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        failed = []
        for ip in list(data.keys()):
            ok, _ = _firewall_unblock(ip)
            if ok:
                data.pop(ip, None)
            else:
                failed.append(ip)
        _save_blocked(data)
        self.refresh()
        if failed:
            self._set_status(
                f"Unblocked {count - len(failed)}/{count}. Failed: {', '.join(failed)}", "#fbbf24"
            )
        else:
            self._set_status(f"All {count} IP(s) unblocked.", "#34d399")

    def _set_status(self, msg: str, color: str = "#34d399") -> None:
        self._panel_status.setText(msg)
        self._panel_status.setStyleSheet(f"font-size:11px; color:{color};")


# ══════════════════════════════════════════════════════════════════════════════
# ── Geo Map tab ───────────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

_MAP_PATH = ROOT / "network_map.html"


class GeoMapTab(QWidget):
    """Embedded Folium network-threat map with live geo stats."""

    _reload_sig = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._geo = None
        self._map_mtime: float = 0.0   # track last loaded file mtime
        self._reload_sig.connect(self._load_map)
        self._build()
        self._stats_timer = QTimer(self)
        self._stats_timer.timeout.connect(self._refresh_stats)
        self._stats_timer.start(10000)

    def set_mapper(self, geo) -> None:
        self._geo = geo
        self._refresh_stats()
        if geo.map_exists():
            self._load_map()

    # ── Build ─────────────────────────────────────────────────────────────────

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        _rb = QPushButton("🔄  Rebuild"); _rb.setObjectName("secondaryBtn"); _rb.setFixedHeight(30)
        _rb.clicked.connect(self._rebuild_map)
        _ob = QPushButton("🌐  Browser"); _ob.setObjectName("secondaryBtn"); _ob.setFixedHeight(30)
        _ob.clicked.connect(self._open_browser)
        root.addWidget(_page_header("🗺", "Geo Map",
            "Attack-origin map — geolocation of all external threat IPs",
            actions=[_rb, _ob]))

        inner = QWidget(); inner.setStyleSheet("background: #0b0d1e;")
        il = QVBoxLayout(inner); il.setContentsMargins(20, 14, 20, 14); il.setSpacing(12)

        # Stats row
        stats_row = QHBoxLayout(); stats_row.setSpacing(10)
        self._lbl_ips,       f1 = self._stat_card("IPs Tracked",  "0", "#4f8ef7")
        self._lbl_countries, f2 = self._stat_card("Countries",    "0", "#a78bfa")
        self._lbl_events,    f3 = self._stat_card("Total Events", "0", "#34d399")
        for f in (f1, f2, f3):
            stats_row.addWidget(f)
        stats_row.addStretch()
        self._lbl_note = _lbl(
            "No external IPs detected yet — start monitoring to populate the map.",
            "color:#445068; font-size:11px; background:transparent;"
        )
        il.addLayout(stats_row)
        il.addWidget(self._lbl_note)
        root.addWidget(inner)

        # Map viewer
        if _HAS_WEBENGINE:
            self._map_view = QWebEngineView()
            self._map_view.setMinimumHeight(420)
            self._show_placeholder_html()
            root.addWidget(self._map_view, 1)
        else:
            self._map_view = None
            fb = QFrame(); fb.setObjectName("card2")
            fl = QVBoxLayout(fb); fl.setContentsMargins(20, 30, 20, 30)
            fl.setAlignment(Qt.AlignmentFlag.AlignCenter); fl.setSpacing(10)
            fl.addWidget(_lbl("🗺", "font-size:52px;"))
            fl.addWidget(_lbl("Install PyQt6-WebEngine to view the map inline.",
                              "font-size:13px; color:#8fa3c0;"))
            fl.addWidget(_lbl("pip install PyQt6-WebEngine",
                              "font-size:12px; color:#445068; font-family:Consolas;"))
            ob2 = QPushButton("🌐  Open Map in Browser"); ob2.setObjectName("primaryBtn")
            ob2.clicked.connect(self._open_browser)
            fl.addWidget(ob2)
            root.addWidget(fb, 1)

    # ── Stats / helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _stat_card(label: str, value: str, color: str) -> tuple:
        f  = QFrame(); f.setObjectName("card2")
        fl = QVBoxLayout(f); fl.setContentsMargins(14, 10, 14, 10); fl.setSpacing(3)
        vl = _lbl(value, f"font-size:22px; font-weight:700; color:{color};")
        fl.addWidget(vl)
        fl.addWidget(_lbl(label, "font-size:11px; color:#8fa3c0;"))
        return vl, f

    def _refresh_stats(self):
        if not self._geo:
            return
        s = self._geo.get_stats()
        self._lbl_ips.setText(str(s["unique_ips"]))
        self._lbl_countries.setText(str(s["unique_countries"]))
        self._lbl_events.setText(str(s["total_events"]))
        if s["total_events"] > 0:
            self._lbl_note.setText(
                f"Tracking {s['unique_ips']} IPs across {s['unique_countries']} countries — "
                f"{s['total_events']} total threat events."
            )
        # Only reload map if file was updated since last load
        if _HAS_WEBENGINE and self._map_view and self._geo.map_exists():
            self._load_map_if_changed()

    def _rebuild_map(self):
        if not self._geo:
            QMessageBox.information(self, "Not Ready",
                                    "GeoMapper is not yet initialised — wait for the first alert.")
            return
        threading.Thread(target=self._do_rebuild, daemon=True).start()

    def _do_rebuild(self):
        try:
            self._geo.build_map()
            self._reload_sig.emit()
        except Exception:
            pass

    def _load_map(self):
        """Force-reload the map regardless of mtime (used after explicit rebuild)."""
        if _HAS_WEBENGINE and self._map_view and _MAP_PATH.exists():
            self._map_mtime = _MAP_PATH.stat().st_mtime
            self._map_view.load(QUrl.fromLocalFile(str(_MAP_PATH.resolve())))

    def _load_map_if_changed(self):
        """Reload the map only when the HTML file has been updated on disk."""
        if not _MAP_PATH.exists():
            return
        try:
            mtime = _MAP_PATH.stat().st_mtime
        except OSError:
            return
        if mtime != self._map_mtime:
            self._map_mtime = mtime
            self._map_view.load(QUrl.fromLocalFile(str(_MAP_PATH.resolve())))

    def _show_placeholder_html(self):
        if _HAS_WEBENGINE and self._map_view:
            self._map_view.setHtml(
                "<!DOCTYPE html><html><body style='background:#0d0f1c;display:flex;"
                "align-items:center;justify-content:center;height:100vh;margin:0;"
                "font-family:Segoe UI,sans-serif;'>"
                "<div style='text-align:center;color:#445068;'>"
                "<div style='font-size:64px;margin-bottom:16px'>🗺</div>"
                "<div style='font-size:17px;color:#8fa3c0;font-weight:600'>"
                "Map appears here once external IPs are detected</div>"
                "<div style='font-size:13px;margin-top:8px;color:#2c3858'>"
                "Click Rebuild to force-generate, or wait for network alerts.</div>"
                "</div></body></html>"
            )

    def _open_browser(self):
        if _MAP_PATH.exists():
            webbrowser.open(_MAP_PATH.as_uri())
        else:
            QMessageBox.information(
                self, "No Map Yet",
                "The map hasn't been built yet.\n\n"
                "External IP addresses must be detected first.\n"
                "Click 'Rebuild' after some network alerts appear.",
            )

    def on_new_alert(self):
        """Call from MainWindow whenever a new alert arrives."""
        self._refresh_stats()


# ══════════════════════════════════════════════════════════════════════════════
# ── File Scanner tab ──────────────────────────────════════════════════════════
# ══════════════════════════════════════════════════════════════════════════════

class FileScannerTab(QWidget):
    """USB drive monitor, download watcher, and malware scanner."""

    # Thread-safe signals
    _usb_sig      = pyqtSignal(str, str)   # mountpoint, label
    _newfile_sig  = pyqtSignal(str)         # path string
    _result_sig   = pyqtSignal(object)      # ScanResult
    _status_sig   = pyqtSignal(str)
    _drives_sig   = pyqtSignal()            # request drives refresh

    alert_signal  = pyqtSignal(dict)        # routed up to MainWindow

    def __init__(self, parent=None):
        super().__init__(parent)
        self._scanner    = None
        self._usb_mon    = None
        self._dl_watcher = None
        self._auto_scan  = True
        self._scan_count = 0
        self._threat_count = 0
        self._results: list = []

        self._usb_sig.connect(self._on_usb_detected)
        self._newfile_sig.connect(self._on_new_download)
        self._result_sig.connect(self._on_scan_result)
        self._status_sig.connect(self._set_status)
        self._drives_sig.connect(self._refresh_drives)

        self._build()

    # ── Build ──────────────────────────────────────────────────────────────────

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self._status_lbl = _lbl("Initialising…", "color:#8fa3c0; font-size:11px; background:transparent;")
        root.addWidget(_page_header("🔍", "File Scanner",
            "USB monitor · download watcher · MalwareBazaar cloud lookup",
            actions=[self._status_lbl]))

        inner = QWidget(); inner.setStyleSheet("background: #0b0d1e;")
        il = QVBoxLayout(inner); il.setContentsMargins(20, 14, 20, 14); il.setSpacing(12)
        root.addWidget(inner, 1)

        # Stats row
        sr = QHBoxLayout(); sr.setSpacing(10)
        self._lbl_drives,   fs1 = self._mini_stat("Drives", "0", "#4f8ef7")
        self._lbl_scanned,  fs2 = self._mini_stat("Scanned", "0", "#34d399")
        self._lbl_threats,  fs3 = self._mini_stat("Threats", "0", "#f47070")
        for f in (fs1, fs2, fs3):
            sr.addWidget(f)
        sr.addStretch()
        il.addLayout(sr)

        # ── Middle row: drives + watcher ──────────────────────────────────────
        mid = QHBoxLayout(); mid.setSpacing(12)

        # Drive monitor panel
        drive_frame = QFrame(); drive_frame.setObjectName("card2")
        drive_frame.setMinimumWidth(280)
        dl = QVBoxLayout(drive_frame); dl.setContentsMargins(14, 12, 14, 12); dl.setSpacing(8)
        dh = QHBoxLayout()
        dh.addWidget(_lbl("💾  Drive Monitor", "font-size:13px; font-weight:700; color:#dde6f0;"), 1)
        refresh_btn = QPushButton("↻")
        refresh_btn.setObjectName("secondaryBtn")
        refresh_btn.setFixedSize(26, 26)
        refresh_btn.setToolTip("Refresh drive list")
        refresh_btn.clicked.connect(self._refresh_drives)
        dh.addWidget(refresh_btn)
        dl.addLayout(dh)
        dl.addWidget(_lbl("USB and removable drives appear here automatically.",
                          "color:#445068; font-size:11px;"))

        self._drives_scroll = QScrollArea()
        self._drives_scroll.setWidgetResizable(True)
        self._drives_scroll.setFrameShape(QFrame.Shape.NoFrame)
        self._drives_scroll.setMaximumHeight(200)
        self._drives_inner = QWidget()
        self._drives_lay   = QVBoxLayout(self._drives_inner)
        self._drives_lay.setContentsMargins(0, 0, 0, 0)
        self._drives_lay.setSpacing(5)
        self._drives_lay.addStretch()
        self._drives_scroll.setWidget(self._drives_inner)
        dl.addWidget(self._drives_scroll)
        mid.addWidget(drive_frame, 1)

        # Download watcher panel
        watch_frame = QFrame(); watch_frame.setObjectName("card2")
        watch_frame.setMinimumWidth(260)
        wl = QVBoxLayout(watch_frame); wl.setContentsMargins(14, 12, 14, 12); wl.setSpacing(8)
        wl.addWidget(_lbl("📥  Download Watcher",
                          "font-size:13px; font-weight:700; color:#dde6f0;"))
        wl.addWidget(_lbl("Watches these folders for newly created files:",
                          "color:#445068; font-size:11px;"))

        self._watch_dirs_lbl = _lbl("—", "color:#8fa3c0; font-size:11px;")
        self._watch_dirs_lbl.setWordWrap(True)
        wl.addWidget(self._watch_dirs_lbl)

        auto_row = QHBoxLayout(); auto_row.setSpacing(8)
        auto_row.addWidget(_lbl("Auto-scan new files:", "color:#8fa3c0; font-size:12px;"))
        self._auto_chk = QCheckBox()
        self._auto_chk.setChecked(True)
        self._auto_chk.toggled.connect(lambda v: setattr(self, "_auto_scan", v))
        auto_row.addWidget(self._auto_chk)
        auto_row.addStretch()
        wl.addLayout(auto_row)
        wl.addStretch()
        mid.addWidget(watch_frame, 1)
        il.addLayout(mid)

        # ── Manual scan row ────────────────────────────────────────────────────
        ms_frame = QFrame(); ms_frame.setObjectName("card2")
        ml = QVBoxLayout(ms_frame); ml.setContentsMargins(14, 10, 14, 10); ml.setSpacing(8)
        ml.addWidget(_lbl("📁  Manual Scan", "font-size:13px; font-weight:700; color:#dde6f0;"))
        scan_row = QHBoxLayout(); scan_row.setSpacing(6)
        self._scan_path = QLineEdit()
        self._scan_path.setPlaceholderText("Path to file or folder…")
        scan_row.addWidget(self._scan_path, 1)
        for lbl, fn in [("File", self._browse_file), ("Folder", self._browse_folder)]:
            b = QPushButton(lbl); b.setObjectName("secondaryBtn")
            b.setFixedHeight(30); b.clicked.connect(fn)
            scan_row.addWidget(b)
        ml.addLayout(scan_row)
        btn_row = QHBoxLayout(); btn_row.setSpacing(6)
        for lbl, fn in [("🔍  Scan File", self._scan_file_manual),
                        ("📂  Scan Folder (shallow)", lambda: self._scan_dir_manual(False)),
                        ("🔎  Scan Folder (deep)", lambda: self._scan_dir_manual(True))]:
            b = QPushButton(lbl); b.setObjectName("secondaryBtn")
            b.setFixedHeight(30); b.clicked.connect(fn)
            btn_row.addWidget(b)
        btn_row.addStretch()
        ml.addLayout(btn_row)
        il.addWidget(ms_frame)

        # ── Results ────────────────────────────────────────────────────────────
        res_hdr = QHBoxLayout()
        res_hdr.addWidget(_lbl("Scan Results", "font-size:13px; font-weight:700; color:#dde6f0;"), 1)
        clear_btn = QPushButton("Clear All")
        clear_btn.setObjectName("secondaryBtn")
        clear_btn.setFixedHeight(26)
        clear_btn.clicked.connect(self._clear_results)
        res_hdr.addWidget(clear_btn)
        il.addLayout(res_hdr)

        self._tbl = QTableWidget()
        self._tbl.setColumnCount(5)
        self._tbl.setHorizontalHeaderLabels(
            ["File", "Verdict", "Risk", "Size", "Scanned At"])
        self._tbl.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for i in range(1, 5):
            self._tbl.horizontalHeader().setSectionResizeMode(
                i, QHeaderView.ResizeMode.ResizeToContents)
        self._tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._tbl.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._tbl.setAlternatingRowColors(False)
        self._tbl.verticalHeader().setVisible(False)
        self._tbl.setMinimumHeight(160)
        self._tbl.doubleClicked.connect(self._show_result_detail)
        il.addWidget(self._tbl, 1)

    # ── Monitors ──────────────────────────────────────────────────────────────

    def start_monitors(self):
        """Start USB detection and download watching. Call once from MainWindow."""
        try:
            from detectors.file_scanner import (
                FileScanner, USBMonitor, DownloadWatcher, get_all_drives
            )
            self._scanner    = FileScanner(use_cloud=True)
            self._usb_mon    = USBMonitor(
                on_device=lambda mp, lbl: self._usb_sig.emit(mp, lbl),
                on_alert=lambda a: self.alert_signal.emit(a),
            )
            self._dl_watcher = DownloadWatcher(
                on_new_file=lambda p: self._newfile_sig.emit(str(p)),
            )
            self._usb_mon.start()
            self._dl_watcher.start()

            # Show watched dirs
            dirs_text = "\n".join(
                f"  • {d}" for d in self._dl_watcher.watch_dirs
            )
            self._watch_dirs_lbl.setText(dirs_text or "No watch directories found.")

            # Populate initial drives
            self._refresh_drives()
            self._set_status("Monitoring — USB and downloads watched")
        except Exception as e:
            self._set_status(f"Init error: {e}")

    def stop_monitors(self):
        if self._usb_mon:
            self._usb_mon.stop()
        if self._dl_watcher:
            self._dl_watcher.stop()

    # ── Slot handlers (always called on Qt thread via signals) ─────────────────

    def _on_usb_detected(self, mountpoint: str, label: str):
        self._set_status(f"USB inserted: {label or mountpoint} — scanning…")
        self._refresh_drives()
        if self._auto_scan:
            threading.Thread(
                target=self._bg_scan_dir,
                args=(mountpoint, False),
                daemon=True,
            ).start()

    def _on_new_download(self, path_str: str):
        from pathlib import Path
        path = Path(path_str)
        self._set_status(f"New file: {path.name}")
        if self._auto_scan and path.suffix.lower() in _scan_exts():
            threading.Thread(
                target=self._bg_scan_file,
                args=(path,),
                daemon=True,
            ).start()

    def _on_scan_result(self, result):
        self._scan_count += 1
        self._results.append(result)
        if result.verdict in ("MALWARE", "SUSPICIOUS"):
            self._threat_count += 1

        self._lbl_scanned.setText(str(self._scan_count))
        self._lbl_threats.setText(str(self._threat_count))
        self._add_result_row(result)

        # Route to alert pipeline
        if result.verdict == "MALWARE":
            self.alert_signal.emit({
                "rule_name": "Malware Detected",
                "severity":  "critical",
                "category":  "file_scan",
                "source_ip": "local",
                "message":   f"MALWARE confirmed: {result.filename} — "
                             + (result.indicators[0] if result.indicators else "hash match"),
                "timestamp": result.scanned_at,
            })
        elif result.verdict == "SUSPICIOUS":
            self.alert_signal.emit({
                "rule_name": "Suspicious File",
                "severity":  "high",
                "category":  "file_scan",
                "source_ip": "local",
                "message":   f"Suspicious file: {result.filename} — "
                             + (result.indicators[0] if result.indicators else "heuristic flag"),
                "timestamp": result.scanned_at,
            })

    # ── Background scan workers ────────────────────────────────────────────────

    def _bg_scan_file(self, path):
        from pathlib import Path
        try:
            self._status_sig.emit(f"Scanning {Path(path).name}…")
            result = self._scanner.scan_file(path)
            self._result_sig.emit(result)
            self._status_sig.emit(f"Done — {result.verdict}: {Path(path).name}")
        except Exception as e:
            self._status_sig.emit(f"Scan error: {e}")

    def _bg_scan_dir(self, directory, recursive: bool):
        from pathlib import Path
        try:
            name   = Path(directory).name or directory
            self._status_sig.emit(f"Scanning {name}…")
            results = self._scanner.scan_directory(
                directory, recursive=recursive,
                on_progress=lambda n: self._status_sig.emit(f"Checking {n}…")
            )
            for r in results:
                self._result_sig.emit(r)
            threats = sum(1 for r in results if r.verdict in ("MALWARE", "SUSPICIOUS"))
            self._status_sig.emit(
                f"Scan complete — {len(results)} files checked, {threats} threats found")
        except Exception as e:
            self._status_sig.emit(f"Scan error: {e}")

    # ── UI helpers ────────────────────────────────────────────────────────────

    def _refresh_drives(self):
        try:
            from detectors.file_scanner import get_all_drives
            drives = get_all_drives()
        except Exception:
            return

        # Clear existing drive cards
        while self._drives_lay.count() > 1:
            item = self._drives_lay.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        self._lbl_drives.setText(str(len(drives)))

        for drv in drives:
            mp    = drv["mountpoint"]
            label = drv.get("label") or mp.rstrip("\\")
            fs    = drv.get("fstype", "")
            total = drv.get("total_gb", 0)
            rem   = drv.get("removable", False)
            icon  = "💾" if rem else "🖥"
            color = "#fb923c" if rem else "#445068"

            card = QFrame()
            card.setStyleSheet(
                f"background:{'rgba(251,146,60,0.07)' if rem else '#0c0e1a'};"
                f"border:1px solid {'rgba(251,146,60,0.25)' if rem else '#1a1e34'};"
                "border-radius:8px;"
            )
            cl = QHBoxLayout(card); cl.setContentsMargins(10, 6, 10, 6); cl.setSpacing(8)
            cl.addWidget(_lbl(icon, "font-size:16px;"))
            info_col = QVBoxLayout(); info_col.setSpacing(1)
            info_col.addWidget(_lbl(label, f"font-size:12px; font-weight:600; color:{color};"))
            info_col.addWidget(_lbl(
                f"{mp}  {fs}  {total:.0f} GB",
                "font-size:10px; color:#445068;"
            ))
            cl.addLayout(info_col, 1)

            if rem:
                sb = QPushButton("Scan")
                sb.setObjectName("secondaryBtn")
                sb.setFixedHeight(24)
                sb.clicked.connect(lambda _, m=mp: self._scan_drive(m))
                cl.addWidget(sb)

            self._drives_lay.insertWidget(self._drives_lay.count() - 1, card)

    def _scan_drive(self, mountpoint: str):
        self._set_status(f"Scanning drive {mountpoint}…")
        threading.Thread(
            target=self._bg_scan_dir,
            args=(mountpoint, False),
            daemon=True,
        ).start()

    def _add_result_row(self, result):
        row = self._tbl.rowCount()
        self._tbl.insertRow(row)

        # File
        fi = QTableWidgetItem(result.filename)
        fi.setToolTip(result.path)
        self._tbl.setItem(row, 0, fi)

        # Verdict
        vi = QTableWidgetItem(result.verdict)
        vi.setForeground(QColor(result.verdict_color))
        self._tbl.setItem(row, 1, vi)

        # Risk
        ri = QTableWidgetItem(f"{result.risk_score}%")
        if result.risk_score >= 80:
            ri.setForeground(QColor("#f47070"))
        elif result.risk_score >= 22:
            ri.setForeground(QColor("#f5c542"))
        else:
            ri.setForeground(QColor("#34d399"))
        self._tbl.setItem(row, 2, ri)

        # Size
        size_str = (
            f"{result.size / (1024*1024):.1f} MB" if result.size > 1024*1024
            else f"{result.size // 1024} KB" if result.size > 1024
            else f"{result.size} B"
        )
        self._tbl.setItem(row, 3, QTableWidgetItem(size_str))

        # Time
        self._tbl.setItem(row, 4, QTableWidgetItem(result.scanned_at))

        # Scroll to newest
        self._tbl.scrollToBottom()

    def _show_result_detail(self, idx):
        if idx.row() >= len(self._results):
            return
        result = self._results[idx.row()]
        dlg = QDialog(self)
        dlg.setWindowTitle(f"Scan Detail — {result.filename}")
        dlg.resize(620, 480)
        lay = QVBoxLayout(dlg)
        lay.setContentsMargins(20, 16, 20, 16)
        lay.setSpacing(10)

        # Verdict banner
        banner = QFrame()
        banner.setStyleSheet(
            f"background:rgba(0,0,0,0.3); border:1px solid {result.verdict_color}; border-radius:10px;"
        )
        bl = QHBoxLayout(banner); bl.setContentsMargins(14, 10, 14, 10)
        bl.addWidget(_lbl(
            {"MALWARE": "🚨", "SUSPICIOUS": "⚠", "CLEAN": "✅", "ERROR": "❌", "SKIPPED": "⏭"}.get(result.verdict, "?"),
            "font-size:24px;"
        ))
        vt = QVBoxLayout(); vt.setSpacing(2)
        vt.addWidget(_lbl(result.verdict, f"font-size:18px; font-weight:700; color:{result.verdict_color};"))
        vt.addWidget(_lbl(result.path, "font-size:10px; color:#445068;"))
        bl.addLayout(vt, 1)
        lay.addWidget(banner)

        # Info grid
        info_grid = QFormLayout(); info_grid.setSpacing(6)
        info_grid.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        for lbl_txt, val in [
            ("SHA-256:", result.sha256),
            ("MD5:",     result.md5),
            ("Size:",    f"{result.size:,} bytes"),
            ("Risk:",    f"{result.risk_score}%"),
            ("Scanned:", result.scanned_at),
        ]:
            info_grid.addRow(_lbl(lbl_txt, "color:#445068;font-size:12px;"),
                             _lbl(val, "color:#8fa3c0;font-size:12px;font-family:Consolas;"))
        lay.addLayout(info_grid)

        # Indicators
        lay.addWidget(_lbl("Indicators:", "font-size:12px; font-weight:700; color:#dde6f0;"))
        if result.indicators:
            for ind in result.indicators:
                icon = "🔴" if result.verdict == "MALWARE" else "🟡"
                row_lbl = _lbl(f"{icon}  {ind}", "font-size:12px; color:#8fa3c0;")
                row_lbl.setWordWrap(True)
                lay.addWidget(row_lbl)
        else:
            lay.addWidget(_lbl("No suspicious indicators found.", "font-size:12px; color:#34d399;"))

        # MalwareBazaar hit
        if result.cloud_match:
            mb = result.cloud_match
            lay.addWidget(_lbl("MalwareBazaar Entry:", "font-size:12px; font-weight:700; color:#f47070;"))
            for k, v in [("Type", mb.get("file_type", "?")), ("Tags", ", ".join(mb.get("tags") or [])),
                         ("First seen", mb.get("first_seen", "?")),
                         ("Reporter", mb.get("reporter", "?"))]:
                lay.addWidget(_lbl(f"  {k}: {v}", "font-size:11px; color:#8fa3c0;font-family:Consolas;"))

        if result.error:
            lay.addWidget(_lbl(f"Error: {result.error}", "font-size:11px; color:#f59e0b;"))

        lay.addStretch()
        close = QPushButton("Close"); close.setObjectName("primaryBtn")
        close.setFixedHeight(32); close.clicked.connect(dlg.accept)
        lay.addWidget(close)
        dlg.exec()

    def _clear_results(self):
        self._tbl.setRowCount(0)
        self._results.clear()
        self._scan_count  = 0
        self._threat_count = 0
        self._lbl_scanned.setText("0")
        self._lbl_threats.setText("0")

    def _set_status(self, msg: str):
        self._status_lbl.setText(msg[:80])

    def _browse_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select File to Scan")
        if path:
            self._scan_path.setText(path)

    def _browse_folder(self):
        path = QFileDialog.getExistingDirectory(self, "Select Folder to Scan")
        if path:
            self._scan_path.setText(path)

    def _scan_file_manual(self):
        path = self._scan_path.text().strip()
        if not path:
            QMessageBox.warning(self, "No path", "Enter a file path first.")
            return
        from pathlib import Path as _P
        if not _P(path).is_file():
            QMessageBox.warning(self, "Not a file", f"'{path}' is not a file.")
            return
        threading.Thread(target=self._bg_scan_file, args=(_P(path),), daemon=True).start()

    def _scan_dir_manual(self, recursive: bool):
        path = self._scan_path.text().strip()
        if not path:
            QMessageBox.warning(self, "No path", "Enter a folder path first.")
            return
        from pathlib import Path as _P
        if not _P(path).is_dir():
            QMessageBox.warning(self, "Not a folder", f"'{path}' is not a folder.")
            return
        threading.Thread(target=self._bg_scan_dir, args=(path, recursive), daemon=True).start()

    @staticmethod
    def _mini_stat(label: str, value: str, color: str) -> tuple:
        f  = QFrame(); f.setObjectName("card2")
        fl = QHBoxLayout(f); fl.setContentsMargins(12, 8, 12, 8); fl.setSpacing(6)
        vl = _lbl(value, f"font-size:18px; font-weight:700; color:{color};")
        fl.addWidget(vl)
        fl.addWidget(_lbl(label, "font-size:11px; color:#8fa3c0;"))
        return vl, f


def _scan_exts():
    try:
        from detectors.file_scanner import SCAN_EXTENSIONS
        return SCAN_EXTENSIONS
    except Exception:
        return frozenset()


# ══════════════════════════════════════════════════════════════════════════════
# ── Tools tab ─────────────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

class ToolsTab(QWidget):
    _email_done      = pyqtSignal(dict)
    _prediction_done = pyqtSignal(dict)
    demo_alert       = pyqtSignal(dict)   # routed to MainWindow → correct tab
    demo_sys_alert   = pyqtSignal(dict)   # routed to SystemMonitorTab

    def __init__(self, model_ready: bool = False, parent=None):
        super().__init__(parent)
        self._model_ready = model_ready
        self._email_done.connect(self._show_email_result)
        self._prediction_done.connect(self._show_prediction)
        self._vs_done_sig.connect(self._vs_show_results)
        self._vs_status_sig.connect(self._vs_show_status)
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.addWidget(_page_header("🧪", "Test & Analyse",
            "Simulate attacks, test the DDoS classifier, scan emails and hosts"))
        inner = QWidget(); inner.setStyleSheet("background: #0b0d1e;")
        il = QVBoxLayout(inner); il.setContentsMargins(12, 10, 12, 10); il.setSpacing(0)
        tabs = QTabWidget()
        tabs.setObjectName("innerTabs")
        self._build_sim_tab(tabs)
        self._build_ddos_tab(tabs)
        self._build_email_tab(tabs)
        self._build_vuln_tab(tabs)
        self._build_threat_test_tab(tabs)
        il.addWidget(tabs)
        root.addWidget(inner, 1)
        self._vuln_scanner = None

    # ── Simulation tab ─────────────────────────────────────────────────────

    def _sim_card(self, icon: str, name: str, severity: str, desc: str,
                  where: str, on_fire) -> QFrame:
        sev_color = {"critical": "#f87171", "high": "#fb923c",
                     "medium": "#fbbf24", "low": "#34d399"}.get(severity, "#8fa3c0")
        f = QFrame(); f.setObjectName("card2")
        fl = QVBoxLayout(f); fl.setContentsMargins(12, 10, 12, 10); fl.setSpacing(5)
        hrow = QHBoxLayout(); hrow.setSpacing(8)
        hrow.addWidget(_lbl(icon, "font-size:17px;"))
        hrow.addWidget(_lbl(name, "font-size:13px; font-weight:700; color:#dde6f0;"), 1)
        badge = _lbl(f"  {severity.upper()}  ",
                     f"font-size:9px; font-weight:700; color:{sev_color};"
                     f"background:rgba(0,0,0,.25); border:1px solid {sev_color}; border-radius:99px;")
        hrow.addWidget(badge)
        fl.addLayout(hrow)
        dl = _lbl(desc, "color:#8fa3c0; font-size:11px;")
        dl.setWordWrap(True)
        fl.addWidget(dl)
        fl.addWidget(_lbl(f"📍 {where}", "color:#445068; font-size:10px;"))
        btn = QPushButton("⚡  Fire Simulation"); btn.setObjectName("secondaryBtn")
        btn.setFixedHeight(28); btn.clicked.connect(on_fire)
        fl.addWidget(btn)
        return f

    def _build_sim_tab(self, tabs: QTabWidget):
        page = QWidget()
        outer = QVBoxLayout(page); outer.setContentsMargins(0, 0, 0, 0); outer.setSpacing(0)
        scroll = QScrollArea(); scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        inner = QWidget()
        lay = QVBoxLayout(inner); lay.setContentsMargins(20, 16, 20, 20); lay.setSpacing(14)
        scroll.setWidget(inner); outer.addWidget(scroll)

        # ── How-to guide ────────────────────────────────────────────────────
        guide = QFrame(); guide.setObjectName("card2")
        gl = QVBoxLayout(guide); gl.setContentsMargins(16, 14, 16, 14); gl.setSpacing(8)
        gl.addWidget(_lbl("🎭  Simulation Lab", "font-size:15px; font-weight:700; color:#e2eeff;"))
        gl.addWidget(_lbl(
            "Fire safe in-memory test alerts to verify every detector is working and see exactly "
            "what each threat looks like — no real attack traffic needed.",
            "color:#8fa3c0; font-size:12px;"
        ))
        steps_row = QHBoxLayout(); steps_row.setSpacing(4)
        for step_n, step_txt in [
            ("① Fire",   "Click ⚡ Fire Simulation\non any card below"),
            ("② Switch", "Go to Threats & Alerts\nor System Monitor tab"),
            ("③ Expand", "Click the new alert card\nto open full details"),
            ("④ Read",   "What happened · Why dangerous\n· What to do · MITRE ID"),
        ]:
            sf = QFrame()
            sf.setStyleSheet(
                "background:rgba(79,142,247,.07);border:1px solid rgba(79,142,247,.16);"
                "border-radius:9px;"
            )
            sl = QVBoxLayout(sf); sl.setContentsMargins(10, 8, 10, 8); sl.setSpacing(2)
            sl.addWidget(_lbl(step_n, "font-size:11px; color:#4f8ef7; font-weight:700;"))
            stl = _lbl(step_txt, "font-size:11px; color:#8fa3c0;")
            stl.setWordWrap(True); sl.addWidget(stl)
            steps_row.addWidget(sf, 1)
            if step_n != "④ Read":
                steps_row.addWidget(_lbl("›", "font-size:18px; color:#28304e;"))
        gl.addLayout(steps_row)
        lay.addWidget(guide)

        # ── Simulation data ──────────────────────────────────────────────────
        _DEMO_NET = [
            ("🔗", "ARP Spoofing",     "arp",         "critical",
             "ARP Spoofing — Gateway!", "192.168.1.1",
             "ARP cache poisoning: 192.168.1.1 changed MAC from aa:bb:cc:dd:ee:ff to 11:22:33:44:55:66 [GATEWAY HIJACK]",
             "Attacker reroutes all traffic through their machine to eavesdrop (Man-in-the-Middle)."),
            ("🌍", "DNS Tunneling",    "dns",         "critical",
             "DNS Tunneling", "exfil.evil.xyz",
             "DNS tunneling suspected: subdomain label 'aGVsbG8td29ybGQtdGhpcyBpcy1hLXRlc3Q...' (52 chars) in evil.xyz",
             "Data smuggled out of your network hidden inside DNS queries."),
            ("🔑", "SSH Brute Force",  "brute_force", "high",
             "SSH Brute Force", "203.0.113.42",
             "Brute force: 10 SSH (port 22) attempts from 203.0.113.42 within 60s",
             "Automated password guessing on SSH — could gain remote shell access."),
            ("🔑", "Password Spray",   "brute_force", "critical",
             "Password Spray", "198.51.100.7",
             "Password spray: 198.51.100.7 targeting 4 services simultaneously — SSH, RDP, FTP, SMB",
             "Low-and-slow attack using common passwords across many accounts to evade lockout."),
            ("🌐", "Threat Intel Hit", "threat_intel","high",
             "Threat Intelligence Hit", "185.220.101.45",
             "AbuseIPDB: 185.220.101.45 scored 98% abuse confidence (1284 reports, ISP: Tor Exit Node, DE)",
             "Known malicious IP contacting or contacted by your network."),
            ("🌍", "Fast-Flux DNS",    "dns",         "high",
             "Fast-Flux DNS", "botnet-c2.top",
             "Fast-flux: botnet-c2.top resolved to 8+ distinct IPs — likely bulletproof hosting or botnet C2",
             "Domain rotates IPs rapidly to avoid takedown — sign of active C2 infrastructure."),
        ]
        _DEMO_SYS = [
            ("🪟", "Failed Login",    "event_log", "high",
             "Failed Logon", "WORKSTATION-01",
             "Failed logon by 'Administrator' from WORKSTATION-01 (type 3 — Network)",
             "Repeated failures can signal a brute-force or credential stuffing attack."),
            ("👑", "New Admin Added", "event_log", "critical",
             "Added to Administrators", "192.168.1.55",
             "User 'hacker' added to Administrators group by 'SYSTEM'",
             "Privilege escalation — attacker granting themselves full system control."),
            ("⚙",  "New Service",    "event_log", "critical",
             "New Service Installed", "localhost",
             "New service installed: 'svchost_update.exe' by 'SYSTEM' — possible persistence",
             "Malware installs services to survive reboots — classic persistence mechanism."),
            ("📁", "File Modified",  "fim",       "high",
             "FIM — File Modified", "localhost",
             r"Monitored file hash changed: C:\Windows\System32\drivers\etc\hosts",
             "Critical system file tampered — could redirect web traffic or disable defences."),
            ("📁", "File Created",   "fim",       "medium",
             "FIM — File Created", "localhost",
             r"New file in monitored directory: C:\Windows\System32\evil.dll",
             "Unexpected file in system folder — could be a dropped malware payload."),
            ("🪟", "Log Cleared",    "event_log", "critical",
             "Audit Log Cleared", "DESKTOP-ABC",
             "Windows Security audit log CLEARED by 'Administrator' — sign of log tampering",
             "Attackers clear event logs to erase evidence of activity after a breach."),
        ]
        _DEMO_ADV = [
            ("🔐", "Weak TLS Ciphers",    "tls",        "medium",
             "Weak TLS Ciphers", "192.168.1.100",
             "Weak ciphers from 192.168.1.100: RC4(0x0005), 3DES(0x000A), AES-CBC(0x002F) — BEAST/POODLE risk",
             "Obsolete crypto — attacker can decrypt your HTTPS in a BEAST/POODLE attack."),
            ("🔐", "TLS without SNI",     "tls",        "medium",
             "TLS without SNI", "10.0.0.55",
             "TLS ClientHello on port 443 from 10.0.0.55 with no SNI — possible direct-IP C2",
             "Encrypted C2 beacons often skip SNI to bypass domain-based firewalls."),
            ("🔐", "Malicious TLS JA3",   "tls",        "critical",
             "Malicious TLS", "185.220.101.5",
             "JA3 fingerprint matches Cobalt Strike beacon (72a589da586844d7f0818ce684948eea) from 185.220.101.5",
             "TLS fingerprint of known post-exploitation C2 — active attacker tool in your network."),
            ("👤", "UEBA Off-Hours",      "ueba",       "high",
             "UEBA — Off-Hours Login", "WORKSTATION-55",
             "UEBA anomaly: user 'jsmith' logged in at 02:47 (outside 07:00–20:00) on WORKSTATION-55",
             "Unusual-hours login — could indicate stolen credentials or an insider threat."),
            ("👤", "UEBA New Workstation","ueba",       "high",
             "UEBA — New Workstation", "WORKSTATION-NEW",
             "UEBA anomaly: user 'jsmith' authenticated from WORKSTATION-NEW — device not in baseline",
             "Login from unknown machine — possible lateral movement with stolen credentials."),
            ("🚫", "IP Auto-Blocked",     "ip_blocker", "high",
             "IP Auto-Blocked", "203.0.113.99",
             "IP 203.0.113.99 auto-blocked via Windows Firewall (inbound+outbound) — Brute Force — TTL 60 min",
             "Simulates the auto-block response; shows firewall rule creation and TTL countdown."),
        ]

        groups = [
            ("🌐  Network Threats",          "#5b9cf6",  _DEMO_NET, self.demo_alert),
            ("🖥  Host & System Threats",    "#a78bfa",  _DEMO_SYS, self.demo_sys_alert),
            ("🔬  Advanced Detectors",       "#2dd4bf",  _DEMO_ADV, self.demo_alert),
        ]
        dest = {self.demo_alert: "Threats & Alerts tab",
                self.demo_sys_alert: "System Monitor tab"}

        for grp_label, grp_color, grp_data, emit_fn in groups:
            hdr_txt = f"{grp_label}  →  {dest[emit_fn]}"
            lay.addWidget(_lbl(hdr_txt,
                               f"font-size:12px; font-weight:700; color:{grp_color}; letter-spacing:0.3px;"))
            grid = QHBoxLayout(); grid.setSpacing(10)
            col_l = QVBoxLayout(); col_l.setSpacing(8)
            col_r = QVBoxLayout(); col_r.setSpacing(8)
            for i, (icon, name, cat, sev, rule, ip, msg, desc) in enumerate(grp_data):
                card = self._sim_card(
                    icon, name, sev, desc, dest[emit_fn],
                    lambda _, c=cat, s=sev, r=rule, ip_=ip, m=msg, ef=emit_fn: ef.emit({
                        "rule_name": r, "severity": s, "source_ip": ip_,
                        "message": m,
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "category": c,
                    })
                )
                (col_l if i < 3 else col_r).addWidget(card)
            grid.addLayout(col_l); grid.addLayout(col_r)
            lay.addLayout(grid)

        lay.addStretch()
        tabs.addTab(page, "🎭  Simulations")

    # ── DDoS Test tab ──────────────────────────────────────────────────────

    def _build_ddos_tab(self, tabs: QTabWidget):
        page = QWidget()
        root = QVBoxLayout(page); root.setContentsMargins(20, 16, 20, 16); root.setSpacing(12)

        lcard = QFrame(); lcard.setObjectName("card")
        ll = QVBoxLayout(lcard); ll.setContentsMargins(18, 16, 18, 16); ll.setSpacing(10)
        ll.addWidget(_lbl("🧪  DDoS Detection Test", "font-size:15px; font-weight:700;"))
        ll.addWidget(_lbl(
            "Fill in network flow statistics and press Run Detection to see what the ML model predicts. "
            "Use the presets to quickly load a typical normal or attack traffic profile.",
            "color:#8fa3c0; font-size:12px; line-height:1.5;"
        ))
        pr = QHBoxLayout(); pr.setSpacing(8)
        for label, ptype in [("✅  Normal Traffic", "normal"), ("🚨  DDoS Attack", "attack")]:
            b = QPushButton(label); b.setObjectName("secondaryBtn")
            b.clicked.connect(lambda _, t=ptype: self._preset(t))
            pr.addWidget(b)
        ll.addLayout(pr)

        form = QFormLayout(); form.setSpacing(8); form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        self._f = {}
        fields = [
            ("Protocol",           "protocol", QComboBox,  None),
            ("Flow Duration (µs)", "duration", QSpinBox,   (1, 99_999_999, 100)),
            ("Packets Sent",       "fwd",      QSpinBox,   (0, 999_999, 10)),
            ("Packets Received",   "bwd",      QSpinBox,   (0, 999_999, 10)),
            ("SYN Count",          "syn",      QSpinBox,   (0, 999_999, 0)),
            ("Flow Bytes/s",       "bytes",    QSpinBox,   (0, 99_999_999, 1000)),
            ("Largest Packet (B)", "pktmax",   QSpinBox,   (0, 65535, 200)),
            ("Init Window Size",   "win",      QSpinBox,   (0, 65535, 65535)),
        ]
        for label, key, wtype, cfg in fields:
            if wtype == QComboBox:
                w = QComboBox(); w.addItems(["TCP (6)", "UDP (17)", "Other (0)"])
            else:
                w = QSpinBox()
                if cfg:
                    w.setRange(cfg[0], cfg[1])
                    w.setValue(cfg[2])
            w.setFixedHeight(32)
            form.addRow(_lbl(label, "color:#8fa3c0;font-size:12px;"), w)
            self._f[key] = w
        ll.addLayout(form)

        self._run_btn = QPushButton("Run Detection →"); self._run_btn.setObjectName("primaryBtn")
        if not self._model_ready:
            self._run_btn.setEnabled(False)
            self._run_btn.setText("⚠  Model not loaded — run: python main_app.py --train")
        self._run_btn.clicked.connect(self._run_prediction)
        ll.addWidget(self._run_btn)

        self._result_frame = QFrame(); self._result_frame.setObjectName("card2")
        self._result_frame.hide()
        rl = QVBoxLayout(self._result_frame); rl.setContentsMargins(14, 12, 14, 12); rl.setSpacing(6)
        self._res_icon  = _lbl("", "font-size:24px;")
        self._res_title = _lbl("", "font-size:15px; font-weight:700;")
        self._res_sub   = _lbl("", "color:#8fa3c0; font-size:12px;")
        self._res_sub.setWordWrap(True)
        self._res_detail = _lbl("", "color:#8fa3c0; font-size:11px; font-family:Consolas;")
        for w in [self._res_icon, self._res_title, self._res_sub, self._res_detail]:
            rl.addWidget(w)
        ll.addWidget(self._result_frame)
        ll.addStretch()
        root.addWidget(lcard, 1)
        tabs.addTab(page, "🧪  DDoS Test")

    # ── Email tab ──────────────────────────────────────────────────────────

    def _build_email_tab(self, tabs: QTabWidget):
        page = QWidget()
        root = QVBoxLayout(page); root.setContentsMargins(20, 16, 20, 16); root.setSpacing(12)

        rcard = QFrame(); rcard.setObjectName("card")
        rl2 = QVBoxLayout(rcard); rl2.setContentsMargins(18, 16, 18, 16); rl2.setSpacing(10)
        rl2.addWidget(_lbl("📧  Email Phishing Checker", "font-size:15px; font-weight:700;"))
        rl2.addWidget(_lbl(
            "Paste the full email text below — including the Subject and From line. "
            "We scan for phishing keywords and run AI analysis via Gemini.",
            "color:#8fa3c0; font-size:12px; line-height:1.5;"
        ))
        self._email_input = QTextEdit()
        self._email_input.setPlaceholderText(
            "From: support@paypal.com\nSubject: Urgent: account suspended\n\n"
            "Dear customer, your account has been limited…"
        )
        self._email_input.setMinimumHeight(200)
        rl2.addWidget(self._email_input, 1)
        self._email_btn = QPushButton("Analyse Email"); self._email_btn.setObjectName("primaryBtn")
        self._email_btn.clicked.connect(self._run_email)
        rl2.addWidget(self._email_btn)
        self._email_result_area = QScrollArea(); self._email_result_area.setWidgetResizable(True)
        self._email_result_area.setFrameShape(QFrame.Shape.NoFrame)
        self._email_result_inner = QWidget()
        self._email_result_lay   = QVBoxLayout(self._email_result_inner)
        self._email_result_lay.setContentsMargins(0, 0, 0, 0)
        self._email_result_area.setWidget(self._email_result_inner)
        rl2.addWidget(self._email_result_area, 1)
        root.addWidget(rcard, 1)
        tabs.addTab(page, "📧  Email")

    # ── Vuln Scan tab ──────────────────────────────────────────────────────

    def _build_vuln_tab(self, tabs: QTabWidget):
        page = QWidget()
        root = QVBoxLayout(page); root.setContentsMargins(20, 16, 20, 16); root.setSpacing(12)

        vcard = QFrame(); vcard.setObjectName("card")
        vl = QVBoxLayout(vcard); vl.setContentsMargins(18, 16, 18, 16); vl.setSpacing(10)
        vl.addWidget(_lbl("🔍  Network Vulnerability Scanner", "font-size:15px; font-weight:700;"))
        vl.addWidget(_lbl(
            "Scan a host or CIDR subnet for open ports and identify risky services. "
            "No nmap required — uses pure Python sockets.",
            "color:#8fa3c0; font-size:12px;"
        ))
        vf = QHBoxLayout(); vf.setSpacing(8)
        vf.addWidget(_lbl("Target:", "font-size:13px; min-width:50px;"))
        self._vs_target = QLineEdit()
        self._vs_target.setPlaceholderText("192.168.1.1  or  192.168.1.0/24  or  hostname")
        self._vs_target.setFixedHeight(32); vf.addWidget(self._vs_target, 1)
        self._vs_btn = QPushButton("Start Scan"); self._vs_btn.setObjectName("primaryBtn")
        self._vs_btn.setFixedHeight(32); self._vs_btn.clicked.connect(self._run_vuln_scan)
        vf.addWidget(self._vs_btn)
        self._vs_cancel_btn = QPushButton("Cancel"); self._vs_cancel_btn.setObjectName("secondaryBtn")
        self._vs_cancel_btn.setFixedHeight(32); self._vs_cancel_btn.setEnabled(False)
        self._vs_cancel_btn.clicked.connect(self._cancel_vuln_scan)
        vf.addWidget(self._vs_cancel_btn)
        vl.addLayout(vf)
        self._vs_status = _lbl("Enter a target and press Start Scan.",
                                "color:#8fa3c0; font-size:12px; font-family:Consolas;")
        vl.addWidget(self._vs_status)
        self._vs_tbl = QTableWidget(0, 4)
        self._vs_tbl.setHorizontalHeaderLabels(["Host", "Port", "Service", "Risk / Banner"])
        self._vs_tbl.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self._vs_tbl.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._vs_tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._vs_tbl.setAlternatingRowColors(False)
        self._vs_tbl.setMinimumHeight(300)
        vl.addWidget(self._vs_tbl, 1)
        root.addWidget(vcard, 1)
        tabs.addTab(page, "🔍  Vuln Scan")

    def _run_vuln_scan(self):
        target = self._vs_target.text().strip()
        if not target:
            return
        from detectors.vuln_scanner import VulnScanner
        self._vs_tbl.setRowCount(0)
        self._vs_btn.setEnabled(False); self._vs_cancel_btn.setEnabled(True)
        self._vuln_scanner = VulnScanner(
            on_progress=self._vs_progress,
            on_done=self._vs_done_sig.emit,
        )
        self._vuln_scanner.scan_async(target)

    _vs_done_sig = pyqtSignal(dict)

    def _cancel_vuln_scan(self):
        if self._vuln_scanner:
            self._vuln_scanner.cancel()
        self._vs_btn.setEnabled(True); self._vs_cancel_btn.setEnabled(False)

    def _vs_progress(self, msg: str):
        self._vs_status_sig.emit(msg)

    _vs_status_sig = pyqtSignal(str)

    def _vs_show_status(self, msg: str):
        self._vs_status.setText(msg)

    def _vs_show_results(self, results: dict):
        self._vs_btn.setEnabled(True); self._vs_cancel_btn.setEnabled(False)
        hosts = results.get("hosts", {})
        self._vs_tbl.setRowCount(0)
        for host, findings in hosts.items():
            for f in findings:
                r   = self._vs_tbl.rowCount()
                self._vs_tbl.insertRow(r)
                self._vs_tbl.setItem(r, 0, QTableWidgetItem(host))
                self._vs_tbl.setItem(r, 1, QTableWidgetItem(str(f["port"])))
                self._vs_tbl.setItem(r, 2, QTableWidgetItem(f.get("service", "")))
                risk   = f.get("risk", "MEDIUM")
                banner = f.get("banner", "") or ""
                cell   = QTableWidgetItem(f"{risk}  {banner[:60]}")
                cell.setForeground(QColor("#f87171" if risk == "HIGH" else "#fbbf24"))
                self._vs_tbl.setItem(r, 3, cell)
        n = sum(len(v) for v in hosts.values())
        self._vs_status.setText(
            f"Scan complete — {len(hosts)} host(s) found with open ports, {n} finding(s) total."
            if hosts else "Scan complete — no open ports found on the scanned target(s)."
        )

    # ── Threat Test File tab ───────────────────────────────────────────────────

    _tt_done_sig = pyqtSignal(list)   # list[dict] of per-row results

    def _build_threat_test_tab(self, tabs: QTabWidget):
        """
        Custom Threat Test — load any CSV or JSON file with network flow
        features and run every row through the DDoS ML classifier.
        Supports: CICDDoS2019 CSV, raw-feature CSV, JSON array of dicts.
        """
        self._tt_done_sig.connect(self._tt_show_results)

        page = QWidget()
        root = QVBoxLayout(page); root.setContentsMargins(20, 16, 20, 16); root.setSpacing(12)

        # ── Explanation banner ─────────────────────────────────────────────
        info = QFrame(); info.setObjectName("card2")
        il = QVBoxLayout(info); il.setContentsMargins(16, 14, 16, 14); il.setSpacing(8)
        il.addWidget(_lbl("📂  Custom Threat Test", "font-size:15px; font-weight:700; color:#e2eeff;"))
        il.addWidget(_lbl(
            "Load any CSV or JSON file containing network flow features and run every row "
            "through the trained DDoS ML classifier. The tool auto-detects the format and "
            "compares predictions against ground-truth labels when a Label/Class column is present.",
            "color:#8fa3c0; font-size:12px;"
        ))
        # format hint row
        fmts = QHBoxLayout(); fmts.setSpacing(8)
        for icon, label, desc in [
            ("📊", "CICDDoS2019 CSV", "Has Label col — shows accuracy vs ground truth"),
            ("📋", "Feature CSV",     "Columns match model features — predicts only"),
            ("📄", "JSON array",      "Array of {feature: value} dicts — predicts only"),
        ]:
            ff = QFrame()
            ff.setStyleSheet(
                "background:rgba(79,142,247,.06); border:1px solid rgba(79,142,247,.15);"
                "border-radius:8px;"
            )
            fl2 = QVBoxLayout(ff); fl2.setContentsMargins(10, 7, 10, 7); fl2.setSpacing(2)
            fl2.addWidget(_lbl(f"{icon}  {label}", "font-size:11px; font-weight:700; color:#7baef7;"))
            d2 = _lbl(desc, "font-size:10px; color:#6a7fa0;"); d2.setWordWrap(True)
            fl2.addWidget(d2)
            fmts.addWidget(ff, 1)
        il.addLayout(fmts)
        root.addWidget(info)

        # ── Built-in safe tests ────────────────────────────────────────────
        safe_card = QFrame(); safe_card.setObjectName("card2")
        sl2 = QVBoxLayout(safe_card); sl2.setContentsMargins(16, 12, 16, 12); sl2.setSpacing(8)
        sl2.addWidget(_lbl("Built-in Safe Test Profiles",
                           "font-size:12px; font-weight:700; color:#dde6f0;"))
        sl2.addWidget(_lbl(
            "No file needed — these pre-built attack and benign flow profiles test the model instantly.",
            "font-size:11px; color:#6a7fa0;"
        ))
        btn_row = QHBoxLayout(); btn_row.setSpacing(8)
        self._tt_run_all_btn = QPushButton("Run All Built-in Profiles")
        self._tt_run_all_btn.setObjectName("primaryBtn")
        self._tt_run_all_btn.setFixedHeight(30)
        self._tt_run_all_btn.clicked.connect(self._tt_run_builtin)
        btn_row.addWidget(self._tt_run_all_btn)
        btn_row.addStretch()
        sl2.addLayout(btn_row)
        root.addWidget(safe_card)

        # ── File load row ──────────────────────────────────────────────────
        file_row = QHBoxLayout(); file_row.setSpacing(8)
        self._tt_path = QLineEdit()
        self._tt_path.setPlaceholderText("Or browse for a CSV / JSON test file…")
        self._tt_path.setFixedHeight(32)
        self._tt_path.setStyleSheet(
            "QLineEdit { background:#0d1020; border:1px solid #1e2848; border-radius:8px;"
            " color:#dde6f0; padding:0 10px; font-size:12px; }"
            "QLineEdit:focus { border-color:#4f8ef7; }"
        )
        browse = QPushButton("Browse…"); browse.setObjectName("secondaryBtn")
        browse.setFixedHeight(32); browse.setFixedWidth(80)
        browse.clicked.connect(self._tt_browse)
        self._tt_load_btn = QPushButton("Run Test")
        self._tt_load_btn.setObjectName("dangerBtn")
        self._tt_load_btn.setFixedHeight(32); self._tt_load_btn.setFixedWidth(90)
        self._tt_load_btn.clicked.connect(self._tt_run_file)
        file_row.addWidget(self._tt_path, 1)
        file_row.addWidget(browse)
        file_row.addWidget(self._tt_load_btn)
        root.addLayout(file_row)

        # ── Summary cards ──────────────────────────────────────────────────
        self._tt_sum_row = QHBoxLayout(); self._tt_sum_row.setSpacing(10)
        self._tt_cards: dict[str, QLabel] = {}
        for key, label, color in [
            ("total",      "Total Rows",   "#8fa3c0"),
            ("attack",     "ATTACK",       "#f87171"),
            ("suspicious", "SUSPICIOUS",   "#fbbf24"),
            ("normal",     "NORMAL",       "#34d399"),
            ("rate",       "Detection %",  "#4f8ef7"),
            ("accuracy",   "Accuracy",     "#a78bfa"),
        ]:
            f = QFrame(); f.setObjectName("card2")
            fl2 = QVBoxLayout(f); fl2.setContentsMargins(12, 8, 12, 8); fl2.setSpacing(2)
            vl = _lbl("—", f"font-size:20px; font-weight:700; color:{color};")
            fl2.addWidget(vl)
            fl2.addWidget(_lbl(label, "font-size:10px; color:#8fa3c0;"))
            self._tt_sum_row.addWidget(f, 1)
            self._tt_cards[key] = vl
        root.addLayout(self._tt_sum_row)

        # ── Results table ──────────────────────────────────────────────────
        self._tt_status = _lbl("Load a file or run built-in profiles to begin.",
                                "font-size:11px; color:#445068;")
        root.addWidget(self._tt_status)

        cols = ["#", "Profile / Row", "SYN Flags", "Pkt/s", "Verdict", "Confidence", "Ground Truth"]
        self._tt_tbl = QTableWidget(0, len(cols))
        self._tt_tbl.setHorizontalHeaderLabels(cols)
        self._tt_tbl.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._tt_tbl.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._tt_tbl.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self._tt_tbl.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self._tt_tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._tt_tbl.verticalHeader().setVisible(False)
        root.addWidget(self._tt_tbl, 1)

        tabs.addTab(page, "📂  Threat Test")

    # ── Threat test actions ────────────────────────────────────────────────────

    def _tt_browse(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select threat test file", str(ROOT),
            "Test files (*.csv *.json);;CSV files (*.csv);;JSON files (*.json);;All files (*)"
        )
        if path:
            self._tt_path.setText(path)

    def _tt_run_builtin(self):
        if not _HAS_ADV:
            self._tt_status.setText("adversarial.py not available — cannot run built-in profiles.")
            return
        self._tt_run_all_btn.setEnabled(False)
        self._tt_run_all_btn.setText("Running…")
        threading.Thread(target=self._tt_worker_builtin, daemon=True).start()

    def _tt_worker_builtin(self):
        try:
            from detectors.adversarial import ATTACK_PROFILES, BENIGN_PROFILE
            import config
            from detectors.ddos import DDosDetector
            det = DDosDetector(config.MODEL_FILENAME, config.RULES_CONFIG)
            rows = []
            for name, profile in ATTACK_PROFILES.items():
                r = det.predict(profile)
                rows.append({
                    "label":    name,
                    "features": profile,
                    "verdict":  r.get("verdict", "ERROR"),
                    "conf":     r.get("confidence", 0.0),
                    "ground":   "ATTACK",
                })
            # Benign profile
            r = det.predict(BENIGN_PROFILE)
            rows.append({
                "label":    "Benign Traffic",
                "features": BENIGN_PROFILE,
                "verdict":  r.get("verdict", "ERROR"),
                "conf":     r.get("confidence", 0.0),
                "ground":   "BENIGN",
            })
        except Exception as e:
            rows = [{"label": f"Error: {e}", "features": {}, "verdict": "ERROR", "conf": 0, "ground": ""}]
        self._tt_done_sig.emit(rows)

    def _tt_run_file(self):
        path = self._tt_path.text().strip()
        if not path:
            self._tt_status.setText("Choose a file first.")
            return
        self._tt_load_btn.setEnabled(False)
        self._tt_load_btn.setText("Loading…")
        threading.Thread(target=self._tt_worker_file, args=(path,), daemon=True).start()

    def _tt_worker_file(self, path: str):
        import config
        from detectors.ddos import DDosDetector
        rows = []
        try:
            det = DDosDetector(config.MODEL_FILENAME, config.RULES_CONFIG)
            if not det.model_ready:
                rows = [{"label": "Model not loaded — run train_model.py", "features": {},
                         "verdict": "ERROR", "conf": 0, "ground": ""}]
                self._tt_done_sig.emit(rows)
                return

            feat_names = det.feature_names

            # ── JSON ───────────────────────────────────────────────────────
            if path.lower().endswith(".json"):
                import json as _json
                records = _json.loads(open(path, encoding="utf-8").read())
                if isinstance(records, dict):
                    records = [records]
                for i, rec in enumerate(records[:5000]):
                    r = det.predict(rec)
                    rows.append({
                        "label":    f"Row {i+1}",
                        "features": rec,
                        "verdict":  r.get("verdict", "ERROR"),
                        "conf":     r.get("confidence", 0.0),
                        "ground":   str(rec.get("Label", rec.get("label", rec.get("Class", "")))),
                    })

            # ── CSV ────────────────────────────────────────────────────────
            else:
                import pandas as pd
                df = pd.read_csv(path, low_memory=False, nrows=5000)
                df.columns = df.columns.str.strip()

                # Detect ground-truth label column
                col_map = {c.lower(): c for c in df.columns}
                gt_col = col_map.get("label") or col_map.get("class")

                # Keep only known feature columns (ignore unknowns silently)
                available = [f for f in feat_names if f in df.columns]
                if not available:
                    rows = [{"label": "No recognised feature columns found in this CSV.",
                             "features": {}, "verdict": "ERROR", "conf": 0, "ground": ""}]
                    self._tt_done_sig.emit(rows)
                    return

                for i, (_, row) in enumerate(df.iterrows()):
                    feat = {f: float(row.get(f, 0) or 0) for f in feat_names}
                    r = det.predict(feat)
                    gt = str(row[gt_col]).strip() if gt_col else ""
                    rows.append({
                        "label":    f"Row {i+1}",
                        "features": feat,
                        "verdict":  r.get("verdict", "ERROR"),
                        "conf":     r.get("confidence", 0.0),
                        "ground":   gt,
                    })
        except Exception as e:
            rows = [{"label": f"Error: {e}", "features": {}, "verdict": "ERROR", "conf": 0, "ground": ""}]
        self._tt_done_sig.emit(rows)

    def _tt_show_results(self, rows: list):
        self._tt_run_all_btn.setEnabled(True)
        self._tt_run_all_btn.setText("Run All Built-in Profiles")
        self._tt_load_btn.setEnabled(True)
        self._tt_load_btn.setText("Run Test")

        self._tt_tbl.setRowCount(0)
        total = len(rows)
        attack = suspicious = normal = errors = 0
        correct = total_with_gt = 0

        _VCOL = {"ATTACK": "#f87171", "SUSPICIOUS": "#fbbf24",
                 "NORMAL": "#34d399", "ERROR": "#8fa3c0"}

        for i, row in enumerate(rows):
            v      = row.get("verdict", "ERROR")
            conf   = row.get("conf", 0.0)
            ground = row.get("ground", "")
            feat   = row.get("features", {})

            if v == "ATTACK":      attack += 1
            elif v == "SUSPICIOUS": suspicious += 1
            elif v == "NORMAL":    normal += 1
            else:                  errors += 1

            # Accuracy vs ground truth
            if ground:
                total_with_gt += 1
                gt_is_attack = ground.upper() not in ("BENIGN", "NORMAL", "0", "SAFE")
                pred_is_attack = v in ("ATTACK", "SUSPICIOUS")
                if gt_is_attack == pred_is_attack:
                    correct += 1

            r_idx = self._tt_tbl.rowCount()
            self._tt_tbl.insertRow(r_idx)

            def _cell(text, color="#c8d8f0"):
                it = QTableWidgetItem(str(text))
                it.setForeground(QColor(color))
                return it

            self._tt_tbl.setItem(r_idx, 0, _cell(str(i+1), "#445068"))
            self._tt_tbl.setItem(r_idx, 1, _cell(row.get("label", ""), "#a8c0de"))
            self._tt_tbl.setItem(r_idx, 2, _cell(int(feat.get("SYN Flag Count", 0)), "#8fa3c0"))
            self._tt_tbl.setItem(r_idx, 3, _cell(f"{feat.get('Flow Packets/s', 0):.0f}", "#8fa3c0"))
            self._tt_tbl.setItem(r_idx, 4, _cell(v, _VCOL.get(v, "#8fa3c0")))
            self._tt_tbl.setItem(r_idx, 5, _cell(f"{conf:.1f}%",
                "#f87171" if v == "ATTACK" else "#fbbf24" if v == "SUSPICIOUS" else "#34d399"))
            gt_color = "#34d399" if (not ground or ground.upper() in ("BENIGN", "NORMAL", "0", "SAFE")) else "#f87171"
            self._tt_tbl.setItem(r_idx, 6, _cell(ground or "—", gt_color))

        # Summary cards
        detected = attack + suspicious
        rate = detected / total * 100 if total else 0
        acc  = correct / total_with_gt * 100 if total_with_gt else 0
        self._tt_cards["total"].setText(str(total))
        self._tt_cards["attack"].setText(str(attack))
        self._tt_cards["suspicious"].setText(str(suspicious))
        self._tt_cards["normal"].setText(str(normal))
        self._tt_cards["rate"].setText(f"{rate:.0f}%")
        self._tt_cards["accuracy"].setText(f"{acc:.0f}%" if total_with_gt else "N/A")

        self._tt_status.setText(
            f"{total} rows tested  ·  {detected} detected ({rate:.0f}%)  ·  "
            + (f"Accuracy vs ground truth: {acc:.0f}%  ({correct}/{total_with_gt})" if total_with_gt
               else "No ground-truth labels found in this file.")
        )

    def _preset(self, ptype: str):
        n = {"protocol": 0, "duration": 500,       "fwd": 15,   "bwd": 12,
             "syn": 1,    "bytes": 800,      "pktmax": 180, "win": 65535}
        a = {"protocol": 0, "duration": 10_000_000, "fwd": 5000, "bwd": 10,
             "syn": 5000, "bytes": 9_000_000, "pktmax": 60,  "win": 0}
        vals = n if ptype == "normal" else a
        for k, v in vals.items():
            w = self._f[k]
            if isinstance(w, QComboBox): w.setCurrentIndex(v)
            else: w.setValue(v)

    def _run_prediction(self):
        self._run_btn.setEnabled(False); self._run_btn.setText("Analysing…")
        proto_idx = self._f["protocol"].currentIndex()
        proto_num = [6, 17, 0][proto_idx]
        features = {
            "Protocol":               proto_num,
            "Flow Duration":          self._f["duration"].value(),
            "Total Fwd Packets":      self._f["fwd"].value(),
            "Total Backward Packets": self._f["bwd"].value(),
            "Fwd Packets Length Total": 0, "Bwd Packets Length Total": 0,
            "Fwd Packet Length Max":  self._f["pktmax"].value(),
            "Flow Bytes/s":           self._f["bytes"].value(),
            "Flow Packets/s": 0, "Fwd IAT Min": 0, "Bwd IAT Min": 0,
            "Fwd PSH Flags": 0, "Fwd URG Flags": 0, "FIN Flag Count": 0,
            "SYN Flag Count":         self._f["syn"].value(),
            "RST Flag Count": 0, "ACK Flag Count": 0, "URG Flag Count": 0,
            "Init Fwd Win Bytes":     self._f["win"].value(),
        }

        def _worker():
            try:
                from detectors.ddos import DDosDetector
                import config
                d = DDosDetector(config.MODEL_FILENAME, config.RULES_CONFIG,
                                 config.ATTACK_CONFIDENCE_THRESHOLD)
                ml = d.predict(features)
                try:
                    from detectors.anomaly import AnomalyDetector
                    anm = AnomalyDetector(config.ANOMALY_MODEL_FILENAME).score(features)
                except Exception:
                    anm = {}
                result = {**ml, "anomaly": anm}
            except Exception as e:
                result = {"error": str(e)}
            self._prediction_done.emit(result)   # safe cross-thread signal

        threading.Thread(target=_worker, daemon=True).start()

    def _show_prediction(self, data: dict):
        self._run_btn.setEnabled(True); self._run_btn.setText("Run Detection →")
        self._result_frame.show()
        if data.get("error"):
            self._res_icon.setText("⚠️"); self._res_title.setText("Error")
            self._res_title.setStyleSheet("font-size:15px;font-weight:700;color:#fbbf24;")
            self._res_sub.setText(data["error"]); self._res_detail.setText("")
            return
        status = data.get("verdict", "NORMAL")
        icon = {"ATTACK":"🚨","SUSPICIOUS":"⚡"}.get(status,"✅")
        color = STATUS_COLOR.get(status, "#34d399")
        title = {"ATTACK":  "Attack pattern detected — this looks malicious",
                 "SUSPICIOUS": "Suspicious — worth investigating further"
                }.get(status, "Looks like normal traffic — no threat detected")
        sub   = (f"RF confidence: {data.get('confidence',0):.1f}%  ·  "
                 f"Decision threshold: {data.get('threshold',50):.1f}%")
        anm   = data.get("anomaly", {})
        detail = ""
        if anm:
            detail = (f"Isolation Forest: {'⚠ ANOMALY' if anm.get('anomaly') else '✓ Normal'}"
                      f"  (score: {anm.get('score', 0):.4f})")
        self._res_icon.setText(icon)
        self._res_title.setText(title)
        self._res_title.setStyleSheet(f"font-size:15px;font-weight:700;color:{color};")
        self._res_sub.setText(sub)
        self._res_detail.setText(detail)

    def _run_email(self):
        content = self._email_input.toPlainText().strip()
        if not content:
            return
        self._email_btn.setEnabled(False); self._email_btn.setText("Analysing…")
        def _worker():
            try:
                import config
                from detectors.email_phishing import analyze_email
                result = analyze_email(
                    content,
                    api_key=config.GEMINI_API_KEY,
                    api_url=config.GEMINI_API_URL,
                    groq_api_key=getattr(config, "GROQ_API_KEY", ""),
                    groq_model=getattr(config, "GROQ_MODEL", "openai/gpt-oss-120b"),
                )
            except Exception as e:
                result = {"error": str(e), "keyword_risk": "LOW",
                          "suspicious_keywords": [], "sender": "N/A"}
            self._email_done.emit(result)
        threading.Thread(target=_worker, daemon=True).start()

    def _show_email_result(self, data: dict):
        self._email_btn.setEnabled(True); self._email_btn.setText("Analyse Email")
        # Clear previous
        for i in reversed(range(self._email_result_lay.count())):
            it = self._email_result_lay.itemAt(i)
            if it and it.widget():
                it.widget().deleteLater()

        risk = (data.get("keyword_risk") or "LOW").upper()
        risk_color = {"HIGH":"#f87171","MEDIUM":"#fbbf24","LOW":"#34d399"}.get(risk,"#34d399")
        risk_frame = QFrame(); risk_frame.setObjectName(
            "cCrit" if risk=="HIGH" else "cMed" if risk=="MEDIUM" else "cLow")
        rf_lay = QHBoxLayout(risk_frame); rf_lay.setContentsMargins(12,10,12,10)
        rf_lay.addWidget(_lbl(f"{'⚠' if risk!='LOW' else '✅'}  {risk} RISK",
                               f"font-size:14px;font-weight:700;color:{risk_color};"))
        self._email_result_lay.addWidget(risk_frame)

        human = {"HIGH":"This email looks dangerous — do not click any links.",
                 "MEDIUM":"Some suspicious signs — proceed with caution.",
                 "LOW":"Relatively safe based on keyword scan."}.get(risk,"")
        self._email_result_lay.addWidget(_lbl(human,"color:#8fa3c0;font-size:12px;"))

        kws = data.get("suspicious_keywords", [])
        if kws:
            kw_lay = QHBoxLayout(); kw_lay.setSpacing(6)
            kw_lay.addWidget(_lbl("Keywords:", "color:#445068;font-size:11px;"))
            for kw in kws[:8]:
                kl = _lbl(kw, "color:#fbbf24;background:rgba(251,191,36,.1);"
                              "border:1px solid rgba(251,191,36,.25);"
                              "border-radius:99px;font-size:11px;padding:2px 8px;")
                kw_lay.addWidget(kl)
            kw_lay.addStretch()
            kw_w = QWidget(); kw_w.setLayout(kw_lay)
            self._email_result_lay.addWidget(kw_w)

        if data.get("ai_analysis"):
            provider = data.get("ai_provider", "AI")
            self._email_result_lay.addWidget(_lbl(
                f"AI Analysis  ({provider}):",
                "color:#445068;font-size:11px;margin-top:6px;"
            ))
            ai = QTextEdit(); ai.setReadOnly(True); ai.setFixedHeight(160)
            ai.setPlainText(data["ai_analysis"])
            self._email_result_lay.addWidget(ai)

        if data.get("error"):
            self._email_result_lay.addWidget(
                _lbl(f"ℹ {data['error']}", "color:#fbbf24;font-size:12px;"))
        self._email_result_lay.addStretch()


# ══════════════════════════════════════════════════════════════════════════════
# ── ML Performance Analysis tab ───────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

class MLAnalysisTab(QWidget):
    """ML model performance metrics: confusion matrix, ROC, feature importances."""

    _metrics_ready = pyqtSignal(object)   # dict | None
    score_computed = pyqtSignal(dict)     # SecurityScorer result

    def __init__(self, parent=None):
        super().__init__(parent)
        self._metrics: dict | None = None
        self._metrics_ready.connect(self._on_metrics)
        self._build()

    # ── Build ─────────────────────────────────────────────────────────────────

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self._compute_btn = QPushButton("Compute Metrics")
        self._compute_btn.setObjectName("primaryBtn")
        self._compute_btn.setFixedHeight(30)
        self._compute_btn.clicked.connect(lambda: self._start_compute())
        self._browse_btn = QPushButton("Browse Dataset")
        self._browse_btn.setObjectName("secondaryBtn")
        self._browse_btn.setFixedHeight(30)
        self._browse_btn.clicked.connect(self._browse_dataset)
        root.addWidget(_page_header("📊", "ML Analysis",
            "Model performance — loads cached metrics (training-time) or compute live from CSV",
            actions=[self._browse_btn, self._compute_btn]))

        inner = QWidget(); inner.setStyleSheet("background: #0b0d1e;")
        il = QVBoxLayout(inner); il.setContentsMargins(20, 16, 20, 16); il.setSpacing(12)
        root.addWidget(inner, 1)

        # Metric cards
        cards_row = QHBoxLayout(); cards_row.setSpacing(10)
        self._metric_vals: dict[str, QLabel] = {}
        for key, label, color in [
            ("accuracy",  "Accuracy",   "#4f8ef7"),
            ("f1",        "F1 Score",   "#34d399"),
            ("precision", "Precision",  "#a78bfa"),
            ("recall",    "Recall",     "#fb923c"),
            ("auc",       "ROC AUC",    "#2dd4bf"),
        ]:
            f  = QFrame(); f.setObjectName("card2")
            fl = QVBoxLayout(f); fl.setContentsMargins(14, 10, 14, 10); fl.setSpacing(3)
            vl = _lbl("—", f"font-size:22px; font-weight:700; color:{color};")
            fl.addWidget(vl)
            fl.addWidget(_lbl(label, "font-size:11px; color:#8fa3c0;"))
            cards_row.addWidget(f, 1)
            self._metric_vals[key] = vl
        self._sample_lbl = _lbl("", "font-size:10px; color:#2c3858; background:transparent;")
        il.addLayout(cards_row)
        il.addWidget(self._sample_lbl)

        # Charts
        if _HAS_MPL:
            self._canvas, self._fig, self._axes = self._make_figure()
            il.addWidget(self._canvas, 1)
            self._draw_placeholder()
        else:
            no_mpl = QFrame(); no_mpl.setObjectName("card")
            nl = QVBoxLayout(no_mpl); nl.setContentsMargins(24, 24, 24, 24); nl.setSpacing(8)
            nl.addWidget(_lbl("📊", "font-size:40px;"))
            nl.addWidget(_lbl("matplotlib is required for charts.",
                "font-size:13px; color:#8fa3c0;"))
            nl.addWidget(_lbl("pip install matplotlib",
                "font-family:Consolas; font-size:12px; color:#4f8ef7;"))
            il.addWidget(no_mpl, 1)

    def _make_figure(self):
        fig  = _MplFigure(figsize=(11, 7), facecolor="#0d0f1c")
        axes = fig.subplots(2, 2)
        canvas = _MplCanvas(fig)
        canvas.setMinimumHeight(380)
        return canvas, fig, axes

    # ── Placeholder charts ─────────────────────────────────────────────────────

    def _draw_placeholder(self):
        for ax, title in zip(self._axes.flat,
                             ["Confusion Matrix", "ROC Curve",
                              "Feature Importances (Top 10)", "Precision–Recall Curve"]):
            ax.set_facecolor("#0b0d1a")
            ax.set_title(title, color="#556077", fontsize=9, pad=6)
            ax.text(0.5, 0.5, "Click  ⚡ Compute Metrics", ha="center", va="center",
                    transform=ax.transAxes, color="#2c3858", fontsize=9)
            for sp in ax.spines.values():
                sp.set_color("#1e2240")
            ax.tick_params(colors="#2c3858")
        self._fig.tight_layout(pad=2.2)
        self._canvas.draw()

    # ── Compute ───────────────────────────────────────────────────────────────

    def _start_compute(self, dataset_path: str = ""):
        if not _HAS_ADV:
            QMessageBox.warning(self, "Missing dependency",
                "detectors/adversarial.py not found.")
            return
        self._compute_btn.setText("Computing…")
        self._compute_btn.setEnabled(False)
        path = dataset_path or ""
        threading.Thread(target=self._worker, args=(path,), daemon=True).start()

    def _browse_dataset(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select dataset CSV", str(ROOT),
            "CSV files (*.csv);;All files (*)"
        )
        if path:
            self._start_compute(path)

    def _worker(self, dataset_path: str = ""):
        try:
            import config
            path = dataset_path or config.DATASET_FILENAME
            metrics = ModelAnalyzer().compute_metrics(path)
        except Exception:
            metrics = None
        self._metrics_ready.emit(metrics)

    def _on_metrics(self, metrics: dict | None):
        self._compute_btn.setText("Compute Metrics")
        self._compute_btn.setEnabled(True)
        if metrics is None:
            QMessageBox.warning(self, "Compute failed",
                "Could not compute metrics.\n\n"
                "• The dataset CSV (cicddos2019_dataset.csv) or model_metrics.json\n"
                "  must be present in the app folder.\n"
                "• Click 'Browse Dataset' to select the CSV manually.")
            return
        self._metrics = metrics

        # Update stat cards
        for key in ("accuracy", "f1", "precision", "recall", "auc"):
            if key in metrics:
                self._metric_vals[key].setText(f"{metrics[key]:.1f}%")
        n = metrics.get("sample_size", 0)
        t = metrics.get("threshold", 50)
        source = "pre-computed at training time" if metrics.get("_source") == "cached" else f"{n:,} flows from dataset"
        self._sample_lbl.setText(
            f"Source: {source}  ·  Threshold: {t:.1f}%  ·  "
            f"Estimators: {ModelAnalyzer().quick_info().get('n_estimators','?')}"
        )

        if _HAS_MPL:
            self._draw_charts(metrics)

        # Emit AI Security Score
        if _HAS_ADV:
            score_result = SecurityScorer().compute(metrics=metrics)
            self.score_computed.emit(score_result)

    # ── Charts ────────────────────────────────────────────────────────────────

    def _draw_charts(self, m: dict):
        try:
            self._draw_charts_inner(m)
        except Exception as e:
            import traceback; traceback.print_exc()

    def _draw_charts_inner(self, m: dict):
        import numpy as np
        import math

        axes = self._axes
        dark = "#0b0d1a"
        tick_col = "#445068"
        title_col = "#c0d4f0"

        for ax in axes.flat:
            ax.clear()
            ax.set_facecolor(dark)
            for sp in ax.spines.values():
                sp.set_color("#1e2240")
            ax.tick_params(colors=tick_col, labelsize=7)

        # 1 ── Confusion Matrix
        ax = axes[0, 0]
        cm = np.array(m["cm"])
        im = ax.imshow(cm, cmap="Blues", aspect="auto", vmin=0)
        ax.set_xticks([0, 1]); ax.set_xticklabels(["BENIGN", "ATTACK"],
            color=tick_col, fontsize=8)
        ax.set_yticks([0, 1]); ax.set_yticklabels(["BENIGN", "ATTACK"],
            color=tick_col, fontsize=8)
        ax.set_xlabel("Predicted", color=tick_col, fontsize=8)
        ax.set_ylabel("Actual",    color=tick_col, fontsize=8)
        labels_cm = [["TN", "FP"], ["FN", "TP"]]
        for i in range(2):
            for j in range(2):
                ax.text(j, i, f"{labels_cm[i][j]}\n{cm[i,j]:,}",
                        ha="center", va="center", color="white",
                        fontsize=10, fontweight="bold")
        ax.set_title("Confusion Matrix", color=title_col, fontsize=9, pad=6)

        # 2 ── ROC Curve
        ax = axes[0, 1]
        fpr_arr = np.array(m.get("fpr", [0, 1]))
        tpr_arr = np.array(m.get("tpr", [0, 1]))
        auc_val = m.get("auc", 0)
        auc_str = f"AUC = {auc_val:.1f}%" if auc_val and not math.isnan(auc_val) else "AUC = N/A"
        if len(fpr_arr) > 1 and not np.any(np.isnan(fpr_arr)):
            ax.plot(fpr_arr, tpr_arr, color="#4f8ef7", lw=2, label=auc_str)
            ax.fill_between(fpr_arr, tpr_arr, alpha=0.07, color="#4f8ef7")
        else:
            ax.text(0.5, 0.5, f"ROC N/A\n(single class in sample)",
                    ha="center", va="center", transform=ax.transAxes,
                    color="#556077", fontsize=9)
        ax.plot([0, 1], [0, 1], "--", color="#2c3858", lw=1)
        ax.set_xlabel("False Positive Rate", color=tick_col, fontsize=8)
        ax.set_ylabel("True Positive Rate",  color=tick_col, fontsize=8)
        ax.set_xlim(0, 1); ax.set_ylim(0, 1.02)
        ax.legend(framealpha=0, labelcolor="#8fa3c0", fontsize=8)
        ax.set_title("ROC Curve", color=title_col, fontsize=9, pad=6)

        # 3 ── Feature Importances (top 10 horizontal bar)
        ax = axes[1, 0]
        fi = m.get("feature_importances", {})
        top10 = sorted(fi.items(), key=lambda x: x[1], reverse=True)[:10]
        if top10:
            names_fi  = [FEATURE_DISPLAY.get(k, k)[:22] for k, _ in top10]
            vals_fi   = [v * 100 for _, v in top10]
            max_v     = max(vals_fi) if vals_fi else 1
            colors_fi = ["#4f8ef7" if v == max_v else "#2d5fa8" for v in vals_fi]
            bars = ax.barh(names_fi[::-1], vals_fi[::-1], color=colors_fi[::-1],
                           alpha=0.85, height=0.65)
            for bar, val in zip(bars, vals_fi[::-1]):
                ax.text(val + 0.2, bar.get_y() + bar.get_height() / 2,
                        f"{val:.1f}%", va="center", color="#8fa3c0", fontsize=7)
        ax.set_xlabel("Importance (%)", color=tick_col, fontsize=8)
        ax.set_title("Top 10 Feature Importances", color=title_col, fontsize=9, pad=6)
        ax.tick_params(labelsize=7)

        # 4 ── Precision-Recall
        ax = axes[1, 1]
        rec_arr  = np.array(m.get("rec_arr",  []))
        prec_arr = np.array(m.get("prec_arr", []))
        if len(rec_arr) > 1 and not np.any(np.isnan(prec_arr)):
            ax.plot(rec_arr, prec_arr, color="#34d399", lw=2)
            ax.fill_between(rec_arr, prec_arr, alpha=0.07, color="#34d399")
        else:
            ax.text(0.5, 0.5, "P-R N/A\n(single class in sample)",
                    ha="center", va="center", transform=ax.transAxes,
                    color="#556077", fontsize=9)
        ax.set_xlabel("Recall",    color=tick_col, fontsize=8)
        ax.set_ylabel("Precision", color=tick_col, fontsize=8)
        ax.set_xlim(0, 1); ax.set_ylim(0, 1.02)
        ax.set_title("Precision–Recall Curve", color=title_col, fontsize=9, pad=6)

        self._fig.set_facecolor("#0d0f1c")
        self._fig.tight_layout(pad=2.2)
        self._canvas.draw()

    def get_metrics(self) -> dict | None:
        return self._metrics


# ══════════════════════════════════════════════════════════════════════════════
# ── Adaptive Training tab ──────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

class AdaptiveTrainingTab(QWidget):
    """
    Self-improvement hub: collect feedback, trigger retraining, track model
    version history, and see before/after accuracy deltas.
    """
    _retrain_done  = pyqtSignal(dict)
    _progress_sig  = pyqtSignal(str)
    model_updated  = pyqtSignal()          # emitted so MainWindow can reload detector

    def __init__(self, parent=None):
        super().__init__(parent)
        self._retrain_done.connect(self._on_retrain_done)
        self._progress_sig.connect(self._append_log)
        self._build()
        self._refresh_stats()

    # ── Build ──────────────────────────────────────────────────────────────────

    def _build(self):
        root = QVBoxLayout(self); root.setContentsMargins(0, 0, 0, 0); root.setSpacing(0)
        root.addWidget(_page_header(
            "🧠", "Adaptive Training",
            "Feedback-driven self-improvement — label alerts, retrain, track accuracy gains",
        ))
        inner = QWidget(); inner.setStyleSheet("background:#0b0d1e;")
        scroll = QScrollArea(); scroll.setWidgetResizable(True); scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(inner)
        il = QVBoxLayout(inner); il.setContentsMargins(20, 16, 20, 20); il.setSpacing(14)
        root.addWidget(scroll, 1)

        # ── How feedback improves the model ────────────────────────────────
        how = QFrame(); how.setObjectName("card2")
        hl = QVBoxLayout(how); hl.setContentsMargins(16, 14, 16, 14); hl.setSpacing(8)
        hl.addWidget(_lbl("How the Model Learns From You",
                          "font-size:13px; font-weight:700; color:#dde6f0;"))
        steps_row = QHBoxLayout(); steps_row.setSpacing(6)
        for icon, title, body in [
            ("🚨", "1. Alert fires",       "DDoS or rule-based alert appears in Threats & Alerts"),
            ("✓✗", "2. You label it",       "Click True Positive or False Positive on any alert card"),
            ("⚡",  "3. Instant update",    "Corrective layer adjusts immediately — no retrain needed"),
            ("🔁", "4. Full retrain",       "When you have 10+ labels, click Retrain to update the RF model"),
            ("📈", "5. Model improves",     "Future flows are classified using the improved model"),
        ]:
            sf = QFrame()
            sf.setStyleSheet(
                "background:rgba(79,142,247,.06);border:1px solid rgba(79,142,247,.15);border-radius:9px;"
            )
            sl2 = QVBoxLayout(sf); sl2.setContentsMargins(10, 8, 10, 8); sl2.setSpacing(3)
            sl2.addWidget(_lbl(f"{icon}  {title}", "font-size:11px; font-weight:700; color:#4f8ef7;"))
            bl = _lbl(body, "font-size:10px; color:#6a7fa0;"); bl.setWordWrap(True)
            sl2.addWidget(bl)
            steps_row.addWidget(sf, 1)
        hl.addLayout(steps_row)
        il.addWidget(how)

        # ── Feedback buffer stats ───────────────────────────────────────────
        stat_card = QFrame(); stat_card.setObjectName("card2")
        stl = QVBoxLayout(stat_card); stl.setContentsMargins(16, 12, 16, 12); stl.setSpacing(10)
        stl.addWidget(_lbl("Feedback Buffer", "font-size:12px; font-weight:700; color:#dde6f0;"))

        cards_row = QHBoxLayout(); cards_row.setSpacing(8)
        self._stat_cards: dict[str, QLabel] = {}
        for key, label, color in [
            ("total",    "Total Labeled",   "#4f8ef7"),
            ("attacks",  "Confirmed Attack", "#f87171"),
            ("benign",   "False Positives",  "#34d399"),
            ("corr_n",   "Online Updates",   "#a78bfa"),
        ]:
            f = QFrame(); f.setObjectName("card2")
            fl2 = QVBoxLayout(f); fl2.setContentsMargins(12, 8, 12, 8); fl2.setSpacing(2)
            vl = _lbl("—", f"font-size:20px; font-weight:700; color:{color};")
            fl2.addWidget(vl); fl2.addWidget(_lbl(label, "font-size:10px; color:#8fa3c0;"))
            cards_row.addWidget(f, 1)
            self._stat_cards[key] = vl
        stl.addLayout(cards_row)
        self._last_ts_lbl = _lbl("No feedback recorded yet.",
                                  "font-size:11px; color:#445068;")
        stl.addWidget(self._last_ts_lbl)

        # Buffer action buttons
        buf_btns = QHBoxLayout(); buf_btns.setSpacing(8)
        ref_btn = QPushButton("Refresh Stats"); ref_btn.setObjectName("secondaryBtn")
        ref_btn.setFixedHeight(28); ref_btn.clicked.connect(self._refresh_stats)
        exp_btn = QPushButton("Export CSV"); exp_btn.setObjectName("secondaryBtn")
        exp_btn.setFixedHeight(28); exp_btn.clicked.connect(self._export_csv)
        clr_btn = QPushButton("Clear Buffer"); clr_btn.setObjectName("dangerBtn")
        clr_btn.setFixedHeight(28); clr_btn.clicked.connect(self._clear_buffer)
        buf_btns.addWidget(ref_btn); buf_btns.addWidget(exp_btn)
        buf_btns.addStretch(); buf_btns.addWidget(clr_btn)
        stl.addLayout(buf_btns)
        il.addWidget(stat_card)

        # ── Retrain panel ───────────────────────────────────────────────────
        train_card = QFrame(); train_card.setObjectName("card2")
        tl = QVBoxLayout(train_card); tl.setContentsMargins(16, 14, 16, 14); tl.setSpacing(10)
        tl.addWidget(_lbl("Retrain Model", "font-size:12px; font-weight:700; color:#dde6f0;"))
        tl.addWidget(_lbl(
            "Merges your labeled feedback with the original CICDDoS2019 dataset "
            "(5:1 feedback oversample) and trains a new calibrated Random Forest. "
            "The model is only replaced if the new F1 score does not regress.",
            "font-size:11px; color:#6a7fa0;"
        ))

        tr_row = QHBoxLayout(); tr_row.setSpacing(8)
        self._retrain_btn = QPushButton("Retrain Model Now")
        self._retrain_btn.setObjectName("primaryBtn")
        self._retrain_btn.setFixedHeight(34)
        self._retrain_btn.clicked.connect(self._start_retrain)
        self._auto_retrain_cb = QCheckBox("Auto-retrain after every 50 new labels")
        self._auto_retrain_cb.setStyleSheet("color:#8fa3c0; font-size:11px;")
        tr_row.addWidget(self._retrain_btn)
        tr_row.addWidget(self._auto_retrain_cb)
        tr_row.addStretch()
        tl.addLayout(tr_row)

        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 0)   # indeterminate
        self._progress_bar.setFixedHeight(4)
        self._progress_bar.setTextVisible(False)
        self._progress_bar.setStyleSheet(
            "QProgressBar{background:#0d1020;border:none;border-radius:2px;}"
            "QProgressBar::chunk{background:#4f8ef7;border-radius:2px;}"
        )
        self._progress_bar.hide()
        tl.addWidget(self._progress_bar)

        self._log = QTextEdit()
        self._log.setReadOnly(True)
        self._log.setFixedHeight(120)
        self._log.setStyleSheet(
            "QTextEdit{background:#070918;border:1px solid #1e2848;border-radius:8px;"
            "color:#8fa3c0;font-family:Consolas;font-size:11px;padding:6px;}"
        )
        self._log.setPlaceholderText("Training log will appear here…")
        tl.addWidget(self._log)
        il.addWidget(train_card)

        # ── Version history ─────────────────────────────────────────────────
        hist_card = QFrame(); hist_card.setObjectName("card2")
        hcl = QVBoxLayout(hist_card); hcl.setContentsMargins(16, 14, 16, 14); hcl.setSpacing(8)
        hcl.addWidget(_lbl("Model Version History",
                            "font-size:12px; font-weight:700; color:#dde6f0;"))
        cols_h = ["Version", "Trained At", "F1 Score", "Accuracy", "AUC", "Feedback Used", "Delta F1"]
        self._hist_tbl = QTableWidget(0, len(cols_h))
        self._hist_tbl.setHorizontalHeaderLabels(cols_h)
        self._hist_tbl.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._hist_tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._hist_tbl.verticalHeader().setVisible(False)
        self._hist_tbl.setFixedHeight(180)
        hcl.addWidget(self._hist_tbl)
        il.addWidget(hist_card)

        il.addStretch()
        self._refresh_history()

    # ── Stats ──────────────────────────────────────────────────────────────────

    def _refresh_stats(self):
        if not _HAS_ADAPTIVE:
            return
        stats = get_feedback_buffer().stats()
        self._stat_cards["total"].setText(str(stats["total"]))
        self._stat_cards["attacks"].setText(str(stats["attacks"]))
        self._stat_cards["benign"].setText(str(stats["benign"]))
        corr_n = get_corrective_layer().n_samples if _HAS_ADAPTIVE else 0
        self._stat_cards["corr_n"].setText(str(corr_n))
        if stats["last_ts"]:
            self._last_ts_lbl.setText(f"Last feedback: {stats['last_ts']}")
        # Auto-retrain check
        if (self._auto_retrain_cb.isChecked()
                and stats["total"] > 0
                and stats["total"] % 50 == 0):
            self._start_retrain()

    # ── Retrain ────────────────────────────────────────────────────────────────

    def _start_retrain(self):
        if not _HAS_ADAPTIVE:
            QMessageBox.warning(self, "Not available",
                "adaptive_trainer.py not found.")
            return
        trainer = get_trainer()
        if trainer.is_training():
            return
        self._retrain_btn.setEnabled(False)
        self._retrain_btn.setText("Training…")
        self._progress_bar.show()
        self._log.clear()
        threading.Thread(target=self._retrain_worker, daemon=True).start()

    def _retrain_worker(self):
        trainer = get_trainer()
        result  = trainer.retrain(on_progress=self._progress_sig.emit)
        self._retrain_done.emit(result)

    def _on_retrain_done(self, result: dict):
        self._retrain_btn.setEnabled(True)
        self._retrain_btn.setText("Retrain Model Now")
        self._progress_bar.hide()
        if "error" in result:
            self._append_log(f"ERROR: {result['error']}")
            QMessageBox.warning(self, "Retrain failed", result["error"])
            return
        if result.get("improved"):
            self._append_log(f"\nModel updated: {result.get('version','')}")
            new = result.get("new", {})
            old = result.get("old", {})
            delta = ""
            if old:
                diff = new.get("f1", 0) - old.get("f1", 0)
                delta = f"  (Delta F1: {'+' if diff>=0 else ''}{diff:.2f} pp)"
            self._append_log(
                f"F1={new.get('f1','?')}%  Accuracy={new.get('accuracy','?')}%{delta}"
            )
            self._refresh_history()
            self.model_updated.emit()
            QMessageBox.information(self, "Retrain complete",
                f"Model updated!\n\n"
                f"F1: {new.get('f1','?')}%  (was {old.get('f1','?')}%)\n"
                f"Accuracy: {new.get('accuracy','?')}%\n"
                f"AUC: {new.get('auc','?')}%\n\n"
                f"Saved as: {result.get('version','')}")
        else:
            self._append_log("\nModel NOT updated — new model did not improve.")
            QMessageBox.information(self, "No update",
                result.get("message", "New model did not improve — keeping current."))
        self._refresh_stats()

    def _append_log(self, msg: str):
        self._log.append(msg)
        self._log.verticalScrollBar().setValue(
            self._log.verticalScrollBar().maximum()
        )

    # ── History ────────────────────────────────────────────────────────────────

    def _refresh_history(self):
        if not _HAS_ADAPTIVE:
            return
        history = get_trainer().version_history()
        self._hist_tbl.setRowCount(0)
        for entry in reversed(history[-20:]):
            r = self._hist_tbl.rowCount(); self._hist_tbl.insertRow(r)
            old_f1   = entry.get("old_f1")
            new_f1   = entry.get("new_f1", 0)
            delta    = f"+{new_f1 - old_f1:.2f}" if old_f1 is not None else "baseline"
            delta_cl = "#34d399" if (old_f1 is None or new_f1 >= old_f1) else "#f87171"
            for j, (text, color) in enumerate([
                (entry.get("version","")[:20],  "#8fa3c0"),
                (entry.get("ts","")[:16],        "#6a7fa0"),
                (f"{new_f1:.1f}%",               "#4f8ef7"),
                (f"{entry.get('accuracy',0):.1f}%", "#a78bfa"),
                (f"{entry.get('auc',0):.1f}%",   "#2dd4bf"),
                (str(entry.get("n_feedback",0)), "#fbbf24"),
                (delta,                          delta_cl),
            ]):
                it = QTableWidgetItem(text)
                it.setForeground(QColor(color))
                self._hist_tbl.setItem(r, j, it)

    # ── Export / Clear ─────────────────────────────────────────────────────────

    def _export_csv(self):
        if not _HAS_ADAPTIVE:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Feedback Buffer", "feedback_export.csv",
            "CSV files (*.csv)"
        )
        if not path:
            return
        n = get_trainer().export_feedback_csv(path)
        QMessageBox.information(self, "Exported",
            f"Exported {n} labeled samples to:\n{path}")

    def _clear_buffer(self):
        if not _HAS_ADAPTIVE:
            return
        reply = QMessageBox.question(
            self, "Clear Buffer",
            "Delete all labeled feedback samples?\n"
            "This cannot be undone and will reset the corrective layer.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            get_trainer().clear_feedback()
            self._refresh_stats()
            self._append_log("Feedback buffer cleared.")


# ══════════════════════════════════════════════════════════════════════════════
# ── Adversarial Lab tab ────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

class AdversarialTab(QWidget):
    """
    Adversarial Attack Simulator + Explainable AI lab.

    Left panel  — attack configuration (profile selector + feature viewer)
    Right panel — results: confidence path chart, perturbation table, XAI
    """

    _result_sig   = pyqtSignal(object)   # attack result dict
    _poison_sig   = pyqtSignal(object)   # poisoning result dict
    score_updated = pyqtSignal(dict)     # updated SecurityScorer result

    def __init__(self, parent=None):
        super().__init__(parent)
        self._result_sig.connect(self._on_attack_result)
        self._poison_sig.connect(self._on_poison_result)
        self._last_adv_result: dict | None = None
        self._build()

    # ── Layout ────────────────────────────────────────────────────────────────

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(_page_header("⚡", "Adversarial Lab",
            "FGSM evasion attacks · feature perturbation · model robustness testing"))

        _adv_inner = QWidget(); _adv_inner.setStyleSheet("background: #0b0d1e;")
        _adv_il = QVBoxLayout(_adv_inner); _adv_il.setContentsMargins(20, 14, 20, 14); _adv_il.setSpacing(12)
        root.addWidget(_adv_inner, 1)

        # Explanation banner
        info = QFrame(); info.setObjectName("card2")
        il   = QHBoxLayout(info); il.setContentsMargins(14, 10, 14, 10); il.setSpacing(10)
        il.addWidget(_lbl("🧠", "font-size:20px; background:transparent;"))
        exp_txt = _lbl(
            "<b style='color:#8fa3c0'>How it works:</b> "
            "The FGSM attack iteratively perturbs network flow features — nudging them in the "
            "direction that <i>decreases</i> the model's attack confidence. "
            "If successful, a real DDoS attack would be misclassified as benign traffic.",
            "font-size:11px; color:#556077; line-height:1.5;"
        )
        exp_txt.setWordWrap(True); exp_txt.setTextFormat(Qt.TextFormat.RichText)
        il.addWidget(exp_txt, 1)
        _adv_il.addWidget(info)

        # Main split: left config | right results
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setStyleSheet("QSplitter::handle { background:#1e2240; width:2px; }")

        # ── Left: configuration ───────────────────────────────────────────────
        left_w = QWidget()
        left_w.setMinimumWidth(300)
        ll = QVBoxLayout(left_w); ll.setContentsMargins(0, 0, 8, 0); ll.setSpacing(10)

        # Profile selector
        pf = QFrame(); pf.setObjectName("card")
        pl = QVBoxLayout(pf); pl.setContentsMargins(14, 12, 14, 12); pl.setSpacing(8)
        pl.addWidget(_lbl("Attack Profile", "font-size:12px; font-weight:700; color:#dde6f0;"))
        self._profile_cb = QComboBox()
        if _HAS_ADV:
            self._profile_cb.addItems(list(ATTACK_PROFILES.keys()))
        self._profile_cb.currentTextChanged.connect(self._on_profile_change)
        pl.addWidget(self._profile_cb)

        # Confidence readout
        self._orig_conf_lbl = _lbl("—", "font-size:22px; font-weight:700; color:#f87171;")
        conf_row = QHBoxLayout()
        conf_row.addWidget(_lbl("Model confidence:", "font-size:11px; color:#556077;"))
        conf_row.addWidget(self._orig_conf_lbl)
        conf_row.addStretch()
        pl.addLayout(conf_row)

        ll.addWidget(pf)

        # Feature table
        feat_card = QFrame(); feat_card.setObjectName("card")
        ftl = QVBoxLayout(feat_card); ftl.setContentsMargins(0, 0, 0, 0); ftl.setSpacing(0)
        ftl.addWidget(_lbl("  Feature Vector",
            "font-size:11px; font-weight:700; color:#8fa3c0; padding:10px 14px 8px;"))
        self._feat_table = QTableWidget(0, 3)
        self._feat_table.setHorizontalHeaderLabels(["Feature", "Value", "Importance"])
        self._feat_table.horizontalHeader().setStretchLastSection(False)
        self._feat_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch)
        self._feat_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.ResizeToContents)
        self._feat_table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.ResizeToContents)
        self._feat_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._feat_table.setAlternatingRowColors(True)
        self._feat_table.setFixedHeight(280)
        self._feat_table.horizontalHeader().setStyleSheet(
            "QHeaderView::section { background:#0b0d1a; color:#556077;"
            "font-size:10px; border:none; padding:4px; }")
        ftl.addWidget(self._feat_table)
        ll.addWidget(feat_card)

        # Attack buttons
        self._atk_btn = QPushButton("⚡  Run FGSM Evasion Attack")
        self._atk_btn.setObjectName("primaryBtn")
        self._atk_btn.setFixedHeight(38)
        self._atk_btn.clicked.connect(self._run_attack)

        self._poison_btn = QPushButton("🧪  Run Poisoning Demo (all profiles)")
        self._poison_btn.setObjectName("secondaryBtn")
        self._poison_btn.setFixedHeight(34)
        self._poison_btn.clicked.connect(self._run_poisoning)

        self._xai_btn = QPushButton("🔍  Explain This Sample (XAI)")
        self._xai_btn.setObjectName("secondaryBtn")
        self._xai_btn.setFixedHeight(34)
        self._xai_btn.clicked.connect(self._show_xai)

        ll.addWidget(self._atk_btn)
        ll.addWidget(self._poison_btn)
        ll.addWidget(self._xai_btn)
        ll.addStretch()

        splitter.addWidget(left_w)

        # ── Right: results ────────────────────────────────────────────────────
        right_w = QWidget()
        rl = QVBoxLayout(right_w); rl.setContentsMargins(8, 0, 0, 0); rl.setSpacing(10)

        # Status / summary card
        self._status_card = QFrame(); self._status_card.setObjectName("card")
        self._status_lay  = QVBoxLayout(self._status_card)
        self._status_lay.setContentsMargins(16, 12, 16, 12); self._status_lay.setSpacing(6)
        self._status_lbl  = _lbl(
            "Select an attack profile and click  ⚡ Run FGSM Evasion Attack  to begin.",
            "font-size:12px; color:#445068;"
        )
        self._status_lbl.setWordWrap(True)
        self._status_lay.addWidget(self._status_lbl)
        rl.addWidget(self._status_card)

        # Confidence path chart
        if _HAS_MPL:
            path_card = QFrame(); path_card.setObjectName("card")
            pcl = QVBoxLayout(path_card)
            pcl.setContentsMargins(12, 10, 12, 10); pcl.setSpacing(4)
            pcl.addWidget(_lbl("Attack Confidence Path",
                "font-size:11px; font-weight:700; color:#8fa3c0;"))
            self._path_fig  = _MplFigure(figsize=(7, 2.6), facecolor="#0d0f1c")
            self._path_ax   = self._path_fig.add_subplot(111)
            self._path_canvas = _MplCanvas(self._path_fig)
            self._path_canvas.setMinimumHeight(160)
            self._draw_path_placeholder()
            pcl.addWidget(self._path_canvas)
            rl.addWidget(path_card)

        # Comparison table
        cmp_card = QFrame(); cmp_card.setObjectName("card")
        cml = QVBoxLayout(cmp_card); cml.setContentsMargins(0, 0, 0, 0); cml.setSpacing(0)
        cml.addWidget(_lbl("  Feature Perturbations",
            "font-size:11px; font-weight:700; color:#8fa3c0; padding:10px 14px 8px;"))
        self._cmp_table = QTableWidget(0, 4)
        self._cmp_table.setHorizontalHeaderLabels(["Feature", "Original", "Adversarial", "Δ Change"])
        self._cmp_table.horizontalHeader().setStretchLastSection(False)
        self._cmp_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch)
        for col in (1, 2, 3):
            self._cmp_table.horizontalHeader().setSectionResizeMode(
                col, QHeaderView.ResizeMode.ResizeToContents)
        self._cmp_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._cmp_table.setAlternatingRowColors(True)
        self._cmp_table.setFixedHeight(200)
        self._cmp_table.horizontalHeader().setStyleSheet(
            "QHeaderView::section { background:#0b0d1a; color:#556077;"
            "font-size:10px; border:none; padding:4px; }")
        cml.addWidget(self._cmp_table)
        rl.addWidget(cmp_card)
        rl.addStretch()

        splitter.addWidget(right_w)
        splitter.setSizes([340, 600])
        _adv_il.addWidget(splitter, 1)

        # Populate initial profile
        if _HAS_ADV and self._profile_cb.count():
            self._on_profile_change(self._profile_cb.currentText())

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _draw_path_placeholder(self):
        ax = self._path_ax
        ax.set_facecolor("#0b0d1a")
        ax.text(0.5, 0.5, "Confidence path appears after attack",
                ha="center", va="center", transform=ax.transAxes,
                color="#2c3858", fontsize=9)
        for sp in ax.spines.values():
            sp.set_color("#1e2240")
        ax.tick_params(colors="#2c3858")
        self._path_fig.set_facecolor("#0d0f1c")
        self._path_fig.tight_layout(pad=1.4)
        self._path_canvas.draw()

    def _on_profile_change(self, name: str):
        if not _HAS_ADV:
            return
        profile = ATTACK_PROFILES.get(name, {})
        self._populate_feat_table(profile)
        # Quick confidence readout
        try:
            mw = _ModelWrapper.get() if _HAS_ADV else None
            if mw and mw.ready:
                from detectors.adversarial import _vec
                fnames = mw.feature_names
                v = _vec(profile, fnames)
                p = mw.predict_proba(v)
                self._orig_conf_lbl.setText(f"{p*100:.1f}%")
                col = "#f87171" if p >= mw.threshold else "#34d399"
                self._orig_conf_lbl.setStyleSheet(
                    f"font-size:22px; font-weight:700; color:{col};")
        except Exception:
            pass

    def _populate_feat_table(self, profile: dict):
        if not _HAS_ADV:
            return
        mw = _ModelWrapper.get()
        imp = dict(zip(mw.feature_names, mw.importances)) if mw.ready else {}

        self._feat_table.setRowCount(0)
        for fname, val in profile.items():
            row = self._feat_table.rowCount()
            self._feat_table.insertRow(row)
            display = FEATURE_DISPLAY.get(fname, fname)
            self._feat_table.setItem(row, 0, QTableWidgetItem(display))
            self._feat_table.setItem(row, 1, QTableWidgetItem(f"{val:,.2f}"))
            imp_pct = imp.get(fname, 0) * 100
            imp_item = QTableWidgetItem(f"{imp_pct:.1f}%")
            if imp_pct > 10:
                imp_item.setForeground(QColor("#4f8ef7"))
            elif imp_pct > 5:
                imp_item.setForeground(QColor("#a78bfa"))
            self._feat_table.setItem(row, 2, imp_item)

    # ── Attack ────────────────────────────────────────────────────────────────

    def _run_attack(self):
        if not _HAS_ADV:
            QMessageBox.warning(self, "Missing", "detectors/adversarial.py not found.")
            return
        name = self._profile_cb.currentText()
        profile = ATTACK_PROFILES.get(name)
        if not profile:
            return
        self._atk_btn.setText("⏳  Attacking…"); self._atk_btn.setEnabled(False)
        threading.Thread(
            target=lambda: self._result_sig.emit(AdversarialEngine().attack(profile)),
            daemon=True,
        ).start()

    def _on_attack_result(self, r: dict):
        self._atk_btn.setText("⚡  Run FGSM Evasion Attack"); self._atk_btn.setEnabled(True)

        if "error" in r:
            self._status_lbl.setText(f"Error: {r['error']}")
            return

        if r.get("already_benign"):
            self._status_lbl.setText(r.get("message", "Already benign."))
            return

        self._last_adv_result = r
        success  = r["success"]
        orig_c   = r["original_confidence"]
        final_c  = r["final_confidence"]
        thresh   = r["threshold"]
        iters    = r["iterations"]
        n_feat   = r["features_changed"]

        if success:
            verdict = (
                f"✅  EVASION SUCCESSFUL after {iters} iterations — "
                f"confidence dropped {orig_c:.1f}% → {final_c:.1f}%  "
                f"(threshold: {thresh:.1f}%)\n"
                f"{n_feat} features were perturbed to fool the model."
            )
            self._status_card.setStyleSheet(
                "QFrame { background:#061a0a; border:1px solid #1a4020; border-radius:10px; }")
            self._status_lbl.setStyleSheet("font-size:12px; color:#34d399;")
        else:
            verdict = (
                f"🛡  ATTACK RESISTED — confidence {orig_c:.1f}% → {final_c:.1f}%  "
                f"after {iters} iterations.\n"
                f"The model held above threshold {thresh:.1f}%."
            )
            self._status_card.setStyleSheet(
                "QFrame { background:#10080a; border:1px solid #3a1020; border-radius:10px; }")
            self._status_lbl.setStyleSheet("font-size:12px; color:#f87171;")

        self._status_lbl.setText(verdict)

        # Confidence path chart
        if _HAS_MPL:
            self._draw_confidence_path(r["confidence_path"], thresh, success)

        # Comparison table
        self._fill_comparison(r)

        # Update security score with evasion data
        if _HAS_ADV:
            evasion_rate = 100.0 if success else 0.0
            score = SecurityScorer().compute(adversarial_evasion_rate=evasion_rate)
            self.score_updated.emit(score)

    def _draw_confidence_path(self, path: list, threshold: float, success: bool):
        ax = self._path_ax
        ax.clear()
        ax.set_facecolor("#0b0d1a")
        for sp in ax.spines.values():
            sp.set_color("#1e2240")
        ax.tick_params(colors="#445068", labelsize=7)

        xs = list(range(len(path)))
        color = "#34d399" if success else "#f87171"
        ax.plot(xs, path, color=color, lw=2, marker="o", markersize=3)
        ax.fill_between(xs, path, threshold, where=[p < threshold for p in path],
                        alpha=0.15, color="#34d399", interpolate=True)
        ax.axhline(threshold, color="#fbbf24", lw=1, linestyle="--",
                   label=f"Threshold {threshold:.0f}%")
        ax.set_xlabel("Iteration", color="#445068", fontsize=7)
        ax.set_ylabel("Attack Confidence %", color="#445068", fontsize=7)
        ax.set_ylim(0, 105)
        ax.legend(framealpha=0, labelcolor="#8fa3c0", fontsize=7)

        self._path_fig.set_facecolor("#0d0f1c")
        self._path_fig.tight_layout(pad=1.4)
        self._path_canvas.draw()

    def _fill_comparison(self, r: dict):
        orig = r.get("original_features", {})
        adv  = r.get("adversarial_features", {})
        pert = r.get("perturbations", {})

        self._cmp_table.setRowCount(0)
        for fname, delta in sorted(pert.items(), key=lambda x: abs(x[1]), reverse=True):
            row = self._cmp_table.rowCount()
            self._cmp_table.insertRow(row)
            display = FEATURE_DISPLAY.get(fname, fname)
            o_val   = orig.get(fname, 0)
            a_val   = adv.get(fname, o_val)
            d_val   = delta

            self._cmp_table.setItem(row, 0, QTableWidgetItem(display))
            self._cmp_table.setItem(row, 1, QTableWidgetItem(f"{o_val:,.2f}"))
            adv_item = QTableWidgetItem(f"{a_val:,.2f}")
            adv_item.setForeground(QColor("#f5c542"))
            self._cmp_table.setItem(row, 2, adv_item)
            d_item = QTableWidgetItem(f"{'+'if d_val>0 else ''}{d_val:,.2f}")
            d_item.setForeground(QColor("#34d399" if d_val < 0 else "#f87171"))
            self._cmp_table.setItem(row, 3, d_item)

    # ── Poisoning demo ────────────────────────────────────────────────────────

    def _run_poisoning(self):
        if not _HAS_ADV:
            return
        self._poison_btn.setText("⏳  Running…"); self._poison_btn.setEnabled(False)
        threading.Thread(
            target=lambda: self._poison_sig.emit(AdversarialEngine().poisoning_demo()),
            daemon=True,
        ).start()

    def _on_poison_result(self, r: dict):
        self._poison_btn.setText("🧪  Run Poisoning Demo (all profiles)")
        self._poison_btn.setEnabled(True)
        if "error" in r:
            self._status_lbl.setText(f"Error: {r['error']}")
            return

        tested  = r["profiles_tested"]
        evaded  = r["evasion_successes"]
        rate    = r["evasion_rate"]
        risk    = r["risk"]
        risk_col = {"HIGH": "#f87171", "MEDIUM": "#fbbf24", "LOW": "#34d399"}[risk]

        lines = [
            f"<b style='color:{risk_col}'>Poisoning Demo — Evasion Rate: {rate:.0f}%</b>",
            f"Tested {tested} attack profiles:  {evaded} evaded detection successfully.",
            "",
        ]
        for name, info in r.get("per_profile", {}).items():
            icon = "✅" if info["evaded"] else "🛡"
            lines.append(
                f"{icon}  <b>{name}</b>  {info['original_confidence']:.0f}% → "
                f"{info['final_confidence']:.0f}%  ({info['iterations']} iters)"
            )

        self._status_lbl.setTextFormat(Qt.TextFormat.RichText)
        self._status_lbl.setText("<br>".join(lines))

        score = SecurityScorer().compute(adversarial_evasion_rate=rate)
        self.score_updated.emit(score)

    # ── XAI ───────────────────────────────────────────────────────────────────

    def _show_xai(self):
        if not _HAS_ADV:
            return
        name    = self._profile_cb.currentText()
        profile = ATTACK_PROFILES.get(name, {})
        rows    = FeatureExplainer().explain(profile)
        if not rows:
            QMessageBox.warning(self, "XAI", "Model not loaded — cannot explain.")
            return

        dlg = QDialog(self)
        dlg.setWindowTitle(f"XAI Explanation — {name}")
        dlg.setMinimumSize(640, 500)
        lay = QVBoxLayout(dlg); lay.setContentsMargins(20, 16, 20, 16); lay.setSpacing(10)

        lay.addWidget(_lbl(f"Why is  '{name}'  classified as an ATTACK?",
            "font-size:14px; font-weight:700; color:#e2eeff;"))
        lay.addWidget(_lbl(
            "Features are ranked by how much they pushed the model's decision toward ATTACK. "
            "Red arrows increase attack probability; blue arrows decrease it.",
            "font-size:11px; color:#445068;"
        ))

        tbl = QTableWidget(len(rows), 5)
        tbl.setHorizontalHeaderLabels(["Feature", "Value", "Baseline", "Importance", "Contribution"])
        tbl.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for col in (1, 2, 3, 4):
            tbl.horizontalHeader().setSectionResizeMode(
                col, QHeaderView.ResizeMode.ResizeToContents)
        tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        tbl.setAlternatingRowColors(True)
        tbl.horizontalHeader().setStyleSheet(
            "QHeaderView::section { background:#0b0d1a; color:#556077;"
            "font-size:10px; border:none; padding:4px; }")

        for i, row in enumerate(rows[:15]):
            tbl.setItem(i, 0, QTableWidgetItem(row["display"]))
            tbl.setItem(i, 1, QTableWidgetItem(f"{row['value']:,.2f}"))
            tbl.setItem(i, 2, QTableWidgetItem(f"{row['baseline']:,.2f}"))

            imp_item = QTableWidgetItem(f"{row['importance']:.1f}%")
            tbl.setItem(i, 3, imp_item)

            contrib = row["contribution"]
            c_item  = QTableWidgetItem(f"{row['direction']}  {abs(contrib):.2f}")
            c_item.setForeground(QColor("#f87171" if contrib > 0 else "#4f8ef7"))
            tbl.setItem(i, 4, c_item)

        lay.addWidget(tbl, 1)

        if _HAS_MPL:
            top8 = rows[:8]
            fig  = _MplFigure(figsize=(7, 2.8), facecolor="#0d0f1c")
            ax   = fig.add_subplot(111)
            ax.set_facecolor("#0b0d1a")
            names   = [r["display"][:20] for r in top8]
            contribs = [r["contribution"] for r in top8]
            bar_cols = ["#f87171" if c > 0 else "#4f8ef7" for c in contribs]
            ax.barh(names[::-1], contribs[::-1], color=bar_cols[::-1], alpha=0.85)
            ax.axvline(0, color="#2c3858", lw=1)
            ax.set_xlabel("Contribution toward ATTACK (→) / BENIGN (←)",
                          color="#445068", fontsize=7)
            ax.set_title("Feature Contributions", color="#c0d4f0", fontsize=9)
            ax.tick_params(colors="#445068", labelsize=7)
            for sp in ax.spines.values(): sp.set_color("#1e2240")
            fig.tight_layout(pad=1.4)
            canvas = _MplCanvas(fig)
            canvas.setMinimumHeight(180)
            lay.addWidget(canvas)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dlg.accept)
        lay.addWidget(close_btn)
        dlg.exec()


# ══════════════════════════════════════════════════════════════════════════════
# ── Settings tab ───────────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

class SettingsTab(QWidget):
    """Full settings panel — notifications, appearance, detection, file protection, performance, whitelist, about."""

    accent_changed = pyqtSignal(str)   # emits new hex accent color

    # Category definitions: (key, icon, label)
    _CATS = [
        ("notifications", "\U0001f514", "Notifications"),
        ("appearance",    "\U0001f3a8", "Appearance"),
        ("detection",     "\U0001f6e1", "Detection"),
        ("file_protect",  "\U0001f4c1", "File Protection"),
        ("performance",   "⚡",     "Performance"),
        ("whitelist",     "\U0001f6ab", "IP Whitelist"),
        ("about",         "ℹ",     "About"),
    ]

    def __init__(self, settings: AppSettings, parent=None):
        super().__init__(parent)
        self._s         = settings
        self._cat_btns: dict[str, QPushButton] = {}
        self._build()

    # ── Layout ────────────────────────────────────────────────────────────────

    def _build(self):
        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Left category sidebar
        cat_side = QWidget()
        cat_side.setObjectName("settingsCatSidebar")
        cat_side.setFixedWidth(172)
        cl = QVBoxLayout(cat_side)
        cl.setContentsMargins(10, 20, 10, 10)
        cl.setSpacing(3)
        cl.addWidget(_lbl("Settings",
            "font-size:14px; font-weight:700; color:#e2eeff; padding:0 4px 10px;"))

        # Content stack
        self._stack = QStackedWidget()
        self._stack.setObjectName("settingsPanel")

        for key, icon, label in self._CATS:
            btn = QPushButton(f"  {icon}  {label}")
            btn.setObjectName("catBtn")
            btn.clicked.connect(lambda _, k=key: self._go(k))
            cl.addWidget(btn)
            self._cat_btns[key] = btn

            page = self._make_page(key)
            self._stack.addWidget(page)

        cl.addStretch()
        root.addWidget(cat_side)
        root.addWidget(self._stack, 1)
        self._go("notifications")

    def _go(self, key: str):
        idx = [c[0] for c in self._CATS].index(key)
        self._stack.setCurrentIndex(idx)
        for k, btn in self._cat_btns.items():
            btn.setProperty("active", "1" if k == key else "0")
            btn.style().unpolish(btn)
            btn.style().polish(btn)

    def _make_page(self, key: str) -> QScrollArea:
        page_fn = {
            "notifications": self._page_notifications,
            "appearance":    self._page_appearance,
            "detection":     self._page_detection,
            "file_protect":  self._page_file_protect,
            "performance":   self._page_performance,
            "whitelist":     self._page_whitelist,
            "about":         self._page_about,
        }
        inner = QWidget()
        lay   = QVBoxLayout(inner)
        lay.setContentsMargins(28, 24, 28, 28)
        lay.setSpacing(4)
        page_fn[key](lay)
        lay.addStretch()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(inner)
        return scroll

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _section_hdr(self, title: str) -> QWidget:
        w  = QWidget()
        wl = QVBoxLayout(w)
        wl.setContentsMargins(0, 12, 0, 6)
        wl.setSpacing(5)
        wl.addWidget(_lbl(title.upper(),
            "font-size:10px; font-weight:700; color:#3a5078; letter-spacing:1.2px;"))
        div = QFrame()
        div.setFrameShape(QFrame.Shape.HLine)
        div.setStyleSheet("background:#1a2038; max-height:1px; border:none;")
        wl.addWidget(div)
        return w

    def _row(self, label: str, desc: str, ctrl: QWidget) -> QWidget:
        w  = QWidget()
        hl = QHBoxLayout(w)
        hl.setContentsMargins(0, 8, 0, 8)
        hl.setSpacing(16)
        vl = QVBoxLayout()
        vl.setSpacing(3)
        vl.addWidget(_lbl(label, "font-size:13px; font-weight:600; color:#dde6f0;"))
        if desc:
            dl = _lbl(desc, "font-size:11px; color:#445068;")
            dl.setWordWrap(True)
            vl.addWidget(dl)
        hl.addLayout(vl, 1)
        if ctrl:
            hl.addWidget(ctrl)
        return w

    def _toggle(self, *setting_keys, label: str, desc: str = "",
                on_change=None) -> QWidget:
        val = self._s.get(*setting_keys, default=True)
        sw  = ToggleSwitch(checked=bool(val))
        def _on(v):
            self._s.set(*setting_keys, v)
            if on_change:
                on_change(v)
        sw.toggled.connect(_on)
        return self._row(label, desc, sw)

    def _combo(self, *setting_keys, label: str, desc: str = "",
               options: list, on_change=None) -> QWidget:
        val = self._s.get(*setting_keys, default=options[0][0])
        cb  = QComboBox()
        cb.setFixedWidth(160)
        for v, txt in options:
            cb.addItem(txt, v)
        idx = next((i for i, (v, _) in enumerate(options) if v == val), 0)
        cb.setCurrentIndex(idx)
        def _on(i):
            self._s.set(*setting_keys, options[i][0])
            if on_change:
                on_change(options[i][0])
        cb.currentIndexChanged.connect(_on)
        return self._row(label, desc, cb)

    # ── Pages ─────────────────────────────────────────────────────────────────

    def _page_notifications(self, lay: QVBoxLayout):
        lay.addWidget(_lbl("Notifications",
            "font-size:18px; font-weight:700; color:#e2eeff; padding-bottom:4px;"))
        lay.addWidget(_lbl("Control when and how Security Monitor alerts you.",
            "font-size:12px; color:#445068; padding-bottom:8px;"))

        lay.addWidget(self._section_hdr("Alert pop-ups"))
        lay.addWidget(self._toggle("notifications", "enabled",
            label="System tray notifications",
            desc="Show pop-up alerts in the Windows system tray when threats are detected."))
        lay.addWidget(self._combo("notifications", "min_severity",
            label="Minimum severity",
            desc="Only show notifications for alerts at or above this level.",
            options=[("critical", "Critical only"), ("high", "High and above"),
                     ("medium", "Medium and above"), ("low", "All alerts")]))

        lay.addWidget(self._section_hdr("Alert categories"))
        lay.addWidget(self._toggle("notifications", "network",
            label="Network threats",
            desc="DDoS attacks, ARP spoofing, DNS threats, brute force."))
        lay.addWidget(self._toggle("notifications", "system",
            label="System events",
            desc="Event log, file integrity monitoring, UEBA anomalies."))
        lay.addWidget(self._toggle("notifications", "file_scan",
            label="File scanner",
            desc="USB drives, malicious downloads, malware detections."))

        lay.addWidget(self._section_hdr("Sound"))
        lay.addWidget(self._toggle("notifications", "sound",
            label="Alert sound",
            desc="Play a beep on critical-severity alerts.",
            on_change=lambda v: None))
        snd_btn = QPushButton("▶  Test Sound")
        snd_btn.setObjectName("secondaryBtn")
        snd_btn.setFixedHeight(30)
        snd_btn.setFixedWidth(130)
        snd_btn.clicked.connect(self._test_sound)
        lay.addWidget(self._row("", "", snd_btn))

    def _page_appearance(self, lay: QVBoxLayout):
        lay.addWidget(_lbl("Appearance",
            "font-size:18px; font-weight:700; color:#e2eeff; padding-bottom:4px;"))
        lay.addWidget(_lbl("Personalise your Security Monitor experience.",
            "font-size:12px; color:#445068; padding-bottom:8px;"))

        lay.addWidget(self._section_hdr("Accent colour"))
        lay.addWidget(_lbl("Choose the highlight colour used throughout the interface.",
            "font-size:12px; color:#556077; padding-bottom:6px;"))

        ACCENTS = [
            ("#4f8ef7", "Sky Blue"),
            ("#9b7ce8", "Violet"),
            ("#2dd4bf", "Teal"),
            ("#22c55e", "Emerald"),
            ("#fb923c", "Sunset"),
            ("#f472b6", "Rose"),
        ]
        current_accent = self._s.get("appearance", "accent", default="#4f8ef7")

        swatch_row = QHBoxLayout()
        swatch_row.setSpacing(10)
        swatch_row.setContentsMargins(0, 4, 0, 4)
        self._swatch_btns: list[QPushButton] = []

        for hex_col, name in ACCENTS:
            btn = QPushButton()
            btn.setFixedSize(52, 52)
            btn.setToolTip(name)
            active = hex_col == current_accent
            btn.setStyleSheet(
                f"background:{hex_col}; border-radius:14px;"
                f"border: {'3px solid white' if active else '2px solid rgba(255,255,255,0.15)'};"
            )
            btn.clicked.connect(lambda _, hx=hex_col, b=btn: self._apply_accent(hx, b))
            swatch_row.addWidget(btn)
            self._swatch_btns.append(btn)

        swatch_row.addStretch()
        w = QWidget()
        w.setLayout(swatch_row)
        lay.addWidget(w)

        self._accent_name_lbl = _lbl(
            next((n for h, n in ACCENTS if h == current_accent), "Custom"),
            "font-size:12px; color:#8fa3c0; padding-top:4px;"
        )
        lay.addWidget(self._accent_name_lbl)

        lay.addWidget(self._section_hdr("Interface"))
        lay.addWidget(_lbl("More appearance options coming in a future update.",
            "font-size:12px; color:#2c3858; padding-top:8px;"))

    def _page_detection(self, lay: QVBoxLayout):
        lay.addWidget(_lbl("Detection Settings",
            "font-size:18px; font-weight:700; color:#e2eeff; padding-bottom:4px;"))
        lay.addWidget(_lbl("Control which threat detectors are active. Restart the app to apply changes.",
            "font-size:12px; color:#445068; padding-bottom:8px;"))

        lay.addWidget(self._section_hdr("Network detectors"))
        lay.addWidget(self._toggle("detection", "arp",
            label="ARP Spoofing Monitor",
            desc="Detect ARP cache poisoning and gateway hijack attempts."))
        lay.addWidget(self._toggle("detection", "dns",
            label="DNS Monitoring",
            desc="Detect DNS tunnelling, fast-flux domains, and C2 beaconing."))
        lay.addWidget(self._toggle("detection", "brute_force",
            label="Brute Force Detection",
            desc="Detect SSH, RDP, FTP, and SMB password guessing attacks."))
        lay.addWidget(self._toggle("detection", "tls",
            label="TLS Inspector",
            desc="Detect weak ciphers, missing SNI, and malicious JA3 fingerprints."))
        lay.addWidget(self._toggle("detection", "threat_intel",
            label="Threat Intelligence (AbuseIPDB)",
            desc="Cross-reference attacker IPs with the AbuseIPDB reputation database."))

        lay.addWidget(self._section_hdr("Auto-block"))
        lay.addWidget(self._toggle("detection", "auto_block",
            label="Auto-block attacking IPs",
            desc="Automatically add Windows Firewall rules when an attack is confirmed.",
            on_change=self._on_auto_block_change))

        thresh_row = QHBoxLayout()
        thresh_row.setSpacing(10)
        thresh_val = self._s.get("detection", "attack_threshold", default=75)
        self._thresh_spin = QSpinBox()
        self._thresh_spin.setRange(50, 100)
        self._thresh_spin.setValue(int(thresh_val))
        self._thresh_spin.setSuffix(" %")
        self._thresh_spin.setFixedWidth(90)
        self._thresh_spin.valueChanged.connect(
            lambda v: self._s.set("detection", "attack_threshold", v))
        thresh_row.addWidget(self._thresh_spin)
        thresh_row.addStretch()
        tw = QWidget()
        tw.setLayout(thresh_row)
        lay.addWidget(self._row("Attack confidence threshold",
            "Auto-block fires when DDoS model confidence exceeds this value.", tw))

    def _page_file_protect(self, lay: QVBoxLayout):
        lay.addWidget(_lbl("File Protection",
            "font-size:18px; font-weight:700; color:#e2eeff; padding-bottom:4px;"))
        lay.addWidget(_lbl("Manage how Security Monitor scans files and monitors devices.",
            "font-size:12px; color:#445068; padding-bottom:8px;"))

        lay.addWidget(self._section_hdr("Monitors"))
        lay.addWidget(self._toggle("file_protection", "usb_monitor",
            label="USB drive monitor",
            desc="Detect external drives being inserted and prompt to scan them."))
        lay.addWidget(self._toggle("file_protection", "download_watcher",
            label="Download folder watcher",
            desc="Watch Downloads, Desktop, and Temp for newly transferred files."))
        lay.addWidget(self._toggle("file_protection", "auto_scan",
            label="Auto-scan new files",
            desc="Automatically scan files the moment they appear in watched folders."))

        lay.addWidget(self._section_hdr("Scanning"))
        lay.addWidget(self._toggle("file_protection", "cloud_lookup",
            label="MalwareBazaar cloud lookup",
            desc="Check file SHA-256 hashes against the free MalwareBazaar threat database. "
                 "Requires internet. Disabling speeds up scans but reduces accuracy."))

        lay.addWidget(self._section_hdr("Watched folders"))
        lay.addWidget(_lbl(
            "Downloads, Desktop, and Temp are monitored by default. "
            "Custom folders coming in a future update.",
            "font-size:12px; color:#2c3858; padding:4px 0;"))

    def _page_performance(self, lay: QVBoxLayout):
        lay.addWidget(_lbl("Performance",
            "font-size:18px; font-weight:700; color:#e2eeff; padding-bottom:4px;"))
        lay.addWidget(_lbl("Tune memory and CPU usage. Lower values = less resource usage.",
            "font-size:12px; color:#445068; padding-bottom:8px;"))

        lay.addWidget(self._section_hdr("Memory limits"))

        for setting_key, label, desc, min_v, max_v, default in [
            ("max_alerts", "Max alerts in memory",
             "Oldest alert cards are removed when this limit is reached.", 50, 500, 150),
            ("max_rows", "Max traffic table rows",
             "Rows in the Live Traffic table before oldest are pruned.", 50, 1000, 300),
        ]:
            val  = self._s.get("performance", setting_key, default=default)
            spin = QSpinBox()
            spin.setRange(min_v, max_v)
            spin.setValue(int(val))
            spin.setFixedWidth(100)
            spin.valueChanged.connect(lambda v, k=setting_key: self._s.set("performance", k, v))
            lay.addWidget(self._row(label, desc, spin))

        lay.addWidget(self._section_hdr("Packet display rate"))
        rate_val  = self._s.get("performance", "packet_rate", default=20)
        rate_spin = QSpinBox()
        rate_spin.setRange(5, 60)
        rate_spin.setValue(int(rate_val))
        rate_spin.setSuffix(" /sec")
        rate_spin.setFixedWidth(100)
        rate_spin.valueChanged.connect(lambda v: self._s.set("performance", "packet_rate", v))
        lay.addWidget(self._row("Max UI updates per second",
            "How often the live traffic view refreshes. "
            "Lower = less CPU. Restart required to apply.", rate_spin))

    def _page_whitelist(self, lay: QVBoxLayout):
        lay.addWidget(_lbl("IP Whitelist",
            "font-size:18px; font-weight:700; color:#e2eeff; padding-bottom:4px;"))
        lay.addWidget(_lbl(
            "IPs on this list will never trigger alerts. Useful for trusted internal systems.",
            "font-size:12px; color:#445068; padding-bottom:8px;"))

        add_row = QHBoxLayout()
        add_row.setSpacing(8)
        self._wl_input = QLineEdit()
        self._wl_input.setPlaceholderText("Enter IP address (e.g. 192.168.1.1)…")
        add_btn = QPushButton("Add")
        add_btn.setObjectName("secondaryBtn")
        add_btn.setFixedHeight(36)
        add_btn.clicked.connect(self._wl_add)
        add_row.addWidget(self._wl_input, 1)
        add_row.addWidget(add_btn)
        w = QWidget()
        w.setLayout(add_row)
        lay.addWidget(w)

        self._wl_frame = QFrame()
        self._wl_frame.setObjectName("card2")
        self._wl_lay   = QVBoxLayout(self._wl_frame)
        self._wl_lay.setContentsMargins(12, 10, 12, 10)
        self._wl_lay.setSpacing(4)
        self._wl_empty = _lbl("No IPs whitelisted yet.", "color:#2c3858; font-size:12px; padding:8px;")
        self._wl_lay.addWidget(self._wl_empty)
        lay.addWidget(self._wl_frame)
        self._refresh_whitelist()

        lay.addWidget(_lbl(
            "ℹ  Whitelisted IPs are saved immediately and applied from the next detected packet.",
            "font-size:11px; color:#2c3858; padding-top:6px;"))

    def _page_about(self, lay: QVBoxLayout):
        lay.addWidget(_lbl("About Security Monitor",
            "font-size:18px; font-weight:700; color:#e2eeff; padding-bottom:4px;"))

        info_card = QFrame()
        info_card.setObjectName("card")
        il = QVBoxLayout(info_card)
        il.setContentsMargins(20, 16, 20, 16)
        il.setSpacing(8)

        logo_row = QHBoxLayout()
        logo_row.setSpacing(14)
        logo_lbl = QLabel()
        logo_lbl.setPixmap(_make_shield_logo(52))
        logo_lbl.setFixedSize(52, 52)
        logo_row.addWidget(logo_lbl)
        tv = QVBoxLayout()
        tv.setSpacing(2)
        tv.addWidget(_lbl("Security Monitor",
            "font-size:16px; font-weight:700; color:#e2eeff;"))
        tv.addWidget(_lbl("v1.0.0  ·  Built with PyQt6, Scapy & scikit-learn",
            "font-size:11px; color:#445068;"))
        logo_row.addLayout(tv, 1)
        il.addLayout(logo_row)

        il.addWidget(_sep())
        for label, value in [
            ("14 threat detectors", "Network · System · File · Intelligence"),
            ("Machine learning",    "RandomForest DDoS + Isolation Forest anomaly"),
            ("Free cloud lookups",  "MalwareBazaar · ip-api.com geolocation"),
            ("AI email analysis",   "Groq gpt-oss-120b (free tier)"),
        ]:
            row = QHBoxLayout()
            row.addWidget(_lbl(f"❆  {label}",
                "font-size:12px; color:#4f8ef7; font-weight:600;"))
            row.addWidget(_lbl(value, "font-size:12px; color:#556077;"), 1)
            il.addLayout(row)

        lay.addWidget(info_card)

        lay.addWidget(self._section_hdr("Actions"))
        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)
        for label, fn in [
            ("\U0001f4ca  Export Alerts CSV", self._export_csv),
            ("\U0001f4c2  Open Log File",    self._open_log),
            ("\U0001f504  Reset Settings",   self._reset_settings),
        ]:
            b = QPushButton(label)
            b.setObjectName("secondaryBtn")
            b.setFixedHeight(34)
            b.clicked.connect(fn)
            btn_row.addWidget(b)
        btn_row.addStretch()
        w = QWidget()
        w.setLayout(btn_row)
        lay.addWidget(w)

    # ── Actions ───────────────────────────────────────────────────────────────

    def _apply_accent(self, hex_color: str, clicked_btn: QPushButton):
        self._s.set("appearance", "accent", hex_color)
        for btn in self._swatch_btns:
            is_active = (btn is clicked_btn)
            # Extract the background color from the existing style
            old_style = btn.styleSheet()
            bg = old_style.split(";")[0].split(":")[1].strip()
            btn.setStyleSheet(
                f"background:{bg}; border-radius:14px;"
                f"border: {'3px solid white' if is_active else '2px solid rgba(255,255,255,0.15)'};"
            )
        self.accent_changed.emit(hex_color)

    def _on_auto_block_change(self, v: bool):
        pass  # MainWindow will wire this if needed

    def _test_sound(self):
        try:
            import winsound
            winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
        except Exception:
            pass

    def _wl_add(self):
        ip = self._wl_input.text().strip()
        if not ip:
            return
        if not _validate_ip(ip):
            QMessageBox.warning(self, "Invalid IP", f"'{ip}' is not a valid IP address.")
            return
        wl = self._s.get("whitelist", default=[])
        if ip not in wl:
            wl.append(ip)
            self._s.set("whitelist", wl)
        self._wl_input.clear()
        self._refresh_whitelist()

    def _wl_remove(self, ip: str):
        wl = self._s.get("whitelist", default=[])
        if ip in wl:
            wl.remove(ip)
            self._s.set("whitelist", wl)
        self._refresh_whitelist()

    def _refresh_whitelist(self):
        while self._wl_lay.count():
            item = self._wl_lay.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        wl = self._s.get("whitelist", default=[])
        if not wl:
            self._wl_lay.addWidget(
                _lbl("No IPs whitelisted yet.", "color:#2c3858; font-size:12px; padding:8px;"))
            return
        for ip in wl:
            row = QWidget()
            rl  = QHBoxLayout(row)
            rl.setContentsMargins(0, 2, 0, 2)
            rl.setSpacing(8)
            rl.addWidget(_lbl(ip,
                "font-family:Consolas; font-size:12px; color:#8fa3c0;"), 1)
            rb = QPushButton("Remove")
            rb.setObjectName("dangerBtn")
            rb.setFixedHeight(24)
            rb.clicked.connect(lambda _, i=ip: self._wl_remove(i))
            rl.addWidget(rb)
            self._wl_lay.addWidget(row)

    def _export_csv(self):
        from pathlib import Path as _P
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Alerts", str(_P.home() / "security_alerts.csv"), "CSV (*.csv)")
        if not path:
            return
        try:
            import config
            log = _P(config.LOG_FILE)
            if log.exists():
                import shutil
                shutil.copy(str(log), path)
                QMessageBox.information(self, "Exported", f"Log saved to:\n{path}")
            else:
                QMessageBox.warning(self, "No log", "No alert log file found.")
        except Exception as e:
            QMessageBox.warning(self, "Error", str(e))

    def _open_log(self):
        try:
            import config, os
            log = config.LOG_FILE
            if os.path.exists(log):
                os.startfile(log)
            else:
                QMessageBox.information(self, "No log", "Alert log file not found.")
        except Exception as e:
            QMessageBox.warning(self, "Error", str(e))

    def _reset_settings(self):
        r = QMessageBox.question(
            self, "Reset Settings",
            "Reset all settings to their defaults?\n\nThis cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if r == QMessageBox.StandardButton.Yes:
            SETTINGS_FILE.unlink(missing_ok=True)
            QMessageBox.information(
                self, "Done", "Settings reset. Restart the app to apply.")

    def get_whitelist(self) -> list[str]:
        return self._s.get("whitelist", default=[])


# ══════════════════════════════════════════════════════════════════════════════
# ── Main Window ────────────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

class MainWindow(QMainWindow):
    _sys_alert_sig = pyqtSignal(dict)   # thread-safe route for EventLog/FIM alerts

    def __init__(self, auto_block: bool = False):
        super().__init__()
        self._settings = AppSettings()
        self.setWindowTitle("Security Monitor")
        icon_path = ROOT / "ddos.ico"
        if icon_path.exists():
            self.setWindowIcon(QIcon(str(icon_path)))
        self.setMinimumSize(1100, 680)
        self.resize(1280, 760)

        self._auto_block = auto_block
        self._sniffer:     SnifferThread | None = None
        self._tray:        QSystemTrayIcon | None = None
        self._blocked_tab: BlockedIPsTab | None = None
        self._el_thread:   EventLogThread | None = None
        self._fim_thread:  FIMThread | None = None
        self._sys_alert_sig.connect(self._on_system_alert)

        # Try loading model info
        model_ready = False
        try:
            import config
            from joblib import load as jl_load
            data = jl_load(config.MODEL_FILENAME)
            model_ready = "model" in data
        except Exception:
            pass

        self._model_ready = model_ready
        self._build(model_ready)
        QApplication.instance().setStyleSheet(
            _build_qss(self._settings.get("appearance", "accent", default="#4f8ef7"))
        )
        self._setup_tray()
        self._start_sniffer()
        self._start_host_monitors()

    # ── Build UI ──────────────────────────────────────────────────────────

    def _build(self, model_ready: bool):
        central = QWidget(); central.setObjectName("central")
        central.setStyleSheet("background:#0b0d1e;")
        self.setCentralWidget(central)
        main = QHBoxLayout(central); main.setContentsMargins(0, 0, 0, 0); main.setSpacing(0)

        # Sidebar
        sidebar = QWidget(); sidebar.setObjectName("sidebar")
        sl = QVBoxLayout(sidebar); sl.setContentsMargins(12, 16, 12, 14); sl.setSpacing(2)

        # Brand / logo area
        brand = QFrame()
        brand.setStyleSheet(
            "background: rgba(79,142,247,0.08); border: 1px solid rgba(79,142,247,0.16);"
            "border-radius: 12px;"
        )
        bl = QHBoxLayout(brand); bl.setContentsMargins(12, 10, 12, 10); bl.setSpacing(10)
        logo_lbl = QLabel()
        logo_lbl.setPixmap(_make_shield_logo(40))
        logo_lbl.setFixedSize(40, 40)
        bl.addWidget(logo_lbl)
        brand_txt = QVBoxLayout(); brand_txt.setSpacing(1)
        brand_txt.addWidget(_lbl("Security Monitor",
                                  "font-size:13px; font-weight:700; color:#e2eeff;"))
        brand_txt.addWidget(_lbl("Your Personal Defence Shield",
                                  "font-size:10px; color:#4a6a99; letter-spacing:0.2px;"))
        bl.addLayout(brand_txt, 1)
        sl.addWidget(brand)
        sl.addSpacing(10)

        sep = QFrame(); sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("background:rgba(255,255,255,0.05);max-height:1px;border:none;")
        sl.addWidget(sep)
        sl.addSpacing(6)

        sl.addWidget(_lbl("MONITOR", "color:#2a4060;font-size:10px;font-weight:700;letter-spacing:1.4px;padding:6px 4px 2px;"))
        self._nav_btns: dict[str, QPushButton] = {}
        self._pages: dict[str, int] = {}

        self._stack = QStackedWidget()

        # Dashboard
        self._dashboard = DashboardTab()
        self._dashboard.navigate_to.connect(self._go_to)
        self._add_tab("overview", "Overview",          self._dashboard,    sl, "🏠", "#4f8ef7")

        # Traffic
        self._traffic = TrafficTab()
        self._add_tab("traffic",  "Live Traffic",      self._traffic,      sl, "📡", "#34d399")

        # Threats
        self._alerts_tab = AlertsTab()
        self._alerts_tab.block_requested.connect(self._do_block)
        self._add_tab("threats",  "Threats & Alerts",  self._alerts_tab,   sl, "🚨", "#f47070")

        # System Monitor
        self._sys_tab = SystemMonitorTab()
        self._add_tab("system",   "System Monitor",    self._sys_tab,      sl, "🖥", "#a78bfa")

        # Geo Map
        self._geo_tab = GeoMapTab()
        self._add_tab("geomap",   "Geo Map",           self._geo_tab,      sl, "🗺", "#2dd4bf")

        sl.addSpacing(6)
        sl.addWidget(_lbl("PROTECTION", "color:#2a4060;font-size:10px;font-weight:700;letter-spacing:1.4px;padding:6px 4px 2px;"))

        # Blocked IPs
        self._blocked_tab = BlockedIPsTab()
        self._add_tab("blocked",  "Blocked IPs",       self._blocked_tab,  sl, "🔒", "#fb923c")

        # File Scanner
        self._file_scanner_tab = FileScannerTab()
        self._file_scanner_tab.alert_signal.connect(self._on_file_scan_alert)
        self._add_tab("filescanner", "File Scanner",   self._file_scanner_tab, sl, "🔍", "#f5c542")

        sl.addSpacing(6)
        sl.addWidget(_lbl("TOOLS", "color:#2a4060;font-size:10px;font-weight:700;letter-spacing:1.4px;padding:6px 4px 2px;"))

        # Tools
        self._tools = ToolsTab(model_ready=model_ready)
        self._tools.demo_alert.connect(self._on_alert)
        self._tools.demo_sys_alert.connect(self._on_system_alert)
        self._add_tab("tools",    "Test & Analyse",    self._tools,        sl, "🧪", "#7c8fbf")

        sl.addSpacing(6)
        sl.addWidget(_lbl("AI LAB", "color:#2a4060;font-size:10px;font-weight:700;letter-spacing:1.4px;padding:6px 4px 2px;"))

        # ML Analysis
        self._ml_tab = MLAnalysisTab()
        self._ml_tab.score_computed.connect(self._on_ai_score)
        self._add_tab("mlanalysis", "ML Analysis",    self._ml_tab,       sl, "📊", "#2dd4bf")

        # Adaptive Training
        self._adapt_tab = AdaptiveTrainingTab()
        self._adapt_tab.model_updated.connect(self._on_model_updated)
        self._add_tab("adaptive", "Adaptive Training", self._adapt_tab,   sl, "🧠", "#34d399")

        # Adversarial Lab
        self._adv_tab = AdversarialTab()
        self._adv_tab.score_updated.connect(self._on_ai_score)
        self._add_tab("advlab",    "Adversarial Lab", self._adv_tab,      sl, "⚡", "#f5c542")

        sl.addSpacing(6)
        sl.addWidget(_lbl("SETTINGS", "color:#2a4060;font-size:10px;font-weight:700;letter-spacing:1.4px;padding:6px 4px 2px;"))

        # Settings
        self._settings_tab = SettingsTab(self._settings)
        self._settings_tab.accent_changed.connect(self._on_accent_change)
        self._add_tab("settings", "Settings", self._settings_tab, sl, "⚙", "#8fa3c0")

        sl.addStretch()

        # Status panel at bottom of sidebar
        status_frame = QFrame()
        status_frame.setStyleSheet(
            "background: rgba(0,0,0,0.25); border: 1px solid rgba(255,255,255,0.05); border-radius: 10px;"
        )
        sfl = QVBoxLayout(status_frame); sfl.setContentsMargins(10, 8, 10, 8); sfl.setSpacing(5)

        rf_color  = "#34d399" if model_ready else "#f59e0b"
        rf_status = "Ready" if model_ready else "Not trained"
        sfl.addWidget(_lbl(f"◉  RF Model — {rf_status}",
                            f"color:{rf_color}; font-size:11px; font-weight:600;"))
        self._sniffer_status_lbl = _lbl("◉  Sniffer — Starting…",
                                         "color:#f59e0b; font-size:11px; font-weight:600;")
        sfl.addWidget(self._sniffer_status_lbl)

        if not IS_ADMIN:
            admin_lbl = _lbl("⚠  Not admin — blocking off",
                              "color:#f59e0b; font-size:10px;")
            sfl.addWidget(admin_lbl)

        sl.addSpacing(4)
        sl.addWidget(_sep())
        sl.addSpacing(4)
        sl.addWidget(status_frame)

        if not model_ready:
            sl.addSpacing(6)
            sl.addWidget(_lbl("To train: python train_model.py",
                               "color:#4a6a99; font-size:10px; padding:0 4px;"))

        main.addWidget(sidebar)
        main.addWidget(self._stack, 1)

        # Status bar
        sb = QStatusBar(); self.setStatusBar(sb)
        self._sb_sniffer = QLabel("◉  Connecting…")
        self._sb_sniffer.setStyleSheet("color:#f59e0b; font-weight:600; padding:0 6px;")
        self._sb_flows = QLabel("0 flows")
        self._sb_flows.setStyleSheet("color:#667799; font-family:Consolas; padding:0 6px;")
        if IS_ADMIN:
            admin_txt = "✓  Admin — IP blocking enabled"
            admin_style = "color:#34d399; font-weight:600; padding:0 6px;"
        else:
            admin_txt = "⚠  Not admin — blocking disabled"
            admin_style = "color:#f59e0b; padding:0 6px;"
        self._sb_admin = QLabel(admin_txt)
        self._sb_admin.setStyleSheet(admin_style)
        sb.addWidget(self._sb_sniffer)
        sb.addPermanentWidget(self._sb_flows)
        sb.addPermanentWidget(self._sb_admin)

        self._go_to("overview")

    def _add_tab(self, key: str, label: str, widget: QWidget, sl: QVBoxLayout,
                 icon_emoji: str = "", icon_color: str = "#4f8ef7"):
        idx = self._stack.addWidget(widget)
        self._pages[key] = idx
        btn = QPushButton(label); btn.setObjectName("navBtn")
        if icon_emoji:
            btn.setIcon(_make_badge_icon(icon_emoji, icon_color))
            btn.setIconSize(QSize(30, 30))
        btn.clicked.connect(lambda _, k=key: self._go_to(k))
        sl.addWidget(btn)
        self._nav_btns[key] = btn

    def _go_to(self, key: str):
        if key not in self._pages:
            return
        self._stack.setCurrentIndex(self._pages[key])
        for k, btn in self._nav_btns.items():
            active = "1" if k == key else "0"
            btn.setProperty("active", active)
            btn.style().unpolish(btn); btn.style().polish(btn)
        if key == "blocked" and self._blocked_tab:
            self._blocked_tab.refresh()

    def _on_accent_change(self, hex_color: str):
        QApplication.instance().setStyleSheet(_build_qss(hex_color))

    def _on_ai_score(self, result: dict):
        """Forward AI Security Score result to the dashboard banner."""
        try:
            self._dashboard.update_ai_score(result)
        except Exception:
            pass

    def _on_model_updated(self):
        """Reload the DDoS detector singleton after adaptive retraining."""
        try:
            from detectors.adversarial import _ModelWrapper
            _ModelWrapper._instance = None   # force reload on next prediction
            # Update sidebar RF status label
            self._sniffer_status_lbl  # triggers attribute lookup (safe no-op)
        except Exception:
            pass
        # Refresh ML Analysis metrics from new model_metrics.json
        try:
            self._ml_tab._start_compute()
        except Exception:
            pass

    # ── Sniffer ────────────────────────────────────────────────────────────

    def _start_sniffer(self):
        self._sniffer = SnifferThread(auto_block=self._auto_block, parent=self)
        self._sniffer.packet_signal.connect(self._on_packet)
        self._sniffer.alert_signal.connect(self._on_alert)
        self._sniffer.status_signal.connect(self._on_sniffer_status)
        self._sniffer.start()

    def _stop_sniffer(self):
        if self._sniffer and self._sniffer.isRunning():
            self._sniffer.stop()
            self._sniffer.wait(3000)

    def _start_host_monitors(self):
        """Start EventLog, FIM, UEBA, GeoMapper, and web dashboard threads."""
        try:
            import config

            # UEBA engine — feeds on event log alerts
            try:
                from detectors.ueba import UEBAEngine
                self._ueba = UEBAEngine(on_alert=lambda a: self._sys_alert_sig.emit(a))
            except Exception:
                self._ueba = None

            # GeoMapper — tracks attacker IPs from all alert sources
            try:
                from detectors.geo_mapper import GeoMapper
                self._geo = GeoMapper(on_alert=lambda a: self._sys_alert_sig.emit(a))
                self._geo_tab.set_mapper(self._geo)
            except Exception:
                self._geo = None

            # Event Log
            self._el_thread = EventLogThread(parent=self)
            self._el_thread.new_alert.connect(lambda a: self._sys_alert_sig.emit(a))
            self._el_thread.new_alert.connect(self._on_event_log_alert)
            self._el_thread.status_sig.connect(
                lambda t, c: self._sys_tab.set_eventlog_status(t, c)
            )
            self._el_thread.start()

            # FIM
            self._fim_thread = FIMThread(
                watch_dirs    = getattr(config, "FIM_WATCH_DIRS", [str(ROOT)]),
                baseline_path = getattr(config, "FIM_BASELINE_FILE", str(ROOT / "fim_baseline.json")),
                parent        = self,
            )
            self._fim_thread.new_alert.connect(lambda a: self._sys_alert_sig.emit(a))
            self._fim_thread.status_sig.connect(
                lambda t, c: self._sys_tab.set_fim_status(t, c)
            )
            self._fim_thread.start()

            # Threat Intel status
            api_key = getattr(config, "ABUSEIPDB_API_KEY", "")
            if api_key:
                self._sys_tab.set_ti_status("Active — checking flagged IPs", "#34d399")
            else:
                self._sys_tab.set_ti_status("No API key — add ABUSEIPDB_API_KEY to .env", "#fbbf24")

            # Web dashboard (mobile companion) on port 8080
            try:
                import queue as _q
                from web_dashboard.app import create_app, push_alert as _push
                self._web_bus = _q.Queue(maxsize=500)
                web_app = create_app(shared_bus=self._web_bus)
                threading.Thread(
                    target=lambda: web_app.run(host="0.0.0.0", port=8080, threaded=True, debug=False),
                    daemon=True, name="WebDashboard",
                ).start()
                self._web_push = _push
            except Exception:
                self._web_push = None

            # File Scanner — USB monitor + download watcher
            try:
                self._file_scanner_tab.start_monitors()
            except Exception:
                pass

        except Exception:
            pass

    def _on_file_scan_alert(self, a: dict):
        """Route file-scanner alerts: malware → Threats, others → System Monitor."""
        category = a.get("category", "")
        rule     = a.get("rule_name", "")
        sev      = a.get("severity", "low")
        if rule == "Malware Detected" or (category == "file_scan" and sev == "critical"):
            self._on_alert(a)
        else:
            self._on_system_alert(a)

    def _on_event_log_alert(self, a: dict) -> None:
        """Feed event log alerts into UEBA and GeoMapper."""
        if self._ueba:
            self._ueba.update(a)
        if self._geo:
            ip = a.get("source_ip", "")
            if ip and ip not in ("localhost", "local"):
                self._geo.track_ip(ip, rule_name=a.get("rule_name", ""), severity=a.get("severity", "low"))

    def _on_system_alert(self, a: dict):
        """Route EventLog / FIM / ThreatIntel alerts to the System Monitor tab."""
        self._sys_tab.add_alert(a)
        sev = (a.get("severity") or "low").lower()
        if sev in ("critical", "high") and self._tray:
            self._tray.showMessage(
                "⚠  System Alert",
                f"{a.get('rule_name', 'Event')} — {a.get('source_ip', '')}\n"
                f"{a.get('message', '')[:100]}",
                QSystemTrayIcon.MessageIcon.Critical,
                5000,
            )

    def _on_packet(self, d: dict):
        self._dashboard.on_packet(d)
        self._traffic.add_row(d)
        flows = d.get("active_flows", 0)
        self._sb_flows.setText(f"{flows:,} active flows")

        if d.get("status") == "ATTACK" and self._tray:
            self._tray.setIcon(self._make_tray_icon("#f87171"))
        elif d.get("status") == "SUSPICIOUS" and self._tray:
            self._tray.setIcon(self._make_tray_icon("#fbbf24"))

    def _on_alert(self, a: dict):
        self._dashboard.on_alert(a)
        self._alerts_tab.add_alert(a)
        sev = (a.get("severity") or "low").lower()
        _sev_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        _min_sev   = self._settings.get("notifications", "min_severity", default="high")
        _notif_ok  = (
            self._settings.get("notifications", "enabled", default=True)
            and _sev_order.get(sev, 0) >= _sev_order.get(_min_sev, 2)
            and self._settings.get("notifications", "network", default=True)
        )
        if _notif_ok and sev in ("critical", "high") and self._tray:
            self._tray.showMessage(
                "⚠  Security Alert",
                f"{a.get('rule_name','Threat')} — {a.get('source_ip','unknown IP')}\n"
                f"{_humanize(a)[:100]}",
                QSystemTrayIcon.MessageIcon.Critical,
                5000,
            )
            self._tray.setIcon(self._make_tray_icon("#f87171"))

        # Feed GeoMapper and notify Geo Map tab
        try:
            geo = getattr(self, "_geo", None)
            ip  = a.get("source_ip", "")
            if geo and ip and ip not in ("localhost", "local", ""):
                geo.track_ip(ip, rule_name=a.get("rule_name",""), severity=a.get("severity","low"))
            self._geo_tab.on_new_alert()
        except Exception:
            pass

        # Forward to web dashboard SSE bus
        try:
            push = getattr(self, "_web_push", None)
            if push:
                push(a)
        except Exception:
            pass

    def _on_sniffer_status(self, s: str):
        if s == "running":
            self._sniffer_status_lbl.setText("◉  Sniffer — Live")
            self._sniffer_status_lbl.setStyleSheet(
                "color:#34d399; font-size:11px; font-weight:600;")
            self._sb_sniffer.setText("◉  Sniffer live")
            self._sb_sniffer.setStyleSheet("color:#34d399; font-weight:600; padding:0 6px;")
        elif s == "stopped":
            self._sniffer_status_lbl.setText("◉  Sniffer — Stopped")
            self._sniffer_status_lbl.setStyleSheet(
                "color:#3a4a68; font-size:11px; font-weight:600;")
            self._sb_sniffer.setText("◉  Sniffer stopped")
            self._sb_sniffer.setStyleSheet("color:#3a4a68; font-weight:600; padding:0 6px;")
            if self._tray:
                self._tray.setIcon(self._make_tray_icon("#3a4a68"))
        elif s.startswith("error:"):
            msg = s[6:]
            self._sniffer_status_lbl.setText("◉  Sniffer — Error")
            self._sniffer_status_lbl.setStyleSheet(
                "color:#f87171; font-size:11px; font-weight:600;")
            self._sb_sniffer.setText(f"◉  {msg[:60]}")
            self._sb_sniffer.setStyleSheet("color:#f87171; font-weight:600; padding:0 6px;")

    # ── IP Blocking ────────────────────────────────────────────────────────

    def _do_block(self, ip: str, reason: str):
        ok, msg = _firewall_block(ip)
        if ok:
            if self._blocked_tab:
                self._blocked_tab.add_entry(ip, reason, auto=False)
            if self._sniffer:
                self._sniffer.refresh_blocked()
            QMessageBox.information(self, "IP Blocked", msg)
        else:
            QMessageBox.warning(self, "Block Failed", msg)

    # ── System tray ────────────────────────────────────────────────────────

    def _make_tray_icon(self, color: str = "#34d399") -> QIcon:
        px = QPixmap(32, 32)
        px.fill(Qt.GlobalColor.transparent)
        p = QPainter(px)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        path = QPainterPath()
        path.moveTo(16, 2);  path.lineTo(29, 7)
        path.lineTo(29, 17)
        path.cubicTo(QPointF(29, 27), QPointF(16, 31), QPointF(16, 31))
        path.cubicTo(QPointF(16, 31), QPointF(3, 27),  QPointF(3, 17))
        path.lineTo(3, 7); path.closeSubpath()
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QBrush(QColor(color)))
        p.drawPath(path)
        p.end()
        return QIcon(px)

    def _setup_tray(self):
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
        icon_path = ROOT / "ddos.ico"
        icon = QIcon(str(icon_path)) if icon_path.exists() else self._make_tray_icon()
        self._tray = QSystemTrayIcon(icon, self)
        self._tray.setToolTip("Security Monitor — running in background")

        menu = QMenu()
        menu.setStyleSheet(
            "QMenu{background:#13162a;border:1px solid rgba(255,255,255,0.08);color:#d4e4f8;"
            "border-radius:10px;padding:4px 0;}"
            "QMenu::item{padding:8px 24px 8px 16px;border-radius:6px;}"
            "QMenu::item:selected{background:rgba(79,142,247,0.16);color:#cee0ff;}"
            "QMenu::separator{height:1px;background:rgba(255,255,255,0.06);margin:4px 8px;}"
        )
        show_act = QAction("🏠  Show Window", self)
        show_act.triggered.connect(self._show_window)
        menu.addAction(show_act)
        menu.addSeparator()
        self._toggle_act = QAction("⏸  Pause Sniffer", self)
        self._toggle_act.triggered.connect(self._toggle_sniffer)
        menu.addAction(self._toggle_act)
        menu.addSeparator()
        blk_act = QAction("🔒  View Blocked IPs", self)
        blk_act.triggered.connect(lambda: (self._show_window(), self._go_to("blocked")))
        menu.addAction(blk_act)
        menu.addSeparator()
        quit_act = QAction("✖  Quit", self)
        quit_act.triggered.connect(self._quit)
        menu.addAction(quit_act)

        self._tray.setContextMenu(menu)
        self._tray.activated.connect(lambda reason:
            self._show_window() if reason == QSystemTrayIcon.ActivationReason.DoubleClick else None)
        self._tray.show()

    def _show_window(self):
        self.showNormal(); self.raise_(); self.activateWindow()

    def _toggle_sniffer(self):
        if self._sniffer and self._sniffer.isRunning():
            self._sniffer.stop()
            self._toggle_act.setText("▶  Resume Sniffer")
        else:
            self._start_sniffer()
            self._toggle_act.setText("⏸  Pause Sniffer")

    def _quit(self):
        self._stop_sniffer()
        if self._el_thread:
            self._el_thread.stop(); self._el_thread.wait(2000)
        if self._fim_thread:
            self._fim_thread.stop(); self._fim_thread.wait(2000)
        try:
            self._file_scanner_tab.stop_monitors()
        except Exception:
            pass
        QApplication.quit()

    # ── Window events ──────────────────────────────────────────────────────

    def showEvent(self, e):
        super().showEvent(e)
        try:
            _apply_dark_titlebar(int(self.winId()))
        except Exception:
            pass

    def closeEvent(self, e):
        if self._tray and self._tray.isVisible():
            e.ignore()
            self.hide()
            self._tray.showMessage(
                "Security Monitor",
                "Still running in the background. Double-click the tray icon to reopen.",
                QSystemTrayIcon.MessageIcon.Information,
                3000,
            )
        else:
            self._stop_sniffer()
            if self._el_thread:
                self._el_thread.stop()
            if self._fim_thread:
                self._fim_thread.stop()
            try:
                self._file_scanner_tab.stop_monitors()
            except Exception:
                pass
            e.accept()


# ══════════════════════════════════════════════════════════════════════════════
# ── Entry point ────────────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

def main():
    # High-DPI support
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )
    app = QApplication(sys.argv)
    app.setApplicationName("Security Monitor")
    app.setApplicationDisplayName("Security Monitor")
    app.setStyleSheet(_build_qss())

    # Ask for auto-block preference via arg
    auto_block = "--auto-block" in sys.argv

    window = MainWindow(auto_block=auto_block)
    window.show()

    if not IS_ADMIN:
        QTimer.singleShot(800, lambda: QMessageBox.information(
            window, "Not running as administrator",
            "Security Monitor is running without admin rights.\n\n"
            "• Network sniffing may work with limited visibility.\n"
            "• IP blocking via Windows Firewall is disabled.\n\n"
            "For full functionality, right-click the app and choose\n"
            "\"Run as administrator\"."
        ))

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
