"""
QR Code alert sharing utility.

Encodes a security alert as a compact JSON payload inside a QR code
so administrators can hand off incidents to mobile devices by scanning.

Requires:  pip install qrcode[pil]

Usage (standalone):
    from utils.qr_share import alert_to_qr_bytes, AlertQRDialog
    png_bytes = alert_to_qr_bytes(alert_dict)

Usage (PyQt6 dialog):
    dlg = AlertQRDialog(alert_dict, parent=main_window)
    dlg.exec()
"""

import io
import json
from datetime import datetime
from typing import TYPE_CHECKING

try:
    import qrcode
    from qrcode.image.pil import PilImage
    _QR_OK = True
except ImportError:
    _QR_OK = False

try:
    from PyQt6.QtCore import Qt
    from PyQt6.QtGui import QPixmap
    from PyQt6.QtWidgets import (
        QDialog, QHBoxLayout, QLabel, QPushButton, QTextEdit, QVBoxLayout,
    )
    _QT_OK = True
except ImportError:
    _QT_OK = False


def alert_to_qr_bytes(alert: dict, max_chars: int = 500) -> bytes | None:
    """
    Convert an alert dict to a PNG QR code (bytes).
    Returns None if qrcode / Pillow is not installed.
    """
    if not _QR_OK:
        return None

    payload = _compact_payload(alert, max_chars)
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=6,
        border=3,
    )
    qr.add_data(payload)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _compact_payload(alert: dict, max_chars: int) -> str:
    """Build a compact, scannable JSON string from an alert."""
    compact = {
        "app":   "SecurityMonitor",
        "ts":    alert.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        "rule":  alert.get("rule_name", ""),
        "sev":   alert.get("severity", ""),
        "ip":    alert.get("source_ip", ""),
        "msg":   alert.get("message", "")[:200],
        "cat":   alert.get("category", ""),
    }
    text = json.dumps(compact, separators=(",", ":"))
    if len(text) > max_chars:
        compact["msg"] = compact["msg"][:max_chars - len(text)]
        text = json.dumps(compact, separators=(",", ":"))
    return text


if _QT_OK:

    class AlertQRDialog(QDialog):
        """
        PyQt6 dialog that displays:
          - Left panel: QR code PNG of the alert (scannable by phone)
          - Right panel: Full alert details in a text box
          - Copy JSON / Save PNG buttons
        """

        def __init__(self, alert: dict, parent=None):
            super().__init__(parent)
            self._alert = alert
            self.setWindowTitle("Share Alert via QR Code")
            self.setFixedSize(580, 420)
            self.setStyleSheet("""
                QDialog  { background: #0f1326; color: #dde6f0; }
                QLabel   { background: transparent; color: #dde6f0; }
                QTextEdit{ background: #111525; color: #ccddf0; border: 1px solid #1c2440;
                           border-radius: 6px; font-family: 'Consolas'; font-size: 12px; }
                QPushButton {
                    background: #3b82f6; color: white; border: none;
                    padding: 7px 18px; border-radius: 7px; font-weight: 600;
                }
                QPushButton:hover  { background: #2563eb; }
                QPushButton#close  { background: #374151; }
                QPushButton#close:hover { background: #4b5563; }
            """)
            self._build()

        def _build(self) -> None:
            root = QHBoxLayout(self)
            root.setSpacing(16)
            root.setContentsMargins(16, 16, 16, 16)

            # ── Left: QR code ──────────────────────────────────────────────
            left = QVBoxLayout()
            lbl_title = QLabel("Scan with mobile device")
            lbl_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
            left.addWidget(lbl_title)

            self._qr_label = QLabel()
            self._qr_label.setFixedSize(220, 220)
            self._qr_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self._qr_label.setStyleSheet("border: 2px solid #1c2440; border-radius: 8px; background: white;")
            left.addWidget(self._qr_label)

            self._status = QLabel("")
            self._status.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self._status.setStyleSheet("color: #9aa3b5; font-size: 11px;")
            left.addWidget(self._status)

            save_btn = QPushButton("Save QR PNG")
            save_btn.clicked.connect(self._save_png)
            left.addWidget(save_btn)
            root.addLayout(left)

            # ── Right: alert detail ─────────────────────────────────────────
            right = QVBoxLayout()
            rull_lbl = QLabel(f"  {self._alert.get('rule_name','')}")
            rull_lbl.setStyleSheet(
                f"font-size:14px;font-weight:700;color:{_sev_color(self._alert.get('severity',''))};"
            )
            right.addWidget(rull_lbl)

            self._text = QTextEdit()
            self._text.setReadOnly(True)
            self._text.setText(json.dumps(self._alert, indent=2))
            right.addWidget(self._text)

            btn_row = QHBoxLayout()
            copy_btn = QPushButton("Copy JSON")
            copy_btn.clicked.connect(self._copy_json)
            btn_row.addWidget(copy_btn)

            close_btn = QPushButton("Close")
            close_btn.setObjectName("close")
            close_btn.clicked.connect(self.reject)
            btn_row.addWidget(close_btn)
            right.addLayout(btn_row)
            root.addLayout(right)

            self._render_qr()

        def _render_qr(self) -> None:
            png = alert_to_qr_bytes(self._alert)
            if png is None:
                self._status.setText("Install qrcode[pil] to enable QR sharing")
                return
            px = QPixmap()
            px.loadFromData(png)
            self._qr_label.setPixmap(
                px.scaled(220, 220, Qt.AspectRatioMode.KeepAspectRatio,
                          Qt.TransformationMode.SmoothTransformation)
            )
            compact = _compact_payload(self._alert, 500)
            self._status.setText(f"{len(compact)} chars in QR payload")

        def _copy_json(self) -> None:
            from PyQt6.QtWidgets import QApplication
            QApplication.clipboard().setText(json.dumps(self._alert, indent=2))

        def _save_png(self) -> None:
            from PyQt6.QtWidgets import QFileDialog
            png = alert_to_qr_bytes(self._alert)
            if not png:
                return
            path, _ = QFileDialog.getSaveFileName(
                self, "Save QR Code", "alert_qr.png", "PNG Images (*.png)"
            )
            if path:
                with open(path, "wb") as f:
                    f.write(png)


def _sev_color(severity: str) -> str:
    return {
        "critical": "#ef4444",
        "high":     "#f97316",
        "medium":   "#eab308",
        "low":      "#3b82f6",
    }.get(severity, "#9aa3b5")
