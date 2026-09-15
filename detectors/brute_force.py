"""
Brute Force / Credential Attack Detector.
Tracks TCP SYN packets to authentication-sensitive ports and alerts on:
- Brute force: many connections from one IP to a single auth service
- Password spray: one IP probing many auth services
- Credential stuffing: high-rate connections to web login ports

Note: private/RFC-1918 source IPs are skipped to avoid false positives from
the monitored machine's own outgoing connections (SSH, SMB, email clients).
"""
import ipaddress
import threading
import time
from collections import defaultdict
from datetime import datetime
from typing import Callable


def _is_private(ip: str) -> bool:
    """Return True for RFC-1918 / loopback / link-local addresses."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


# Ports that accept credentials — worth monitoring for brute force
_AUTH_PORTS: dict[int, str] = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    110:  "POP3",
    143:  "IMAP",
    445:  "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
}

_HTTP_PORTS: set[int] = {80, 443, 8080, 8443}

_WINDOW        = 60   # sliding window in seconds
_THRESH_AUTH   = 25   # SYN packets/window to same auth port  → brute force
_THRESH_HTTP   = 80   # SYN packets/window to HTTP port       → credential stuffing
_SPRAY_PORTS   = 6    # distinct auth ports hit in window     → password spray
_SPRAY_MIN_SYN = 3    # minimum SYNs per port to count toward spray


class BruteForceDetector:
    """
    Processes Scapy TCP packets to detect credential-based attacks.
    Tracks per-source-IP, per-port SYN rates within a sliding time window.
    """

    def __init__(self, on_alert: Callable[[dict], None] | None = None):
        self._alert_cb = on_alert or (lambda _: None)
        # {src_ip: {dst_port: [timestamps]}}
        self._conn:    dict[str, dict[int, list[float]]] = \
            defaultdict(lambda: defaultdict(list))
        self._alerted: set[str] = set()
        self._lock = threading.Lock()

    # ── Public ──────────────────────────────────────────────────────────────

    def process_packet(self, pkt) -> None:
        """Pass every Scapy packet here; only TCP SYN packets are inspected."""
        try:
            from scapy.layers.inet import TCP, IP
        except ImportError:
            return
        if not (pkt.haslayer(TCP) and pkt.haslayer(IP)):
            return
        tcp = pkt[TCP]
        # Only SYN (0x02) without ACK (0x10) — pure connection initiations
        if not (tcp.flags & 0x02 and not tcp.flags & 0x10):
            return

        src_ip   = pkt[IP].src
        dst_port = tcp.dport
        if dst_port not in _AUTH_PORTS and dst_port not in _HTTP_PORTS:
            return
        # Skip outgoing connections from the local machine itself (private IPs)
        # to avoid false positives from normal SSH/SMB/email client usage.
        if _is_private(src_ip):
            return

        ts  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        now = time.time()

        with self._lock:
            # Trim old entries
            bucket = self._conn[src_ip][dst_port]
            self._conn[src_ip][dst_port] = [t for t in bucket if now - t < _WINDOW]
            self._conn[src_ip][dst_port].append(now)
            count = len(self._conn[src_ip][dst_port])

            # ── Auth port brute force ────────────────────────────────────────
            if dst_port in _AUTH_PORTS and count == _THRESH_AUTH:
                service = _AUTH_PORTS[dst_port]
                key = f"bf:{src_ip}:{dst_port}"
                if key not in self._alerted:
                    self._alerted.add(key)
                    self._alert_cb({
                        "rule_name": f"{service} Brute Force",
                        "severity":  "high",
                        "source_ip": src_ip,
                        "message":   (
                            f"Brute force: {count} {service} (port {dst_port}) "
                            f"connection attempts from {src_ip} within {_WINDOW}s"
                        ),
                        "timestamp": ts,
                        "category":  "brute_force",
                    })

            # ── HTTP credential stuffing ─────────────────────────────────────
            if dst_port in _HTTP_PORTS and count == _THRESH_HTTP:
                key = f"cs:{src_ip}:{dst_port}"
                if key not in self._alerted:
                    self._alerted.add(key)
                    self._alert_cb({
                        "rule_name": "Credential Stuffing",
                        "severity":  "medium",
                        "source_ip": src_ip,
                        "message":   (
                            f"Credential stuffing: {count} HTTP(S) connections "
                            f"from {src_ip} to port {dst_port} within {_WINDOW}s"
                        ),
                        "timestamp": ts,
                        "category":  "brute_force",
                    })

            # ── Password spray: one IP hitting many auth ports ───────────────
            # Require _SPRAY_MIN_SYN connections per port to avoid false positives
            # from normal multi-service connectivity.
            active_auth = [
                p for p in _AUTH_PORTS
                if len(self._conn[src_ip].get(p, [])) >= _SPRAY_MIN_SYN
            ]
            if len(active_auth) == _SPRAY_PORTS:
                key = f"spray:{src_ip}"
                if key not in self._alerted:
                    self._alerted.add(key)
                    services = [_AUTH_PORTS[p] for p in active_auth]
                    self._alert_cb({
                        "rule_name": "Password Spray",
                        "severity":  "critical",
                        "source_ip": src_ip,
                        "message":   (
                            f"Password spray: {src_ip} is targeting "
                            f"{len(services)} auth services simultaneously — "
                            + ", ".join(services)
                        ),
                        "timestamp": ts,
                        "category":  "brute_force",
                    })
