"""
Network Vulnerability Scanner.
Pure-Python socket-based port scanner with banner grabbing.
No nmap or external tools required.
"""
import ipaddress
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Callable


# Well-known ports and their service names
DEFAULT_PORTS: dict[int, str] = {
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    80:    "HTTP",
    110:   "POP3",
    135:   "MSRPC",
    139:   "NetBIOS-SSN",
    143:   "IMAP",
    443:   "HTTPS",
    445:   "SMB",
    1433:  "MSSQL",
    1723:  "PPTP",
    3306:  "MySQL",
    3389:  "RDP",
    5432:  "PostgreSQL",
    5900:  "VNC",
    6379:  "Redis",
    8080:  "HTTP-Alt",
    8443:  "HTTPS-Alt",
    27017: "MongoDB",
}

# Ports that are inherently risky if exposed on a workstation / internal host
HIGH_RISK_PORTS: set[int] = {23, 135, 139, 445, 1433, 3306, 3389, 5900, 6379, 27017}

_CONNECT_TIMEOUT = 0.6   # seconds per port probe
_BANNER_TIMEOUT  = 1.2
_MAX_WORKERS     = 120   # concurrent socket threads
_MAX_HOSTS       = 256   # cap for subnet scans to prevent runaway


class VulnScanner:
    """
    On-demand host / subnet vulnerability scanner.
    Call scan_async() to start a background scan; results arrive via on_done().
    Progress messages stream via on_progress().
    """

    def __init__(
        self,
        on_progress: Callable[[str], None] | None = None,
        on_done:     Callable[[dict], None] | None = None,
    ):
        self._progress_cb = on_progress or (lambda _: None)
        self._done_cb     = on_done     or (lambda _: None)
        self._cancel      = threading.Event()
        self._running     = False

    # ── Public ──────────────────────────────────────────────────────────────

    def scan_async(self, target: str, ports: list[int] | None = None) -> None:
        """
        Start a background scan of `target` (single IP, hostname, or CIDR).
        `ports` defaults to DEFAULT_PORTS keys if omitted.
        """
        if self._running:
            return
        self._cancel.clear()
        self._running = True
        threading.Thread(
            target=self._scan_thread,
            args=(target, ports or list(DEFAULT_PORTS.keys())),
            daemon=True,
            name="VulnScanner",
        ).start()

    def cancel(self) -> None:
        self._cancel.set()

    def is_running(self) -> bool:
        return self._running

    # ── Internal ────────────────────────────────────────────────────────────

    def _scan_thread(self, target: str, ports: list[int]) -> None:
        try:
            hosts = self._resolve_target(target)
            total = len(hosts)
            self._progress_cb(
                f"Starting scan of {total} host(s) across {len(ports)} port(s)…"
            )
            results: dict = {
                "target":     target,
                "scanned_at": datetime.now().isoformat(),
                "hosts":      {},
            }

            for i, host in enumerate(hosts, 1):
                if self._cancel.is_set():
                    self._progress_cb("Scan cancelled.")
                    break
                self._progress_cb(f"[{i}/{total}] Scanning {host}…")
                open_ports = self._scan_host(str(host), ports)
                if open_ports:
                    findings = []
                    for port, banner in sorted(open_ports.items()):
                        risk = "HIGH" if port in HIGH_RISK_PORTS else "MEDIUM"
                        findings.append({
                            "port":    port,
                            "service": DEFAULT_PORTS.get(port, "unknown"),
                            "banner":  banner,
                            "risk":    risk,
                        })
                    results["hosts"][str(host)] = findings

            self._progress_cb(
                f"Scan complete. {len(results['hosts'])} host(s) with open ports found."
            )
            self._done_cb(results)
        finally:
            self._running = False

    def _scan_host(self, host: str, ports: list[int]) -> dict[int, str]:
        open_ports: dict[int, str] = {}
        lock = threading.Lock()

        def probe(port: int) -> None:
            if self._cancel.is_set():
                return
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(_CONNECT_TIMEOUT)
                if s.connect_ex((host, port)) == 0:
                    banner = self._grab_banner(s, port)
                    with lock:
                        open_ports[port] = banner
                s.close()
            except Exception:
                pass

        with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as ex:
            futs = [ex.submit(probe, p) for p in ports]
            for _ in as_completed(futs):
                pass

        return open_ports

    @staticmethod
    def _grab_banner(sock: socket.socket, port: int) -> str:
        try:
            sock.settimeout(_BANNER_TIMEOUT)
            # Send HTTP HEAD for web ports, generic probe for others
            if port in (80, 443, 8080, 8443):
                sock.send(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
            else:
                sock.send(b"\r\n")
            data = sock.recv(256)
            return data.decode("utf-8", errors="replace").strip()[:120]
        except Exception:
            return ""

    @staticmethod
    def _resolve_target(target: str) -> list:
        # Try CIDR first
        try:
            net   = ipaddress.ip_network(target, strict=False)
            hosts = list(net.hosts()) or [net.network_address]
            return hosts[:_MAX_HOSTS]
        except ValueError:
            pass
        # Single IP
        try:
            return [ipaddress.ip_address(target)]
        except ValueError:
            pass
        # Hostname
        try:
            resolved = socket.gethostbyname(target)
            return [ipaddress.ip_address(resolved)]
        except Exception:
            return []
