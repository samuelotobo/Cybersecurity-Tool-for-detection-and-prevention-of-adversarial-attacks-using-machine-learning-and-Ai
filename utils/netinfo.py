"""Small helper so alerts can say whether traffic came from this machine or
from somewhere else on the network, without every detector needing to know
the host's own IPs."""
import socket
from functools import lru_cache


@lru_cache(maxsize=1)
def local_ips() -> frozenset[str]:
    ips = {"127.0.0.1"}
    try:
        ips.update(socket.gethostbyname_ex(socket.gethostname())[2])
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.connect(("8.8.8.8", 80))
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    return frozenset(ips)


def direction_of(source_ip: str, destination_ip: str = "") -> tuple[str, str]:
    """Returns (label, color_hex) describing which side of the wire an alert's
    source_ip is on, relative to this machine."""
    mine = local_ips()
    if source_ip in mine:
        return "OUTBOUND — from this PC", "#f97316"
    if destination_ip and destination_ip in mine:
        return "INBOUND — targeting this PC", "#ef4444"
    if not destination_ip and source_ip:
        return "INBOUND — from another device", "#ef4444"
    return "NETWORK — other device", "#8fa3c0"
