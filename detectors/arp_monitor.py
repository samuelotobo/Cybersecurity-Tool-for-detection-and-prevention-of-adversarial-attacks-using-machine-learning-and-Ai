"""
ARP Spoofing / Man-in-the-Middle Detection.
Monitors ARP broadcasts for IP-to-MAC mapping conflicts and flood activity.
"""
import threading
import time
from datetime import datetime
from typing import Callable


class ARPMonitor:
    """
    Tracks IP → MAC mappings from live ARP traffic and alerts on:
    - ARP cache poisoning: a known IP claims a different MAC
    - Gateway hijack: the same but for the default gateway (critical)
    - Gratuitous ARP flood: >20 ARP packets in 10 s from one MAC
    """

    _FLOOD_WINDOW    = 10   # seconds
    _FLOOD_THRESH    = 50   # ARP packets within window before flood alert
    _SPOOF_COOLDOWN  = 300  # seconds before re-alerting on same IP's MAC change

    def __init__(
        self,
        on_alert: Callable[[dict], None] | None = None,
        gateway_ip: str = "",
    ):
        self._alert_cb   = on_alert or (lambda _: None)
        self._gateway_ip = gateway_ip
        self._cache: dict[str, str]         = {}   # ip  → mac
        self._rate:  dict[str, list[float]] = {}   # mac → [timestamps]
        self._spoof_ts: dict[str, float]    = {}   # ip  → last spoof alert time
        self._lock   = threading.Lock()

    # ── Public ──────────────────────────────────────────────────────────────

    def process_packet(self, pkt) -> None:
        """Pass every Scapy packet here; non-ARP packets are ignored."""
        try:
            from scapy.layers.l2 import ARP
        except ImportError:
            return
        if not pkt.haslayer(ARP):
            return
        arp = pkt.getlayer(ARP)
        if arp.op not in (1, 2):           # 1 = who-has, 2 = is-at
            return
        src_ip  = arp.psrc  or ""
        src_mac = (arp.hwsrc or "").lower()
        if not src_ip or src_ip == "0.0.0.0" or not src_mac:
            return

        now = time.time()
        ts  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with self._lock:
            # ── flood detection ─────────────────────────────────────────────
            bucket = self._rate.setdefault(src_mac, [])
            self._rate[src_mac] = [t for t in bucket if now - t < self._FLOOD_WINDOW]
            self._rate[src_mac].append(now)
            if len(self._rate[src_mac]) == self._FLOOD_THRESH:
                self._alert_cb({
                    "rule_name": "ARP Flood",
                    "severity":  "high",
                    "source_ip": src_ip,
                    "message":   (
                        f"ARP flood: {self._FLOOD_THRESH} ARP packets in "
                        f"{self._FLOOD_WINDOW}s from MAC {src_mac}"
                    ),
                    "timestamp": ts,
                    "category":  "arp",
                })

            # ── spoofing detection ───────────────────────────────────────────
            known = self._cache.get(src_ip)
            if known is None:
                self._cache[src_ip] = src_mac
            elif known != src_mac:
                # Suppress re-alerts for the same IP within cooldown window
                last_alert = self._spoof_ts.get(src_ip, 0.0)
                if now - last_alert >= self._SPOOF_COOLDOWN:
                    self._spoof_ts[src_ip] = now
                    is_gw = src_ip == self._gateway_ip
                    self._alert_cb({
                        "rule_name": "ARP Spoofing" + (" — Gateway!" if is_gw else ""),
                        "severity":  "critical" if is_gw else "high",
                        "source_ip": src_ip,
                        "message":   (
                            f"ARP cache poisoning: {src_ip} changed MAC "
                            f"from {known} to {src_mac}"
                            + (" [GATEWAY HIJACK]" if is_gw else "")
                        ),
                        "timestamp": ts,
                        "category":  "arp",
                    })
                self._cache[src_ip] = src_mac   # update to latest claimed MAC

    def get_arp_table(self) -> dict[str, str]:
        """Return a snapshot of the current IP → MAC cache."""
        with self._lock:
            return dict(self._cache)
