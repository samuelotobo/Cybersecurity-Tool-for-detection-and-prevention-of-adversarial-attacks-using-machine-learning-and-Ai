"""
DNS Anomaly Detection.
Detects DNS tunneling, fast-flux domains, high-rate C2 beaconing,
and queries to known-risky TLDs.
"""
import threading
import time
from collections import defaultdict
from datetime import datetime
from typing import Callable


# TLDs frequently abused by malware and phishing infrastructure.
# Removed .xyz (used by Alphabet/Google) to reduce legitimate-site false positives.
_RISKY_TLDS = {
    ".top", ".work", ".click", ".loan", ".download",
    ".win", ".gq", ".cf", ".tk", ".ml", ".ga", ".pw",
}

# Well-known CDN/cloud domains that legitimately resolve to many IPs via anycast.
# Queries to these are excluded from fast-flux detection.
_CDN_DOMAINS = {
    "google.com", "googleapis.com", "gstatic.com", "googlevideo.com",
    "cloudflare.com", "cloudfront.net", "fastly.net",
    "akamai.net", "akamaiedge.net", "akadns.net", "akamaized.net",
    "amazonaws.com", "azure.com", "microsoft.com", "windows.com",
    "windowsupdate.com", "office.com", "office365.com",
    "github.com", "github.io", "githubusercontent.com",
    "youtube.com", "ytimg.com", "netflix.com", "nflxvideo.net",
    "apple.com", "icloud.com", "apple-dns.net",
    "twitter.com", "twimg.com", "x.com",
    "facebook.com", "fbcdn.net", "instagram.com",
}

_MAX_LABEL_LEN = 60   # subdomain label longer than this → likely DNS tunneling
_RATE_WINDOW   = 60   # seconds
_RATE_THRESH   = 150  # queries/min to same domain (2.5/s) → DGA / C2 beacon
_FLUX_THRESH   = 20   # distinct IPs for one hostname within window → fast-flux


class DNSMonitor:
    """
    Inspects DNS packets (UDP/TCP port 53) for:
    - Long subdomain labels (DNS tunneling / data exfiltration)
    - High query rate to a single domain (DGA beaconing / C2)
    - Fast-flux: many distinct IPs for the same hostname
    - Queries to high-risk TLDs
    """

    def __init__(self, on_alert: Callable[[dict], None] | None = None):
        self._alert_cb     = on_alert or (lambda _: None)
        self._query_times: dict[str, list[float]] = defaultdict(list)  # domain → [ts]
        self._domain_ips:  dict[str, set[str]]   = defaultdict(set)   # domain → {ip}
        self._alerted:     set[str]              = set()              # spam prevention
        self._lock         = threading.Lock()

    # ── Public ──────────────────────────────────────────────────────────────

    def process_packet(self, pkt) -> None:
        """Pass every Scapy packet here; non-DNS packets are ignored."""
        try:
            from scapy.layers.dns import DNS, DNSQR
        except ImportError:
            return
        if not pkt.haslayer(DNS):
            return
        dns = pkt[DNS]
        ts  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # ── DNS query (qr == 0) ────────────────────────────────────────────
        if dns.qr == 0 and pkt.haslayer(DNSQR):
            try:
                qname = pkt[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
            except Exception:
                return
            if qname:
                self._check_query(qname, ts)

        # ── DNS response (qr == 1) — fast-flux check ──────────────────────
        if dns.qr == 1 and dns.ancount > 0:
            try:
                qname = dns.qd.qname.decode("utf-8", errors="replace").rstrip(".")
            except Exception:
                return
            # Skip fast-flux check for well-known CDN/cloud domains
            parts_q = qname.split(".")
            registrable = ".".join(parts_q[-2:]) if len(parts_q) >= 2 else qname
            if registrable in _CDN_DOMAINS or qname in _CDN_DOMAINS:
                return
            rr = dns.an
            while rr:
                try:
                    ip = str(rr.rdata)
                    if "." in ip and not ip.startswith("::"):
                        with self._lock:
                            self._domain_ips[qname].add(ip)
                            if len(self._domain_ips[qname]) == _FLUX_THRESH:
                                key = f"flux:{qname}"
                                if key not in self._alerted:
                                    self._alerted.add(key)
                                    self._alert_cb({
                                        "rule_name": "Fast-Flux DNS",
                                        "severity":  "high",
                                        "source_ip": qname,
                                        "message":   (
                                            f"Fast-flux detected: {qname} resolved to "
                                            f"{_FLUX_THRESH}+ distinct IPs — "
                                            "likely bulletproof hosting or botnet C2"
                                        ),
                                        "timestamp": ts,
                                        "category":  "dns",
                                    })
                    rr = rr.payload if hasattr(rr, "payload") and hasattr(rr.payload, "rrname") else None
                except Exception:
                    break

    # ── Internal ────────────────────────────────────────────────────────────

    def _check_query(self, qname: str, ts: str) -> None:
        parts  = qname.split(".")
        domain = ".".join(parts[-2:]) if len(parts) >= 2 else qname
        tld    = ("." + parts[-1]) if parts else ""
        now    = time.time()

        with self._lock:
            # ── DNS tunneling: abnormally long subdomain label ───────────────
            for label in parts[:-2]:
                if len(label) > _MAX_LABEL_LEN:
                    key = f"tunnel:{qname}"
                    if key not in self._alerted:
                        self._alerted.add(key)
                        self._alert_cb({
                            "rule_name": "DNS Tunneling",
                            "severity":  "critical",
                            "source_ip": qname,
                            "message":   (
                                f"DNS tunneling suspected: subdomain label "
                                f"'{label[:35]}...' ({len(label)} chars) in {domain} — "
                                "data may be exfiltrated via DNS"
                            ),
                            "timestamp": ts,
                            "category":  "dns",
                        })

            # ── Suspicious TLD ───────────────────────────────────────────────
            if tld in _RISKY_TLDS:
                key = f"tld:{domain}"
                if key not in self._alerted:
                    self._alerted.add(key)
                    self._alert_cb({
                        "rule_name": "Suspicious TLD",
                        "severity":  "medium",
                        "source_ip": qname,
                        "message":   (
                            f"Query to high-risk TLD '{tld}': {qname} — "
                            "these domains are frequently used in phishing and malware"
                        ),
                        "timestamp": ts,
                        "category":  "dns",
                    })

            # ── High query rate (DGA / C2 beacon) ───────────────────────────
            bucket = self._query_times[domain]
            self._query_times[domain] = [t for t in bucket if now - t < _RATE_WINDOW]
            self._query_times[domain].append(now)
            count = len(self._query_times[domain])
            if count == _RATE_THRESH:
                key = f"rate:{domain}"
                if key not in self._alerted:
                    self._alerted.add(key)
                    self._alert_cb({
                        "rule_name": "DNS C2 Beacon",
                        "severity":  "high",
                        "source_ip": domain,
                        "message":   (
                            f"High DNS query rate: {count} queries in "
                            f"{_RATE_WINDOW}s to {domain} — "
                            "possible DGA malware or C2 beaconing"
                        ),
                        "timestamp": ts,
                        "category":  "dns",
                    })
