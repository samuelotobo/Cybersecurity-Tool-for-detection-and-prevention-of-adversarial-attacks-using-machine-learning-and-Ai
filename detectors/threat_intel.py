"""
Threat Intelligence — AbuseIPDB reputation checks with in-memory caching.
Checks are performed asynchronously (background threads) to avoid blocking
the main detection pipeline.
"""
import threading
import time
from datetime import datetime
from typing import Callable

try:
    import requests as _requests
    _REQUESTS_OK = True
except ImportError:
    _REQUESTS_OK = False


_CACHE_TTL    = 3600    # seconds to keep a result before re-checking (1 hour)
_ABUSE_THRESH = 25      # abuseConfidenceScore % that triggers an alert
_API_URL      = "https://api.abuseipdb.com/api/v2/check"
_TIMEOUT      = 8       # HTTP request timeout


class ThreatIntel:
    """
    Provides asynchronous AbuseIPDB IP reputation lookups.

    Usage:
        ti = ThreatIntel(api_key="...", on_alert=my_callback)
        ti.check_ip_async("1.2.3.4")   # fires in background; calls on_alert if malicious
        result = ti.get_cached("1.2.3.4")  # returns cached dict or None
    """

    def __init__(
        self,
        api_key: str = "",
        on_alert: Callable[[dict], None] | None = None,
    ):
        self._api_key  = api_key.strip()
        self._alert_cb = on_alert or (lambda _: None)
        self._cache:   dict[str, dict] = {}   # ip → {"result": ..., "ts": float}
        self._pending: set[str]        = set()
        self._lock = threading.Lock()

    # ── Public ──────────────────────────────────────────────────────────────

    def check_ip_async(self, ip: str) -> None:
        """
        Queue a background reputation check for `ip`.
        No-op if already pending, recently cached, or no API key configured.
        """
        if not self._api_key or not _REQUESTS_OK:
            return
        if not ip or ip.startswith(("10.", "172.", "192.168.", "127.")):
            return   # skip RFC-1918 / loopback
        with self._lock:
            if ip in self._pending:
                return
            cached = self._cache.get(ip)
            if cached and time.time() - cached["ts"] < _CACHE_TTL:
                return
            self._pending.add(ip)
        threading.Thread(target=self._check, args=(ip,), daemon=True,
                         name=f"ThreatIntel-{ip}").start()

    def get_cached(self, ip: str) -> dict | None:
        """Return the cached AbuseIPDB result dict for `ip`, or None."""
        with self._lock:
            c = self._cache.get(ip)
            if c and time.time() - c["ts"] < _CACHE_TTL:
                return c["result"]
        return None

    def is_ready(self) -> bool:
        return bool(self._api_key) and _REQUESTS_OK

    # ── Internal ────────────────────────────────────────────────────────────

    def _check(self, ip: str) -> None:
        try:
            resp = _requests.get(
                _API_URL,
                headers={"Key": self._api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=_TIMEOUT,
            )
            if resp.status_code == 200:
                data  = resp.json().get("data", {})
                score = data.get("abuseConfidenceScore", 0)
                with self._lock:
                    self._cache[ip] = {"result": data, "ts": time.time()}
                    self._pending.discard(ip)
                if score >= _ABUSE_THRESH:
                    sev = "critical" if score >= 80 else "high"
                    self._alert_cb({
                        "rule_name":    "Threat Intelligence Hit",
                        "severity":     sev,
                        "source_ip":    ip,
                        "message":      (
                            f"AbuseIPDB: {ip} scored {score}% abuse confidence "
                            f"({data.get('totalReports', 0)} reports, "
                            f"ISP: {data.get('isp', 'unknown')}, "
                            f"Country: {data.get('countryCode', '?')})"
                        ),
                        "timestamp":    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "category":     "threat_intel",
                        "abuse_score":  score,
                        "country":      data.get("countryCode", ""),
                        "isp":          data.get("isp", ""),
                    })
            else:
                with self._lock:
                    self._pending.discard(ip)
        except Exception:
            with self._lock:
                self._pending.discard(ip)
