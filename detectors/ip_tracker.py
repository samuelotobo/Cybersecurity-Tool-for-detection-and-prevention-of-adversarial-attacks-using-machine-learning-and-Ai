"""
Per-source-IP sliding-window heuristics for attack detection.

Three independent indicators are tracked per source IP over a rolling time window:
  1. SYN:ACK ratio      — detects SYN floods (floods of unanswered SYNs)
  2. Connection rate     — detects volumetric floods (too many new connections/s)
  3. Destination port spread — detects port scans (many different ports touched)
  4. Sustained ML verdicts  — requires N consecutive ATTACK predictions before alerting

None of these indicators alone is conclusive; they are combined with ML and rules
in main_app.py to produce the final verdict.
"""
import time
from collections import defaultdict, deque
from threading import Lock
from typing import Optional


# ── Sliding window ────────────────────────────────────────────────────────────

class _Window:
    """Append-only deque that automatically drops events older than `duration_s`."""

    __slots__ = ("_d", "_dur")

    def __init__(self, duration_s: float) -> None:
        self._d: deque = deque()
        self._dur = duration_s

    def add(self, value=1, now: Optional[float] = None) -> None:
        t = now if now is not None else time.monotonic()
        self._d.append((t, value))
        self._expire(t)

    def count(self, now: Optional[float] = None) -> int:
        self._expire(now if now is not None else time.monotonic())
        return len(self._d)

    def sum(self, now: Optional[float] = None) -> float:
        self._expire(now if now is not None else time.monotonic())
        return sum(v for _, v in self._d)

    def unique(self, now: Optional[float] = None) -> int:
        self._expire(now if now is not None else time.monotonic())
        return len({v for _, v in self._d})

    def _expire(self, now: float) -> None:
        cutoff = now - self._dur
        while self._d and self._d[0][0] < cutoff:
            self._d.popleft()


# ── IP Tracker ────────────────────────────────────────────────────────────────

class IPTracker:
    """
    Thread-safe per-IP statistics tracker.

    Call `update()` once per packet.  Returns a (possibly empty) list of alert
    dicts whenever a heuristic threshold is crossed.  Each dict has:
        rule_name, severity, message, source_ip
    """

    def __init__(
        self,
        window_s: float = 10.0,
        syn_ack_ratio_threshold: float = 5.0,   # >5 SYNs per ACK → flood
        syn_count_minimum: int = 20,             # don't alert until we've seen this many SYNs
        conn_rate_threshold: int = 150,          # new connections per window
        port_spread_threshold: int = 30,         # unique dst ports per window
        sustained_n: int = 3,                    # consecutive ML ATTACKs to confirm
    ) -> None:
        self._window          = window_s
        self._syn_ratio       = syn_ack_ratio_threshold
        self._syn_min         = syn_count_minimum
        self._conn_rate       = conn_rate_threshold
        self._port_spread     = port_spread_threshold
        self._sustained_n     = sustained_n

        # Per-IP sliding windows
        self._syns:      dict[str, _Window] = defaultdict(lambda: _Window(window_s))
        self._acks:      dict[str, _Window] = defaultdict(lambda: _Window(window_s))
        self._new_conns: dict[str, _Window] = defaultdict(lambda: _Window(window_s))
        self._ports:     dict[str, _Window] = defaultdict(lambda: _Window(window_s))

        # Per-IP deque of (timestamp, is_attack) for sustained-attack detection
        self._verdicts: dict[str, deque] = defaultdict(lambda: deque(maxlen=50))

        self._lock = Lock()
        self._last_cleanup = time.monotonic()

    # ── Public API ────────────────────────────────────────────────────────────

    def update(
        self,
        src_ip: str,
        dst_port: int = 0,
        is_syn: bool = False,
        is_ack: bool = False,
        is_new_connection: bool = False,
        ml_verdict: Optional[str] = None,
    ) -> list[dict]:
        """
        Record one packet from src_ip.
        - is_new_connection: True when this packet starts a new connection
          (i.e. SYN without ACK for TCP; any first packet for UDP).
        - ml_verdict: "ATTACK" or "NORMAL" from the flow-level ML model,
          or None if no flow prediction was made for this packet.

        Returns a list of heuristic alert dicts (may be empty).
        """
        now = time.monotonic()
        alerts: list[dict] = []

        with self._lock:
            if is_syn:
                self._syns[src_ip].add(now=now)
            if is_ack:
                self._acks[src_ip].add(now=now)
            if is_new_connection:
                self._new_conns[src_ip].add(now=now)
            if dst_port:
                self._ports[src_ip].add(value=dst_port, now=now)
            if ml_verdict is not None:
                self._verdicts[src_ip].append((now, ml_verdict == "ATTACK"))

            alerts.extend(self._check_syn_flood(src_ip, now))
            alerts.extend(self._check_conn_rate(src_ip, now))
            alerts.extend(self._check_port_scan(src_ip, now))
            if ml_verdict is not None:
                alerts.extend(self._check_sustained(src_ip, now))

            self._maybe_cleanup(now)

        return alerts

    # ── Heuristic checks ─────────────────────────────────────────────────────

    def _check_syn_flood(self, ip: str, now: float) -> list[dict]:
        syn_count = self._syns[ip].count(now)
        ack_count = max(self._acks[ip].count(now), 1)
        ratio = syn_count / ack_count
        if syn_count >= self._syn_min and ratio >= self._syn_ratio:
            return [{
                "rule_name": "SYN Flood",
                "severity":  "critical",
                "message":   f"SYN:ACK ratio {ratio:.1f}:1 ({syn_count} SYNs in {self._window}s)",
                "source_ip": ip,
            }]
        return []

    def _check_conn_rate(self, ip: str, now: float) -> list[dict]:
        count = self._new_conns[ip].count(now)
        if count >= self._conn_rate:
            return [{
                "rule_name": "Connection Flood",
                "severity":  "high",
                "message":   f"{count} new connections in {self._window}s",
                "source_ip": ip,
            }]
        return []

    def _check_port_scan(self, ip: str, now: float) -> list[dict]:
        unique = self._ports[ip].unique(now)
        if unique >= self._port_spread:
            return [{
                "rule_name": "Port Scan",
                "severity":  "high",
                "message":   f"{unique} unique destination ports in {self._window}s",
                "source_ip": ip,
            }]
        return []

    def _check_sustained(self, ip: str, now: float) -> list[dict]:
        """Alert when the last N ML predictions for this IP are all ATTACK."""
        recent = self._verdicts[ip]
        if len(recent) < self._sustained_n:
            return []
        cutoff = now - self._window
        # Only consider verdicts within the window
        in_window = [is_atk for ts, is_atk in recent if ts >= cutoff]
        if len(in_window) >= self._sustained_n and all(in_window[-self._sustained_n:]):
            return [{
                "rule_name": "Sustained Attack",
                "severity":  "critical",
                "message":   f"{self._sustained_n} consecutive ATTACK verdicts in {self._window}s",
                "source_ip": ip,
            }]
        return []

    # ── Cleanup ───────────────────────────────────────────────────────────────

    def _maybe_cleanup(self, now: float) -> None:
        if now - self._last_cleanup < 60.0:
            return
        self._last_cleanup = now
        for store in (self._syns, self._acks, self._new_conns, self._ports):
            dead = [ip for ip, w in store.items() if w.count(now) == 0]
            for ip in dead:
                del store[ip]
        # Trim verdict deques for IPs with no recent verdicts
        stale = [
            ip for ip, dq in self._verdicts.items()
            if not dq or now - dq[-1][0] > self._window * 6
        ]
        for ip in stale:
            del self._verdicts[ip]
