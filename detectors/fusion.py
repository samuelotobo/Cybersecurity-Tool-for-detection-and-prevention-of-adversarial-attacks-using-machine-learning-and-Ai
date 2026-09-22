"""
Verdict fusion and the ML corroboration gate.

The RF/Isolation-Forest models are trained on CICDDoS2019, whose benign class is
lab-generated. Measured on real home-network traffic they flag almost every
flow, so an ML/anomaly verdict on a single flow is not trustworthy on its own.
A DDoS, however, is a burst: many flagged flows toward or from the same host in
a short window. The gate below only lets ML/anomaly verdicts influence the
status once that burst condition holds. Rule and heuristic detections are never
gated.
"""
import time
from collections import defaultdict, deque
from threading import Lock
from typing import Optional

_PURGE_AT = 5000  # distinct hosts tracked before expired entries are purged


class MLCorroborator:
    """Counts ML/anomaly-flagged flows per source and per destination in a sliding window."""

    def __init__(self, min_flows: int = 60, window_s: float = 10.0) -> None:
        self._min = max(1, int(min_flows))
        self._window = float(window_s)
        self._src: dict[str, deque] = defaultdict(deque)
        self._dst: dict[str, deque] = defaultdict(deque)
        self._lock = Lock()

    def record(self, src: str, dst: str, now: Optional[float] = None) -> None:
        now = time.monotonic() if now is None else now
        with self._lock:
            for table, key in ((self._src, src), (self._dst, dst)):
                q = table[key]
                q.append(now)
                self._trim(q, now)
                if len(table) > _PURGE_AT:
                    self._purge(table, now)

    def is_active(self, src: str, dst: str, now: Optional[float] = None) -> bool:
        now = time.monotonic() if now is None else now
        with self._lock:
            return (self._count(self._src, src, now) >= self._min
                    or self._count(self._dst, dst, now) >= self._min)

    @property
    def min_flows(self) -> int:
        return self._min

    def _trim(self, q: deque, now: float) -> None:
        while q and now - q[0] > self._window:
            q.popleft()

    def _count(self, table: dict, key: str, now: float) -> int:
        q = table.get(key)
        if not q:
            return 0
        self._trim(q, now)
        return len(q)

    def _purge(self, table: dict, now: float) -> None:
        for k in [k for k, q in table.items() if not q or now - q[-1] > self._window]:
            del table[k]


_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def fuse_verdict(ml: dict, anomaly: dict, rules: list, heuristics: list,
                 corroborated: bool = True) -> str:
    """
    Combine detection layers into SAFE / SUSPICIOUS / ATTACK / a rule severity.

      1. Heuristic alerts (SYN flood, port scan, sustained attack)  -> ATTACK
      2. ML ATTACK confirmed by the anomaly layer                   -> ATTACK
      3. ML ATTACK or SUSPICIOUS alone, or anomaly alone            -> SUSPICIOUS
      4. Rule hit                                                   -> that rule's severity
      5. Otherwise                                                  -> SAFE

    Layers 2-3 apply only when `corroborated` is true (see MLCorroborator).
    """
    if heuristics:
        return "ATTACK"
    if corroborated:
        ml_verdict = ml.get("verdict", "NORMAL")
        is_anomaly = anomaly.get("anomaly", False)
        if ml_verdict == "ATTACK" and is_anomaly:
            return "ATTACK"
        if ml_verdict in ("ATTACK", "SUSPICIOUS") or is_anomaly:
            return "SUSPICIOUS"
    if rules:
        worst = max(rules, key=lambda a: _SEVERITY_RANK.get(a.severity, 0))
        return worst.severity.upper()
    return "SAFE"
