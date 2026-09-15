"""
Flow tracker — aggregates individual packets into network flows, then computes
the flow-level features the DDoS model was trained on.

A flow is identified by its 5-tuple: (src_ip, dst_ip, src_port, dst_port, proto).
Once a flow has accumulated enough packets OR exceeded its timeout, it is
finalised and returned for ML prediction.
"""
import time
from collections import defaultdict
from dataclasses import dataclass, field
from threading import Lock
from typing import Optional


# Match the features used in train_model.py
FLOW_FEATURES = [
    "Protocol", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Fwd Packets Length Total", "Bwd Packets Length Total", "Fwd Packet Length Max",
    "Flow Bytes/s", "Flow Packets/s", "Fwd IAT Min", "Bwd IAT Min",
    "Fwd PSH Flags", "Fwd URG Flags", "FIN Flag Count", "SYN Flag Count",
    "RST Flag Count", "ACK Flag Count", "URG Flag Count", "Init Fwd Win Bytes",
]

# Emit a prediction after this many packets or this many seconds — whichever comes first
MIN_PACKETS_TO_PREDICT = 5
FLOW_TIMEOUT_S = 10.0
FLOW_CLEANUP_INTERVAL_S = 30.0


@dataclass
class _Flow:
    # Identification
    src_ip: str
    dst_ip: str
    proto_num: int  # 6=TCP, 17=UDP

    # Timing
    start_time: float = field(default_factory=time.monotonic)
    last_seen: float = field(default_factory=time.monotonic)

    # Packet counts
    fwd_pkts: int = 0
    bwd_pkts: int = 0

    # Byte sums
    fwd_bytes: int = 0
    bwd_bytes: int = 0

    # Packet-length extremes (forward direction)
    fwd_pkt_max: int = 0

    # TCP flag accumulators
    fin: int = 0
    syn: int = 0
    rst: int = 0
    psh: int = 0
    ack: int = 0
    urg: int = 0

    # Initial window size from first SYN
    init_fwd_win: int = 0

    # Inter-arrival time tracking
    _fwd_times: list = field(default_factory=list)
    _bwd_times: list = field(default_factory=list)

    # Prevent re-emitting the same flow repeatedly
    emitted: bool = False

    def add_packet(self, is_forward: bool, pkt_len: int, flags: int, win: int, now: float) -> None:
        self.last_seen = now
        if is_forward:
            self._fwd_times.append(now)
            self.fwd_pkts += 1
            self.fwd_bytes += pkt_len
            self.fwd_pkt_max = max(self.fwd_pkt_max, pkt_len)
            if self.fwd_pkts == 1 and win:
                self.init_fwd_win = win
        else:
            self._bwd_times.append(now)
            self.bwd_pkts += 1
            self.bwd_bytes += pkt_len

        # Flag accumulation (TCP only; flags=0 for UDP)
        if flags & 0x01: self.fin += 1
        if flags & 0x02: self.syn += 1
        if flags & 0x04: self.rst += 1
        if flags & 0x08: self.psh += 1
        if flags & 0x10: self.ack += 1
        if flags & 0x20: self.urg += 1

    def _min_iat(self, times: list) -> float:
        if len(times) < 2:
            return 0.0
        diffs = [times[i] - times[i - 1] for i in range(1, len(times))]
        return min(diffs) * 1e6  # convert to microseconds like CICFlowMeter

    def to_feature_dict(self) -> dict:
        duration = max(self.last_seen - self.start_time, 1e-6)
        total_bytes = self.fwd_bytes + self.bwd_bytes
        total_pkts = self.fwd_pkts + self.bwd_pkts
        return {
            "Protocol":               self.proto_num,
            "Flow Duration":          duration * 1e6,  # microseconds
            "Total Fwd Packets":      self.fwd_pkts,
            "Total Backward Packets": self.bwd_pkts,
            "Fwd Packets Length Total": self.fwd_bytes,
            "Bwd Packets Length Total": self.bwd_bytes,
            "Fwd Packet Length Max":  self.fwd_pkt_max,
            "Flow Bytes/s":           total_bytes / duration,
            "Flow Packets/s":         total_pkts / duration,
            "Fwd IAT Min":            self._min_iat(self._fwd_times),
            "Bwd IAT Min":            self._min_iat(self._bwd_times),
            "Fwd PSH Flags":          self.psh,
            "Fwd URG Flags":          self.urg,
            "FIN Flag Count":         self.fin,
            "SYN Flag Count":         self.syn,
            "RST Flag Count":         self.rst,
            "ACK Flag Count":         self.ack,
            "URG Flag Count":         self.urg,
            "Init Fwd Win Bytes":     self.init_fwd_win,
        }

    @property
    def total_packets(self) -> int:
        return self.fwd_pkts + self.bwd_pkts


class FlowTracker:
    """
    Thread-safe flow table.
    Call update() for each packet; it returns a completed flow's feature dict
    (ready for the ML model) when a flow is mature enough, or None otherwise.
    """

    def __init__(
        self,
        min_packets: int = MIN_PACKETS_TO_PREDICT,
        timeout_s: float = FLOW_TIMEOUT_S,
    ) -> None:
        self._flows: dict[tuple, _Flow] = {}
        self._lock = Lock()
        self._min_packets = min_packets
        self._timeout = timeout_s
        self._last_cleanup = time.monotonic()

    def update(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        proto_num: int,
        pkt_len: int,
        tcp_flags: int = 0,
        win: int = 0,
    ) -> Optional[tuple[dict, str]]:
        """
        Process one packet. Returns (feature_dict, flow_key_str) when the flow
        is ready for prediction, else None.
        """
        now = time.monotonic()

        # Canonical key: sort endpoints so A→B and B→A share the same flow
        ep_a = (src_ip, src_port)
        ep_b = (dst_ip, dst_port)
        key = (min(ep_a, ep_b), max(ep_a, ep_b), proto_num)
        is_forward = (src_ip, src_port) == key[0]

        with self._lock:
            if key not in self._flows:
                self._flows[key] = _Flow(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    proto_num=proto_num,
                )

            flow = self._flows[key]
            flow.add_packet(is_forward, pkt_len, tcp_flags, win, now)

            result = None
            elapsed = now - flow.start_time
            ready = (
                not flow.emitted and (
                    flow.total_packets >= self._min_packets
                    or elapsed >= self._timeout
                )
            )
            if ready:
                flow.emitted = True
                result = (flow.to_feature_dict(), f"{src_ip}:{src_port}→{dst_ip}:{dst_port}")

            # Periodic cleanup of stale flows
            if now - self._last_cleanup > FLOW_CLEANUP_INTERVAL_S:
                self._cleanup(now)
                self._last_cleanup = now

        return result

    def _cleanup(self, now: float) -> None:
        stale = [k for k, f in self._flows.items() if now - f.last_seen > self._timeout * 3]
        for k in stale:
            del self._flows[k]

    @property
    def active_flows(self) -> int:
        with self._lock:
            return len(self._flows)
