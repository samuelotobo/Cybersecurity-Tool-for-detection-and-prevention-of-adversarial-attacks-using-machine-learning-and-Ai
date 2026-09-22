"""Corroboration gate, verdict fusion and rule-engine false-positive guards."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config as cfg
from detectors.ddos import DDosDetector
from detectors.fusion import MLCorroborator, fuse_verdict


class _Rule:
    def __init__(self, severity):
        self.severity = severity


ML_ATTACK = {"verdict": "ATTACK", "confidence": 99.0}
ANOMALY = {"anomaly": True}


class CorroborationGateTests(unittest.TestCase):

    def test_below_burst_is_not_active(self):
        g = MLCorroborator(min_flows=60, window_s=10)
        for i in range(29):                      # measured benign peak per destination
            g.record(f"1.1.1.{i}", "192.168.0.10", now=100 + i * 0.1)
        self.assertFalse(g.is_active("1.1.1.1", "192.168.0.10", now=103))

    def test_burst_to_one_destination_activates(self):
        g = MLCorroborator(min_flows=60, window_s=10)
        for i in range(60):                      # distributed flood: many sources, one victim
            g.record(f"9.9.{i // 250}.{i % 250}", "192.168.0.10", now=100 + i * 0.05)
        self.assertTrue(g.is_active("8.8.8.8", "192.168.0.10", now=104))

    def test_burst_from_one_source_activates(self):
        g = MLCorroborator(min_flows=60, window_s=10)
        for i in range(60):
            g.record("6.6.6.6", f"10.0.{i // 250}.{i % 250}", now=100 + i * 0.05)
        self.assertTrue(g.is_active("6.6.6.6", "10.0.0.1", now=104))

    def test_window_expires(self):
        g = MLCorroborator(min_flows=5, window_s=10)
        for i in range(5):
            g.record("6.6.6.6", "10.0.0.1", now=100 + i)
        self.assertTrue(g.is_active("6.6.6.6", "10.0.0.1", now=105))
        self.assertFalse(g.is_active("6.6.6.6", "10.0.0.1", now=200))


class FuseVerdictTests(unittest.TestCase):

    def test_ml_and_anomaly_ignored_without_corroboration(self):
        self.assertEqual(fuse_verdict(ML_ATTACK, ANOMALY, [], [], corroborated=False), "SAFE")

    def test_ml_and_anomaly_attack_when_corroborated(self):
        self.assertEqual(fuse_verdict(ML_ATTACK, ANOMALY, [], [], corroborated=True), "ATTACK")

    def test_ml_alone_is_suspicious_when_corroborated(self):
        self.assertEqual(fuse_verdict(ML_ATTACK, {}, [], [], corroborated=True), "SUSPICIOUS")

    def test_heuristics_are_never_gated(self):
        self.assertEqual(fuse_verdict({}, {}, [], [{"rule_name": "SYN Flood"}], corroborated=False), "ATTACK")

    def test_rules_are_never_gated(self):
        self.assertEqual(fuse_verdict(ML_ATTACK, ANOMALY, [_Rule("high")], [], corroborated=False), "HIGH")


class RuleEngineFalsePositiveTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.det = DDosDetector(cfg.MODEL_FILENAME, cfg.RULES_CONFIG)

    def _names(self, **kw):
        info = {"src_ip": "192.168.31.1", "dst_ip": "239.255.255.250", "protocol": "UDP",
                "Length": 200, "TTL": 1}
        info.update(kw)
        return [a.rule_name for a in self.det.check_rules(info)]

    def test_multicast_ttl1_is_not_suspicious(self):
        self.assertNotIn("Suspicious TTL", self._names())

    def test_unicast_low_ttl_still_flagged(self):
        self.assertIn("Suspicious TTL", self._names(dst_ip="192.168.31.70"))

    def test_offload_sized_frame_is_not_oversized(self):
        self.assertNotIn("Oversized Packets", self._names(Length=1522, TTL=64))


if __name__ == "__main__":
    unittest.main()
