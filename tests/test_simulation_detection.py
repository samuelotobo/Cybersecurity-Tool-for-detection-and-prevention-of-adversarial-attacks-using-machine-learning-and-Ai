"""
Simulation Detection Tests
--------------------------
Tests the attack-profile simulation pipeline end-to-end using the
DDoS ML classifier (DDosDetector) and pre-built attack profiles from
the adversarial module (AdversarialEngine / ATTACK_PROFILES).

All tests are safe: no real network packets are transmitted and no
external API calls are made.
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config as cfg
from detectors.ddos import DDosDetector
from detectors.adversarial import ATTACK_PROFILES, BENIGN_PROFILE, AdversarialEngine


class SimulationDetectionTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """Load the DDoS detector once for all tests."""
        cls.detector = DDosDetector(cfg.MODEL_FILENAME, cfg.RULES_CONFIG)
        cls.model_ready = cls.detector.model_ready

    # ── Test 1: model loads ────────────────────────────────────────────────

    def test_model_loads(self):
        """DDosDetector should load a trained model from ddos_detector_model.joblib."""
        self.assertTrue(
            self.model_ready,
            "DDoS model not loaded — run 'python train_model.py' first"
        )

    # ── Test 2: packet feature keys ────────────────────────────────────────

    def test_packet_features_present(self):
        """predict() result must contain verdict, confidence, and threshold keys."""
        if not self.model_ready:
            self.skipTest("Model not trained")
        result = self.detector.predict(ATTACK_PROFILES["SYN Flood"])
        self.assertIn("verdict",    result, "Missing 'verdict' key in predict() result")
        self.assertIn("confidence", result, "Missing 'confidence' key in predict() result")
        self.assertIn("threshold",  result, "Missing 'threshold' key in predict() result")

    # ── Test 3: SYN flood detected ─────────────────────────────────────────

    def test_syn_flood_detected(self):
        """SYN Flood attack profile must be classified as ATTACK or SUSPICIOUS."""
        if not self.model_ready:
            self.skipTest("Model not trained")
        result = self.detector.predict(ATTACK_PROFILES["SYN Flood"])
        self.assertIn(
            result.get("verdict"),
            ("ATTACK", "SUSPICIOUS"),
            f"SYN Flood not detected — got {result.get('verdict')}"
        )

    # ── Test 4: UDP flood detected ─────────────────────────────────────────

    def test_udp_flood_detected(self):
        """UDP Flood attack profile must be classified as ATTACK or SUSPICIOUS."""
        if not self.model_ready:
            self.skipTest("Model not trained")
        result = self.detector.predict(ATTACK_PROFILES["UDP Flood"])
        self.assertIn(
            result.get("verdict"),
            ("ATTACK", "SUSPICIOUS"),
            f"UDP Flood not detected — got {result.get('verdict')}"
        )

    # ── Test 5: detection rate across all attack profiles ──────────────────

    def test_detection_rate_threshold(self):
        """Run all attack profiles and assert at least 50% are detected."""
        if not self.model_ready:
            self.skipTest("Model not trained")
        detected = 0
        total = len(ATTACK_PROFILES)
        for name, profile in ATTACK_PROFILES.items():
            result = self.detector.predict(profile)
            if result.get("verdict") in ("ATTACK", "SUSPICIOUS"):
                detected += 1
        rate = detected / total if total > 0 else 0
        self.assertGreaterEqual(
            rate, 0.50,
            f"Detection rate too low: {rate:.0%} ({detected}/{total} profiles detected)"
        )

    # ── Test 6: benign traffic not flagged ─────────────────────────────────

    def test_benign_not_flagged_as_attack(self):
        """Normal (BENIGN) traffic profile should NOT be classified as ATTACK."""
        if not self.model_ready:
            self.skipTest("Model not trained")
        result = self.detector.predict(BENIGN_PROFILE)
        self.assertNotEqual(
            result.get("verdict"),
            "ATTACK",
            "False positive: benign traffic classified as ATTACK"
        )

    # ── Test 7: adversarial engine returns evasion result ──────────────────

    def test_adversarial_engine_attack(self):
        """AdversarialEngine.attack() must return a result dict for an attack profile."""
        if not self.model_ready:
            self.skipTest("Model not trained")
        engine = AdversarialEngine()
        result = engine.attack(ATTACK_PROFILES["SYN Flood"])
        # Should return a dict (either success/failure result, never an exception)
        self.assertIsInstance(result, dict,
                              "AdversarialEngine.attack() must return a dict")
        self.assertFalse("error" in result and result["error"] == "Model not loaded",
                         "AdversarialEngine could not load model")

    # ── Test 8: confidence score is numeric ────────────────────────────────

    def test_confidence_is_numeric(self):
        """Confidence score returned by predict() must be a float in range 0–100."""
        if not self.model_ready:
            self.skipTest("Model not trained")
        result = self.detector.predict(ATTACK_PROFILES["HTTP Flood"])
        conf = result.get("confidence", -1)
        self.assertIsInstance(conf, float, "Confidence must be a float")
        self.assertGreaterEqual(conf, 0.0,  "Confidence below 0")
        self.assertLessEqual(conf, 100.0,   "Confidence above 100")


if __name__ == "__main__":
    unittest.main(verbosity=2)
