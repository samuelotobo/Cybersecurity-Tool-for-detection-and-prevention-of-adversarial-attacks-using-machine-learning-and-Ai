"""
DDoS detector — ML prediction + rule engine.

Three-tier verdict system:
  ATTACK     — high-confidence ML hit OR confirmed by anomaly layer
  SUSPICIOUS — ML says attack but confidence is below the optimal threshold,
               or anomaly layer flags it while ML is uncertain
  SAFE       — no indicators triggered

The decision threshold is saved alongside the model during training (F1-optimal).
A config override (ATTACK_CONFIDENCE_THRESHOLD > 0) overrides the saved value.
"""
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime

import numpy as np
import pandas as pd
from joblib import load

logger = logging.getLogger(__name__)

# Default fallback if no threshold is saved in the model artifact
_DEFAULT_THRESHOLD = 0.50


@dataclass
class Alert:
    timestamp: str
    rule_name: str
    severity: str
    message: str
    source_ip: str
    destination_ip: str
    protocol: str
    packet_features: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


class DDosDetector:
    def __init__(self, model_path: str, rules_path: str, threshold_override: float = 0) -> None:
        """
        threshold_override — if > 0 (i.e. set via config/env), use this value
                             (as a percentage 0–100) instead of the saved F1-optimal
                             threshold from the model file.
        """
        self.model  = None
        self.scaler = None
        self.feature_names: list[str] = []
        self.rules: dict = {}

        # Threshold in [0, 1] for predict_proba[:,1]
        self._saved_threshold: float     = _DEFAULT_THRESHOLD
        self._threshold_override: float  = threshold_override / 100.0  # convert % → fraction

        self._load_model(model_path)
        self._load_rules(rules_path)

    # ── Setup ─────────────────────────────────────────────────────────────────

    def _load_model(self, path: str) -> None:
        try:
            data = load(path)
            self.model           = data["model"]
            self.scaler          = data["scaler"]
            self.feature_names   = data["features"]
            self._saved_threshold = float(data.get("optimal_threshold", _DEFAULT_THRESHOLD))
            logger.info(
                f"DDoS ML model loaded. "
                f"Saved F1-optimal threshold: {self._saved_threshold:.4f}"
            )
        except FileNotFoundError:
            logger.warning("Model not found — run: python main_app.py --train")
        except Exception as e:
            logger.error(f"Model load error: {e}")

    def _load_rules(self, path: str) -> None:
        try:
            with open(path, encoding="utf-8") as f:
                self.rules = json.load(f).get("rules", {})
            logger.info("Detection rules loaded.")
        except Exception as e:
            logger.error(f"Rules load error: {e}")

    # ── Properties ───────────────────────────────────────────────────────────

    @property
    def model_ready(self) -> bool:
        return self.model is not None

    @property
    def threshold(self) -> float:
        """Effective decision threshold in [0, 1]."""
        if self._threshold_override > 0:
            return self._threshold_override
        return self._saved_threshold

    # ── Prediction ────────────────────────────────────────────────────────────

    def predict(self, features: dict) -> dict:
        """
        Run ML prediction on a flow feature dict.

        Returns:
            verdict     : "ATTACK" | "SUSPICIOUS" | "NORMAL"
            confidence  : float 0–100 (calibrated probability × 100)
            threshold   : float 0–100 (the threshold used for this prediction)
            proba_attack: float 0–1   (raw calibrated probability)
        """
        if not self.model_ready:
            return {"error": "Model not loaded. Run: python main_app.py --train"}
        try:
            vals = [float(features.get(f, 0)) for f in self.feature_names]
            X    = pd.DataFrame([vals], columns=self.feature_names)
            X_sc = self.scaler.transform(X)

            proba_attack = float(self.model.predict_proba(X_sc)[0][1])
            confidence   = round(proba_attack * 100, 2)
            t            = self.threshold

            if proba_attack >= t:
                verdict = "ATTACK"
            elif proba_attack >= t * 0.70:
                # Within 70% of the threshold — flag as suspicious
                verdict = "SUSPICIOUS"
            else:
                verdict = "NORMAL"

            return {
                "verdict":      verdict,
                "confidence":   confidence,
                "threshold":    round(t * 100, 2),
                "proba_attack": round(proba_attack, 4),
                "features_used": self.feature_names,
            }
        except Exception as e:
            logger.error(f"Prediction error: {e}")
            return {"error": str(e)}

    # ── Rule engine ───────────────────────────────────────────────────────────

    def check_rules(self, packet_info: dict) -> list[Alert]:
        """Apply the rule engine to a packet info dict. Returns triggered alerts."""
        alerts: list[Alert] = []
        ts    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        src   = packet_info.get("src_ip",   "N/A")
        dst   = packet_info.get("dst_ip",   "N/A")
        proto = str(packet_info.get("protocol", "N/A"))

        # IP reputation check
        rep = self.rules.get("ip_reputation", {})
        if rep.get("enabled") and src in rep.get("malicious_ips", []):
            alerts.append(Alert(
                ts, "IP Reputation", "critical",
                f"Traffic from known malicious IP: {src}",
                src, dst, proto, packet_info,
            ))

        # Custom threshold rules
        for rule in self.rules.get("custom_rules", []):
            if not rule.get("enabled", True):
                continue
            field_val = packet_info.get(rule["field"])
            if field_val is None:
                continue
            op, threshold = rule["operator"], rule["value"]
            triggered = (
                (op == ">"  and field_val >  threshold) or
                (op == "<"  and field_val <  threshold) or
                (op == ">=" and field_val >= threshold) or
                (op == "<=" and field_val <= threshold) or
                (op == "==" and field_val == threshold)
            )
            if triggered:
                alerts.append(Alert(
                    ts, rule["name"], rule.get("severity", "low"),
                    f"{rule['name']}: value {field_val} {op} {threshold}",
                    src, dst, proto, packet_info,
                ))

        return alerts
