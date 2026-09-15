"""
Adversarial ML Analysis Module

Provides four components for the academic AI security lab:

  ModelAnalyzer     — accuracy / F1 / confusion matrix / ROC from dataset sample
  FeatureExplainer  — per-prediction XAI using RF feature importances
  AdversarialEngine — greedy FGSM-style evasion attack on tabular DDoS features
  SecurityScorer    — composite AI Security Score (0–100)
"""
from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd

try:
    from joblib import load as _jload
    _JOBLIB_OK = True
except ImportError:
    _JOBLIB_OK = False

logger = logging.getLogger(__name__)

# ── Feature display names for UI ──────────────────────────────────────────────
FEATURE_DISPLAY: dict[str, str] = {
    "Protocol":               "Protocol (TCP=6 / UDP=17)",
    "Flow Duration":          "Flow Duration (μs)",
    "Total Fwd Packets":      "Forward Packets",
    "Total Backward Packets": "Backward Packets",
    "Fwd Packets Length Total": "Fwd Bytes Total",
    "Bwd Packets Length Total": "Bwd Bytes Total",
    "Fwd Packet Length Max":  "Max Fwd Packet (bytes)",
    "Flow Bytes/s":           "Flow Rate (bytes/s)",
    "Flow Packets/s":         "Packet Rate (pkt/s)",
    "Fwd IAT Min":            "Min Fwd Inter-Arrival (μs)",
    "Bwd IAT Min":            "Min Bwd Inter-Arrival (μs)",
    "Fwd PSH Flags":          "PSH Flags",
    "Fwd URG Flags":          "URG Flags",
    "FIN Flag Count":         "FIN Flags",
    "SYN Flag Count":         "SYN Flags",
    "RST Flag Count":         "RST Flags",
    "ACK Flag Count":         "ACK Flags",
    "URG Flag Count":         "URG Flags (total)",
    "Init Fwd Win Bytes":     "Initial Window Size",
}

# ── Realistic attack feature vectors ─────────────────────────────────────────
ATTACK_PROFILES: dict[str, dict] = {
    "SYN Flood": {
        "Protocol": 6,  "Flow Duration": 500_000,
        "Total Fwd Packets": 150, "Total Backward Packets": 5,
        "Fwd Packets Length Total": 9_000, "Bwd Packets Length Total": 300,
        "Fwd Packet Length Max": 60, "Flow Bytes/s": 18_600,
        "Flow Packets/s": 310, "Fwd IAT Min": 0, "Bwd IAT Min": 0,
        "Fwd PSH Flags": 0, "Fwd URG Flags": 0, "FIN Flag Count": 0,
        "SYN Flag Count": 150, "RST Flag Count": 0, "ACK Flag Count": 5,
        "URG Flag Count": 0, "Init Fwd Win Bytes": 1_024,
    },
    "UDP Flood": {
        "Protocol": 17, "Flow Duration": 200_000,
        "Total Fwd Packets": 500, "Total Backward Packets": 0,
        "Fwd Packets Length Total": 512_000, "Bwd Packets Length Total": 0,
        "Fwd Packet Length Max": 1_472, "Flow Bytes/s": 2_560_000,
        "Flow Packets/s": 2_500, "Fwd IAT Min": 100, "Bwd IAT Min": 0,
        "Fwd PSH Flags": 0, "Fwd URG Flags": 0, "FIN Flag Count": 0,
        "SYN Flag Count": 0, "RST Flag Count": 0, "ACK Flag Count": 0,
        "URG Flag Count": 0, "Init Fwd Win Bytes": 0,
    },
    "HTTP Flood": {
        "Protocol": 6,  "Flow Duration": 1_000_000,
        "Total Fwd Packets": 200, "Total Backward Packets": 200,
        "Fwd Packets Length Total": 280_000, "Bwd Packets Length Total": 800_000,
        "Fwd Packet Length Max": 1_460, "Flow Bytes/s": 1_080_000,
        "Flow Packets/s": 400, "Fwd IAT Min": 500, "Bwd IAT Min": 500,
        "Fwd PSH Flags": 200, "Fwd URG Flags": 0, "FIN Flag Count": 1,
        "SYN Flag Count": 1, "RST Flag Count": 0, "ACK Flag Count": 200,
        "URG Flag Count": 0, "Init Fwd Win Bytes": 65_535,
    },
    "ICMP Flood": {
        "Protocol": 1,  "Flow Duration": 100_000,
        "Total Fwd Packets": 1000, "Total Backward Packets": 0,
        "Fwd Packets Length Total": 64_000, "Bwd Packets Length Total": 0,
        "Fwd Packet Length Max": 64, "Flow Bytes/s": 640_000,
        "Flow Packets/s": 10_000, "Fwd IAT Min": 50, "Bwd IAT Min": 0,
        "Fwd PSH Flags": 0, "Fwd URG Flags": 0, "FIN Flag Count": 0,
        "SYN Flag Count": 0, "RST Flag Count": 0, "ACK Flag Count": 0,
        "URG Flag Count": 0, "Init Fwd Win Bytes": 0,
    },
}

# Median feature values of real BENIGN flows sampled from cicddos2019_dataset.csv
# (~63,000 rows). The earlier hand-picked values scored 98%+ attack probability
# under the trained RF — they didn't resemble the model's actual training
# distribution, which produced a misleading false-positive in the test suite
# even though the model itself tests at 99.9% accuracy on real held-out data.
BENIGN_PROFILE: dict[str, float] = {
    "Protocol": 6, "Flow Duration": 22_252,
    "Total Fwd Packets": 2, "Total Backward Packets": 2,
    "Fwd Packets Length Total": 70, "Bwd Packets Length Total": 94,
    "Fwd Packet Length Max": 35, "Flow Bytes/s": 6_313.68,
    "Flow Packets/s": 188.09, "Fwd IAT Min": 1, "Bwd IAT Min": 1,
    "Fwd PSH Flags": 0, "Fwd URG Flags": 0, "FIN Flag Count": 0,
    "SYN Flag Count": 0, "RST Flag Count": 0, "ACK Flag Count": 0,
    "URG Flag Count": 0, "Init Fwd Win Bytes": 254,
}


# ══════════════════════════════════════════════════════════════════════════════
# ── Model wrapper (lazy singleton) ────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

class _ModelWrapper:
    _instance: Optional[_ModelWrapper] = None
    _lock = threading.Lock()

    def __init__(self):
        self.model         = None
        self.scaler        = None
        self.feature_names: list[str] = []
        self.threshold:     float     = 0.5
        self.importances:   np.ndarray = np.array([])
        self._ready        = False

    @classmethod
    def get(cls) -> _ModelWrapper:
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = _ModelWrapper()
                    cls._instance._load()
        return cls._instance

    def _load(self) -> None:
        if not _JOBLIB_OK:
            return
        try:
            import config
            data = _jload(config.MODEL_FILENAME)
            self.model         = data["model"]
            self.scaler        = data["scaler"]
            self.feature_names = data["features"]
            self.threshold     = float(data.get("optimal_threshold", 0.5))
            self.importances   = self._extract_importances(self.model, len(self.feature_names))
            self._ready        = True
            logger.info("AdversarialEngine: model loaded OK")
        except Exception as e:
            logger.warning(f"AdversarialEngine: model load failed — {e}")

    @staticmethod
    def _extract_importances(model, n_features: int) -> np.ndarray:
        """Extract feature_importances_ from RF or CalibratedClassifierCV wrapper."""
        # Direct RF / GBT
        if hasattr(model, "feature_importances_"):
            return np.array(model.feature_importances_)
        # CalibratedClassifierCV wrapping an RF
        if hasattr(model, "estimator") and hasattr(model.estimator, "feature_importances_"):
            return np.array(model.estimator.feature_importances_)
        if hasattr(model, "calibrated_classifiers_"):
            try:
                base = model.calibrated_classifiers_[0].estimator
                return np.array(base.feature_importances_)
            except Exception:
                pass
        # Fallback: uniform importances
        return np.ones(n_features) / n_features

    @property
    def ready(self) -> bool:
        return self._ready

    def predict_proba(self, vec: np.ndarray) -> float:
        """Return P(attack) for a 1-D unscaled feature array."""
        X_df = pd.DataFrame([vec], columns=self.feature_names)
        X = self.scaler.transform(X_df)
        return float(self.model.predict_proba(X)[0][1])


def _vec(features: dict, names: list[str]) -> np.ndarray:
    return np.array([float(features.get(n, 0)) for n in names], dtype=np.float64)


# ══════════════════════════════════════════════════════════════════════════════
# ── Model Performance Analyzer ────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

class ModelAnalyzer:
    """Computes classification metrics from a sample of the training dataset."""

    def __init__(self):
        self._mw = _ModelWrapper.get()

    def ready(self) -> bool:
        return self._mw.ready

    def quick_info(self) -> dict:
        """Return model metadata without loading the dataset (instant)."""
        if not self._mw.ready:
            return {}
        return {
            "feature_importances": dict(zip(
                self._mw.feature_names,
                [round(float(x), 5) for x in self._mw.importances],
            )),
            "threshold":     round(self._mw.threshold * 100, 2),
            "n_features":    len(self._mw.feature_names),
            "n_estimators":  getattr(self._mw.model, "n_estimators", "?"),
        }

    def compute_metrics(self, dataset_path: str, sample_size: int = 10_000) -> dict | None:
        """
        Compute performance metrics.

        Priority:
          1. Dataset CSV (full live computation — most up-to-date).
          2. model_metrics.json sidecar (pre-computed during training — works in packaged app).
        Returns dict or None on failure.
        """
        if not self._mw.ready:
            return None

        # If dataset is absent, fall back to the pre-computed metrics JSON
        if not Path(dataset_path).exists():
            metrics_path = Path(dataset_path).parent / "model_metrics.json"
            if not metrics_path.exists():
                # Also try next to the model file
                try:
                    import config as _cfg
                    metrics_path = Path(_cfg.METRICS_FILE)
                except Exception:
                    pass
            if metrics_path.exists():
                try:
                    data = json.loads(metrics_path.read_text(encoding="utf-8"))
                    data["_source"] = "cached"   # flag so UI can note it
                    return data
                except Exception as e:
                    logger.warning(f"Could not load cached metrics: {e}")
            return None

        try:
            import pandas as pd
            from sklearn.metrics import (
                accuracy_score, precision_score, recall_score, f1_score,
                confusion_matrix, roc_curve, roc_auc_score, precision_recall_curve,
            )

            # Read a capped number of rows to avoid loading the whole file into RAM
            df = pd.read_csv(dataset_path, low_memory=False, nrows=80_000)

            # Find a usable label column — prefer 'Class' (Attack/Benign) then 'Label'
            col_map = {c.strip().lower(): c for c in df.columns}
            label_col = col_map.get("class") or col_map.get("label")
            if label_col is None:
                return None

            df[label_col] = df[label_col].astype(str).str.strip()
            # Case-insensitive BENIGN check — "Benign" / "BENIGN" / "benign" all work
            df["_y"] = (~df[label_col].str.upper().isin({"BENIGN"})).astype(int)

            n = min(sample_size, len(df))
            # Stratified sample: keep class balance
            pos = df[df["_y"] == 1]
            neg = df[df["_y"] == 0]
            n_pos = min(len(pos), n // 2)
            n_neg = min(len(neg), n - n_pos)
            df = pd.concat([
                pos.sample(n=n_pos, random_state=42),
                neg.sample(n=n_neg, random_state=42),
            ]).sample(frac=1, random_state=42)

            X_raw = (
                df[self._mw.feature_names]
                .fillna(0)
                .replace([np.inf, -np.inf], 0)
            )
            y    = df["_y"].values
            X_sc = self._mw.scaler.transform(X_raw)
            prob = self._mw.model.predict_proba(X_sc)[:, 1]
            pred = (prob >= self._mw.threshold).astype(int)

            fpr, tpr, _ = roc_curve(y, prob)
            prec_arr, rec_arr, _ = precision_recall_curve(y, prob)

            return {
                "accuracy":  round(float(accuracy_score(y, pred)) * 100, 2),
                "precision": round(float(precision_score(y, pred, zero_division=0)) * 100, 2),
                "recall":    round(float(recall_score(y, pred,    zero_division=0)) * 100, 2),
                "f1":        round(float(f1_score(y, pred,        zero_division=0)) * 100, 2),
                "auc":       round(float(roc_auc_score(y, prob))  * 100, 2),
                "cm":        confusion_matrix(y, pred).tolist(),
                "fpr":       fpr.tolist(),
                "tpr":       tpr.tolist(),
                "prec_arr":  prec_arr.tolist(),
                "rec_arr":   rec_arr.tolist(),
                "feature_importances": dict(zip(
                    self._mw.feature_names,
                    [round(float(x), 5) for x in self._mw.importances],
                )),
                "sample_size": int(n_pos + n_neg),
                "threshold":   round(self._mw.threshold * 100, 2),
            }
        except Exception as e:
            logger.error(f"compute_metrics: {e}")
            return None


# ══════════════════════════════════════════════════════════════════════════════
# ── Feature Explainer (XAI) ───────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

class FeatureExplainer:
    """
    Local per-prediction explanation using RF feature importances scaled
    by how far each input deviates from the benign baseline.
    """

    def __init__(self):
        self._mw = _ModelWrapper.get()

    def explain(self, features: dict) -> list[dict]:
        """
        Returns a list of contribution records, sorted by |contribution| desc.
        Each record: feature, display_name, value, baseline, importance,
                     direction, contribution, pct_of_total.
        """
        if not self._mw.ready:
            return []

        imp   = self._mw.importances
        total = imp.sum() or 1.0
        rows  = []

        for i, fname in enumerate(self._mw.feature_names):
            val   = float(features.get(fname, 0))
            base  = float(BENIGN_PROFILE.get(fname, 0))
            w     = float(imp[i])
            denom = max(abs(base), 1.0)
            deviation   = (val - base) / denom
            contribution = w * deviation

            rows.append({
                "feature":      fname,
                "display":      FEATURE_DISPLAY.get(fname, fname),
                "value":        round(val, 4),
                "baseline":     round(base, 4),
                "importance":   round(w * 100, 2),
                "contribution": round(contribution * 100, 3),
                "direction":    "↑ Attack" if contribution > 0 else "↓ Benign",
                "pct_of_total": round(w / total * 100, 1),
            })

        rows.sort(key=lambda x: abs(x["contribution"]), reverse=True)
        return rows


# ══════════════════════════════════════════════════════════════════════════════
# ── Adversarial Attack Engine (FGSM-tabular) ─────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

class AdversarialEngine:
    """
    Greedy FGSM-style evasion attack.
    Perturbs the top-K most important features iteratively to push the model
    below its decision threshold (ATTACK → BENIGN misclassification).
    """

    def __init__(self, epsilon: float = 0.20, max_iters: int = 80, top_k: int = 8):
        self._mw       = _ModelWrapper.get()
        self.epsilon   = epsilon
        self.max_iters = max_iters
        self.top_k     = top_k

    def ready(self) -> bool:
        return self._mw.ready

    def attack(self, features: dict) -> dict:
        """
        Attempt to craft an adversarial sample that evades detection.
        Returns a result dict with all findings.
        """
        if not self._mw.ready:
            return {"error": "Model not loaded"}

        mw     = self._mw
        fnames = mw.feature_names
        orig   = _vec(features, fnames)
        orig_p = mw.predict_proba(orig)

        if orig_p < mw.threshold:
            return {
                "success":     False,
                "already_benign": True,
                "message": (
                    f"This sample is already classified as BENIGN "
                    f"(confidence {orig_p*100:.1f}%).\n"
                    "Select an attack profile to demonstrate evasion."
                ),
                "original_confidence": round(orig_p * 100, 1),
            }

        # Estimate per-feature std across all profiles for scaling the step
        all_vecs    = [_vec(p, fnames) for p in ATTACK_PROFILES.values()]
        all_vecs.append(_vec(BENIGN_PROFILE, fnames))
        feat_stds   = np.std(np.vstack(all_vecs), axis=0)
        feat_stds   = np.where(feat_stds < 1e-6, 1.0, feat_stds)

        # Sort features by importance — only perturb top-K
        top_idxs = np.argsort(mw.importances)[::-1][:self.top_k]

        current   = orig.copy()
        cur_p     = orig_p
        path      = [round(orig_p * 100, 2)]
        perturbed: dict[str, float] = {}

        for _iter in range(self.max_iters):
            improved = False
            for idx in top_idxs:
                step      = self.epsilon * feat_stds[idx]
                best_p    = cur_p
                best_d    = 0.0

                for direction in (-1.0, 1.0):
                    candidate      = current.copy()
                    candidate[idx] = max(0.0, candidate[idx] + direction * step)
                    p              = mw.predict_proba(candidate)
                    if p < best_p:
                        best_p = p
                        best_d = direction * step

                if best_d != 0.0:
                    current[idx]  = max(0.0, current[idx] + best_d)
                    cur_p         = best_p
                    fname         = fnames[idx]
                    perturbed[fname] = perturbed.get(fname, 0.0) + best_d
                    improved      = True

            path.append(round(cur_p * 100, 2))

            if cur_p < mw.threshold:
                break
            if not improved:
                break

        adv_features = {f: float(current[i]) for i, f in enumerate(fnames)}

        return {
            "success":              cur_p < mw.threshold,
            "original_confidence":  round(orig_p  * 100, 1),
            "final_confidence":     round(cur_p   * 100, 1),
            "threshold":            round(mw.threshold * 100, 1),
            "iterations":           len(path) - 1,
            "original_features":    {f: float(orig[i])    for i, f in enumerate(fnames)},
            "adversarial_features": adv_features,
            "perturbations":        {k: round(v, 4) for k, v in perturbed.items()},
            "confidence_path":      path,
            "features_changed":     len(perturbed),
        }

    def poisoning_demo(self) -> dict:
        """
        Demonstrate data poisoning: test how many attack profiles can evade detection.
        """
        if not self._mw.ready:
            return {"error": "Model not loaded"}

        results = {}
        for name, profile in ATTACK_PROFILES.items():
            r = self.attack(profile)
            results[name] = {
                "evaded":               r.get("success", False),
                "original_confidence":  r.get("original_confidence", 0),
                "final_confidence":     r.get("final_confidence", 0),
                "iterations":           r.get("iterations", 0),
                "features_changed":     r.get("features_changed", 0),
            }

        n_evaded     = sum(1 for v in results.values() if v["evaded"])
        evasion_rate = n_evaded / len(results) * 100

        return {
            "per_profile":       results,
            "profiles_tested":   len(results),
            "evasion_successes": n_evaded,
            "evasion_rate":      round(evasion_rate, 1),
            "risk":              (
                "HIGH"   if evasion_rate > 50 else
                "MEDIUM" if evasion_rate > 0  else
                "LOW"
            ),
        }


# ══════════════════════════════════════════════════════════════════════════════
# ── AI Security Scorer ────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

class SecurityScorer:
    """Computes a composite AI Security Score (0–100) with letter grade."""

    _WEIGHTS = {
        "detection_rate":        0.35,
        "false_positive_rate":   0.25,
        "model_confidence":      0.20,
        "adversarial_robustness":0.20,
    }

    def compute(
        self,
        metrics:                dict | None = None,
        adversarial_evasion_rate: float     = 0.0,
        session_alerts:           int       = 0,
        session_false_positives:  int       = 0,
    ) -> dict:
        w = self._WEIGHTS

        # Detection rate — from F1 (balanced) or fallback
        det = (metrics["f1"] / 100) if metrics and "f1" in metrics else 0.87

        # False-positive component
        if metrics and "cm" in metrics:
            cm = metrics["cm"]
            tn, fp = cm[0][0], cm[0][1]
            fp_rate = fp / max(tn + fp, 1)
        elif session_alerts > 0:
            fp_rate = min(session_false_positives / session_alerts, 1.0)
        else:
            fp_rate = 0.04
        fp_comp = max(0.0, 1.0 - fp_rate * 4)

        # Model confidence — AUC proxy
        conf = (metrics["auc"] / 100) if metrics and "auc" in metrics else 0.91

        # Adversarial robustness
        rob  = max(0.0, 1.0 - adversarial_evasion_rate / 100)

        raw   = det * w["detection_rate"] + fp_comp * w["false_positive_rate"] \
                + conf * w["model_confidence"] + rob * w["adversarial_robustness"]
        score = round(raw * 100)
        grade = "A+" if score >= 90 else "A" if score >= 80 else "B" if score >= 70 \
                else "C" if score >= 60 else "D"

        descriptions = {
            "A+": "Excellent — highly robust against attacks and adversarial evasion.",
            "A":  "Strong — accurate detection with low false positives.",
            "B":  "Good — effective detection with minor room for improvement.",
            "C":  "Moderate — noticeable false positives or evasion vulnerability.",
            "D":  "Needs work — significant adversarial vulnerabilities detected.",
        }

        return {
            "score": score,
            "grade": grade,
            "description": descriptions[grade],
            "components": {
                "detection_rate":        round(det  * 100, 1),
                "false_positive_rate":   round((1 - fp_rate) * 100, 1),
                "model_confidence":      round(conf * 100, 1),
                "adversarial_robustness":round(rob  * 100, 1),
            },
            "weights": w,
        }
