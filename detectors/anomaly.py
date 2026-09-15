"""
Isolation Forest anomaly detector — second-layer detection for novel attacks.

The Isolation Forest is trained exclusively on BENIGN traffic samples.
It learns what "normal" looks like without ever seeing attack labels, making
it effective against attack types not present in the training dataset.

Decision logic:
  - predict() == -1  →  anomaly (traffic deviates from BENIGN baseline)
  - decision_function() returns a raw score; we negate it so:
      positive score  → anomalous (further from normal)
      negative score  → normal
"""
import logging

import numpy as np
import pandas as pd
from joblib import dump, load
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)

FEATURES = [
    "Protocol", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Fwd Packets Length Total", "Bwd Packets Length Total", "Fwd Packet Length Max",
    "Flow Bytes/s", "Flow Packets/s", "Fwd IAT Min", "Bwd IAT Min",
    "Fwd PSH Flags", "Fwd URG Flags", "FIN Flag Count", "SYN Flag Count",
    "RST Flag Count", "ACK Flag Count", "URG Flag Count", "Init Fwd Win Bytes",
]


# ── Inference ─────────────────────────────────────────────────────────────────

class AnomalyDetector:
    """Load a pre-trained Isolation Forest and score flow feature dicts."""

    def __init__(self, model_path: str) -> None:
        self._model:    IsolationForest | None = None
        self._scaler:   StandardScaler  | None = None
        self._features: list[str]               = FEATURES
        self._load(model_path)

    def _load(self, path: str) -> None:
        try:
            data = load(path)
            self._model    = data["model"]
            self._scaler   = data["scaler"]
            self._features = data.get("features", FEATURES)
            logger.info("Anomaly (Isolation Forest) model loaded.")
        except FileNotFoundError:
            logger.warning("Anomaly model not found — retrain with python main_app.py --train")
        except Exception as e:
            logger.error(f"Anomaly model load error: {e}")

    @property
    def ready(self) -> bool:
        return self._model is not None

    def score(self, features: dict) -> dict:
        """
        Score a flow feature dict.

        Returns:
            anomaly (bool)  — True if the flow looks like an attack
            score   (float) — positive = more anomalous, negative = more normal
        """
        if not self.ready:
            return {"anomaly": False, "score": 0.0, "error": "Anomaly model not loaded"}
        try:
            vals = [float(features.get(f, 0)) for f in self._features]
            X    = pd.DataFrame([vals], columns=self._features)
            X_sc = self._scaler.transform(X)
            # Negate so positive = anomalous (sklearn convention is reversed)
            raw_score = float(self._model.decision_function(X_sc)[0])
            score     = -raw_score
            anomaly   = self._model.predict(X_sc)[0] == -1
            return {"anomaly": bool(anomaly), "score": round(score, 4)}
        except Exception as e:
            logger.debug(f"Anomaly scoring error: {e}")
            return {"anomaly": False, "score": 0.0, "error": str(e)}


# ── Training ──────────────────────────────────────────────────────────────────

def train_anomaly_model(dataset_path: str, model_path: str) -> bool:
    """
    Train Isolation Forest on BENIGN-only samples and save to model_path.
    Returns True on success.
    """
    logger.info("Training Isolation Forest on BENIGN traffic samples…")
    try:
        df = pd.read_csv(dataset_path, low_memory=False)
        df.columns = df.columns.str.strip()
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.dropna(inplace=True)

        available = [f for f in FEATURES if f in df.columns]
        if not available:
            logger.error("No recognised feature columns in dataset.")
            return False

        benign_mask = df["Label"].astype(str).str.strip().isin(["BENIGN", "Benign"])
        X_benign = df.loc[benign_mask, available].copy()

        if len(X_benign) < 100:
            logger.error(f"Too few BENIGN samples ({len(X_benign)}) to train anomaly model.")
            return False

        # Cap at 200k rows so training stays fast even on large datasets
        if len(X_benign) > 200_000:
            X_benign = X_benign.sample(200_000, random_state=42)

        logger.info(f"  Training on {len(X_benign):,} BENIGN samples ({len(available)} features)…")

        scaler = StandardScaler()
        X_sc   = scaler.fit_transform(X_benign)

        model = IsolationForest(
            n_estimators=200,
            max_samples="auto",
            contamination=0.01,   # ~1% of "benign" samples assumed mislabelled
            random_state=42,
            n_jobs=-1,
        )
        model.fit(X_sc)

        dump({"model": model, "scaler": scaler, "features": available}, model_path)
        logger.info(f"  Anomaly model saved → {model_path}")
        return True

    except Exception as e:
        logger.error(f"Anomaly model training failed: {e}")
        return False
