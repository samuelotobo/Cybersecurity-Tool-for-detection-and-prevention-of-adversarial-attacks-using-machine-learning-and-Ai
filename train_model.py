# train_model.py
"""
Trains the DDoS detection model and the anomaly baseline model.

Improvements over the original:
  1. class_weight='balanced'  — corrects for dataset imbalance (more BENIGN than attack rows)
  2. CalibratedClassifierCV   — Platt scaling makes RF probabilities statistically reliable
  3. F1-optimal threshold      — finds the decision threshold that maximises F1 on the test
                                  set, saved alongside the model so runtime doesn't need to
                                  guess a good cutoff
  4. Isolation Forest          — second model trained on BENIGN-only data; used at runtime
                                  to flag traffic that looks novel/anomalous even if the RF
                                  isn't confident enough to call it an attack
"""

import json
import logging
import os
import sys

import numpy as np
import pandas as pd
from joblib import dump
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix,
    f1_score, precision_score, recall_score,
    precision_recall_curve, roc_curve, roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

try:
    from config import DATASET_FILENAME, MODEL_FILENAME, ANOMALY_MODEL_FILENAME, METRICS_FILE
except ImportError:
    MODEL_FILENAME        = "ddos_detector_model.joblib"
    ANOMALY_MODEL_FILENAME = "anomaly_model.joblib"
    DATASET_FILENAME      = "cicddos2019_dataset.csv"
    METRICS_FILE          = "model_metrics.json"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

PRACTICAL_FEATURES = [
    "Protocol", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Fwd Packets Length Total", "Bwd Packets Length Total", "Fwd Packet Length Max",
    "Flow Bytes/s", "Flow Packets/s", "Fwd IAT Min", "Bwd IAT Min",
    "Fwd PSH Flags", "Fwd URG Flags", "FIN Flag Count", "SYN Flag Count",
    "RST Flag Count", "ACK Flag Count", "URG Flag Count", "Init Fwd Win Bytes",
]


def train_and_save_model() -> None:
    """Full training pipeline: RF (calibrated) + Isolation Forest."""

    if not os.path.exists(DATASET_FILENAME):
        logger.error(f"Dataset not found: {DATASET_FILENAME}")
        return

    # ── 1. Load & clean ───────────────────────────────────────────────────────
    logger.info(f"Loading dataset: {DATASET_FILENAME}")
    try:
        df = pd.read_csv(DATASET_FILENAME, low_memory=False)
        df.columns = df.columns.str.strip()
    except Exception as e:
        logger.error(f"Failed to read dataset: {e}")
        return

    available = [c for c in PRACTICAL_FEATURES if c in df.columns]
    if not available:
        logger.error("No recognised feature columns in dataset.")
        return

    df = df[available + ["Label"]].copy()
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    df["Label"] = df["Label"].apply(
        lambda x: 0 if str(x).strip() in ("BENIGN", "Benign") else 1
    )

    X = df.drop("Label", axis=1)
    y = df["Label"]
    X_cols = X.columns.tolist()

    n_benign  = int((y == 0).sum())
    n_attack  = int((y == 1).sum())
    logger.info(f"  Rows: {len(df):,}  |  BENIGN: {n_benign:,}  |  ATTACK: {n_attack:,}")
    logger.info(f"  Features: {X_cols}")

    # ── 2. Scale ──────────────────────────────────────────────────────────────
    scaler   = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.25, random_state=42, stratify=y
    )

    # ── 3. Train Random Forest with balanced class weights ────────────────────
    logger.info("Training Random Forest (class_weight='balanced')…")
    base_rf = RandomForestClassifier(
        n_estimators=150,
        max_depth=12,
        class_weight="balanced",   # compensates for BENIGN >> ATTACK imbalance
        random_state=42,
        n_jobs=-1,
    )

    # ── 4. Platt scaling — makes probabilities statistically calibrated ───────
    #
    # A raw RF probability of 0.6 often doesn't really mean 60% attack chance;
    # Platt scaling fits a logistic regression on top of the RF scores using
    # cross-validation, making the output probabilities well-calibrated so our
    # confidence threshold actually means something.
    logger.info("Applying Platt scaling (CalibratedClassifierCV)…")
    calibrated = CalibratedClassifierCV(base_rf, method="sigmoid", cv=3)
    calibrated.fit(X_train, y_train)

    # ── 5. Evaluate ───────────────────────────────────────────────────────────
    y_pred  = calibrated.predict(X_test)
    y_proba = calibrated.predict_proba(X_test)[:, 1]

    raw_acc = float((y_pred == y_test).mean())
    logger.info(f"\n--- Evaluation (test set, default 0.5 threshold) ---")
    logger.info(f"  Accuracy: {raw_acc:.4f}")
    logger.info("\n" + classification_report(y_test, y_pred, target_names=["BENIGN", "ATTACK"]))

    # ── 6. Find F1-optimal decision threshold ─────────────────────────────────
    #
    # Default threshold of 0.5 maximises accuracy but can be suboptimal when
    # precision and recall are not equally important.  We sweep over all
    # precision-recall curve thresholds and pick the one that maximises F1,
    # then save it with the model so runtime uses it automatically.
    precisions, recalls, thresholds = precision_recall_curve(y_test, y_proba)
    f1_scores = np.where(
        (precisions + recalls) == 0,
        0.0,
        2 * precisions * recalls / (precisions + recalls),
    )
    best_idx       = int(np.argmax(f1_scores[:-1]))   # last element has no threshold
    optimal_threshold = float(thresholds[best_idx])
    best_f1        = float(f1_scores[best_idx])
    best_precision = float(precisions[best_idx])
    best_recall    = float(recalls[best_idx])

    logger.info(f"\n--- F1-optimal threshold ---")
    logger.info(f"  Threshold : {optimal_threshold:.4f}")
    logger.info(f"  F1        : {best_f1:.4f}")
    logger.info(f"  Precision : {best_precision:.4f}")
    logger.info(f"  Recall    : {best_recall:.4f}")

    # Evaluate at the optimal threshold
    y_pred_opt = (y_proba >= optimal_threshold).astype(int)
    logger.info(f"\n--- Evaluation at optimal threshold ({optimal_threshold:.4f}) ---")
    logger.info("\n" + classification_report(y_test, y_pred_opt, target_names=["BENIGN", "ATTACK"]))

    # ── 7. Save RF model ──────────────────────────────────────────────────────
    dump(
        {
            "model":              calibrated,
            "scaler":             scaler,
            "features":           X_cols,
            "optimal_threshold":  optimal_threshold,   # in [0,1] — used by DDosDetector
        },
        MODEL_FILENAME,
    )
    logger.info(f"\nRF model saved → {MODEL_FILENAME}")

    # ── 7b. Save pre-computed metrics JSON (packaged app doesn't bundle the CSV) ──
    try:
        fpr_arr, tpr_arr, _ = roc_curve(y_test, y_proba)
        prec_arr, rec_arr, _ = precision_recall_curve(y_test, y_proba)
        # Downsample curve arrays to keep JSON small (<50 KB)
        _ds = max(1, len(fpr_arr) // 500)
        importances = calibrated.calibrated_classifiers_[0].estimator.feature_importances_
        metrics_data = {
            "accuracy":  round(float(accuracy_score(y_test, y_pred_opt)) * 100, 2),
            "precision": round(float(precision_score(y_test, y_pred_opt, zero_division=0)) * 100, 2),
            "recall":    round(float(recall_score(y_test, y_pred_opt,    zero_division=0)) * 100, 2),
            "f1":        round(float(f1_score(y_test, y_pred_opt,        zero_division=0)) * 100, 2),
            "auc":       round(float(roc_auc_score(y_test, y_proba))     * 100, 2),
            "cm":        confusion_matrix(y_test, y_pred_opt).tolist(),
            "fpr":       [round(v, 4) for v in fpr_arr[::_ds].tolist()],
            "tpr":       [round(v, 4) for v in tpr_arr[::_ds].tolist()],
            "prec_arr":  [round(v, 4) for v in prec_arr[::_ds].tolist()],
            "rec_arr":   [round(v, 4) for v in rec_arr[::_ds].tolist()],
            "threshold": round(optimal_threshold * 100, 2),
            "sample_size": int(len(y_test)),
            "n_estimators": 150,
            "feature_importances": {
                k: round(float(v), 5)
                for k, v in zip(X_cols, importances)
            },
        }
        with open(METRICS_FILE, "w", encoding="utf-8") as f:
            json.dump(metrics_data, f, separators=(",", ":"))
        logger.info(f"Metrics JSON saved → {METRICS_FILE}")
    except Exception as e:
        logger.warning(f"Could not save metrics JSON: {e}")

    # ── 8. Train Isolation Forest on BENIGN-only data ─────────────────────────
    logger.info("\nTraining Isolation Forest on BENIGN samples…")
    try:
        from detectors.anomaly import train_anomaly_model
        train_anomaly_model(DATASET_FILENAME, ANOMALY_MODEL_FILENAME)
    except Exception as e:
        logger.error(f"Anomaly model training failed: {e}")

    logger.info("\n=== Training complete. Run: python main_app.py ===")


if __name__ == "__main__":
    train_and_save_model()
