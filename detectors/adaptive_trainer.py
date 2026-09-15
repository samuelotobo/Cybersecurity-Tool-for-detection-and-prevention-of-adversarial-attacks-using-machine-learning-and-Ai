"""
Adaptive ML Training Engine
============================
Enables the DDoS classifier to improve continuously from user feedback
and accumulated real-world flow data.

Architecture
------------
FeedbackBuffer      — Persists labeled flow samples to a JSONL file.
                      Each line: {features, label, source, ts, verdict, confidence}

CorrectiveLayer     — Lightweight online SGDClassifier that trains immediately
                      on user feedback. Blends with the base RF score to provide
                      instant corrections between full retrains.

AdaptiveTrainer     — Full pipeline: merges feedback with original training data,
                      retrains the calibrated Random Forest, evaluates improvement,
                      and versions the model if accuracy improves.

Blending strategy
-----------------
  final_prob = (1 - alpha) * p_rf  +  alpha * p_sgd
  alpha starts at 0.0 and rises to max 0.35 as more labeled samples accumulate.
  Minimum 20 samples needed before the corrective layer influences decisions.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

_LOCK = threading.Lock()

# ── Feature list (must match train_model.py PRACTICAL_FEATURES) ──────────────
FEATURE_NAMES = [
    "Protocol", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Fwd Packets Length Total", "Bwd Packets Length Total", "Fwd Packet Length Max",
    "Flow Bytes/s", "Flow Packets/s", "Fwd IAT Min", "Bwd IAT Min",
    "Fwd PSH Flags", "Fwd URG Flags", "FIN Flag Count", "SYN Flag Count",
    "RST Flag Count", "ACK Flag Count", "URG Flag Count", "Init Fwd Win Bytes",
]


# ══════════════════════════════════════════════════════════════════════════════
# ── Feedback Buffer ────────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

class FeedbackBuffer:
    """
    Persists user-labeled flow samples for adaptive retraining.
    Thread-safe JSONL file — one JSON dict per line.
    """

    def __init__(self, path: str):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def add(
        self,
        features: dict,
        label: int,           # 0 = BENIGN, 1 = ATTACK
        source: str = "user", # "user_tp" | "user_fp" | "test_import" | "auto"
        verdict: str = "",
        confidence: float = 0.0,
    ) -> None:
        """Append a labeled sample. Thread-safe."""
        record = {
            "features":   {k: float(features.get(k, 0)) for k in FEATURE_NAMES},
            "label":      int(label),
            "source":     source,
            "verdict":    verdict,
            "confidence": round(confidence, 2),
            "ts":         datetime.now().isoformat(timespec="seconds"),
        }
        with _LOCK:
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, separators=(",", ":")) + "\n")

    def get_all(self) -> list[dict]:
        """Return all labeled samples."""
        if not self._path.exists():
            return []
        records = []
        with _LOCK:
            for line in self._path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except Exception:
                        pass
        return records

    def stats(self) -> dict:
        records = self.get_all()
        attacks = sum(1 for r in records if r.get("label") == 1)
        benign  = sum(1 for r in records if r.get("label") == 0)
        last_ts = records[-1]["ts"] if records else ""
        by_src: dict[str, int] = {}
        for r in records:
            by_src[r.get("source", "?")] = by_src.get(r.get("source", "?"), 0) + 1
        return {
            "total":   len(records),
            "attacks": attacks,
            "benign":  benign,
            "by_source": by_src,
            "last_ts": last_ts,
        }

    def clear(self) -> None:
        with _LOCK:
            self._path.write_text("", encoding="utf-8")

    def export_csv(self, out_path: str) -> int:
        """Export buffer as CSV for external analysis. Returns row count."""
        import csv
        records = self.get_all()
        if not records:
            return 0
        with open(out_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["label", "source", "ts", "verdict",
                                                    "confidence"] + FEATURE_NAMES)
            writer.writeheader()
            for r in records:
                row = {
                    "label":      r["label"],
                    "source":     r.get("source", ""),
                    "ts":         r.get("ts", ""),
                    "verdict":    r.get("verdict", ""),
                    "confidence": r.get("confidence", 0),
                }
                row.update(r.get("features", {}))
                writer.writerow(row)
        return len(records)


# ══════════════════════════════════════════════════════════════════════════════
# ── Corrective Layer (online SGD) ─────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

class CorrectiveLayer:
    """
    Online corrective model using SGDClassifier with log-loss.

    Trains incrementally on each new labeled sample (partial_fit) without
    a full retrain. Blends its probability with the base RF score to provide
    immediate corrections after user feedback.

    Minimum 20 samples required before the corrective layer has any influence.
    Alpha (blending weight) rises linearly from 0 → 0.35 as samples accumulate.
    """

    MIN_SAMPLES  = 20
    MAX_ALPHA    = 0.35

    def __init__(self, corrective_path: str, scaler=None):
        self._path    = Path(corrective_path)
        self._scaler  = scaler
        self._clf     = None
        self._n_samples = 0
        self._lock    = threading.Lock()
        self._load()

    # ── Public ────────────────────────────────────────────────────────────────

    def fit_one(self, features: dict, label: int) -> None:
        """Immediate online update on a single labeled sample."""
        X = self._vec(features)
        # Weight attacks (1) higher to compensate for class imbalance
        weight = [2.0 if label == 1 else 1.0]
        with self._lock:
            self._ensure_init()
            try:
                self._clf.partial_fit(X, [int(label)], classes=[0, 1],
                                      sample_weight=weight)
                self._n_samples += 1
                self._save()
            except Exception as e:
                logger.warning(f"CorrectiveLayer.fit_one: {e}")

    def fit_batch(self, records: list[dict]) -> None:
        """Batch update from a list of {features, label} dicts."""
        if not records:
            return
        with self._lock:
            self._ensure_init()
            for rec in records:
                try:
                    X = self._vec(rec.get("features", rec))
                    y = int(rec.get("label", 0))
                    w = [2.0 if y == 1 else 1.0]
                    self._clf.partial_fit(X, [y], classes=[0, 1], sample_weight=w)
                    self._n_samples += 1
                except Exception:
                    pass
            self._save()

    def predict_proba(self, features: dict) -> float:
        """Return probability of ATTACK (0–1). Returns -1 if not ready."""
        if not self.ready:
            return -1.0
        try:
            X = self._vec(features)
            with self._lock:
                return float(self._clf.predict_proba(X)[0][1])
        except Exception:
            return -1.0

    def blend(self, p_rf: float, features: dict) -> float:
        """
        Compute the blended final probability.
        alpha = 0 until MIN_SAMPLES, then rises to MAX_ALPHA.
        """
        if not self.ready or self._n_samples < self.MIN_SAMPLES:
            return p_rf
        p_sgd = self.predict_proba(features)
        if p_sgd < 0:
            return p_rf
        alpha = min(self.MAX_ALPHA, (self._n_samples - self.MIN_SAMPLES) / 200)
        return (1.0 - alpha) * p_rf + alpha * p_sgd

    @property
    def ready(self) -> bool:
        return self._clf is not None and self._n_samples > 0

    @property
    def n_samples(self) -> int:
        return self._n_samples

    # ── Internal ──────────────────────────────────────────────────────────────

    def _vec(self, features: dict) -> np.ndarray:
        vals = np.array(
            [float(features.get(k, 0)) for k in FEATURE_NAMES],
            dtype=np.float64,
        ).reshape(1, -1)
        if self._scaler is not None:
            try:
                vals = self._scaler.transform(vals)
            except Exception:
                pass
        return vals

    def _ensure_init(self) -> None:
        if self._clf is None:
            from sklearn.linear_model import SGDClassifier
            # class_weight='balanced' is not supported for partial_fit —
            # pass explicit sample_weight per call instead
            self._clf = SGDClassifier(
                loss="log_loss",
                penalty="l2",
                alpha=0.001,
                random_state=42,
                max_iter=1,
                tol=None,
            )
            # Warm-start with a seed so partial_fit knows the class set
            seed_X = np.zeros((2, len(FEATURE_NAMES)))
            self._clf.partial_fit(seed_X, [0, 1], classes=[0, 1])

    def _save(self) -> None:
        try:
            from joblib import dump
            dump({"clf": self._clf, "n_samples": self._n_samples}, self._path)
        except Exception as e:
            logger.debug(f"CorrectiveLayer save: {e}")

    def _load(self) -> None:
        try:
            if self._path.exists():
                from joblib import load
                data = load(self._path)
                self._clf      = data["clf"]
                self._n_samples = int(data.get("n_samples", 0))
                logger.info(f"CorrectiveLayer loaded ({self._n_samples} samples)")
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════════════
# ── Adaptive Trainer (full retrain pipeline) ──────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

class AdaptiveTrainer:
    """
    Full retraining pipeline.

    Merges original CICDDoS2019 data (if available) with all labeled feedback
    samples, retrains a calibrated Random Forest, and saves a new versioned model
    if the F1 score improves.

    Thread-safe — can be triggered from any thread.
    Progress messages are delivered via on_progress(str) callback.
    """

    # Oversample feedback relative to original data to bias toward recent patterns
    FEEDBACK_OVERSAMPLE = 5

    def __init__(
        self,
        model_path:    str,
        rules_path:    str,
        feedback_file: str,
        version_dir:   str,
        history_file:  str,
        dataset_path:  str = "",
        corrective_path: str = "",
    ):
        self._model_path    = model_path
        self._rules_path    = rules_path
        self._dataset_path  = dataset_path
        self._version_dir   = Path(version_dir)
        self._history_file  = Path(history_file)
        self._feedback      = FeedbackBuffer(feedback_file)
        self._corrective_path = corrective_path
        self._training      = False
        self._lock          = threading.Lock()

    # ── Public ────────────────────────────────────────────────────────────────

    def is_training(self) -> bool:
        return self._training

    def feedback_stats(self) -> dict:
        return self._feedback.stats()

    def add_feedback(
        self,
        features: dict,
        label: int,
        source: str = "user",
        verdict: str = "",
        confidence: float = 0.0,
    ) -> None:
        self._feedback.add(features, label, source, verdict, confidence)

    def version_history(self) -> list[dict]:
        try:
            if self._history_file.exists():
                return json.loads(self._history_file.read_text(encoding="utf-8"))
        except Exception:
            pass
        return []

    def retrain(
        self,
        on_progress: Callable[[str], None] | None = None,
        min_feedback: int = 10,
    ) -> dict:
        """
        Run full retrain in the calling thread (call from a background thread).
        Returns a result dict with before/after metrics and whether the model improved.
        """
        def progress(msg: str) -> None:
            logger.info(msg)
            if on_progress:
                on_progress(msg)

        with self._lock:
            if self._training:
                return {"error": "Training already in progress"}
            self._training = True

        try:
            return self._run_retrain(progress, min_feedback)
        finally:
            self._training = False

    def export_feedback_csv(self, out_path: str) -> int:
        return self._feedback.export_csv(out_path)

    def clear_feedback(self) -> None:
        self._feedback.clear()

    # ── Internal ──────────────────────────────────────────────────────────────

    def _run_retrain(self, progress, min_feedback: int) -> dict:
        import pandas as pd
        from joblib import dump, load as jload
        from sklearn.calibration import CalibratedClassifierCV
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.metrics import (
            accuracy_score, f1_score, precision_score,
            recall_score, roc_auc_score, precision_recall_curve,
        )
        from sklearn.model_selection import train_test_split
        from sklearn.preprocessing import StandardScaler

        # ── 1. Load feedback samples ────────────────────────────────────────
        records = self._feedback.get_all()
        n_feedback = len(records)
        progress(f"Feedback buffer: {n_feedback} labeled samples")

        if n_feedback < min_feedback:
            return {
                "error": f"Need at least {min_feedback} labeled samples to retrain "
                         f"(currently {n_feedback}). Keep confirming/rejecting alerts."
            }

        fb_rows = []
        for r in records:
            row = dict(r.get("features", {}))
            row["Label"] = int(r.get("label", 0))
            fb_rows.append(row)
        df_fb = pd.DataFrame(fb_rows).fillna(0)

        # ── 2. Load original dataset (optional but strongly recommended) ────
        df_orig = None
        if self._dataset_path and Path(self._dataset_path).exists():
            try:
                progress("Loading original dataset sample (50,000 rows)…")
                df_orig = pd.read_csv(self._dataset_path, low_memory=False, nrows=50_000)
                df_orig.columns = df_orig.columns.str.strip()
                col_map = {c.lower(): c for c in df_orig.columns}
                label_col = col_map.get("label") or col_map.get("class")
                if label_col:
                    df_orig["Label"] = (
                        ~df_orig[label_col].astype(str).str.upper().isin({"BENIGN"})
                    ).astype(int)
                    avail = [f for f in FEATURE_NAMES if f in df_orig.columns]
                    df_orig = df_orig[avail + ["Label"]].fillna(0)
                    # Align columns to feedback df
                    for col in FEATURE_NAMES:
                        if col not in df_orig.columns:
                            df_orig[col] = 0.0
                    progress(f"Original dataset: {len(df_orig):,} rows loaded")
                else:
                    df_orig = None
            except Exception as e:
                progress(f"Dataset load warning: {e} — retraining on feedback only")
                df_orig = None

        # ── 3. Build combined training dataset ──────────────────────────────
        # Oversample feedback to give it more influence than the original data
        df_feedback_os = pd.concat([df_fb] * self.FEEDBACK_OVERSAMPLE, ignore_index=True)

        if df_orig is not None:
            df_all = pd.concat([df_orig, df_feedback_os], ignore_index=True)
        else:
            df_all = df_feedback_os

        df_all = df_all.replace([np.inf, -np.inf], np.nan).fillna(0)
        available = [f for f in FEATURE_NAMES if f in df_all.columns]

        X = df_all[available].values.astype(np.float64)
        y = df_all["Label"].values.astype(int)

        n_pos = int(y.sum())
        n_neg = int(len(y) - n_pos)
        progress(f"Training set: {len(y):,} rows  |  ATTACK: {n_pos:,}  |  BENIGN: {n_neg:,}")

        if n_pos < 5 or n_neg < 5:
            return {"error": "Not enough samples of both classes. Add more feedback."}

        # ── 4. Get baseline metrics from current model ───────────────────────
        old_metrics = self._evaluate_current(X, y, available)
        if old_metrics:
            progress(
                f"Current model  F1={old_metrics['f1']:.1f}%  "
                f"Accuracy={old_metrics['accuracy']:.1f}%"
            )

        # ── 5. Scale + split ────────────────────────────────────────────────
        scaler = StandardScaler()
        X_sc   = scaler.fit_transform(X)
        test_size = max(0.2, min(0.3, 200 / len(y)))
        X_train, X_test, y_train, y_test = train_test_split(
            X_sc, y, test_size=test_size, random_state=42,
            stratify=y if min(n_pos, n_neg) >= 2 else None,
        )

        # ── 6. Train new calibrated Random Forest ───────────────────────────
        progress("Training new Random Forest (150 trees, Platt scaling)…")
        n_estimators = max(100, min(200, 50 + n_feedback * 2))
        base_rf = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=14,
            class_weight="balanced",
            min_samples_leaf=max(1, n_feedback // 50),
            random_state=42,
            n_jobs=-1,
        )
        calibrated = CalibratedClassifierCV(base_rf, method="sigmoid", cv=3)
        calibrated.fit(X_train, y_train)

        # ── 7. Evaluate new model ────────────────────────────────────────────
        y_proba    = calibrated.predict_proba(X_test)[:, 1]
        from sklearn.metrics import precision_recall_curve as prc
        precs, recs, thrs = prc(y_test, y_proba)
        f1s = np.where(
            (precs + recs) == 0, 0.0,
            2 * precs * recs / (precs + recs),
        )
        best_idx   = int(np.argmax(f1s[:-1]))
        opt_thresh = float(thrs[best_idx])
        y_pred_opt = (y_proba >= opt_thresh).astype(int)

        new_metrics = {
            "accuracy":  round(float(accuracy_score(y_test, y_pred_opt)) * 100, 2),
            "precision": round(float(precision_score(y_test, y_pred_opt, zero_division=0)) * 100, 2),
            "recall":    round(float(recall_score(y_test, y_pred_opt,    zero_division=0)) * 100, 2),
            "f1":        round(float(f1_score(y_test, y_pred_opt,        zero_division=0)) * 100, 2),
            "auc":       round(float(roc_auc_score(y_test, y_proba))     * 100, 2),
            "threshold": round(opt_thresh * 100, 2),
            "sample_size": int(len(y_test)),
            "n_estimators": n_estimators,
            "n_feedback": n_feedback,
        }
        progress(
            f"New model      F1={new_metrics['f1']:.1f}%  "
            f"Accuracy={new_metrics['accuracy']:.1f}%  "
            f"AUC={new_metrics['auc']:.1f}%"
        )

        # ── 8. Decide whether to adopt ───────────────────────────────────────
        improved = True
        if old_metrics:
            # Accept if F1 doesn't regress by more than 0.5 pp (small regression OK
            # because model is adapting to new distribution)
            improved = new_metrics["f1"] >= old_metrics["f1"] - 0.5
            if not improved:
                progress(
                    f"New model F1 ({new_metrics['f1']:.1f}%) is more than 0.5 pp below "
                    f"current ({old_metrics['f1']:.1f}%) — keeping current model."
                )
                return {
                    "improved": False,
                    "old": old_metrics,
                    "new": new_metrics,
                    "message": "Model NOT updated — new model performed worse on test set.",
                }

        # ── 9. Save versioned model ──────────────────────────────────────────
        self._version_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        version_path = self._version_dir / f"model_v{ts}.joblib"

        # Back up current model first
        if Path(self._model_path).exists():
            import shutil
            shutil.copy2(self._model_path, self._version_dir / f"model_before_{ts}.joblib")

        artifact = {
            "model":             calibrated,
            "scaler":            scaler,
            "features":          available,
            "optimal_threshold": opt_thresh,
            "trained_at":        ts,
            "n_feedback":        n_feedback,
        }
        dump(artifact, version_path)
        dump(artifact, self._model_path)
        progress(f"Model saved → {version_path.name}")

        # ── 10. Save updated metrics JSON ────────────────────────────────────
        try:
            from sklearn.metrics import roc_curve, confusion_matrix
            fpr, tpr, _ = roc_curve(y_test, y_proba)
            _ds = max(1, len(fpr) // 500)
            importances = calibrated.calibrated_classifiers_[0].estimator.feature_importances_
            metrics_data = dict(new_metrics)
            metrics_data.update({
                "cm":      confusion_matrix(y_test, y_pred_opt).tolist(),
                "fpr":     [round(v, 4) for v in fpr[::_ds].tolist()],
                "tpr":     [round(v, 4) for v in tpr[::_ds].tolist()],
                "feature_importances": {
                    k: round(float(v), 5) for k, v in zip(available, importances)
                },
            })
            metrics_path = Path(self._model_path).parent / "model_metrics.json"
            metrics_path.write_text(
                json.dumps(metrics_data, separators=(",", ":")), encoding="utf-8"
            )
        except Exception as e:
            logger.warning(f"Metrics JSON update failed: {e}")

        # ── 11. Rebuild corrective layer on feedback ─────────────────────────
        if self._corrective_path:
            try:
                corr = CorrectiveLayer(self._corrective_path, scaler=scaler)
                corr.fit_batch(records)
                progress(f"Corrective layer rebuilt with {n_feedback} samples")
            except Exception as e:
                logger.warning(f"Corrective rebuild: {e}")

        # ── 12. Reload the singleton model wrapper ───────────────────────────
        try:
            from detectors.adversarial import _ModelWrapper
            _ModelWrapper._instance = None  # force reload on next access
        except Exception:
            pass

        # ── 13. Record version history ────────────────────────────────────────
        history = self.version_history()
        history.append({
            "ts":       ts,
            "version":  version_path.name,
            "old_f1":   old_metrics.get("f1") if old_metrics else None,
            "new_f1":   new_metrics["f1"],
            "accuracy": new_metrics["accuracy"],
            "auc":      new_metrics["auc"],
            "n_feedback": n_feedback,
            "n_estimators": n_estimators,
        })
        try:
            self._history_file.write_text(
                json.dumps(history[-50:], indent=2), encoding="utf-8"
            )
        except Exception:
            pass

        delta = ""
        if old_metrics:
            diff = new_metrics["f1"] - old_metrics["f1"]
            delta = f" ({'+' if diff >= 0 else ''}{diff:.2f} pp vs previous)"
        progress(f"Retrain complete. F1={new_metrics['f1']:.1f}%{delta}")

        return {
            "improved":  True,
            "old":       old_metrics,
            "new":       new_metrics,
            "version":   version_path.name,
            "message":   f"Model updated to {version_path.name}",
        }

    def _evaluate_current(self, X: np.ndarray, y: np.ndarray, features: list) -> dict | None:
        """Quick evaluation of the current model on the combined dataset."""
        try:
            from joblib import load as jload
            from sklearn.metrics import accuracy_score, f1_score, roc_auc_score
            if not Path(self._model_path).exists():
                return None
            data   = jload(self._model_path)
            model  = data["model"]
            scaler = data["scaler"]
            saved_feats = data.get("features", features)
            # Align feature order
            X_aligned = np.zeros((len(X), len(saved_feats)))
            for i, fname in enumerate(saved_feats):
                if fname in features:
                    j = features.index(fname)
                    X_aligned[:, i] = X[:, j]
            X_sc  = scaler.transform(pd.DataFrame(X_aligned, columns=saved_feats))
            prob  = model.predict_proba(X_sc)[:, 1]
            t     = float(data.get("optimal_threshold", 0.5))
            pred  = (prob >= t).astype(int)
            return {
                "accuracy": round(float(accuracy_score(y, pred)) * 100, 2),
                "f1":       round(float(f1_score(y, pred, zero_division=0)) * 100, 2),
                "auc":      round(float(roc_auc_score(y, prob)) * 100, 2),
            }
        except Exception as e:
            logger.debug(f"_evaluate_current: {e}")
            return None


# ══════════════════════════════════════════════════════════════════════════════
# ── Module-level singleton helpers ────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

_feedback_buf: FeedbackBuffer | None = None
_corrective:   CorrectiveLayer | None = None
_trainer:      AdaptiveTrainer | None = None


def get_feedback_buffer() -> FeedbackBuffer:
    global _feedback_buf
    if _feedback_buf is None:
        try:
            import config as _cfg
            _feedback_buf = FeedbackBuffer(_cfg.FEEDBACK_FILE)
        except Exception:
            _feedback_buf = FeedbackBuffer("feedback_buffer.jsonl")
    return _feedback_buf


def get_corrective_layer(scaler=None) -> CorrectiveLayer:
    global _corrective
    if _corrective is None:
        try:
            import config as _cfg
            _corrective = CorrectiveLayer(_cfg.CORRECTIVE_FILE, scaler=scaler)
        except Exception:
            _corrective = CorrectiveLayer("corrective_layer.joblib", scaler=scaler)
    return _corrective


def get_trainer() -> AdaptiveTrainer:
    global _trainer
    if _trainer is None:
        try:
            import config as _cfg
            _trainer = AdaptiveTrainer(
                model_path     = _cfg.MODEL_FILENAME,
                rules_path     = _cfg.RULES_CONFIG,
                feedback_file  = _cfg.FEEDBACK_FILE,
                version_dir    = _cfg.MODEL_VERSION_DIR,
                history_file   = _cfg.VERSION_HISTORY_FILE,
                dataset_path   = _cfg.DATASET_FILENAME,
                corrective_path= _cfg.CORRECTIVE_FILE,
            )
        except Exception:
            _trainer = AdaptiveTrainer(
                model_path    = "ddos_detector_model.joblib",
                rules_path    = "rules_config.json",
                feedback_file = "feedback_buffer.jsonl",
                version_dir   = "model_versions",
                history_file  = "model_version_history.json",
            )
    return _trainer
