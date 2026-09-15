import logging

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

logger = logging.getLogger(__name__)

_model_cache: dict | None = None


def _load_or_train(dataset_path: str) -> dict | None:
    global _model_cache
    if _model_cache is not None:
        return _model_cache

    try:
        df = pd.read_csv(dataset_path)
        df = df.loc[:, ~df.columns.str.contains("^Unnamed")]

        # Find the label column (tolerates "Phising" typo in dataset)
        target_col = next(
            (c for c in df.columns if "phish" in c.lower()),
            None,
        )
        if target_col is None:
            logger.error("No phishing label column found in dataset.")
            return None

        X = df.drop(columns=[target_col]).select_dtypes(include=[np.number]).fillna(0)
        y = df[target_col]

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42
        )
        clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
        clf.fit(X_train, y_train)
        acc = clf.score(X_test, y_test)
        logger.info(f"URL phishing model trained — accuracy: {acc:.4f}")

        _model_cache = {"clf": clf, "features": list(X.columns)}
    except FileNotFoundError:
        logger.warning(f"Phishing dataset not found: {dataset_path}")
    except Exception as e:
        logger.error(f"URL phishing model error: {e}")

    return _model_cache


def predict_url(features: list, dataset_path: str = "") -> dict:
    """
    Predict phishing given a list of numerical feature values.
    Values must align with the order returned by get_feature_names().
    """
    data = _load_or_train(dataset_path)
    if not data:
        return {"error": "URL phishing model unavailable — check dataset file."}

    clf = data["clf"]
    feature_names: list[str] = data["features"]

    try:
        arr = np.array(features[: len(feature_names)], dtype=np.float64).reshape(1, -1)
        pred = int(clf.predict(arr)[0])
        proba = clf.predict_proba(arr)[0]
        return {
            "prediction": pred,
            "verdict": "PHISHING" if pred == 1 else "LEGITIMATE",
            "confidence": round(float(max(proba)) * 100, 2),
            "features_used": feature_names,
        }
    except Exception as e:
        return {"error": str(e)}


def get_feature_names(dataset_path: str = "") -> list[str]:
    data = _load_or_train(dataset_path)
    return data["features"] if data else []
