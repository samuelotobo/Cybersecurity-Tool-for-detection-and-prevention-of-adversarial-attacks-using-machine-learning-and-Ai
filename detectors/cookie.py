import logging
import threading

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.svm import SVC

logger = logging.getLogger(__name__)

_TRAINING_DATA = [
    {"name": "_ga",        "is_third_party": True,  "expires_in_days": 730, "is_secure": False, "is_http_only": False, "label": 1},
    {"name": "session_id", "is_third_party": False, "expires_in_days": 0,   "is_secure": True,  "is_http_only": True,  "label": 0},
    {"name": "JSESSIONID", "is_third_party": False, "expires_in_days": 0,   "is_secure": True,  "is_http_only": True,  "label": 0},
    {"name": "NID",        "is_third_party": True,  "expires_in_days": 180, "is_secure": True,  "is_http_only": False, "label": 1},
    {"name": "user_pref",  "is_third_party": False, "expires_in_days": 365, "is_secure": False, "is_http_only": False, "label": 0},
    {"name": "__utma",     "is_third_party": True,  "expires_in_days": 730, "is_secure": False, "is_http_only": False, "label": 1},
    {"name": "csrftoken",  "is_third_party": False, "expires_in_days": 0,   "is_secure": True,  "is_http_only": False, "label": 0},
]

_FEATURES = ["name_encoded", "is_third_party", "expires_in_days", "is_secure", "is_http_only"]


class CookieDetector:
    def __init__(self) -> None:
        self._model: SVC | None = None
        self._scaler: StandardScaler | None = None
        self._encoder: LabelEncoder | None = None
        self._train()

    def _train(self) -> None:
        df = pd.DataFrame(_TRAINING_DATA)
        enc = LabelEncoder()
        df["name_encoded"] = enc.fit_transform(df["name"])
        for col in ("is_third_party", "is_secure", "is_http_only"):
            df[col] = df[col].astype(int)

        X = df[_FEATURES]
        y = df["label"]
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.3, random_state=42
        )
        model = SVC(probability=True, random_state=42)
        model.fit(X_train, y_train)

        self._model = model
        self._scaler = scaler
        self._encoder = enc
        logger.info(f"Cookie detector trained — accuracy: {model.score(X_test, y_test):.2f}")

    def classify(self, cookie: dict) -> dict:
        """Classify a cookie dict as TRACKER or BENIGN."""
        name = cookie.get("name", "unknown")
        try:
            name_enc = self._encoder.transform([name])[0]
        except ValueError:
            name_enc = -1

        row = pd.DataFrame([{
            "name_encoded":    name_enc,
            "is_third_party":  int(cookie.get("is_third_party", False)),
            "expires_in_days": int(cookie.get("expires_in_days", 0)),
            "is_secure":       int(cookie.get("is_secure", False)),
            "is_http_only":    int(cookie.get("is_http_only", False)),
        }])

        try:
            X_scaled = self._scaler.transform(row[_FEATURES])
            pred = int(self._model.predict(X_scaled)[0])
            proba = self._model.predict_proba(X_scaled)[0]
            return {
                "name":       name,
                "verdict":    "TRACKER" if pred == 1 else "BENIGN",
                "confidence": round(float(max(proba)) * 100, 2),
            }
        except Exception as e:
            return {"name": name, "verdict": "UNKNOWN", "error": str(e)}


def start_sniffer(callback) -> None:
    """
    Start a Scapy HTTP sniffer in a daemon thread.
    callback(result_dict) is called for each detected cookie.
    Requires elevated privileges (administrator / root).
    """
    try:
        from scapy.all import sniff
        from scapy.layers.http import HTTPResponse  # fixed: was HTTP.Response

        detector = CookieDetector()

        def _process(pkt):
            if not pkt.haslayer(HTTPResponse):
                return
            layer = pkt[HTTPResponse]
            raw_cookie = layer.fields.get("Set_Cookie") or layer.fields.get("Cookie")
            if not raw_cookie:
                return
            raw = raw_cookie.decode("utf-8", errors="ignore") if isinstance(raw_cookie, bytes) else raw_cookie
            name = raw.split(";")[0].strip().split("=", 1)[0]
            result = detector.classify({"name": name})
            callback(result)

        t = threading.Thread(
            target=lambda: sniff(
                filter="tcp port 80 or tcp port 443",
                prn=_process,
                store=False,
            ),
            daemon=True,
            name="cookie-sniffer",
        )
        t.start()
        logger.info("Cookie sniffer started.")
    except PermissionError:
        logger.error("Cookie sniffer requires administrator/root privileges.")
    except Exception as e:
        logger.error(f"Cookie sniffer failed: {e}")
