import os
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

BASE_DIR = Path(__file__).parent

# Secrets — set in .env, never hardcoded
GEMINI_API_KEY: str = os.environ.get("GEMINI_API_KEY", "")
GEMINI_API_URL: str = (
    "https://generativelanguage.googleapis.com/v1beta"
    "/models/gemini-2.0-flash:generateContent"
)

# Groq — free LLM API (llama-3.3-70b-versatile, 30 req/min free tier)
GROQ_API_KEY: str = os.environ.get("GROQ_API_KEY", "")
GROQ_MODEL: str   = "llama-3.3-70b-versatile"

# File paths
MODEL_FILENAME: str         = str(BASE_DIR / "ddos_detector_model.joblib")
ANOMALY_MODEL_FILENAME: str = str(BASE_DIR / "anomaly_model.joblib")
DATASET_FILENAME: str       = str(BASE_DIR / "cicddos2019_dataset.csv")
METRICS_FILE: str           = str(BASE_DIR / "model_metrics.json")
FEEDBACK_FILE: str          = str(BASE_DIR / "feedback_buffer.jsonl")
CORRECTIVE_FILE: str        = str(BASE_DIR / "corrective_layer.joblib")
MODEL_VERSION_DIR: str      = str(BASE_DIR / "model_versions")
VERSION_HISTORY_FILE: str   = str(BASE_DIR / "model_version_history.json")
PHISHING_DATASET: str       = str(BASE_DIR / "Phising_dataset_predict.csv")
RULES_CONFIG: str           = str(BASE_DIR / "rules_config.json")
LOG_FILE: str               = str(BASE_DIR / "security_alerts.log")

# Server
FLASK_HOST: str = os.environ.get("HOST", "0.0.0.0")
FLASK_PORT: int = int(os.environ.get("PORT", 5000))
FLASK_DEBUG: bool = os.environ.get("DEBUG", "false").lower() == "true"

# Runtime limits
MAX_ALERTS_IN_MEMORY: int = 500
SNIFFER_FILTER: str = "ip"

# ── New-feature settings ──────────────────────────────────────────────────────

# Threat Intelligence — AbuseIPDB (get free key at https://www.abuseipdb.com/account/api)
ABUSEIPDB_API_KEY: str = os.environ.get("ABUSEIPDB_API_KEY", "")

# ARP monitor — set to your router/gateway IP to flag gateway-MAC hijacks as critical
GATEWAY_IP: str = os.environ.get("GATEWAY_IP", "")

# File Integrity Monitoring — comma-separated list of directories to watch.
# Default is the detectors/ source directory only (stable Python source, not runtime files).
# The project root is intentionally excluded from the default: it contains dynamic files
# like fim_baseline.json and blocked_ips.json that change constantly and cause false alarms.
# Set FIM_WATCH_DIRS in .env to monitor your own directories (e.g. Documents, System32).
_fim_default = str(BASE_DIR / "detectors")
FIM_WATCH_DIRS: list[str] = [
    d.strip() for d in os.environ.get("FIM_WATCH_DIRS", _fim_default).split(",")
    if d.strip()
]
FIM_BASELINE_FILE: str = str(BASE_DIR / "fim_baseline.json")

# ML confidence threshold (0–100 %).  When the model is retrained, an F1-optimal
# threshold is computed automatically and stored in the .joblib file — that value
# is used at runtime unless overridden here via the environment variable.
# Set ATTACK_THRESHOLD=0 to always use the model's own optimal threshold.
ATTACK_CONFIDENCE_THRESHOLD: float = float(os.environ.get("ATTACK_THRESHOLD", 0))

# Flow tracker settings
FLOW_MIN_PACKETS: int = int(os.environ.get("FLOW_MIN_PACKETS", 5))
FLOW_TIMEOUT_S: float = float(os.environ.get("FLOW_TIMEOUT_S", 10.0))

# IP heuristics (sliding window in seconds)
IP_WINDOW_S: float            = float(os.environ.get("IP_WINDOW_S", 10.0))
SYN_ACK_RATIO_THRESHOLD: float = float(os.environ.get("SYN_ACK_RATIO", 5.0))
CONN_RATE_THRESHOLD: int      = int(os.environ.get("CONN_RATE", 150))
PORT_SPREAD_THRESHOLD: int    = int(os.environ.get("PORT_SPREAD", 30))
SUSTAINED_ATTACK_N: int       = int(os.environ.get("SUSTAINED_N", 3))
