"""
Security Monitor — unified Flask dashboard.
Run:  python main_app.py          (start server + open browser)
      python main_app.py --train  (train all models then exit)
"""
import json
import logging
import queue
import sys
import threading
import webbrowser
from collections import deque
from datetime import datetime

from flask import Flask, Response, jsonify, render_template, request, stream_with_context

import config
from detectors.anomaly import AnomalyDetector
from detectors.ddos import Alert, DDosDetector
from detectors.email_phishing import analyze_email
from detectors.flow_tracker import FlowTracker
from detectors.ip_tracker import IPTracker
from detectors.fusion import MLCorroborator, fuse_verdict
from detectors.url_phishing import get_feature_names, predict_url

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(config.LOG_FILE, encoding="utf-8"),
    ],
)
logger = logging.getLogger(__name__)

# ── Flask app ─────────────────────────────────────────────────────────────────
app = Flask(__name__)

# ── Detectors ─────────────────────────────────────────────────────────────────
ddos = DDosDetector(
    model_path=config.MODEL_FILENAME,
    rules_path=config.RULES_CONFIG,
    threshold_override=config.ATTACK_CONFIDENCE_THRESHOLD,
)

anomaly = AnomalyDetector(config.ANOMALY_MODEL_FILENAME)

flow_tracker = FlowTracker(
    min_packets=config.FLOW_MIN_PACKETS,
    timeout_s=config.FLOW_TIMEOUT_S,
)

ip_tracker = IPTracker(
    window_s=config.IP_WINDOW_S,
    syn_ack_ratio_threshold=config.SYN_ACK_RATIO_THRESHOLD,
    conn_rate_threshold=config.CONN_RATE_THRESHOLD,
    port_spread_threshold=config.PORT_SPREAD_THRESHOLD,
    sustained_n=config.SUSTAINED_ATTACK_N,
)

ml_gate = MLCorroborator(config.ML_ALERT_MIN_FLOWS, config.IP_WINDOW_S)

# ── Shared state ──────────────────────────────────────────────────────────────
_alerts: deque[dict] = deque(maxlen=config.MAX_ALERTS_IN_MEMORY)
_traffic: deque[dict] = deque(maxlen=300)
_sse_clients: list[queue.Queue] = []
_stats: dict = {
    "total": 0, "attacks": 0, "suspicious": 0, "safe": 0,
    "rule_alerts": 0, "heuristic_alerts": 0,
}
_lock = threading.Lock()


def _broadcast(event: dict) -> None:
    payload = json.dumps(event)
    dead: list[queue.Queue] = []
    for q in _sse_clients:
        try:
            q.put_nowait(payload)
        except queue.Full:
            dead.append(q)
    for q in dead:
        try:
            _sse_clients.remove(q)
        except ValueError:
            pass


# ── Three-layer verdict fusion ─────────────────────────────────────────────────

def _fuse_verdict(
    ml_result: dict,
    anomaly_result: dict,
    rule_alerts: list[Alert],
    heuristic_alerts: list[dict],
    corroborated: bool = True,
) -> str:
    """Combine the three detection layers into a status (see detectors/fusion.py)."""
    return fuse_verdict(ml_result, anomaly_result, rule_alerts, heuristic_alerts, corroborated)


# ── Network sniffer ───────────────────────────────────────────────────────────

def _sniffer() -> None:
    try:
        from scapy.all import IP, TCP, UDP, sniff
    except ImportError:
        logger.warning("Scapy unavailable — live sniffing disabled.")
        return

    def _process(pkt) -> None:
        if not pkt.haslayer(IP):
            return

        ip     = pkt[IP]
        tcp_l  = pkt[TCP] if pkt.haslayer(TCP) else None
        udp_l  = pkt[UDP] if pkt.haslayer(UDP) else None
        proto  = "TCP" if tcp_l else "UDP" if udp_l else str(ip.proto)
        length = len(pkt)

        src_port  = (tcp_l or udp_l).sport if (tcp_l or udp_l) else 0
        dst_port  = (tcp_l or udp_l).dport if (tcp_l or udp_l) else 0
        proto_num = 6 if tcp_l else 17 if udp_l else int(ip.proto)
        tcp_flags = int(tcp_l.flags) if tcp_l else 0
        win       = int(tcp_l.window) if tcp_l else 0

        is_syn = bool(tcp_flags & 0x02) and not bool(tcp_flags & 0x10)
        is_ack = bool(tcp_flags & 0x10)
        is_new = is_syn  # SYN-only = new connection initiation

        # ── Layer 1: rule engine (per-packet) ────────────────────────────────
        packet_info = {
            "src_ip": ip.src, "dst_ip": ip.dst,
            "protocol": proto, "Length": length, "TTL": ip.ttl,
        }
        rule_alerts = ddos.check_rules(packet_info)

        # ── Layer 2: ML on mature flows ───────────────────────────────────────
        ml_result:      dict = {}
        anomaly_result: dict = {}

        flow_ready = flow_tracker.update(
            src_ip=ip.src, dst_ip=ip.dst,
            src_port=src_port, dst_port=dst_port,
            proto_num=proto_num, pkt_len=length,
            tcp_flags=tcp_flags, win=win,
        )
        if flow_ready:
            flow_features, _ = flow_ready
            if ddos.model_ready:
                ml_result = ddos.predict(flow_features)
            if anomaly.ready:
                anomaly_result = anomaly.score(flow_features)
            if (ml_result.get("verdict") in ("ATTACK", "SUSPICIOUS")
                    or anomaly_result.get("anomaly")):
                ml_gate.record(ip.src, ip.dst)

        # ── Layer 3: per-IP heuristics ────────────────────────────────────────
        heuristic_alerts = ip_tracker.update(
            src_ip=ip.src,
            dst_port=dst_port,
            is_syn=is_syn,
            is_ack=is_ack,
            is_new_connection=is_new,
            ml_verdict=ml_result.get("verdict") if ml_result else None,
        )

        # ── Verdict fusion ────────────────────────────────────────────────────
        status = _fuse_verdict(ml_result, anomaly_result, rule_alerts, heuristic_alerts,
                               ml_gate.is_active(ip.src, ip.dst))

        entry = {
            "timestamp":       datetime.now().strftime("%H:%M:%S"),
            "src_ip":          ip.src,
            "dst_ip":          ip.dst,
            "protocol":        proto,
            "length":          length,
            "ttl":             ip.ttl,
            "status":          status,
            "confidence":      ml_result.get("confidence"),
            "anomaly_score":   anomaly_result.get("score"),
            "rule_alerts":     [a.rule_name for a in rule_alerts],
            "heuristic_alerts":[h["rule_name"] for h in heuristic_alerts],
        }

        with _lock:
            _traffic.append(entry)
            _stats["total"] += 1
            if status == "ATTACK":
                _stats["attacks"] += 1
            elif status == "SUSPICIOUS":
                _stats["suspicious"] += 1
            else:
                _stats["safe"] += 1

            # Persist all rule-engine alerts
            for a in rule_alerts:
                _stats["rule_alerts"] += 1
                _alerts.append(a.to_dict())

            # Persist heuristic alerts as Alert-shaped dicts
            for h in heuristic_alerts:
                _stats["heuristic_alerts"] += 1
                _alerts.append({
                    "timestamp":       datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "rule_name":       h["rule_name"],
                    "severity":        h["severity"],
                    "message":         h["message"],
                    "source_ip":       h.get("source_ip", ip.src),
                    "destination_ip":  ip.dst,
                    "protocol":        proto,
                    "packet_features": {},
                })

        _broadcast({"type": "traffic", **entry})

    try:
        logger.info("Network sniffer starting…")
        sniff(filter=config.SNIFFER_FILTER, prn=_process, store=False)
    except Exception as e:
        logger.error(f"Sniffer stopped: {e}")


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template(
        "index.html",
        model_ready=ddos.model_ready,
        anomaly_ready=anomaly.ready,
        feature_names=ddos.feature_names,
        threshold=round(ddos.threshold * 100, 1),
    )


@app.route("/api/status")
def api_status():
    with _lock:
        return jsonify({
            "model_ready":   ddos.model_ready,
            "anomaly_ready": anomaly.ready,
            "threshold":     round(ddos.threshold * 100, 1),
            "stats":         dict(_stats),
            "active_flows":  flow_tracker.active_flows,
            "timestamp":     datetime.now().isoformat(),
        })


@app.route("/api/predict", methods=["POST"])
def api_predict():
    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"error": "JSON body required"}), 400
    ml     = ddos.predict(data)
    anm    = anomaly.score(data) if anomaly.ready else {}
    status = _fuse_verdict(ml, anm, [], [])
    return jsonify({**ml, "anomaly": anm, "status": status})


@app.route("/api/alerts")
def api_alerts():
    limit = min(int(request.args.get("limit", 100)), 500)
    with _lock:
        return jsonify(list(_alerts)[-limit:])


@app.route("/api/traffic")
def api_traffic():
    limit = min(int(request.args.get("limit", 50)), 300)
    with _lock:
        return jsonify(list(_traffic)[-limit:])


@app.route("/api/analyze-email", methods=["POST"])
def api_analyze_email():
    data    = request.get_json(force=True, silent=True) or {}
    content = data.get("content", "").strip()
    if not content:
        return jsonify({"error": "Email content required"}), 400
    return jsonify(analyze_email(content, config.GEMINI_API_KEY, config.GEMINI_API_URL))


@app.route("/api/analyze-url", methods=["POST"])
def api_analyze_url():
    data     = request.get_json(force=True, silent=True) or {}
    features = data.get("features")
    if not isinstance(features, list) or not features:
        return jsonify({"error": "features array required"}), 400
    return jsonify(predict_url(features, config.PHISHING_DATASET))


@app.route("/api/url-features")
def api_url_features():
    return jsonify({"features": get_feature_names(config.PHISHING_DATASET)})


@app.route("/stream")
def stream():
    client_q: queue.Queue = queue.Queue(maxsize=200)
    with _lock:
        _sse_clients.append(client_q)

    def _generate():
        yield "data: {\"type\":\"connected\"}\n\n"
        try:
            while True:
                try:
                    payload = client_q.get(timeout=20)
                    yield f"data: {payload}\n\n"
                except queue.Empty:
                    yield "data: {\"type\":\"heartbeat\"}\n\n"
        except GeneratorExit:
            pass
        finally:
            with _lock:
                try:
                    _sse_clients.remove(client_q)
                except ValueError:
                    pass

    return Response(
        stream_with_context(_generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    if "--train" in sys.argv:
        import train_model
        train_model.train_and_save_model()
        return

    sniffer = threading.Thread(target=_sniffer, daemon=True, name="sniffer")
    sniffer.start()

    url = f"http://127.0.0.1:{config.FLASK_PORT}"
    logger.info(f"Security Monitor → {url}")
    threading.Timer(1.5, lambda: webbrowser.open(url)).start()

    app.run(
        host=config.FLASK_HOST,
        port=config.FLASK_PORT,
        debug=config.FLASK_DEBUG,
        use_reloader=False,
        threaded=True,
    )


if __name__ == "__main__":
    main()
