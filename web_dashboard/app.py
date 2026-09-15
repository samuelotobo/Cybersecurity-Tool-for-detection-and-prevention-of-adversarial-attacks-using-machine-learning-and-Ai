"""
Security Monitor — Web Dashboard & Mobile Companion API.

Provides:
  - REST JSON API for all detectors (shared alert bus with desktop app)
  - Server-Sent Events (SSE) stream for real-time browser updates
  - Multi-tenant JWT authentication (one token per host/agent)
  - Mobile-responsive PWA frontend served at /
  - Interactive network map route served at /map

Run standalone (demo mode — no live sniffer):
    python -m web_dashboard.app

Run integrated (share bus with desktop_app.py):
    from web_dashboard.app import create_app, push_alert
    app = create_app(shared_bus=alert_queue)
    app.run(host="0.0.0.0", port=8080, threaded=True)

Requires:  pip install flask flask-cors PyJWT
"""

import json
import os
import queue
import secrets
import threading
import time
from collections import deque
from datetime import datetime, timezone, timedelta
from functools import wraps
from pathlib import Path
from typing import Callable

from flask import (
    Flask, Response, jsonify, render_template, request,
    send_from_directory, stream_with_context,
)

try:
    from flask_cors import CORS
    _CORS_OK = True
except ImportError:
    _CORS_OK = False

try:
    import jwt as pyjwt
    _JWT_OK = True
except ImportError:
    _JWT_OK = False


ROOT = Path(__file__).parent.parent

# ── Shared in-memory alert store ─────────────────────────────────────────────

_MAX_ALERTS = 1000
_alert_store: deque[dict] = deque(maxlen=_MAX_ALERTS)
_alert_lock  = threading.Lock()
_sse_queues: list[queue.Queue] = []
_sse_lock    = threading.Lock()

# Tenant registry: {tenant_id: {name, token, created_at, alert_count}}
_tenants: dict[str, dict] = {}
_tenants_lock = threading.Lock()

# JWT secret — generated fresh each run, stored in memory only
_JWT_SECRET = secrets.token_hex(32)
_JWT_ALGO   = "HS256"
_JWT_EXP_H  = 24   # token expires after 24 hours


def push_alert(alert: dict) -> None:
    """Thread-safe: push an alert to the in-memory store and broadcast to SSE clients."""
    entry = {**alert, "_id": int(time.time() * 1000)}
    with _alert_lock:
        _alert_store.appendleft(entry)
    with _sse_lock:
        dead = []
        for q in _sse_queues:
            try:
                q.put_nowait(entry)
            except queue.Full:
                dead.append(q)
        for q in dead:
            _sse_queues.remove(q)


# ── App factory ───────────────────────────────────────────────────────────────

def create_app(shared_bus: queue.Queue | None = None) -> Flask:
    """
    Create and configure the Flask application.

    shared_bus: if provided, a background thread will drain this queue
                and call push_alert() for each item (integration with desktop_app).
    """
    app = Flask(
        __name__,
        template_folder=str(Path(__file__).parent / "templates"),
        static_folder=str(Path(__file__).parent / "static"),
    )

    if _CORS_OK:
        CORS(app, resources={r"/api/*": {"origins": "*"}})

    if shared_bus is not None:
        _start_bus_relay(shared_bus)

    # ── Auth helpers ──────────────────────────────────────────────────────

    def _make_token(tenant_id: str) -> str:
        if not _JWT_OK:
            return f"demo-{tenant_id}"
        payload = {
            "sub": tenant_id,
            "iat": datetime.now(tz=timezone.utc),
            "exp": datetime.now(tz=timezone.utc) + timedelta(hours=_JWT_EXP_H),
        }
        return pyjwt.encode(payload, _JWT_SECRET, algorithm=_JWT_ALGO)

    def _verify_token(token: str) -> str | None:
        """Returns tenant_id or None."""
        if not _JWT_OK:
            # Demo mode: accept any "demo-<id>" token
            if token.startswith("demo-"):
                return token[5:]
            return None
        try:
            data = pyjwt.decode(token, _JWT_SECRET, algorithms=[_JWT_ALGO])
            return data.get("sub")
        except Exception:
            return None

    def require_auth(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            auth = request.headers.get("Authorization", "")
            token = auth.removeprefix("Bearer ").strip()
            if not token:
                token = request.args.get("token", "")
            tid = _verify_token(token)
            if tid is None:
                return jsonify({"error": "Unauthorized"}), 401
            return f(*args, tenant_id=tid, **kwargs)
        return decorated

    # ── Routes ────────────────────────────────────────────────────────────

    @app.route("/")
    def index():
        return render_template("mobile_dashboard.html")

    @app.route("/map")
    def network_map():
        map_path = ROOT / "network_map.html"
        if map_path.exists():
            return send_from_directory(str(ROOT), "network_map.html")
        return "<h2 style='font-family:sans-serif;color:#ef4444'>Map not yet generated — trigger some detections first.</h2>", 404

    # ── Auth API ──────────────────────────────────────────────────────────

    @app.route("/api/register", methods=["POST"])
    def register():
        """Register a new monitoring agent / tenant. Returns a JWT."""
        data = request.get_json(silent=True) or {}
        name = str(data.get("name", "unnamed"))[:64]
        tid  = secrets.token_hex(8)
        token = _make_token(tid)
        with _tenants_lock:
            _tenants[tid] = {
                "name":        name,
                "token":       token,
                "created_at":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "alert_count": 0,
            }
        return jsonify({"tenant_id": tid, "token": token, "name": name})

    @app.route("/api/login", methods=["POST"])
    def login():
        """Demo login: POST {name, password}. Returns a token. Password = 'monitor'."""
        data = request.get_json(silent=True) or {}
        pwd  = data.get("password", "")
        if pwd != os.environ.get("MONITOR_PASSWORD", "monitor"):
            return jsonify({"error": "Invalid credentials"}), 401
        name  = str(data.get("name", "admin"))[:64]
        tid   = secrets.token_hex(8)
        token = _make_token(tid)
        with _tenants_lock:
            _tenants[tid] = {
                "name":        name,
                "token":       token,
                "created_at":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "alert_count": 0,
            }
        return jsonify({"token": token, "tenant_id": tid})

    # ── Alerts API ────────────────────────────────────────────────────────

    @app.route("/api/alerts")
    @require_auth
    def get_alerts(tenant_id: str = ""):
        limit   = min(int(request.args.get("limit", 100)), _MAX_ALERTS)
        since   = request.args.get("since_id")
        sev     = request.args.get("severity")
        cat     = request.args.get("category")
        with _alert_lock:
            alerts = list(_alert_store)
        if since:
            try:
                since_id = int(since)
                alerts = [a for a in alerts if a.get("_id", 0) > since_id]
            except ValueError:
                pass
        if sev:
            alerts = [a for a in alerts if a.get("severity") == sev]
        if cat:
            alerts = [a for a in alerts if a.get("category") == cat]
        return jsonify({"alerts": alerts[:limit], "total": len(alerts)})

    @app.route("/api/alerts", methods=["POST"])
    @require_auth
    def post_alert(tenant_id: str = ""):
        """Remote agent posts an alert here."""
        data = request.get_json(silent=True)
        if not data or "rule_name" not in data:
            return jsonify({"error": "Missing rule_name"}), 400
        data["_tenant"] = tenant_id
        push_alert(data)
        with _tenants_lock:
            if tenant_id in _tenants:
                _tenants[tenant_id]["alert_count"] += 1
        return jsonify({"status": "ok"})

    @app.route("/api/alerts/clear", methods=["DELETE"])
    @require_auth
    def clear_alerts(tenant_id: str = ""):
        with _alert_lock:
            _alert_store.clear()
        return jsonify({"status": "cleared"})

    # ── SSE stream ────────────────────────────────────────────────────────

    @app.route("/api/stream")
    def sse_stream():
        """
        Server-Sent Events endpoint.  Browsers connect here for real-time updates.
        Supports optional ?token=<jwt> query param for mobile clients.
        """
        token = request.args.get("token", "")
        if not token:
            # Try Authorization header
            auth  = request.headers.get("Authorization", "")
            token = auth.removeprefix("Bearer ").strip()

        if not _verify_token(token):
            return Response("event: error\ndata: {\"error\":\"Unauthorized\"}\n\n",
                            status=401, mimetype="text/event-stream")

        q: queue.Queue = queue.Queue(maxsize=200)
        with _sse_lock:
            _sse_queues.append(q)

        def generate():
            yield "event: connected\ndata: {\"status\":\"connected\"}\n\n"
            try:
                while True:
                    try:
                        alert = q.get(timeout=25)
                        payload = json.dumps(alert, default=str)
                        yield f"event: alert\ndata: {payload}\n\n"
                    except queue.Empty:
                        yield "event: ping\ndata: {\"ts\":" + str(int(time.time())) + "}\n\n"
            except GeneratorExit:
                pass
            finally:
                with _sse_lock:
                    if q in _sse_queues:
                        _sse_queues.remove(q)

        return Response(
            stream_with_context(generate()),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
                "Connection": "keep-alive",
            },
        )

    # ── Stats & System ────────────────────────────────────────────────────

    @app.route("/api/stats")
    @require_auth
    def get_stats(tenant_id: str = ""):
        with _alert_lock:
            alerts = list(_alert_store)
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        cats   = {}
        for a in alerts:
            sev = a.get("severity", "low")
            counts[sev] = counts.get(sev, 0) + 1
            cat = a.get("category", "other")
            cats[cat] = cats.get(cat, 0) + 1
        return jsonify({
            "total_alerts":    len(alerts),
            "by_severity":     counts,
            "by_category":     cats,
            "connected_clients": len(_sse_queues),
            "server_time":     datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        })

    @app.route("/api/tenants")
    @require_auth
    def get_tenants(tenant_id: str = ""):
        with _tenants_lock:
            safe = {
                tid: {k: v for k, v in info.items() if k != "token"}
                for tid, info in _tenants.items()
            }
        return jsonify({"tenants": safe})

    @app.route("/api/blocked")
    @require_auth
    def get_blocked(tenant_id: str = ""):
        blocked_file = ROOT / "blocked_ips.json"
        try:
            if blocked_file.exists():
                return jsonify(json.loads(blocked_file.read_text(encoding="utf-8")))
        except Exception:
            pass
        return jsonify({})

    @app.route("/api/block", methods=["POST"])
    @require_auth
    def block_ip(tenant_id: str = ""):
        data = request.get_json(silent=True) or {}
        ip   = str(data.get("ip", "")).strip()
        if not ip:
            return jsonify({"error": "ip required"}), 400
        from detectors.ip_blocker import IPBlocker
        blocker = IPBlocker(on_event=push_alert)
        ttl = int(data.get("ttl_minutes", 60))
        ok, msg = blocker.block(ip, reason=data.get("reason", "Web dashboard block"), ttl_minutes=ttl)
        return jsonify({"ok": ok, "message": msg})

    # ── Health check ──────────────────────────────────────────────────────

    @app.route("/api/health")
    def health():
        return jsonify({"status": "ok", "time": datetime.now().isoformat()})

    return app


def _start_bus_relay(bus: queue.Queue) -> None:
    """Drain a shared queue and call push_alert() for each item."""
    def relay():
        while True:
            try:
                alert = bus.get(timeout=1)
                push_alert(alert)
            except queue.Empty:
                pass
            except Exception:
                pass
    threading.Thread(target=relay, daemon=True, name="BusRelay").start()


# ── Standalone entry point ────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(ROOT))

    app = create_app()

    # Seed a few demo alerts so the dashboard is not empty
    _demo_alerts = [
        {"rule_name": "ARP Spoofing — Gateway!", "severity": "critical", "source_ip": "192.168.1.50",
         "message": "Gateway MAC changed — possible MitM attack", "category": "arp",
         "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
        {"rule_name": "SSH Brute Force", "severity": "high", "source_ip": "185.220.101.34",
         "message": "26 SSH attempts from 185.220.101.34 within 60 s", "category": "brute_force",
         "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
        {"rule_name": "DNS C2 Beacon", "severity": "high", "source_ip": "10.0.0.42",
         "message": "152 DNS queries/min to beacon.attacker.io", "category": "dns",
         "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
        {"rule_name": "UEBA — Off-Hours Login", "severity": "medium", "source_ip": "DESKTOP-XYZ",
         "message": "User 'john.smith' logged in at 02:14 (night)", "category": "ueba",
         "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
        {"rule_name": "FIM — File Modified", "severity": "high", "source_ip": "localhost",
         "message": "Monitored file hash changed: C:\\Windows\\System32\\hosts", "category": "fim",
         "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    ]
    for a in _demo_alerts:
        push_alert(a)

    host = os.environ.get("MONITOR_HOST", "0.0.0.0")
    port = int(os.environ.get("MONITOR_PORT", 8080))
    print(f"\n  Security Monitor Web Dashboard")
    print(f"  Local:   http://127.0.0.1:{port}")
    print(f"  Network: http://<your-ip>:{port}")
    print(f"  Default password: monitor\n")
    app.run(host=host, port=port, threaded=True, debug=False)
