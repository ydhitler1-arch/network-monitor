"""Flask API server: routes + background monitoring loop."""

import hashlib
import os
import threading
import time
from datetime import timedelta

from flask import Flask, jsonify, make_response, request
from flask_cors import CORS

from backend import alerts, auth, config, db, devices, ports, security, traffic
from backend.limiter import limiter

FRONTEND_DIST = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend", "dist"
)

app = Flask(__name__, static_folder=FRONTEND_DIST, static_url_path="")
app.secret_key = config.SECRET_KEY
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=config.COOKIE_SECURE,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
)

CORS(app, origins=config.CORS_ORIGINS, supports_credentials=True)
limiter.init_app(app)
app.register_blueprint(auth.auth_bp)


@app.before_request
def _require_auth():
    return auth.enforce_auth()


@app.after_request
def _security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


_state_lock = threading.Lock()
_state = {"devices": [], "devices_scanned_at": None}

TRAFFIC_INTERVAL = 2
TRAFFIC_PERSIST_INTERVAL = 5
DEVICE_SCAN_INTERVAL = 30
RISKY_PORT_LIST = list(alerts.HIGH_RISK_PORTS.keys())
MAX_PORTS_PER_SCAN = 1024


def _monitor_loop():
    last_device_scan = 0
    last_persist = 0
    while True:
        try:
            sample = traffic.sample()
            alerts.check_traffic_spike(traffic.get_history())

            now = time.time()
            if now - last_persist >= TRAFFIC_PERSIST_INTERVAL:
                db.insert_traffic(sample)
                last_persist = now

            if now - last_device_scan >= DEVICE_SCAN_INTERVAL:
                found = devices.scan_devices()
                with _state_lock:
                    _state["devices"] = found
                    _state["devices_scanned_at"] = now
                alerts.check_new_devices(found)
                for dev in found:
                    try:
                        result = ports.socket_scan(dev["ip"], ports=RISKY_PORT_LIST, timeout=0.3)
                        if result:
                            alerts.check_risky_ports(dev["ip"], result)
                    except Exception:
                        pass
                last_device_scan = now
        except Exception:
            pass
        time.sleep(TRAFFIC_INTERVAL)


def start_background_monitor():
    db.init_db()
    thread = threading.Thread(target=_monitor_loop, daemon=True)
    thread.start()


@app.route("/")
def index():
    index_path = os.path.join(FRONTEND_DIST, "index.html")
    if not os.path.exists(index_path):
        return (
            "Frontend build not found. Run `npm run build` in frontend/ first, "
            "or use `npm run dev` there for local development instead.",
            404,
        )
    return app.send_static_file("index.html")


@app.route("/api/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/api/meta")
def meta():
    return jsonify(
        {
            "nmap_available": ports.nmap_available(),
            "scapy_available": devices.scapy_available(),
            "high_risk_ports": alerts.HIGH_RISK_PORTS,
        }
    )


@app.route("/api/traffic/current")
def traffic_current():
    return jsonify(traffic.get_current() or {})


@app.route("/api/traffic/history")
def traffic_history():
    limit = request.args.get("limit", default=120, type=int)
    data = traffic.get_history(limit)
    # Build an ETag from the last timestamp so unchanged data returns 304.
    etag = hashlib.md5(
        str(data[-1]["timestamp"]).encode() if data else b"empty"
    ).hexdigest()[:16]
    if request.headers.get("If-None-Match") == etag:
        return make_response("", 304)
    resp = make_response(jsonify(data))
    resp.headers["ETag"] = etag
    resp.headers["Cache-Control"] = "no-cache"
    return resp


@app.route("/api/traffic/history/extended")
def traffic_history_extended():
    """Longer-range history from SQLite (5s cadence, ~24h retention) rather
    than the in-memory ring buffer (2s cadence, ~10 minutes)."""
    limit = request.args.get("limit", default=2000, type=int)
    limit = max(1, min(limit, db.TRAFFIC_HISTORY_RETENTION))
    return jsonify(db.get_traffic_history(limit))


@app.route("/api/devices")
def list_devices():
    with _state_lock:
        return jsonify({"devices": _state["devices"], "scanned_at": _state["devices_scanned_at"]})


@app.route("/api/devices/scan", methods=["POST"])
@limiter.limit(config.SCAN_RATE_LIMIT)
def rescan_devices():
    found = devices.scan_devices()
    with _state_lock:
        _state["devices"] = found
        _state["devices_scanned_at"] = time.time()
    new_alerts = alerts.check_new_devices(found)
    return jsonify({"devices": found, "new_alerts": new_alerts})


@app.route("/api/ports/scan")
@limiter.limit(config.SCAN_RATE_LIMIT)
def scan_ports_route():
    host = request.args.get("host")
    if not host:
        return jsonify({"error": "host query parameter is required"}), 400

    allowed, resolved_or_reason = security.is_scan_target_allowed(host)
    if not allowed:
        return jsonify({"error": resolved_or_reason}), 403

    ports_param = request.args.get("ports")
    port_list = None
    if ports_param:
        try:
            port_list = [int(p.strip()) for p in ports_param.split(",") if p.strip()]
        except ValueError:
            return jsonify({"error": "ports must be a comma-separated list of integers"}), 400
        if len(port_list) > MAX_PORTS_PER_SCAN:
            return jsonify({"error": f"too many ports requested (max {MAX_PORTS_PER_SCAN})"}), 400
        if any(p < 1 or p > 65535 for p in port_list):
            return jsonify({"error": "ports must be between 1 and 65535"}), 400

    use_nmap = request.args.get("engine") == "nmap"
    result = ports.scan_ports(host, ports=port_list, use_nmap=use_nmap)
    result["new_alerts"] = alerts.check_risky_ports(host, result["open_ports"])
    return jsonify(result)


@app.route("/api/alerts")
def list_alerts():
    limit = request.args.get("limit", default=100, type=int)
    data = alerts.get_recent_alerts(limit)
    etag = hashlib.md5(
        str(data[0]["id"]).encode() if data else b"empty"
    ).hexdigest()[:16]
    if request.headers.get("If-None-Match") == etag:
        return make_response("", 304)
    resp = make_response(jsonify(data))
    resp.headers["ETag"] = etag
    resp.headers["Cache-Control"] = "no-cache"
    return resp
