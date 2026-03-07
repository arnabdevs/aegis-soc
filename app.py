"""
╔══════════════════════════════════════════════════════════════╗
║        AEGIS SOC ENGINE v5.0 — HARDENED EDITION             ║
║        Owner : Arnab Kumar Das                               ║
║        GitHub: https://github.com/arnabdevs                ║
╚══════════════════════════════════════════════════════════════╝

Upgrades in v5:
  • bcrypt password hashing
  • Supabase PostgreSQL (data survives restarts)
  • Redis (Upstash) rate-limiter — persists across dyno restarts
  • Email verification on register
  • Cloudflare real-IP header handling (CF-Connecting-IP)
  • init_db() creates tables on first boot automatically
"""
import os
import datetime

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv

from routes.auth    import auth_bp
from routes.scan    import scan_bp
from routes.monitor import monitor_bp
from routes.admin   import admin_bp
from routes.protect import protect_bp
import utils.database as dbl
from utils.logger import log_event
from services.monitor_daemon import start_monitor_daemon

load_dotenv()

# ── App ───────────────────────────────────────────────────────
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "CHANGE-THIS-IN-PRODUCTION")

# ── CORS ──────────────────────────────────────────────────────
_frontend = os.getenv("FRONTEND_URL", "*")
CORS(
    app,
    resources={r"/api/*": {"origins": _frontend}},
    supports_credentials=True,
    allow_headers=["Content-Type", "Authorization"],
    methods=["GET", "POST", "DELETE", "OPTIONS"],
)


# ── Real-IP helper (respects Cloudflare CF-Connecting-IP) ─────
def _real_ip() -> str:
    # Cloudflare sets CF-Connecting-IP when proxying
    cf = request.headers.get("CF-Connecting-IP")
    if cf:
        return cf.strip()
    # Standard proxy header
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return get_remote_address()


# ── Rate limiter ──────────────────────────────────────────────
_redis_url = os.getenv("REDIS_URL", "").strip()
if _redis_url and "://" not in _redis_url:
    _redis_url = f"redis://{_redis_url}"

_limiter_storage = _redis_url if _redis_url else "memory://"

limiter = Limiter(
    key_func=_real_ip,
    app=app,
    default_limits=["500 per day", "100 per hour"],
    storage_uri=_limiter_storage,
)
print(f"[AEGIS] Rate limiter: {'Redis ✅' if _redis_url else 'memory'}")


# ── Firewall (blocks known malicious IPs) ─────────────────────
@app.before_request
def firewall():
    ip = _real_ip()
    if ip in dbl.get_blocked_ips():
        log_event("BLOCKED_REQUEST", ip=ip)
        return jsonify({
            "error": "Your IP is permanently blocked by AEGIS Firewall.",
            "code":  "IP_BLOCKED",
        }), 403


# ── Security headers ──────────────────────────────────────────
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"]        = "DENY"
    response.headers["X-XSS-Protection"]       = "1; mode=block"
    response.headers["Referrer-Policy"]        = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"]          = "no-store"
    return response


# ── Blueprints ────────────────────────────────────────────────
app.register_blueprint(auth_bp,    url_prefix="/api/auth")
app.register_blueprint(scan_bp,    url_prefix="/api/scan")
app.register_blueprint(monitor_bp, url_prefix="/api/monitor")
app.register_blueprint(admin_bp,   url_prefix="/api/admin")
app.register_blueprint(protect_bp, url_prefix="/api/protect")


# ── Public endpoints ──────────────────────────────────────────
@app.route("/", methods=["GET"])
def root():
    return jsonify({
        "name":    "AEGIS SOC Engine",
        "version": "5.0",
        "owner":   "Arnab Kumar Das",
        "github":  "https://github.com/arnabdevs",
        "status":  "online",
    })


@app.route("/api/health", methods=["GET"])
def health():
    s = dbl.get_stats()
    return jsonify({
        "status":         "AEGIS SOC Engine Online",
        "version":        "4.0",
        "owner":          "Arnab Kumar Das",
        "github":         "arnabdevs",
        "total_users":    dbl.count_users(),
        "blocked_ips":    dbl.count_blocked_ips(),
        "total_scans":    s.get("total_scans", 0),
        "high_risk":      s.get("high_risk",   0),
        "uptime_since":   app.config.get("start_time", ""),
        "time":           datetime.datetime.utcnow().isoformat(),
    })


@app.route("/api/stats/dashboard", methods=["GET"])
def dashboard_stats():
    s      = dbl.get_stats()
    scans  = dbl.get_scan_logs(20)
    users  = dbl.get_all_users()

    risk_dist = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for scan in scans:
        lvl = scan.get("threat_level", "LOW")
        risk_dist[lvl] = risk_dist.get(lvl, 0) + 1

    return jsonify({
        "total_scans":       s.get("total_scans", 0),
        "high_risk":         s.get("high_risk",   0),
        "blocked_ips":       dbl.count_blocked_ips(),
        "active_monitors":   sum(len(u.get("monitored", [])) for u in users),
        "risk_distribution": risk_dist,
        "recent_scans":      scans[:5],
        "api_usage":         dbl.get_api_usage(),
    })


# ── Boot sequence ─────────────────────────────────────────────
# Must run outside __main__ so gunicorn workers also execute it
app.config["start_time"] = datetime.datetime.utcnow().isoformat()
dbl.init_db()          # creates Postgres tables on first deploy (noop for memory mode)
start_monitor_daemon() # background 24-h report thread


# ── Local dev ─────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    print(f"\n  🛡  AEGIS SOC Engine v5.0\n"
          f"  👤  Arnab Kumar Das | github.com/arnabdevs\n"
          f"  🌐  http://localhost:{port}\n")
    app.run(host="0.0.0.0", port=port, debug=False)
