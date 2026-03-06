"""routes/admin.py — IP blocking, event logs, admin stats."""
import datetime
from flask import Blueprint, request, jsonify
import utils.database as dbl
from utils.auth   import token_required
from utils.logger import log_event

admin_bp = Blueprint("admin", __name__)


@admin_bp.route("/blocked-ips", methods=["GET"])
@token_required
def get_blocked_ips(current_user):
    blocked = list(dbl.get_blocked_ips())
    return jsonify({"blocked_ips": blocked, "count": len(blocked)})


@admin_bp.route("/block-ip", methods=["POST"])
@token_required
def block_ip(current_user):
    ip = (request.get_json(force=True) or {}).get("ip", "").strip()
    if not ip:
        return jsonify({"error": "IP address required"}), 400
    dbl.add_blocked_ip(ip, reason=f"manual by {current_user}")
    log_event("MANUAL_BLOCK", ip=ip, by=current_user)
    return jsonify({"message": f"✅ IP {ip} permanently blocked"})


@admin_bp.route("/unblock-ip", methods=["POST"])
@token_required
def unblock_ip(current_user):
    ip = (request.get_json(force=True) or {}).get("ip", "").strip()
    dbl.remove_blocked_ip(ip)
    return jsonify({"message": f"IP {ip} unblocked"})


@admin_bp.route("/events", methods=["GET"])
@token_required
def get_events(current_user):
    return jsonify({"events": dbl.get_events(50)})


@admin_bp.route("/api-usage", methods=["GET"])
@token_required
def api_usage(current_user):
    return jsonify({
        "api_calls": dbl.get_api_usage(),
        "api_logs":  dbl.get_api_logs(20),
    })


@admin_bp.route("/stats", methods=["GET"])
@token_required
def stats(current_user):
    s = dbl.get_stats()
    users = dbl.get_all_users()
    return jsonify({
        "total_users":     dbl.count_users(),
        "blocked_ips":     dbl.count_blocked_ips(),
        "total_scans":     s.get("total_scans", 0),
        "high_risk":       s.get("high_risk",   0),
        "api_calls":       dbl.get_api_usage(),
        "monitored_sites": sum(len(u.get("monitored", [])) for u in users),
        "server_time":     datetime.datetime.utcnow().isoformat(),
    })
