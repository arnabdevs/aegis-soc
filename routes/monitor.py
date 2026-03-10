"""routes/monitor.py — Daily monitoring management."""
import re
from flask import Blueprint, request, jsonify
import utils.database as dbl
from utils.auth import token_required

monitor_bp = Blueprint("monitor", __name__)


@monitor_bp.route("/list", methods=["GET"])
@token_required
def list_monitors(current_user):
    user = dbl.get_user(current_user) or {}
    return jsonify({
        "monitored":        user.get("monitored", []),
        "count":            len(user.get("monitored", [])),
        "telegram_enabled": bool(user.get("telegram_chat_id")),
        "email":            current_user,
    })


@monitor_bp.route("/add", methods=["POST"])
@token_required
def add_monitor(current_user):
    data   = request.get_json(force=True) or {}
    domain = data.get("domain", "").strip().lower()
    domain = re.sub(r"^https?://", "", domain).split("/")[0].strip()

    if not domain or "." not in domain:
        return jsonify({"error": "Valid domain required"}), 400

    user      = dbl.get_user(current_user) or {}
    monitored = list(user.get("monitored", []))

    if domain in monitored:
        return jsonify({"message": f"{domain} is already monitored"})
    if len(monitored) >= 10:
        return jsonify({"error": "Max 10 monitored sites on free tier"}), 400

    monitored.append(domain)
    dbl.update_user(current_user, {"monitored": monitored})
    return jsonify({"message": f"✅ {domain} added to daily monitoring"})


@monitor_bp.route("/remove", methods=["POST"])
@token_required
def remove_monitor(current_user):
    data   = request.get_json(force=True) or {}
    domain = data.get("domain", "").strip()
    user   = dbl.get_user(current_user) or {}
    lst    = list(user.get("monitored", []))

    if domain not in lst:
        return jsonify({"error": "Domain not in monitor list"}), 404

    lst.remove(domain)
    dbl.update_user(current_user, {"monitored": lst})
    return jsonify({"message": f"Removed {domain}"})


@monitor_bp.route("/settings", methods=["POST"])
@token_required
def update_settings(current_user):
    data    = request.get_json(force=True) or {}
    updates = {}
    if "telegram_chat_id" in data:
        updates["telegram_chat_id"] = data["telegram_chat_id"]
    if updates:
        dbl.update_user(current_user, updates)
    return jsonify({"message": "Settings updated ✅"})
