"""
routes/protect.py
━━━━━━━━━━━━━━━━━
AEGIS Active Defence endpoints.

All routes require auth (JWT).
Client provides their Cloudflare API token + Zone ID once,
stored encrypted in their profile. AEGIS then acts on their behalf.

Endpoints:
  POST /api/protect/connect          Connect a domain to Cloudflare
  GET  /api/protect/status           Get protection status for all connected zones
  POST /api/protect/auto-defend      Scan domain + push all fixes automatically
  POST /api/protect/block-ip         Block an IP at Cloudflare edge
  POST /api/protect/unblock-ip       Remove IP block
  GET  /api/protect/blocked-ips      List IPs blocked at Cloudflare
  GET  /api/protect/analytics        24-hour attack analytics
  POST /api/protect/harden           Apply all security settings
  GET  /api/protect/email-security   Check SPF/DKIM/DMARC
  DELETE /api/protect/disconnect     Remove a zone
"""
import re
from flask import Blueprint, request, jsonify
import utils.db_core as dbl
from utils.auth   import token_required
from utils.logger import log_event
from services.cloudflare_service import (
    validate_zone, block_ip, unblock_ip, get_blocked_ips,
    get_security_settings, apply_security_hardening,
    get_waf_status, get_security_analytics,
    check_email_security, auto_defend,
)
from services.domain_service import (
    get_virustotal, get_security_headers,
    get_urlscan, get_alienvault_otx,
)
from services.ip_service     import get_ip_reputation, get_abuseipdb
from utils.scoring_engine    import ai_threat_score, compute_health_score
import threading

protect_bp = Blueprint("protect", __name__)


def _clean_domain(raw: str) -> str:
    d = raw.strip().lower()
    return re.sub(r"^https?://", "", d).split("/")[0].strip()


def _get_zone(user: dict, domain: str) -> dict | None:
    """Return the stored zone config for a domain."""
    zones = user.get("cf_zones", {})
    return zones.get(domain)


def _save_zone(email: str, user: dict, domain: str, zone_data: dict):
    zones = dict(user.get("cf_zones", {}))
    zones[domain] = zone_data
    dbl.update_user(email, {"cf_zones": zones})


def _remove_zone(email: str, user: dict, domain: str):
    zones = dict(user.get("cf_zones", {}))
    zones.pop(domain, None)
    dbl.update_user(email, {"cf_zones": zones})


# ── Connect a domain ──────────────────────────────────────────
@protect_bp.route("/connect", methods=["POST"])
@token_required
def connect_zone(current_user):
    """
    Register a client's Cloudflare zone with AEGIS.
    Body: { domain, cf_token, zone_id }
    """
    data    = request.get_json(force=True) or {}
    domain  = _clean_domain(data.get("domain",   ""))
    token   = data.get("cf_token",  "").strip()
    zone_id = data.get("zone_id",   "").strip()

    if not domain or not token or not zone_id:
        return jsonify({"error": "domain, cf_token and zone_id are all required"}), 400

    # Validate credentials with Cloudflare
    info = validate_zone(token, zone_id)
    if not info.get("valid"):
        return jsonify({"error": f"Cloudflare validation failed: {info.get('error')}"}), 400

    user = dbl.get_user(current_user) or {}
    _save_zone(current_user, user, domain, {
        "cf_token": token,
        "zone_id":  zone_id,
        "domain":   info.get("domain", domain),
        "plan":     info.get("plan", "Free"),
        "status":   info.get("status", "active"),
        "ns":       info.get("ns", []),
        "connected_at": __import__("datetime").datetime.utcnow().isoformat(),
    })
    log_event("CF_ZONE_CONNECTED", user=current_user, domain=domain,
              plan=info.get("plan"))
    return jsonify({
        "message": f"✅ {domain} connected to AEGIS Active Defence",
        "domain":  domain,
        "plan":    info.get("plan"),
        "ns":      info.get("ns"),
    })


# ── Protection status ─────────────────────────────────────────
@protect_bp.route("/status", methods=["GET"])
@token_required
def protection_status(current_user):
    """Return Cloudflare security settings for all connected zones."""
    user  = dbl.get_user(current_user) or {}
    zones = user.get("cf_zones", {})

    if not zones:
        return jsonify({"protected_domains": [], "count": 0,
                        "message": "No domains connected yet"})

    results = []
    for domain, cfg in zones.items():
        token   = cfg.get("cf_token", "")
        zone_id = cfg.get("zone_id",  "")
        settings = get_security_settings(token, zone_id)
        blocked  = get_blocked_ips(token, zone_id)

        # Score the current settings
        score = 0
        if str(settings.get("ssl",              "")).lower() in ("full", "strict"): score += 20
        if str(settings.get("always_use_https", "")).lower() == "on":               score += 15
        if str(settings.get("bot_fight_mode",   "")).lower() == "on":               score += 20
        if str(settings.get("min_tls_version",  "")).lower() in ("1.2", "1.3"):     score += 15
        if str(settings.get("security_level",   "")).lower() in ("high","under_attack"): score += 20
        if str(settings.get("automatic_https_rewrites","")).lower() == "on":        score += 10

        results.append({
            "domain":          domain,
            "plan":            cfg.get("plan", "Free"),
            "protection_score":score,
            "grade":           "A+" if score>=95 else "A" if score>=80 else "B" if score>=60 else "C" if score>=40 else "F",
            "settings":        settings,
            "blocked_ip_count":len(blocked),
            "connected_at":    cfg.get("connected_at", ""),
        })

    return jsonify({"protected_domains": results, "count": len(results)})


# ── Auto-defend ───────────────────────────────────────────────
@protect_bp.route("/auto-defend", methods=["POST"])
@token_required
def run_auto_defend(current_user):
    """
    One-click: scan the domain with AEGIS + push all possible
    Cloudflare defences automatically.
    Body: { domain }
    """
    data   = request.get_json(force=True) or {}
    domain = _clean_domain(data.get("domain", ""))

    if not domain:
        return jsonify({"error": "domain required"}), 400

    user = dbl.get_user(current_user) or {}
    cfg  = _get_zone(user, domain)
    if not cfg:
        return jsonify({
            "error": f"{domain} is not connected to AEGIS. Connect it first via /api/protect/connect"
        }), 404

    token   = cfg["cf_token"]
    zone_id = cfg["zone_id"]

    # Run AEGIS scan in parallel
    scan_results: dict = {}
    lock = threading.Lock()

    def run(key, fn, *args):
        try:   val = fn(*args)
        except Exception as e: val = {"error": str(e)}
        with lock: scan_results[key] = val

    threads = [
        threading.Thread(target=run, args=("virustotal",       get_virustotal,       domain)),
        threading.Thread(target=run, args=("security_headers", get_security_headers, domain)),
        threading.Thread(target=run, args=("urlscan",          get_urlscan,          domain)),
        threading.Thread(target=run, args=("alienvault",       get_alienvault_otx,   domain)),
        threading.Thread(target=run, args=("ip_reputation",    get_ip_reputation,    domain)),
    ]
    for t in threads: t.start()
    for t in threads: t.join(timeout=25)

    ip = scan_results.get("ip_reputation", {}).get("query", domain)
    scan_results["abuseipdb"]    = get_abuseipdb(ip)
    scan_results["ai_threat"]    = ai_threat_score(scan_results)
    scan_results["health_score"] = compute_health_score(scan_results)

    # Push all defences
    defence_report = auto_defend(token, zone_id, domain, scan_results)

    log_event("AUTO_DEFEND", user=current_user, domain=domain,
              actions=defence_report.get("actions_taken", 0),
              ips_blocked=len(defence_report.get("ips_blocked", [])))

    return jsonify({
        "domain":         domain,
        "scan":           {
            "health_score": scan_results.get("health_score", 0),
            "threat_level": scan_results.get("ai_threat", {}).get("level", "N/A"),
            "threat_score": scan_results.get("ai_threat", {}).get("score", 0),
        },
        "defence":        defence_report,
        "message":        defence_report.get("summary", "Auto-defend complete"),
    })


# ── Block IP at Cloudflare edge ───────────────────────────────
@protect_bp.route("/block-ip", methods=["POST"])
@token_required
def cf_block_ip(current_user):
    data    = request.get_json(force=True) or {}
    domain  = _clean_domain(data.get("domain", ""))
    ip      = data.get("ip",     "").strip()
    reason  = data.get("reason", "Manual block via AEGIS")

    if not domain or not ip:
        return jsonify({"error": "domain and ip required"}), 400

    user = dbl.get_user(current_user) or {}
    cfg  = _get_zone(user, domain)
    if not cfg:
        return jsonify({"error": f"{domain} not connected"}), 404

    result = block_ip(cfg["cf_token"], cfg["zone_id"], ip, reason)
    log_event("CF_BLOCK_IP", user=current_user, domain=domain, ip=ip,
              success=result.get("success"))
    return jsonify(result)


# ── Unblock IP ────────────────────────────────────────────────
@protect_bp.route("/unblock-ip", methods=["POST"])
@token_required
def cf_unblock_ip(current_user):
    data   = request.get_json(force=True) or {}
    domain = _clean_domain(data.get("domain", ""))
    ip     = data.get("ip", "").strip()

    if not domain or not ip:
        return jsonify({"error": "domain and ip required"}), 400

    user = dbl.get_user(current_user) or {}
    cfg  = _get_zone(user, domain)
    if not cfg:
        return jsonify({"error": f"{domain} not connected"}), 404

    result = unblock_ip(cfg["cf_token"], cfg["zone_id"], ip)
    return jsonify(result)


# ── List blocked IPs ──────────────────────────────────────────
@protect_bp.route("/blocked-ips", methods=["GET"])
@token_required
def cf_blocked_ips(current_user):
    domain = _clean_domain(request.args.get("domain", ""))
    if not domain:
        return jsonify({"error": "domain query param required"}), 400

    user = dbl.get_user(current_user) or {}
    cfg  = _get_zone(user, domain)
    if not cfg:
        return jsonify({"error": f"{domain} not connected"}), 404

    blocked = get_blocked_ips(cfg["cf_token"], cfg["zone_id"])
    return jsonify({"domain": domain, "blocked_ips": blocked, "count": len(blocked)})


# ── Analytics ─────────────────────────────────────────────────
@protect_bp.route("/analytics", methods=["GET"])
@token_required
def cf_analytics(current_user):
    domain = _clean_domain(request.args.get("domain", ""))
    if not domain:
        return jsonify({"error": "domain query param required"}), 400

    user = dbl.get_user(current_user) or {}
    cfg  = _get_zone(user, domain)
    if not cfg:
        return jsonify({"error": f"{domain} not connected"}), 404

    analytics = get_security_analytics(cfg["cf_token"], cfg["zone_id"])
    return jsonify({"domain": domain, **analytics})


# ── One-click hardening ───────────────────────────────────────
@protect_bp.route("/harden", methods=["POST"])
@token_required
def cf_harden(current_user):
    data   = request.get_json(force=True) or {}
    domain = _clean_domain(data.get("domain", ""))
    if not domain:
        return jsonify({"error": "domain required"}), 400

    user = dbl.get_user(current_user) or {}
    cfg  = _get_zone(user, domain)
    if not cfg:
        return jsonify({"error": f"{domain} not connected"}), 404

    report = apply_security_hardening(cfg["cf_token"], cfg["zone_id"])
    log_event("CF_HARDEN", user=current_user, domain=domain,
              applied=len(report.get("applied", [])))
    return jsonify({"domain": domain, **report})


# ── Email security ────────────────────────────────────────────
@protect_bp.route("/email-security", methods=["GET"])
@token_required
def cf_email_security(current_user):
    domain = _clean_domain(request.args.get("domain", ""))
    if not domain:
        return jsonify({"error": "domain query param required"}), 400

    user = dbl.get_user(current_user) or {}
    cfg  = _get_zone(user, domain)
    if not cfg:
        return jsonify({"error": f"{domain} not connected"}), 404

    result = check_email_security(cfg["cf_token"], cfg["zone_id"], domain)
    return jsonify(result)


# ── Disconnect zone ───────────────────────────────────────────
@protect_bp.route("/disconnect", methods=["DELETE"])
@token_required
def disconnect_zone(current_user):
    data   = request.get_json(force=True) or {}
    domain = _clean_domain(data.get("domain", ""))
    if not domain:
        return jsonify({"error": "domain required"}), 400

    user = dbl.get_user(current_user) or {}
    if not _get_zone(user, domain):
        return jsonify({"error": f"{domain} is not connected"}), 404

    _remove_zone(current_user, user, domain)
    log_event("CF_ZONE_DISCONNECTED", user=current_user, domain=domain)
    return jsonify({"message": f"✅ {domain} disconnected from AEGIS Active Defence"})
