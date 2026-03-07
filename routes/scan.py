"""routes/scan.py — Website / Email / Password scan endpoints."""
import re
import threading
import datetime
from flask import Blueprint, request, jsonify

from services.domain_service import (
    get_virustotal, get_ssl_grade, get_security_headers,
    get_dns_records, get_subdomains, get_whois,
    get_urlscan, get_alienvault_otx,
)
from services.ip_service     import get_ip_reputation, get_abuseipdb
from services.breach_service import check_email_breach, check_password_pwned
from utils.scoring_engine    import (
    ai_threat_score, compute_health_score, email_health_score,
)
import utils.db_core as dbl
from utils.logger import log_event

scan_bp = Blueprint("scan", __name__)


# ── Website scan ──────────────────────────────────────────────
@scan_bp.route("/website", methods=["POST"])
def scan_website():
    data   = request.get_json(force=True) or {}
    domain = data.get("domain", "").strip().lower()
    domain = re.sub(r"^https?://", "", domain).split("/")[0].strip()

    if not domain or "." not in domain:
        return jsonify({"error": "Valid domain required (e.g. example.com)"}), 400

    cached = dbl.cache_get(f"website:{domain}", max_age=300)
    if cached:
        cached["cached"] = True
        return jsonify(cached)

    results: dict = {}
    lock = threading.Lock()

    def run(key, fn, *args):
        try:
            val = fn(*args)
        except Exception as exc:
            val = {"error": str(exc)}
        with lock:
            results[key] = val

    threads = [
        threading.Thread(target=run, args=("ip_reputation",   get_ip_reputation,   domain)),
        threading.Thread(target=run, args=("dns_records",     get_dns_records,     domain)),
        threading.Thread(target=run, args=("subdomains",      get_subdomains,      domain)),
        threading.Thread(target=run, args=("whois",           get_whois,           domain)),
        threading.Thread(target=run, args=("security_headers",get_security_headers,domain)),
        threading.Thread(target=run, args=("virustotal",      get_virustotal,      domain)),
        threading.Thread(target=run, args=("urlscan",         get_urlscan,         domain)),
        threading.Thread(target=run, args=("alienvault",      get_alienvault_otx,  domain)),
    ]
    for t in threads: t.start()
    for t in threads: t.join(timeout=28)

    ip = results.get("ip_reputation", {}).get("query", domain)
    results["abuseipdb"]    = get_abuseipdb(ip)
    results["ssl_grade"]    = get_ssl_grade(domain)
    results["ai_threat"]    = ai_threat_score(results)
    results["health_score"] = compute_health_score(results)
    results["domain"]       = domain
    results["scanned_at"]   = datetime.datetime.utcnow().isoformat()
    results["cached"]       = False

    dbl.cache_set(f"website:{domain}", results)
    dbl.log_scan(domain, "website",
                 results["health_score"],
                 results["ai_threat"]["level"],
                 results["ai_threat"]["score"])
    log_event("SCAN_WEBSITE", domain=domain,
              health=results["health_score"],
              threat=results["ai_threat"]["level"])
    return jsonify(results)


# ── Email breach scan ─────────────────────────────────────────
@scan_bp.route("/email", methods=["POST"])
def scan_email():
    data  = request.get_json(force=True) or {}
    email = data.get("email", "").strip()
    if not email or "@" not in email:
        return jsonify({"error": "Valid email required"}), 400

    cached = dbl.cache_get(f"email:{email}", max_age=600)
    if cached:
        cached["cached"] = True
        return jsonify(cached)

    breach_data   = check_email_breach(email)
    password_data = {"pwned": False, "count": 0}
    health        = email_health_score(breach_data, password_data)

    result = {
        "email":          email,
        "breach_data":    breach_data,
        "password_check": password_data,
        "health":         health,
        "scanned_at":     datetime.datetime.utcnow().isoformat(),
        "cached":         False,
    }
    dbl.cache_set(f"email:{email}", result)
    dbl.log_scan(email, "email",
                 health["score"], health["level"], 100 - health["score"])
    return jsonify(result)


# ── Password k-anonymity check ────────────────────────────────
@scan_bp.route("/password", methods=["POST"])
def scan_password():
    password = (request.get_json(force=True) or {}).get("password", "")
    if not password:
        return jsonify({"error": "Password required"}), 400
    result = check_password_pwned(password)
    result["note"] = (
        "Only the first 5 characters of the SHA-1 hash were sent. "
        "Your actual password never left your browser."
    )
    return jsonify(result)


# ── Recent scans (public) ─────────────────────────────────────
@scan_bp.route("/history", methods=["GET"])
def scan_history():
    return jsonify({"scans": dbl.get_scan_logs(20)})
