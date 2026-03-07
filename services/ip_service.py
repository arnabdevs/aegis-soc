"""services/ip_service.py — ip-api.com IP intelligence + AbuseIPDB with auto-block."""
import os
import requests as req
from utils.logger import log_api_call, log_event


def get_ip_reputation(domain_or_ip: str) -> dict:
    fields = (
        "status,message,country,countryCode,region,regionName,"
        "city,zip,lat,lon,timezone,isp,org,as,query,proxy,tor,hosting"
    )
    try:
        r = req.get(
            f"http://ip-api.com/json/{domain_or_ip}?fields={fields}",
            timeout=10,
        )
        log_api_call("ipapi", "ok")
        return r.json() if r.status_code == 200 else {}
    except Exception:
        log_api_call("ipapi", "error")
        return {}


def get_abuseipdb(ip: str) -> dict:
    api_key = os.getenv("ABUSEIPDB_API_KEY", "")
    if not api_key:
        return {"error": "ABUSEIPDB_API_KEY not configured",
                "abuse_confidence": 0, "total_reports": 0}
    try:
        r = req.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=10,
        )
        log_api_call("abuseipdb", "ok" if r.status_code == 200 else "error")

        if r.status_code == 200:
            d    = r.json().get("data", {})
            conf = d.get("abuseConfidenceScore", 0)

            if conf >= 80:
                import utils.db_core as dbl
                dbl.add_blocked_ip(ip, reason=f"AbuseIPDB confidence {conf}%")
                log_event("AUTO_BLOCK", ip=ip,
                          reason=f"AbuseIPDB confidence {conf}%")

            return {
                "abuse_confidence":   conf,
                "total_reports":      d.get("totalReports",      0),
                "num_distinct_users": d.get("numDistinctUsers",  0),
                "last_reported":      d.get("lastReportedAt",    None),
                "country":            d.get("countryCode",       ""),
                "isp":                d.get("isp",               ""),
                "domain":             d.get("domain",            ""),
                "is_tor":             d.get("isTor",             False),
                "is_whitelisted":     d.get("isWhitelisted",     False),
            }
        return {"abuse_confidence": 0,
                "error": f"AbuseIPDB returned {r.status_code}"}
    except Exception as exc:
        log_api_call("abuseipdb", "error")
        return {"abuse_confidence": 0, "error": str(exc)}
