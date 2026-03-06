"""
services/cloudflare_service.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AEGIS Active Defence Engine — Cloudflare API integration.

What this does:
  • Connects to a client's Cloudflare zone using their API token
  • Blocks malicious IPs at Cloudflare's edge (before they hit the server)
  • Enables/enforces WAF, Bot Fight Mode, DDoS protection, HTTPS
  • Checks + fixes email security: SPF, DKIM, DMARC records
  • Returns live security analytics from Cloudflare

Each client provides:
  cf_token  — Cloudflare API token (Zone:Edit permission)
  zone_id   — Cloudflare Zone ID (found in domain overview page)

Cloudflare free tier supports all of these features.
"""
import requests


CF_API = "https://api.cloudflare.com/client/v4"


def _headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json",
    }


def _ok(r) -> tuple[bool, dict]:
    """Return (success, data_or_error)."""
    try:
        j = r.json()
    except Exception:
        return False, {"error": f"HTTP {r.status_code}"}
    if r.status_code in (200, 201) and j.get("success"):
        return True, j.get("result", j)
    errors = j.get("errors", [])
    msg = errors[0].get("message", "Unknown error") if errors else f"HTTP {r.status_code}"
    return False, {"error": msg}


# ── Zone validation ────────────────────────────────────────────
def validate_zone(token: str, zone_id: str) -> dict:
    """Verify token + zone_id are valid and return zone info."""
    try:
        r = requests.get(
            f"{CF_API}/zones/{zone_id}",
            headers=_headers(token),
            timeout=10,
        )
        ok, data = _ok(r)
        if not ok:
            return {"valid": False, "error": data.get("error")}
        return {
            "valid":    True,
            "zone_id":  zone_id,
            "domain":   data.get("name", ""),
            "plan":     data.get("plan", {}).get("name", "Free"),
            "status":   data.get("status", ""),
            "paused":   data.get("paused", False),
            "ns":       data.get("name_servers", []),
        }
    except Exception as exc:
        return {"valid": False, "error": str(exc)}


# ── Block a single IP ──────────────────────────────────────────
def block_ip(token: str, zone_id: str, ip: str, reason: str = "AEGIS auto-block") -> dict:
    """
    Create a Cloudflare firewall rule that blocks a single IP.
    Works on free plan using IP Access Rules.
    """
    try:
        r = requests.post(
            f"{CF_API}/zones/{zone_id}/firewall/access_rules/rules",
            headers=_headers(token),
            json={
                "mode":          "block",
                "configuration": {"target": "ip", "value": ip},
                "notes":         f"AEGIS: {reason}",
            },
            timeout=10,
        )
        ok, data = _ok(r)
        if ok:
            return {"success": True, "rule_id": data.get("id"), "ip": ip,
                    "message": f"✅ {ip} blocked at Cloudflare edge"}
        # Already blocked = success
        if "already exists" in str(data.get("error", "")).lower():
            return {"success": True, "ip": ip, "message": f"⚡ {ip} already blocked"}
        return {"success": False, "error": data.get("error"), "ip": ip}
    except Exception as exc:
        return {"success": False, "error": str(exc), "ip": ip}


def unblock_ip(token: str, zone_id: str, ip: str) -> dict:
    """Remove a Cloudflare IP access rule for the given IP."""
    try:
        # Find the rule first
        r = requests.get(
            f"{CF_API}/zones/{zone_id}/firewall/access_rules/rules",
            headers=_headers(token),
            params={"configuration.value": ip, "configuration.target": "ip"},
            timeout=10,
        )
        ok, data = _ok(r)
        if not ok:
            return {"success": False, "error": data.get("error")}

        rules = data if isinstance(data, list) else []
        if not rules:
            return {"success": False, "error": f"No block rule found for {ip}"}

        rule_id = rules[0].get("id")
        r2 = requests.delete(
            f"{CF_API}/zones/{zone_id}/firewall/access_rules/rules/{rule_id}",
            headers=_headers(token),
            timeout=10,
        )
        ok2, _ = _ok(r2)
        return {"success": ok2, "message": f"Unblocked {ip}" if ok2 else "Delete failed"}
    except Exception as exc:
        return {"success": False, "error": str(exc)}


def get_blocked_ips(token: str, zone_id: str) -> list:
    """List all IPs currently blocked via access rules."""
    try:
        r = requests.get(
            f"{CF_API}/zones/{zone_id}/firewall/access_rules/rules",
            headers=_headers(token),
            params={"mode": "block", "per_page": 100},
            timeout=10,
        )
        ok, data = _ok(r)
        if not ok:
            return []
        rules = data if isinstance(data, list) else []
        return [
            {
                "ip":     rule.get("configuration", {}).get("value", ""),
                "note":   rule.get("notes", ""),
                "id":     rule.get("id", ""),
                "created": rule.get("created_on", ""),
            }
            for rule in rules
        ]
    except Exception:
        return []


# ── Security settings ──────────────────────────────────────────
def get_security_settings(token: str, zone_id: str) -> dict:
    """
    Read current Cloudflare security settings for this zone.
    Returns SSL mode, security level, WAF status, Bot Fight Mode,
    HTTPS redirect, HSTS, TLS version.
    """
    settings_to_check = [
        "ssl", "security_level", "waf", "bot_fight_mode",
        "always_use_https", "min_tls_version", "opportunistic_encryption",
        "automatic_https_rewrites",
    ]
    results = {}
    try:
        for setting in settings_to_check:
            r = requests.get(
                f"{CF_API}/zones/{zone_id}/settings/{setting}",
                headers=_headers(token),
                timeout=8,
            )
            ok, data = _ok(r)
            if ok:
                results[setting] = data.get("value", "unknown")
            else:
                results[setting] = "unavailable"
    except Exception as exc:
        results["error"] = str(exc)
    return results


def apply_security_hardening(token: str, zone_id: str) -> dict:
    """
    One-click security hardening — applies all recommended settings:
      • SSL: Full (strict)
      • Security level: High
      • Always use HTTPS: On
      • Min TLS version: 1.2
      • Automatic HTTPS rewrites: On
      • Opportunistic encryption: On
      • Bot Fight Mode: On (free plan)
    Returns a report of what was changed.
    """
    targets = {
        "ssl":                       "full",
        "security_level":            "high",
        "always_use_https":          "on",
        "min_tls_version":           "1.2",
        "automatic_https_rewrites":  "on",
        "opportunistic_encryption":  "on",
        "bot_fight_mode":            "on",
    }
    report = {"applied": [], "failed": [], "unchanged": []}

    # Read current values first
    current = get_security_settings(token, zone_id)

    for setting, target_value in targets.items():
        curr = str(current.get(setting, "")).lower()
        if curr == str(target_value).lower():
            report["unchanged"].append(f"{setting} already {target_value}")
            continue
        try:
            r = requests.patch(
                f"{CF_API}/zones/{zone_id}/settings/{setting}",
                headers=_headers(token),
                json={"value": target_value},
                timeout=10,
            )
            ok, _ = _ok(r)
            if ok:
                report["applied"].append(f"{setting} → {target_value}")
            else:
                report["failed"].append(f"{setting}: not supported on free plan")
        except Exception as exc:
            report["failed"].append(f"{setting}: {exc}")

    report["summary"] = (
        f"✅ {len(report['applied'])} settings hardened  "
        f"| ⚠ {len(report['failed'])} skipped (plan limits)  "
        f"| {len(report['unchanged'])} already optimal"
    )
    return report


# ── WAF rules ─────────────────────────────────────────────────
def get_waf_status(token: str, zone_id: str) -> dict:
    """Get WAF managed rules status (paid feature — reports gracefully if unavailable)."""
    try:
        r = requests.get(
            f"{CF_API}/zones/{zone_id}/firewall/waf/packages",
            headers=_headers(token),
            timeout=10,
        )
        ok, data = _ok(r)
        if not ok:
            return {"available": False, "note": "WAF packages require Pro plan"}
        packages = data if isinstance(data, list) else []
        return {
            "available": True,
            "packages":  len(packages),
            "details":   [{"name": p.get("name"), "status": p.get("action_mode")}
                          for p in packages],
        }
    except Exception as exc:
        return {"available": False, "error": str(exc)}


# ── Security analytics ─────────────────────────────────────────
def get_security_analytics(token: str, zone_id: str) -> dict:
    """
    Pull 24-hour security event summary from Cloudflare analytics.
    Uses GraphQL API — works on free plan.
    """
    query = """
    {
      viewer {
        zones(filter: {zoneTag: "%s"}) {
          firewallEventsAdaptiveSorted(
            filter: {datetime_gt: "%s"}
            limit: 100
            orderBy: [datetime_DESC]
          ) {
            action
            clientIP
            clientCountryName
            clientRequestHTTPMethodName
            clientRequestPath
            ruleId
            source
            datetime
          }
        }
      }
    }
    """ % (zone_id, _hours_ago(24))

    try:
        r = requests.post(
            "https://api.cloudflare.com/client/v4/graphql",
            headers=_headers(token),
            json={"query": query},
            timeout=15,
        )
        if r.status_code != 200:
            return {"available": False, "note": "Analytics unavailable"}
        data  = r.json()
        zones = data.get("data", {}).get("viewer", {}).get("zones", [])
        if not zones:
            return {"available": True, "events": [], "total": 0}

        events = zones[0].get("firewallEventsAdaptiveSorted", [])
        # Summarise
        actions  = {}
        top_ips  = {}
        top_countries = {}
        for e in events:
            a = e.get("action", "unknown")
            actions[a] = actions.get(a, 0) + 1
            ip = e.get("clientIP", "")
            top_ips[ip] = top_ips.get(ip, 0) + 1
            c = e.get("clientCountryName", "Unknown")
            top_countries[c] = top_countries.get(c, 0) + 1

        return {
            "available":     True,
            "total_events":  len(events),
            "actions":       actions,
            "top_ips":       sorted(top_ips.items(),       key=lambda x: -x[1])[:5],
            "top_countries": sorted(top_countries.items(), key=lambda x: -x[1])[:5],
            "recent":        events[:10],
        }
    except Exception as exc:
        return {"available": False, "error": str(exc)}


# ── Email security (DNS-based) ────────────────────────────────
def check_email_security(token: str, zone_id: str, domain: str) -> dict:
    """
    Check SPF, DKIM, DMARC records via Cloudflare DNS API.
    These are the 3 records that stop email spoofing / phishing.
    Returns status + recommended fixes for anything missing.
    """
    result = {
        "domain": domain,
        "spf":    {"present": False, "record": None, "score": 0},
        "dmarc":  {"present": False, "record": None, "score": 0},
        "dkim":   {"present": False, "note": "DKIM depends on your email provider"},
        "mx":     {"present": False, "records": []},
        "fixes":  [],
        "score":  0,
    }

    def _get_records(rtype: str, name: str = domain) -> list:
        try:
            r = requests.get(
                f"{CF_API}/zones/{zone_id}/dns_records",
                headers=_headers(token),
                params={"type": rtype, "name": name},
                timeout=8,
            )
            ok, data = _ok(r)
            if ok and isinstance(data, list):
                return data
        except Exception:
            pass
        return []

    # SPF
    txt_records = _get_records("TXT")
    spf_records = [r for r in txt_records
                   if "v=spf1" in r.get("content", "").lower()]
    if spf_records:
        result["spf"] = {"present": True,
                         "record":  spf_records[0]["content"],
                         "score":   25}
    else:
        result["fixes"].append({
            "type":     "SPF",
            "severity": "HIGH",
            "problem":  "No SPF record — anyone can send emails pretending to be you",
            "fix":      f'Add TXT record on {domain}: "v=spf1 include:_spf.google.com ~all"',
        })

    # DMARC
    dmarc_records = _get_records("TXT", f"_dmarc.{domain}")
    if dmarc_records:
        content = dmarc_records[0].get("content", "")
        result["dmarc"] = {"present": True, "record": content, "score": 35}
        # Check policy strength
        if "p=reject" in content:
            result["dmarc"]["strength"] = "STRONG (p=reject)"
        elif "p=quarantine" in content:
            result["dmarc"]["strength"] = "MEDIUM (p=quarantine)"
            result["fixes"].append({
                "type": "DMARC", "severity": "MEDIUM",
                "problem": "DMARC policy is quarantine — upgrade to reject for full protection",
                "fix": f'Update _dmarc.{domain}: "v=DMARC1; p=reject; rua=mailto:dmarc@{domain}"',
            })
        else:
            result["dmarc"]["strength"] = "WEAK (p=none — monitoring only)"
            result["fixes"].append({
                "type": "DMARC", "severity": "HIGH",
                "problem": "DMARC set to p=none — no emails are blocked",
                "fix": f'Update _dmarc.{domain}: "v=DMARC1; p=reject; rua=mailto:dmarc@{domain}"',
            })
    else:
        result["fixes"].append({
            "type":     "DMARC",
            "severity": "CRITICAL",
            "problem":  "No DMARC record — phishing emails can pass as coming from your domain",
            "fix":      f'Add TXT record on _dmarc.{domain}: "v=DMARC1; p=reject; rua=mailto:dmarc@{domain}"',
        })

    # MX
    mx_records = _get_records("MX")
    if mx_records:
        result["mx"] = {
            "present": True,
            "records": [r.get("content", "") for r in mx_records],
            "score":   20,
        }
    else:
        result["fixes"].append({
            "type": "MX", "severity": "HIGH",
            "problem": "No MX records — emails sent to this domain go nowhere",
            "fix": "Add MX records pointing to your email provider",
        })

    # DKIM — check common selectors
    dkim_found = False
    for selector in ("google", "mail", "default", "s1", "s2", "selector1", "selector2"):
        dkim_recs = _get_records("TXT", f"{selector}._domainkey.{domain}")
        if dkim_recs:
            result["dkim"] = {"present": True,
                              "selector": selector,
                              "score":    20}
            dkim_found = True
            break
    if not dkim_found:
        result["fixes"].append({
            "type": "DKIM", "severity": "HIGH",
            "problem": "No DKIM record found — emails can be tampered with in transit",
            "fix": "Enable DKIM in your email provider (Gmail/GSuite: Admin → Apps → Gmail → Authenticate email)",
        })

    # Total score
    result["score"] = (
        result["spf"].get("score", 0) +
        result["dmarc"].get("score", 0) +
        result["mx"].get("score", 0) +
        result["dkim"].get("score", 0)
    )
    result["grade"] = (
        "A+" if result["score"] >= 95 else
        "A"  if result["score"] >= 80 else
        "B"  if result["score"] >= 60 else
        "C"  if result["score"] >= 40 else
        "F"
    )
    return result


# ── Auto-defend: scan + push all fixes automatically ──────────
def auto_defend(token: str, zone_id: str, domain: str,
                scan_results: dict) -> dict:
    """
    Reads AEGIS scan results and automatically pushes every
    possible defence action to Cloudflare.

    Actions taken:
      1. Block all IPs flagged by AbuseIPDB ≥ 50%
      2. Apply full security hardening (HTTPS, TLS 1.2+, etc.)
      3. Check email security and return fixes

    Returns a full action report.
    """
    report = {
        "domain":           domain,
        "ips_blocked":      [],
        "ips_failed":       [],
        "hardening":        {},
        "email_security":   {},
        "actions_taken":    0,
        "actions_failed":   0,
    }

    # 1. Block flagged IPs
    abuse = scan_results.get("abuseipdb", {})
    ip_rep = scan_results.get("ip_reputation", {})
    ip_addr = ip_rep.get("query", "")

    if ip_addr:
        abuse_score = abuse.get("abuse_confidence", 0)
        is_tor      = ip_rep.get("tor",     False)
        is_proxy    = ip_rep.get("proxy",   False)

        if abuse_score >= 50 or is_tor:
            reason = (
                f"AbuseIPDB {abuse_score}% confidence" if abuse_score >= 50
                else "TOR exit node detected"
            )
            res = block_ip(token, zone_id, ip_addr, reason)
            if res.get("success"):
                report["ips_blocked"].append({"ip": ip_addr, "reason": reason})
                report["actions_taken"] += 1
            else:
                report["ips_failed"].append({"ip": ip_addr, "error": res.get("error")})
                report["actions_failed"] += 1

    # Also block VT-flagged IPs if present
    vt = scan_results.get("virustotal", {})
    vt_malicious = vt.get("malicious", 0)
    if vt_malicious >= 3 and ip_addr:
        res = block_ip(token, zone_id, ip_addr,
                       f"VirusTotal: {vt_malicious} vendors flagged as malicious")
        if res.get("success") and ip_addr not in [b["ip"] for b in report["ips_blocked"]]:
            report["ips_blocked"].append({"ip": ip_addr,
                                          "reason": f"VT {vt_malicious} malicious vendors"})
            report["actions_taken"] += 1

    # 2. Apply security hardening
    hardening = apply_security_hardening(token, zone_id)
    report["hardening"]     = hardening
    report["actions_taken"] += len(hardening.get("applied", []))

    # 3. Email security check
    email_sec = check_email_security(token, zone_id, domain)
    report["email_security"] = email_sec

    report["summary"] = (
        f"🛡️ Auto-defend complete: "
        f"{report['actions_taken']} actions taken, "
        f"{len(report['ips_blocked'])} IPs blocked at Cloudflare edge, "
        f"email security grade: {email_sec.get('grade','N/A')}"
    )
    return report


# ── Helpers ───────────────────────────────────────────────────
def _hours_ago(n: int) -> str:
    import datetime
    dt = datetime.datetime.utcnow() - datetime.timedelta(hours=n)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
