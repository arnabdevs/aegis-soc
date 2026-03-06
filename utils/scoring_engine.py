def ai_threat_score(results):
    score = 0
    factors = []
    
    vt = results.get("virustotal", {})
    if isinstance(vt, dict):
        malicious = vt.get("malicious", 0)
        if malicious > 0:
            score += min(malicious * 10, 50)
            factors.append(f"{malicious} VT detection(s)")

    abuse = results.get("abuseipdb", {})
    abuse_conf = abuse.get("abuse_confidence", 0)
    if abuse_conf > 0:
        score += (abuse_conf / 2)
        factors.append(f"AbuseIPDB confidence: {abuse_conf}%")

    level = "LOW"
    if score >= 75: level = "CRITICAL"
    elif score >= 50: level = "HIGH"
    elif score >= 25: level = "MEDIUM"

    return {
        "score": min(score, 100),
        "level": level,
        "factors": factors
    }

def compute_health_score(results):
    base = 100
    vt = results.get("virustotal", {})
    if isinstance(vt, dict) and vt.get("malicious", 0) > 0:
        base -= 30
    
    headers = results.get("security_headers", {})
    if isinstance(headers, dict) and any(v is None for k,v in headers.items() if k != "server"):
        base -= 10
        
    return max(base, 0)

def email_health_score(breach_data, password_data):
    score = 100
    if isinstance(breach_data, list) and len(breach_data) > 0:
        score -= min(len(breach_data) * 20, 60)
    
    if password_data.get("pwned"):
        score -= 40
        
    level = "SECURE"
    if score < 40: level = "CRITICAL"
    elif score < 70: level = "RISKY"
    
    return {"score": max(score, 0), "level": level}
