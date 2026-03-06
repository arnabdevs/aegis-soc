import os
import requests
import hashlib

def check_email_breach(email):
    api_key = os.getenv("HIBP_API_KEY")
    if not api_key: return {"error": "HIBP API key missing"}
    try:
        headers = {"hibp-api-key": api_key, "user-agent": "AEGIS-SOC"}
        r = requests.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}", headers=headers, timeout=10)
        if r.status_code == 200: return r.json()
        if r.status_code == 404: return [] # No breaches
        return {"error": f"HIBP error {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def check_password_pwned(password):
    try:
        sha1_pwd = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1_pwd[:5], sha1_pwd[5:]
        r = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=10)
        if r.status_code == 200:
            hashes = (line.split(':') for line in r.text.splitlines())
            for h, count in hashes:
                if h == suffix:
                    return {"pwned": True, "count": int(count)}
        return {"pwned": False, "count": 0}
    except Exception as e:
        return {"error": str(e)}
