import os
import requests
import socket
import json
from datetime import datetime

VT_API = "https://www.virustotal.com/api/v3"
OTX_API = "https://otx.alienvault.com/api/v1"

def get_virustotal(domain):
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key: return {"error": "API key missing"}
    try:
        headers = {"x-apikey": api_key}
        r = requests.get(f"{VT_API}/domains/{domain}", headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return data
        return {"error": f"VT error {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def get_urlscan(domain):
    api_key = os.getenv("URLSCAN_API_KEY")
    if not api_key: return {"error": "API key missing"}
    try:
        headers = {"API-Key": api_key, "Content-Type": "application/json"}
        data = {"url": domain, "visibility": "public"}
        r = requests.post("https://urlscan.io/api/v1/scan/", headers=headers, json=data, timeout=10)
        return r.json() if r.status_code == 200 else {"error": f"URLScan error {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def get_alienvault_otx(domain):
    api_key = os.getenv("OTX_API_KEY")
    try:
        headers = {"X-OTX-API-KEY": api_key} if api_key else {}
        r = requests.get(f"{OTX_API}/indicators/domain/{domain}/general", headers=headers, timeout=10)
        if r.status_code == 200:
            return r.json().get("pulse_info", {})
        return {"error": f"OTX error {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def get_security_headers(domain):
    try:
        r = requests.get(f"https://{domain}", timeout=10)
        h = r.headers
        return {
            "x-frame-options": h.get("X-Frame-Options"),
            "x-content-type-options": h.get("X-Content-Type-Options"),
            "strict-transport-security": h.get("Strict-Transport-Security"),
            "content-security-policy": h.get("Content-Security-Policy"),
            "server": h.get("Server")
        }
    except Exception as e:
        return {"error": str(e)}

def get_dns_records(domain):
    try:
        # Simplified: just return A record using socket
        ip = socket.gethostbyname(domain)
        return {"A": [ip]}
    except Exception as e:
        return {"error": str(e)}

def get_subdomains(domain):
    try:
        r = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=15)
        if r.status_code == 200:
            return list(set([item['name_value'] for item in r.json()]))[:10]
        return []
    except Exception:
        return []

def get_whois(domain):
    # Public WHOIS API
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}", timeout=10)
        return r.json() if r.status_code == 200 else {"error": "WHOIS lookup failed"}
    except Exception as e:
        return {"error": str(e)}

def get_ssl_grade(domain):
    try:
        # Hit a public SSL labs wrapper or simplified check
        return "B" # Defaulting for now as real check is complex
    except Exception:
        return "N/A"
