"""
services/monitor_daemon.py
Background thread that sends daily health reports to every verified
user who has registered sites for monitoring.
"""
import os
import time
import threading
import datetime
import smtplib
from email.mime.text      import MIMEText
from email.mime.multipart import MIMEMultipart


def _send_email(to_email: str, subject: str, html_body: str) -> bool:
    user = os.getenv("MAIL_USERNAME", "")
    pw   = os.getenv("MAIL_PASSWORD", "")
    if not user or not pw:
        return False
    try:
        msg            = MIMEMultipart("alternative")
        msg["From"]    = user
        msg["To"]      = to_email
        msg["Subject"] = subject
        msg.attach(MIMEText(html_body, "html"))
        with smtplib.SMTP("smtp.gmail.com", 587) as s:
            s.ehlo(); s.starttls(); s.login(user, pw)
            s.sendmail(user, to_email, msg.as_string())
        return True
    except Exception as exc:
        print(f"[AEGIS] Email error: {exc}")
        return False


def _send_telegram(chat_id: str, message: str) -> bool:
    token = os.getenv("TELEGRAM_BOT_TOKEN", "")
    if not token or not chat_id:
        return False
    try:
        import requests as req
        req.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": message, "parse_mode": "HTML"},
            timeout=10,
        )
        return True
    except Exception:
        return False


def _scan_domain(domain: str) -> dict:
    from services.domain_service import (
        get_virustotal, get_ssl_grade, get_security_headers,
        get_urlscan, get_alienvault_otx,
    )
    from services.ip_service  import get_ip_reputation, get_abuseipdb
    from utils.scoring_engine import ai_threat_score, compute_health_score

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
        threading.Thread(target=run, args=("virustotal",       get_virustotal,       domain)),
        threading.Thread(target=run, args=("security_headers", get_security_headers, domain)),
        threading.Thread(target=run, args=("urlscan",          get_urlscan,          domain)),
        threading.Thread(target=run, args=("alienvault",       get_alienvault_otx,   domain)),
        threading.Thread(target=run, args=("ip_reputation",    get_ip_reputation,    domain)),
    ]
    for t in threads: t.start()
    for t in threads: t.join(timeout=25)

    ip = results.get("ip_reputation", {}).get("query", domain)
    results["abuseipdb"]    = get_abuseipdb(ip)
    results["ssl_grade"]    = get_ssl_grade(domain)
    results["ai_threat"]    = ai_threat_score(results)
    results["health_score"] = compute_health_score(results)
    return results


def run_daily_monitor():
    """Execute one full cycle of scanning for all users."""
    import utils.db_core as dbl
    users = dbl.get_all_users()
    print(f"[AEGIS] Daily monitor — {len(users)} users")

    for user in users:
        email   = user.get("email", "")
        chat_id = user.get("telegram_chat_id", "")

        for domain in user.get("monitored", []):
            try:
                r      = _scan_domain(domain)
                health = r.get("health_score", 0)
                threat = r.get("ai_threat", {})
                lvl    = threat.get("level", "N/A")
                tscore = threat.get("score", 0)
                ssl    = r.get("ssl_grade", "N/A")
                reasons= threat.get("reasons", [])
                now    = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
                emoji  = "🟢" if health >= 80 else "🟡" if health >= 50 else "🔴"
                hcol   = "#00ff9f" if health >= 80 else "#ffb300" if health >= 50 else "#ff4d6d"
                tcol   = "#ff4d6d" if lvl in ("CRITICAL","HIGH") else "#ffb300" if lvl == "MEDIUM" else "#00ff9f"
                rows   = "".join(f'<li style="margin:.3rem 0;">{r}</li>' for r in reasons)

                html = f"""
<div style="font-family:monospace;background:#020408;color:#c8e0f0;
            padding:24px;border-radius:8px;max-width:600px;">
  <h2 style="color:#00d4ff;letter-spacing:3px;">🛡️ AEGIS DAILY HEALTH REPORT</h2>
  <table style="width:100%;border-collapse:collapse;">
    <tr><td style="color:#3a6a8a;padding:6px 0;">Domain</td>
        <td style="color:#00d4ff;font-weight:bold;">{domain}</td></tr>
    <tr><td style="color:#3a6a8a;padding:6px 0;">Health</td>
        <td style="color:{hcol};font-size:1.3em;font-weight:900;">{emoji} {health}/100</td></tr>
    <tr><td style="color:#3a6a8a;padding:6px 0;">Threat</td>
        <td style="color:{tcol};">{lvl} ({tscore}/100)</td></tr>
    <tr><td style="color:#3a6a8a;padding:6px 0;">SSL</td>
        <td style="color:#00d4ff;">{ssl}</td></tr>
    <tr><td style="color:#3a6a8a;padding:6px 0;">Scanned</td>
        <td>{now}</td></tr>
  </table>
  <h3 style="color:#00d4ff;margin:16px 0 8px;letter-spacing:2px;">AI ANALYSIS</h3>
  <ul style="color:#c8e0f0;padding-left:20px;">{rows}</ul>
  <div style="margin-top:20px;padding:12px;background:rgba(0,212,255,.05);
              border:1px solid rgba(0,212,255,.15);border-radius:4px;
              font-size:.8em;color:#3a6a8a;">
    AEGIS SOC Engine — built by
    <a href="https://github.com/arnabdevs" style="color:#00d4ff;">Arnab Kumar Das</a>
  </div>
</div>"""

                # ── Auto-defend if zone is connected ──────────────────
                auto_defend_report = None
                cfg = user.get("cf_zones", {}).get(domain)
                if cfg:
                    try:
                        from services.cloudflare_service import auto_defend
                        auto_defend_report = auto_defend(
                            cfg["cf_token"], cfg["zone_id"], domain, r
                        )
                        print(f"[AEGIS] Auto-defend → {domain}: {auto_defend_report.get('summary','')}")
                    except Exception as ae:
                        print(f"[AEGIS] Auto-defend error for {domain}: {ae}")

                # ── Build email with auto-defend section ──────────────
                defend_section = ""
                if auto_defend_report:
                    ips_blocked = auto_defend_report.get("ips_blocked", [])
                    applied     = auto_defend_report.get("hardening", {}).get("applied", [])
                    email_grade = auto_defend_report.get("email_security", {}).get("grade", "N/A")
                    ip_rows = "".join(
                        f'<li style="margin:.2rem 0;color:#ff4d6d;">'
                        f'🚫 Blocked {b["ip"]} — {b["reason"]}</li>'
                        for b in ips_blocked
                    )
                    fix_rows = "".join(
                        f'<li style="margin:.2rem 0;color:#00ff9f;">'
                        f'✅ {a}</li>'
                        for a in applied
                    )
                    defend_section = f"""
<h3 style="color:#ff4d6d;margin:16px 0 8px;letter-spacing:2px;">🛡️ AUTO-DEFEND ACTIONS</h3>
<ul style="color:#c8e0f0;padding-left:20px;">
{ip_rows if ip_rows else '<li style="color:#3a6a8a;">No IPs auto-blocked this cycle</li>'}
{fix_rows}
<li style="margin:.2rem 0;">📧 Email security grade: <strong style="color:#00d4ff;">{email_grade}</strong></li>
</ul>"""

                html_final = html.replace("</div>", defend_section + "</div>", 1) if defend_section else html

                _send_email(email,
                            f"[AEGIS] {domain} — Health {health}/100 | {lvl} Risk",
                            html_final)
                if chat_id:
                    defend_line = ""
                    if auto_defend_report:
                        nb = len(auto_defend_report.get("ips_blocked", []))
                        na = len(auto_defend_report.get("hardening", {}).get("applied", []))
                        defend_line = f"\n🛡️ Auto-defend: {nb} IPs blocked, {na} settings hardened"
                    _send_telegram(
                        chat_id,
                        f"🛡️ <b>AEGIS Daily Report</b>\n\n"
                        f"🌐 <code>{domain}</code>\n"
                        f"{emoji} Health: <b>{health}/100</b>\n"
                        f"⚠ Threat: <b>{lvl}</b> ({tscore}/100)\n"
                        f"🔒 SSL: <b>{ssl}</b>"
                        + defend_line + "\n\n"
                        + "\n".join(f"• {rr}" for rr in reasons[:5]),
                    )
                print(f"[AEGIS] Report → {email} | {domain} | {health} | {lvl}")
            except Exception as exc:
                print(f"[AEGIS] Monitor error for {domain}: {exc}")


def _daemon_loop():
    import utils.db_core as dbl
    while True:
        last_run = dbl.get_last_monitor_run()
        now_ts   = int(time.time())
        # Check if we need to run or if we just woke up from a long sleep
        if (now_ts - last_run) > 86400:
            dbl.set_last_monitor_run(now_ts)
            run_daily_monitor()
        
        # Check every hour
        time.sleep(3600)


def start_monitor_daemon():
    t = threading.Thread(target=_daemon_loop, daemon=True, name="monitor-daemon")
    t.start()
    print("[AEGIS] Daily monitor daemon started")
