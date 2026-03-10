"""
routes/auth.py
━━━━━━━━━━━━━━
Authentication endpoints with:
  • bcrypt password verification  (v4)
  • email verification on register (v4)
  • brute-force IP blocking
"""
import os
import smtplib
import datetime
from email.mime.text      import MIMEText
from email.mime.multipart import MIMEMultipart

from flask import Blueprint, request, jsonify
from flask_limiter.util import get_remote_address

import utils.database as dbl
from utils.auth   import (hash_password, check_password,
                           make_token, token_required, email_verify_token)
from utils.logger import log_event

auth_bp = Blueprint("auth", __name__)

_BACKEND_URL  = os.getenv("BACKEND_URL",  "https://soc-velocity-v-1-1.onrender.com")
_FRONTEND_URL = os.getenv("FRONTEND_URL", "https://your-app.vercel.app")


# ── Send verification email ────────────────────────────────────
def _send_verify_email(to_email: str, token: str) -> bool:
    mail_user = os.getenv("MAIL_USERNAME", "")
    mail_pw   = os.getenv("MAIL_PASSWORD", "")
    if not mail_user or not mail_pw:
        return False

    verify_url = f"{_BACKEND_URL}/api/auth/verify-email?token={token}&email={to_email}"
    html = f"""
<div style="font-family:monospace;background:#020408;color:#c8e0f0;
            padding:24px;border-radius:8px;max-width:520px;">
  <h2 style="color:#00d4ff;letter-spacing:3px;">🛡️ AEGIS — Verify Your Email</h2>
  <p style="margin:1rem 0;">Click the button below to activate your account:</p>
  <a href="{verify_url}"
     style="display:inline-block;padding:12px 28px;background:rgba(0,212,255,.1);
            border:1px solid #00d4ff;border-radius:4px;color:#00d4ff;
            text-decoration:none;font-weight:700;letter-spacing:2px;">
    VERIFY EMAIL
  </a>
  <p style="margin-top:1.5rem;font-size:.8em;color:#3a6a8a;">
    Or copy this link:<br/>
    <a href="{verify_url}" style="color:#00d4ff;word-break:break-all;">{verify_url}</a>
  </p>
  <p style="margin-top:1rem;font-size:.75em;color:#3a6a8a;">
    Link expires in 24 hours. If you did not create an account, ignore this email.
  </p>
</div>"""

    try:
        msg            = MIMEMultipart("alternative")
        msg["From"]    = mail_user
        msg["To"]      = to_email
        msg["Subject"] = "🛡️ AEGIS — Verify your email address"
        msg.attach(MIMEText(html, "html"))
        with smtplib.SMTP("smtp.gmail.com", 587) as s:
            s.ehlo(); s.starttls(); s.login(mail_user, mail_pw)
            s.sendmail(mail_user, to_email, msg.as_string())
        return True
    except Exception as e:
        print(f"[AEGIS] Verify-email send error: {e}")
        return False


# ── Register ───────────────────────────────────────────────────
@auth_bp.route("/register", methods=["POST"])
def register():
    data     = request.get_json(force=True) or {}
    email    = data.get("email",    "").lower().strip()
    password = data.get("password", "")

    if not email or "@" not in email or "." not in email.split("@")[-1]:
        return jsonify({"error": "Valid email address required"}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    if dbl.get_user(email):
        return jsonify({"error": "Email already registered"}), 409

    token = email_verify_token()
    dbl.create_user(email, {
        "password":          hash_password(password),
        "name":              data.get("name", ""),
        "telegram_chat_id":  data.get("telegram_chat_id", ""),
        "monitored":         [],
        "verified":          False,
        "verify_token":      token,
        "created":           datetime.datetime.utcnow().isoformat(),
    })

    sent = _send_verify_email(email, token)
    log_event("USER_REGISTER", email=email, verify_email_sent=sent)

    if sent:
        return jsonify({
            "message": "Account created ✅ — check your email to verify your account.",
            "email":   email,
        }), 201
    else:
        # No mail config → auto-verify so local dev still works
        dbl.update_user(email, {"verified": True, "verify_token": ""})
        return jsonify({
            "token":   make_token(email),
            "email":   email,
            "message": "Account created ✅",
        }), 201


# ── Verify email (link from email) ────────────────────────────
@auth_bp.route("/verify-email", methods=["GET"])
def verify_email():
    email = request.args.get("email", "").lower().strip()
    token = request.args.get("token", "")

    user = dbl.get_user(email)
    if not user:
        return jsonify({"error": "Account not found"}), 404
    if user.get("verified"):
        # Already verified — redirect to frontend login
        return f'<meta http-equiv="refresh" content="2;url={_FRONTEND_URL}"/>' \
               '<p style="font-family:monospace;color:#00d4ff;">Already verified. Redirecting…</p>', 200
    if user.get("verify_token") != token:
        return jsonify({"error": "Invalid or expired verification link"}), 400

    dbl.update_user(email, {"verified": True, "verify_token": ""})
    log_event("EMAIL_VERIFIED", email=email)

    return (
        f'<html><head><meta http-equiv="refresh" content="3;url={_FRONTEND_URL}"/>'
        f'<style>body{{font-family:monospace;background:#010306;color:#00d4ff;'
        f'display:flex;align-items:center;justify-content:center;height:100vh;margin:0;}}'
        f'</style></head><body>'
        f'<div style="text-align:center;">'
        f'<div style="font-size:3rem;margin-bottom:1rem;">✅</div>'
        f'<h2 style="letter-spacing:3px;">EMAIL VERIFIED</h2>'
        f'<p style="color:#3a6a8a;">Redirecting to login…</p>'
        f'</div></body></html>'
    ), 200


# ── Login ──────────────────────────────────────────────────────
@auth_bp.route("/login", methods=["POST"])
def login():
    ip   = get_remote_address()
    data = request.get_json(force=True) or {}
    email    = data.get("email",    "").lower().strip()
    password = data.get("password", "")

    # Brute-force protection
    fails = dbl.get_failed_logins(ip)
    if fails >= 10:
        dbl.add_blocked_ip(ip, reason="brute_force")
        log_event("BRUTE_FORCE_BLOCK", ip=ip, email=email)
        return jsonify({"error": "Too many failed attempts — IP blocked"}), 403

    user = dbl.get_user(email)
    if not user or not check_password(password, user["password"]):
        dbl.inc_failed_logins(ip)
        log_event("LOGIN_FAIL", ip=ip, email=email,
                  attempts=dbl.get_failed_logins(ip))
        return jsonify({"error": "Invalid credentials"}), 401

    # Check email is verified (only enforced when mail is configured)
    mail_configured = bool(os.getenv("MAIL_USERNAME"))
    if mail_configured and not user.get("verified", True):
        return jsonify({
            "error":    "Please verify your email first — check your inbox.",
            "unverified": True,
        }), 403

    dbl.clear_failed_logins(ip)
    log_event("LOGIN_SUCCESS", email=email)
    return jsonify({"token": make_token(email), "email": email})


# ── Resend verification email ─────────────────────────────────
@auth_bp.route("/resend-verification", methods=["POST"])
def resend_verification():
    email = (request.get_json(force=True) or {}).get("email", "").lower().strip()
    user  = dbl.get_user(email)
    if not user:
        return jsonify({"error": "Account not found"}), 404
    if user.get("verified"):
        return jsonify({"message": "Already verified"}), 200

    token = email_verify_token()
    dbl.update_user(email, {"verify_token": token})
    sent = _send_verify_email(email, token)
    return jsonify({"message": "Verification email sent ✅" if sent
                   else "Mail not configured on server"})


# ── Profile ────────────────────────────────────────────────────
@auth_bp.route("/profile", methods=["GET"])
@token_required
def profile(current_user):
    user = dbl.get_user(current_user) or {}
    return jsonify({
        "email":            current_user,
        "name":             user.get("name",             ""),
        "monitored_count":  len(user.get("monitored",   [])),
        "telegram_enabled": bool(user.get("telegram_chat_id")),
        "verified":         user.get("verified",         True),
        "created":          user.get("created",          ""),
    })


# ── Update profile ─────────────────────────────────────────────
@auth_bp.route("/profile/update", methods=["POST"])
@token_required
def update_profile(current_user):
    data    = request.get_json(force=True) or {}
    updates = {}
    for field in ("name", "telegram_chat_id"):
        if field in data:
            updates[field] = data[field]
    if updates:
        dbl.update_user(current_user, updates)
    return jsonify({"message": "Profile updated ✅"})
