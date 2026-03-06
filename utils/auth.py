"""
utils/auth.py
━━━━━━━━━━━━━
JWT helpers, bcrypt password hashing, email-verification token,
and the @token_required decorator.

Upgrade history:
  v3 → v4 :  SHA-256 replaced with bcrypt (work factor 12)
             email_verify_token() added for email verification flow
"""
import os
import secrets
import jwt
import bcrypt
import datetime
from functools import wraps
from flask import request, jsonify


# ── Password hashing (bcrypt, work factor 12) ─────────────────
def hash_password(pw: str) -> str:
    """Return bcrypt hash as a UTF-8 string safe for DB storage."""
    return bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def check_password(pw: str, hashed: str) -> bool:
    """Constant-time comparison — immune to timing attacks."""
    try:
        return bcrypt.checkpw(pw.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


# ── JWT session tokens ────────────────────────────────────────
def make_token(user_id: str, days: int = 30) -> str:
    payload = {
        "user_id": user_id,
        "exp":     datetime.datetime.utcnow() + datetime.timedelta(days=days),
    }
    return jwt.encode(payload, _secret(), algorithm="HS256")


def decode_token(token: str) -> dict:
    return jwt.decode(token, _secret(), algorithms=["HS256"])


# ── Email verification tokens ─────────────────────────────────
def email_verify_token() -> str:
    """Generate a 32-byte URL-safe token for email verification link."""
    return secrets.token_urlsafe(32)


# ── Shared secret ─────────────────────────────────────────────
def _secret() -> str:
    return os.getenv("SECRET_KEY", "CHANGE-THIS-IN-PRODUCTION")


# ── Route decorator ───────────────────────────────────────────
def token_required(f):
    """Validates Bearer JWT. Passes current_user email to the route."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth  = request.headers.get("Authorization", "")
        token = auth.replace("Bearer ", "").strip()
        if not token:
            return jsonify({"error": "Authorization token required"}), 401
        try:
            data         = decode_token(token)
            current_user = data["user_id"]
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired — please log in again"}), 401
        except Exception:
            return jsonify({"error": "Invalid token"}), 401
        return f(current_user, *args, **kwargs)
    return decorated
