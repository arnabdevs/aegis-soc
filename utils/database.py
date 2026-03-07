# FINGERPRINT: 2026-03-07-v5.4-FORCED-REDEPLOY
"""
utils/database.py
━━━━━━━━━━━━━━━━━
AEGIS SOC Engine v4 — Dual-mode data layer
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
• If SUPABASE_DB_URL is set  →  PostgreSQL (Supabase) — data survives restarts
• If not set                 →  In-memory dict/set (local dev / first deploy)

The rest of the codebase calls the same helper functions either way:
  get_user(email)            → dict | None
  create_user(email, data)   → None
  update_user(email, data)   → None
  get_blocked_ips()          → set
  add_blocked_ip(ip)         → None
  remove_blocked_ip(ip)      → None
  cache_get(key, max_age)    → dict | None   (Redis if REDIS_URL, else memory)
  cache_set(key, result)     → None
  log_scan(...)              → None
  get_scan_logs(n)           → list
  get_stats()                → dict
  inc_stat(key)              → None
  log_event(...)             → None   (also in logger.py for backwards compat)
  get_events(n)              → list
  log_api_call(api, status)  → None
  get_api_logs(n)            → list
"""
import os
import time
import datetime
import json

# ── Detect which mode to use ──────────────────────────────────
_DB_URL    = os.getenv("SUPABASE_DB_URL", "")   # postgres://user:pw@host:5432/db
def _is_redis_url(url):
    return any(url.startswith(s) for s in ["redis://", "rediss://", "unix://"])

_REDIS_URL = os.getenv("REDIS_URL", "").strip()
if _REDIS_URL and not _is_redis_url(_REDIS_URL):
    if "://" not in _REDIS_URL:
        _REDIS_URL = f"redis://{_REDIS_URL}"
    else:
        _REDIS_URL = "" # Wrong scheme (e.g. http://)

print(f"[AEGIS] Database Redis URL: {(_REDIS_URL[:10] + '...') if _REDIS_URL else 'NONE'}")

USE_POSTGRES = bool(_DB_URL)
USE_REDIS    = False # Will be verified below


# ══════════════════════════════════════════════════════════════
#  POSTGRES LAYER  (Supabase free tier)
# ══════════════════════════════════════════════════════════════
if USE_POSTGRES:
    import psycopg2
    import psycopg2.extras

    def _conn():
        return psycopg2.connect(_DB_URL, cursor_factory=psycopg2.extras.RealDictCursor)

    def init_db():
        """Create tables on first run — idempotent (IF NOT EXISTS)."""
        sql = """
        CREATE TABLE IF NOT EXISTS users (
            email            TEXT PRIMARY KEY,
            password_hash    TEXT NOT NULL,
            name             TEXT DEFAULT '',
            telegram_chat_id TEXT DEFAULT '',
            monitored        JSONB DEFAULT '[]',
            verified         BOOLEAN DEFAULT FALSE,
            verify_token     TEXT DEFAULT '',
            cf_zones         JSONB DEFAULT '{}',
            created_at       TIMESTAMPTZ DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip         TEXT PRIMARY KEY,
            reason     TEXT DEFAULT '',
            blocked_at TIMESTAMPTZ DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS scan_logs (
            id           SERIAL PRIMARY KEY,
            target       TEXT,
            type         TEXT,
            health       INT,
            threat_level TEXT,
            threat_score INT,
            scanned_at   TIMESTAMPTZ DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS event_logs (
            id         SERIAL PRIMARY KEY,
            event      TEXT,
            data       JSONB,
            created_at TIMESTAMPTZ DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS api_logs (
            id         SERIAL PRIMARY KEY,
            api        TEXT,
            status     TEXT,
            created_at TIMESTAMPTZ DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS stats (
            key   TEXT PRIMARY KEY,
            value BIGINT DEFAULT 0
        );

        INSERT INTO stats (key, value) VALUES
            ('total_scans', 0), ('high_risk', 0), ('last_monitor_run', 0)
        ON CONFLICT DO NOTHING;
        """
        with _conn() as con:
            with con.cursor() as cur:
                cur.execute(sql)
            con.commit()
        print("[AEGIS] PostgreSQL tables initialised ✅")

    # ── Users ─────────────────────────────────────────────────
    def get_user(email: str) -> dict | None:
        with _conn() as con:
            with con.cursor() as cur:
                cur.execute("SELECT * FROM users WHERE email = %s", (email,))
                row = cur.fetchone()
        if not row:
            return None
        d = dict(row)
        d["monitored"] = d["monitored"] if isinstance(d["monitored"], list) else json.loads(d["monitored"] or "[]")
        d["cf_zones"]   = d.get("cf_zones") if isinstance(d.get("cf_zones"), dict) else json.loads(d.get("cf_zones") or "{}")
        return d

    def create_user(email: str, data: dict) -> None:
        with _conn() as con:
            with con.cursor() as cur:
                cur.execute("""
                    INSERT INTO users
                        (email, password_hash, name, telegram_chat_id,
                         monitored, verified, verify_token, cf_zones)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    email,
                    data["password"],
                    data.get("name", ""),
                    data.get("telegram_chat_id", ""),
                    json.dumps(data.get("monitored", [])),
                    data.get("verified", False),
                    data.get("verify_token", ""),
                    json.dumps(data.get("cf_zones", {})),
                ))
            con.commit()

    def update_user(email: str, data: dict) -> None:
        allowed = ("password", "name", "telegram_chat_id",
                   "monitored", "verified", "verify_token", "cf_zones")
        sets, vals = [], []
        for k, v in data.items():
            if k not in allowed:
                continue
            col = "password_hash" if k == "password" else k
            sets.append(f"{col} = %s")
            vals.append(json.dumps(v) if k in ("monitored", "cf_zones") else v)
        if not sets:
            return
        vals.append(email)
        with _conn() as con:
            with con.cursor() as cur:
                cur.execute(
                    f"UPDATE users SET {', '.join(sets)} WHERE email = %s",
                    vals,
                )
            con.commit()

    def get_all_users() -> list:
        with _conn() as con:
            with con.cursor() as cur:
                cur.execute("SELECT email, name, monitored, telegram_chat_id FROM users WHERE verified = TRUE")
                rows = cur.fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["monitored"] = d["monitored"] if isinstance(d["monitored"], list) else json.loads(d["monitored"] or "[]")
            result.append(d)
        return result

    def count_users() -> int:
        with _conn() as con:
            with con.cursor() as cur:
                cur.execute("SELECT COUNT(*) AS n FROM users")
                return cur.fetchone()["n"]

    # ── Blocked IPs ───────────────────────────────────────────
    def get_blocked_ips() -> set:
        with _conn() as con:
            with con.cursor() as cur:
                cur.execute("SELECT ip FROM blocked_ips")
                return {r["ip"] for r in cur.fetchall()}

    def add_blocked_ip(ip: str, reason: str = "") -> None:
        with _conn() as con:
            with con.cursor() as cur:
                cur.execute(
                    "INSERT INTO blocked_ips (ip, reason) VALUES (%s, %s) ON CONFLICT DO NOTHING",
                    (ip, reason),
                )
            con.commit()

    def remove_blocked_ip(ip: str) -> None:
        with _conn() as con:
            with con.cursor() as cur:
                cur.execute("DELETE FROM blocked_ips WHERE ip = %s", (ip,))
            con.commit()

    def count_blocked_ips() -> int:
        with _conn() as con:
            with con.cursor() as cur:
                cur.execute("SELECT COUNT(*) AS n FROM blocked_ips")
                return cur.fetchone()["n"]

    # ── Scan logs ─────────────────────────────────────────────
    def log_scan(target: str, scan_type: str, health: int,
                 threat_level: str, threat_score: int) -> None:
        with _conn() as con:
            with con.cursor() as cur:
                cur.execute("""
                    INSERT INTO scan_logs
                        (target, type, health, threat_level, threat_score)
                    VALUES (%s, %s, %s, %s, %s)
                """, (target, scan_type, health, threat_level, threat_score))
                cur.execute(
                    "UPDATE stats SET value = value + 1 WHERE key = 'total_scans'"
                )
                if threat_level in ("HIGH", "CRITICAL"):
                    cur.execute(
                        "UPDATE stats SET value = value + 1 WHERE key = 'high_risk'"
                    )
            con.commit()

    def get_scan_logs(n: int = 20) -> list:
        with _conn() as con:
            with con.cursor() as cur:
                cur.execute("""
                    SELECT target, type AS scan_type, health,
                           threat_level, threat_score,
                           TO_CHAR(scanned_at, 'HH24:MI:SS') AS time
                    FROM scan_logs ORDER BY scanned_at DESC LIMIT %s
                """, (n,))
                return [dict(r) for r in cur.fetchall()]

    # ── Stats ─────────────────────────────────────────────────
    def get_stats() -> dict:
        with _conn() as con:
            with con.cursor() as cur:
                cur.execute("SELECT key, value FROM stats")
                return {r["key"]: r["value"] for r in cur.fetchall()}

    def inc_stat(key: str) -> None:
        with _conn() as con:
            with con.cursor() as cur:
                cur.execute(
                    "INSERT INTO stats (key, value) VALUES (%s, 1) "
                    "ON CONFLICT (key) DO UPDATE SET value = stats.value + 1",
                    (key,),
                )
            con.commit()

    # ── Event logs ────────────────────────────────────────────
    def log_event_db(event: str, data: dict) -> None:
        with _conn() as con:
            with con.cursor() as cur:
                cur.execute(
                    "INSERT INTO event_logs (event, data) VALUES (%s, %s)",
                    (event, json.dumps(data)),
                )
            con.commit()

    def get_events(n: int = 50) -> list:
        with _conn() as con:
            with con.cursor() as cur:
                cur.execute("""
                    SELECT event,
                           data,
                           TO_CHAR(created_at, 'YYYY-MM-DD HH24:MI:SS') AS time
                    FROM event_logs ORDER BY created_at DESC LIMIT %s
                """, (n,))
                rows = []
                for r in cur.fetchall():
                    entry = {"event": r["event"], "time": r["time"]}
                    entry.update(r["data"] if r["data"] else {})
                    rows.append(entry)
                return rows

    # ── API call logs ─────────────────────────────────────────
    def log_api_call_db(api: str, status: str = "ok") -> None:
        with _conn() as con:
            with con.cursor() as cur:
                cur.execute(
                    "INSERT INTO api_logs (api, status) VALUES (%s, %s)",
                    (api, status),
                )
                cur.execute(
                    "INSERT INTO stats (key, value) VALUES (%s, 1) "
                    "ON CONFLICT (key) DO UPDATE SET value = stats.value + 1",
                    (f"api_{api}",),
                )
            con.commit()

    def get_api_logs(n: int = 20) -> list:
        with _conn() as con:
            with con.cursor() as cur:
                cur.execute("""
                    SELECT api, status,
                           TO_CHAR(created_at, 'HH24:MI:SS') AS time
                    FROM api_logs ORDER BY created_at DESC LIMIT %s
                """, (n,))
                return [dict(r) for r in cur.fetchall()]

    def get_api_usage() -> dict:
        with _conn() as con:
            with con.cursor() as cur:
                cur.execute("SELECT key, value FROM stats WHERE key LIKE 'api_%'")
                return {r["key"].replace("api_", ""): r["value"] for r in cur.fetchall()}

    # ── Failed logins (in-memory per process, resets on restart) ──
    _failed_logins: dict = {}

    def get_failed_logins(ip: str) -> int:
        return _failed_logins.get(ip, 0)

    def inc_failed_logins(ip: str) -> int:
        _failed_logins[ip] = _failed_logins.get(ip, 0) + 1
        return _failed_logins[ip]

    def clear_failed_logins(ip: str) -> None:
        _failed_logins.pop(ip, None)

    print("[AEGIS] Database mode: PostgreSQL (Supabase) ✅")

    # ── Monitor persistence ───────────────────────────────────
    def get_last_monitor_run() -> int:
        with _conn() as con:
            with con.cursor() as cur:
                cur.execute("SELECT value FROM stats WHERE key = 'last_monitor_run'")
                row = cur.fetchone()
                return row["value"] if row else 0

    def set_last_monitor_run(ts: int) -> None:
        with _conn() as con:
            with con.cursor() as cur:
                cur.execute("UPDATE stats SET value = %s WHERE key = 'last_monitor_run'", (ts,))
            con.commit()


# ══════════════════════════════════════════════════════════════
#  IN-MEMORY LAYER  (local dev / no SUPABASE_DB_URL set)
# ══════════════════════════════════════════════════════════════
else:
    _mem: dict = {
        "users":         {},
        "failed_logins": {},
        "blocked_ips":   set(),
        "scan_logs":     [],
        "event_logs":    [],
        "api_logs":      [],
        "stats": {
            "total_scans": 0,
            "high_risk":   0,
        },
        "api_usage": {
            "virustotal": 0, "abuseipdb": 0, "urlscan": 0,
            "hibp": 0, "ssllabs": 0, "ipapi": 0,
            "hackertarget": 0, "crtsh": 0, "alienvault": 0,
        },
    }

    def init_db(): pass  # nothing to do in memory mode

    # Users
    def get_user(email: str) -> dict | None:
        return _mem["users"].get(email)

    def create_user(email: str, data: dict) -> None:
        if "cf_zones" not in data:
            data["cf_zones"] = {}
        _mem["users"][email] = data

    def update_user(email: str, data: dict) -> None:
        if email in _mem["users"]:
            _mem["users"][email].update(data)

    def get_all_users() -> list:
        return [
            {"email": e, **u}
            for e, u in _mem["users"].items()
            if u.get("verified", True)  # in-mem: unverified users still allowed
        ]

    def count_users() -> int:
        return len(_mem["users"])

    # Blocked IPs
    def get_blocked_ips() -> set:
        return _mem["blocked_ips"]

    def add_blocked_ip(ip: str, reason: str = "") -> None:
        _mem["blocked_ips"].add(ip)

    def remove_blocked_ip(ip: str) -> None:
        _mem["blocked_ips"].discard(ip)

    def count_blocked_ips() -> int:
        return len(_mem["blocked_ips"])

    # Scan logs
    def log_scan(target: str, scan_type: str, health: int,
                 threat_level: str, threat_score: int) -> None:
        _mem["scan_logs"].append({
            "target":       target,
            "scan_type":    scan_type,
            "health":       health,
            "threat_level": threat_level,
            "threat_score": threat_score,
            "time":         datetime.datetime.utcnow().strftime("%H:%M:%S"),
            "ts":           time.time(),
        })
        if len(_mem["scan_logs"]) > 500:
            _mem["scan_logs"].pop(0)
        _mem["stats"]["total_scans"] += 1
        if threat_level in ("HIGH", "CRITICAL"):
            _mem["stats"]["high_risk"] += 1

    def get_scan_logs(n: int = 20) -> list:
        return sorted(_mem["scan_logs"],
                      key=lambda x: x.get("ts", 0), reverse=True)[:n]

    # Stats
    def get_stats() -> dict:
        return dict(_mem["stats"])

    def inc_stat(key: str) -> None:
        _mem["stats"][key] = _mem["stats"].get(key, 0) + 1

    # Events
    def log_event_db(event: str, data: dict) -> None:
        entry = {"event": event,
                 "time":  datetime.datetime.utcnow().isoformat(),
                 **data}
        _mem["event_logs"].append(entry)
        if len(_mem["event_logs"]) > 1000:
            _mem["event_logs"].pop(0)

    def get_events(n: int = 50) -> list:
        return sorted(_mem["event_logs"],
                      key=lambda x: x.get("time", ""), reverse=True)[:n]

    # API logs
    def log_api_call_db(api: str, status: str = "ok") -> None:
        _mem["api_usage"][api] = _mem["api_usage"].get(api, 0) + 1
        _mem["api_logs"].append({
            "api":    api,
            "status": status,
            "time":   datetime.datetime.utcnow().isoformat(),
        })
        if len(_mem["api_logs"]) > 500:
            _mem["api_logs"].pop(0)

    def get_api_logs(n: int = 20) -> list:
        return _mem["api_logs"][-n:]

    def get_api_usage() -> dict:
        return dict(_mem["api_usage"])

    # Failed logins
    def get_failed_logins(ip: str) -> int:
        return _mem["failed_logins"].get(ip, 0)

    def inc_failed_logins(ip: str) -> int:
        _mem["failed_logins"][ip] = _mem["failed_logins"].get(ip, 0) + 1
        return _mem["failed_logins"][ip]

    def clear_failed_logins(ip: str) -> None:
        _mem["failed_logins"].pop(ip, None)

    # Monitor persistence
    def get_last_monitor_run() -> int:
        return _mem["stats"].get("last_monitor_run", 0)

    def set_last_monitor_run(ts: int) -> None:
        _mem["stats"]["last_monitor_run"] = ts

    print("[AEGIS] Database mode: In-memory (set SUPABASE_DB_URL for PostgreSQL)")


# ══════════════════════════════════════════════════════════════
#  REDIS CACHE LAYER  (Upstash free tier)
# ══════════════════════════════════════════════════════════════
if _REDIS_URL:
    try:
        import redis as _redis_lib
        _redis = _redis_lib.from_url(_REDIS_URL, decode_responses=True)
        # We don't ping here to avoid blocking startup, but if from_url 
        # fails (e.g. scheme error), it will be caught.
        USE_REDIS = True
        print("[AEGIS] Cache mode: Redis (Upstash) ✅")
    except Exception as e:
        print(f"[AEGIS] Redis connection error: {e}. Falling back to memory.")
        USE_REDIS = False

if USE_REDIS:
    # _redis is already initialized above
    def cache_get(key: str, max_age: int = 300) -> dict | None:
        try:
            raw = _redis.get(f"aegis:cache:{key}")
            return json.loads(raw) if raw else None
        except Exception:
            return None

    def cache_set(key: str, result: dict) -> None:
        try:
            _redis.setex(
                f"aegis:cache:{key}",
                300,                        # TTL seconds (Redis handles expiry)
                json.dumps(result, default=str),
            )
        except Exception:
            pass

    print("[AEGIS] Cache mode: Redis (Upstash) ✅")

else:
    # In-memory cache fallback
    _cache: dict = {}

    def cache_get(key: str, max_age: int = 300) -> dict | None:
        entry = _cache.get(key)
        if entry and (time.time() - entry["ts"]) < max_age:
            return entry["result"]
        return None

    def cache_set(key: str, result: dict) -> None:
        _cache[key] = {"result": result, "ts": time.time()}
        if len(_cache) > 200:
            oldest = min(_cache, key=lambda k: _cache[k]["ts"])
            del _cache[oldest]

    print("[AEGIS] Cache mode: In-memory (set REDIS_URL for Redis)")
