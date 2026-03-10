"""
utils/logger.py
Structured event & API-call logging.
Writes to PostgreSQL (via database.py) when configured,
otherwise falls back to in-memory lists.
"""
import datetime
from utils.database import log_event_db, log_api_call_db


def log_event(event_type: str, **kwargs) -> dict:
    entry = {
        "event": event_type,
        "time":  datetime.datetime.utcnow().isoformat(),
        **kwargs,
    }
    log_event_db(event_type, kwargs)
    print(f"[AEGIS] {entry['time']} | {event_type} | {kwargs}")
    return entry


def log_api_call(api_name: str, status: str = "ok") -> None:
    log_api_call_db(api_name, status)
