"""SQLite data layer (users, sessions, scored windows, profiles, security events)."""
import json
import sqlite3
import time
from pathlib import Path

from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  locked_until REAL DEFAULT 0,
  created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  csrf TEXT NOT NULL,
  created_at REAL NOT NULL,
  last_seen REAL NOT NULL,
  ip TEXT, user_agent TEXT, device_hash TEXT,
  new_ip INTEGER DEFAULT 0, new_device INTEGER DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'active',      -- active | step_up | terminated | ended
  risk REAL DEFAULT 0, tier TEXT DEFAULT 'LOW',
  behavior_ewma REAL,
  high_streak INTEGER DEFAULT 0,
  windows_scored INTEGER DEFAULT 0,
  stepups INTEGER DEFAULT 0, failed_stepups INTEGER DEFAULT 0,
  end_reason TEXT
);
CREATE TABLE IF NOT EXISTS windows (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL REFERENCES sessions(id),
  user_id INTEGER NOT NULL,
  start_ms REAL, end_ms REAL, page TEXT,
  features TEXT NOT NULL,
  components TEXT,
  behavior REAL, risk REAL, tier TEXT, action TEXT,
  model TEXT, enrollable INTEGER DEFAULT 0,
  created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_windows_session ON windows(session_id);
CREATE INDEX IF NOT EXISTS ix_windows_user ON windows(user_id, enrollable);
CREATE TABLE IF NOT EXISTS profiles (
  user_id INTEGER PRIMARY KEY REFERENCES users(id),
  model BLOB NOT NULL,
  n_windows INTEGER NOT NULL,
  trained_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS known_devices (
  user_id INTEGER NOT NULL, kind TEXT NOT NULL, value TEXT NOT NULL, first_seen REAL NOT NULL,
  PRIMARY KEY (user_id, kind, value)
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  session_id TEXT, user_id INTEGER,
  kind TEXT NOT NULL, severity TEXT NOT NULL DEFAULT 'info',
  detail TEXT
);
CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts);
CREATE TABLE IF NOT EXISTS notes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  title TEXT NOT NULL, body TEXT NOT NULL, created_at REAL NOT NULL
);
"""


def get_db():
    if "db" not in g:
        path = current_app.config["DATABASE"]
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        g.db = sqlite3.connect(path, timeout=10)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        g.db.execute("PRAGMA journal_mode = WAL")
    return g.db


def close_db(_=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    get_db().executescript(SCHEMA)


def log_event(kind, severity="info", session_id=None, user_id=None, **detail):
    db = get_db()
    db.execute(
        "INSERT INTO events (ts, session_id, user_id, kind, severity, detail) VALUES (?,?,?,?,?,?)",
        (time.time(), session_id, user_id, kind, severity, json.dumps(detail) if detail else None),
    )
    db.commit()
