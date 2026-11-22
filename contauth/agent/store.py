"""Local, file-based storage for the agent — plain SQLite, no server, no network.

Everything the agent keeps lives in one SQLite file in a per-user data directory
(e.g. %LOCALAPPDATA%\\ContAuth on Windows, ~/.local/share/contauth on Linux).
It holds only:
  * enrollable behavioural windows (feature vectors — never keystrokes or text),
  * a rolling security event log,
  * small key/value settings.

The trained model is NOT stored as a pickled object; it is retrained from the
stored feature windows at startup, so it always matches the installed
scikit-learn (the same philosophy as the server's Docker build).
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import time
from pathlib import Path

from contauth.agent.crypto import Vault

SCHEMA = """
CREATE TABLE IF NOT EXISTS windows (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  features TEXT NOT NULL,       -- JSON feature dict for one accepted window
  created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  kind TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'info',
  detail TEXT
);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
"""


def default_data_dir() -> Path:
    if sys.platform.startswith("win"):
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        return Path(base) / "ContAuth"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "ContAuth"
    base = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    return Path(base) / "contauth"


class Store:
    def __init__(self, path: str | os.PathLike | None = None, encrypt: bool = True):
        p = Path(path) if path else default_data_dir() / "agent.db"
        p.parent.mkdir(parents=True, exist_ok=True)
        self.path = str(p)
        # Behavioural features and event details are encrypted at rest (AES-256-GCM).
        # The key lives next to the database with owner-only permissions. See crypto.py
        # for the (honestly stated) threat model.
        self.vault = Vault(p.parent / (p.stem + ".key"), enabled=encrypt)
        self.db = sqlite3.connect(self.path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self.db.commit()

    @property
    def encrypted(self) -> bool:
        return self.vault.active

    # settings
    def get(self, key, default=None):
        row = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return json.loads(row["value"]) if row else default

    def set(self, key, value):
        self.db.execute("INSERT INTO meta (key, value) VALUES (?,?) "
                        "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, json.dumps(value)))
        self.db.commit()

    # enrollable windows
    def add_window(self, feats: dict, cap: int):
        blob = self.vault.encrypt(json.dumps(feats))
        self.db.execute("INSERT INTO windows (features, created_at) VALUES (?,?)", (blob, time.time()))
        # keep only the most recent `cap` windows (rolling profile, handles drift)
        self.db.execute("DELETE FROM windows WHERE id NOT IN (SELECT id FROM windows ORDER BY id DESC LIMIT ?)", (cap,))
        self.db.commit()

    def windows(self, limit: int) -> list[dict]:
        rows = self.db.execute("SELECT features FROM windows ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [json.loads(self.vault.decrypt(r["features"])) for r in rows]

    def window_count(self) -> int:
        return self.db.execute("SELECT COUNT(*) FROM windows").fetchone()[0]

    def clear_windows(self):
        self.db.execute("DELETE FROM windows")
        self.db.commit()

    # events
    def log(self, kind: str, severity: str = "info", detail: str = ""):
        self.db.execute("INSERT INTO events (ts, kind, severity, detail) VALUES (?,?,?,?)",
                        (time.time(), kind, severity, self.vault.encrypt(detail)))
        self.db.execute("DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT 2000)")
        self.db.commit()

    def events(self, limit: int = 50) -> list[dict]:
        rows = self.db.execute("SELECT ts, kind, severity, detail FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["detail"] = self.vault.decrypt(d.get("detail"))
            out.append(d)
        return out

    # ---- user-controlled data: transparency + deletion ----
    def export_summary(self) -> dict:
        """What the agent is holding about the user — for a 'see my data' view. It
        deliberately exposes counts and the schema, never raw keystrokes or text,
        because none are stored. Feature windows are aggregates only."""
        wrow = self.db.execute("SELECT COUNT(*) n, MIN(created_at) a, MAX(created_at) b FROM windows").fetchone()
        erow = self.db.execute("SELECT COUNT(*) n FROM events").fetchone()
        return {
            "profile_windows": wrow["n"],
            "oldest_window_utc": wrow["a"],
            "newest_window_utc": wrow["b"],
            "event_log_entries": erow["n"],
            "encrypted_at_rest": self.encrypted,
            "stores_keystrokes_or_text": False,
            "stored_fields": "aggregated timing/rate features per window; no key identities, no characters, no text",
            "db_path": self.path,
        }

    def wipe(self, crypto_erase: bool = True):
        """Delete all of the user's data: profile windows, event log and settings.
        With crypto_erase, also destroy the encryption key so any residual ciphertext
        on disk or in backups is unrecoverable."""
        self.db.execute("DELETE FROM windows")
        self.db.execute("DELETE FROM events")
        self.db.execute("DELETE FROM meta")
        self.db.commit()
        try:
            self.db.execute("VACUUM")
        except sqlite3.OperationalError:
            pass
        if crypto_erase:
            self.vault.wipe_key()

    def close(self):
        self.db.close()
