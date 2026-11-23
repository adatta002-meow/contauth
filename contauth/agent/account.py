"""Local account for the desktop agent: a password and a verified email.

The agent only starts capturing and comparing behaviour after the operator has
signed in. First run registers an email + password and verifies the email with a
6-digit code; later runs ask for the password. Everything is kept in the agent's
local (encrypted) store — there is no server.

Only a salted PBKDF2 hash of the password and of the one-time code is stored, never
the plaintext. Uses the standard library only (no werkzeug), so it bundles cleanly
into the one-file exe.
"""
from __future__ import annotations

import hashlib
import os
import secrets
import time

PBKDF_ITERS = 120_000
CODE_TTL_S = 600
MAX_CODE_ATTEMPTS = 5
LOGIN_MAX_TRIES = 5
LOGIN_LOCKOUT_S = 300


def _hash(value: str, salt_hex: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", value.encode(), bytes.fromhex(salt_hex), PBKDF_ITERS).hex()


def get_account(store) -> dict | None:
    return store.get("account")


def exists(store) -> bool:
    return bool(store.get("account"))


def is_verified(store) -> bool:
    a = store.get("account")
    return bool(a and a.get("verified"))


def register(store, email: str, password: str) -> dict:
    """Create the local account (unverified) with a fresh salt."""
    salt = os.urandom(16).hex()
    acct = {"email": email, "salt": salt, "hash": _hash(password, salt),
            "verified": False, "created": time.time()}
    store.set("account", acct)
    return acct


def check_password(store, password: str) -> bool:
    a = store.get("account")
    return bool(a) and secrets.compare_digest(_hash(password, a["salt"]), a["hash"])


def login_locked_for(store) -> float:
    """Seconds remaining on a brute-force lockout (0 if not locked)."""
    st = store.get("login_state") or {}
    return max(0.0, st.get("locked_until", 0) - time.time())


def record_login_result(store, ok: bool, max_tries: int = LOGIN_MAX_TRIES, lockout_s: float = LOGIN_LOCKOUT_S):
    """Track failed password attempts and lock the sign-in for a cooldown after too
    many, so the local password can't be brute-forced."""
    if ok:
        store.set("login_state", {"fails": 0, "locked_until": 0})
        return
    st = store.get("login_state") or {"fails": 0, "locked_until": 0}
    st["fails"] = st.get("fails", 0) + 1
    if st["fails"] >= max_tries:
        st = {"fails": 0, "locked_until": time.time() + lockout_s}
    store.set("login_state", st)


def set_verified(store):
    a = store.get("account")
    if a:
        a["verified"] = True
        a["verified_at"] = time.time()
        store.set("account", a)
    store.set("email_code", None)


def issue_code(store) -> str:
    """Generate a 6-digit code, store only its hash + expiry, return the plaintext
    so the caller can email it (or show it in dev mode)."""
    a = store.get("account")
    code = f"{secrets.randbelow(1_000_000):06d}"
    store.set("email_code", {"hash": _hash(code, a["salt"]), "exp": time.time() + CODE_TTL_S, "attempts": 0})
    return code


def check_code(store, code: str) -> str:
    """Return 'ok', 'wrong', 'expired' or 'locked'."""
    rec = store.get("email_code")
    a = store.get("account")
    if not rec or not a or rec["exp"] < time.time():
        return "expired"
    if rec["attempts"] >= MAX_CODE_ATTEMPTS:
        return "locked"
    if secrets.compare_digest(_hash(code, a["salt"]), rec["hash"]):
        set_verified(store)
        return "ok"
    rec["attempts"] += 1
    store.set("email_code", rec)
    return "wrong"
