"""All tunable settings in one place. Override any of them with an environment
variable of the same name prefixed CA_ (e.g. CA_WINDOW_MS=15000)."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _env(name, default, cast=str):
    v = os.environ.get("CA_" + name)
    return cast(v) if v is not None else default


class Config:
    SECRET_KEY = _env("SECRET_KEY", None) or os.urandom(32).hex()
    DATABASE = _env("DATABASE", str(ROOT / "instance" / "contauth.db"))
    POPULATION_MODEL = _env("POPULATION_MODEL", str(ROOT / "models" / "population.joblib"))
    BEHIND_PROXY = _env("BEHIND_PROXY", False, lambda v: v.lower() == "true")
    ADMIN_USER = _env("ADMIN_USER", None)
    ADMIN_PASSWORD = _env("ADMIN_PASSWORD", None)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Strict"
    SESSION_COOKIE_SECURE = _env("COOKIE_SECURE", False, lambda v: v.lower() == "true")

    # Behaviour capture
    WINDOW_MS = _env("WINDOW_MS", 30000, int)          # client batch length
    MIN_EVENTS_PER_WINDOW = _env("MIN_EVENTS", 15, int)  # below this a window carries too little evidence

    # Enrollment / per-user profile
    ENROLL_WINDOWS = _env("ENROLL_WINDOWS", 20, int)    # windows before a personal profile exists
    RETRAIN_EVERY = _env("RETRAIN_EVERY", 20, int)
    PROFILE_MAX_WINDOWS = _env("PROFILE_MAX_WINDOWS", 200, int)
    # Decision thresholds, calibrated per user at enrollment (see reports/tuning.md
    # for the measured FAR/FRR trade-off). A window scoring below the user's
    # threshold maps to the HIGH tier; two in a row trigger step-up.
    OPERATING_FAR = _env("OPERATING_FAR", 0.10, float)    # supervised profile: target impostor acceptance
    ONECLASS_FRR = _env("ONECLASS_FRR", 0.05, float)      # one-class profile: target false rejects per window
    COLD_START_DAMPING = 0.5                           # population model counts half before enrollment
    BEHAVIOR_EWMA_ALPHA = 0.5                           # smoothing of behaviour risk across windows

    # Zero Trust risk engine: Risk = w1*B + w2*C + w3*D + w4*S
    # Behaviour alone can reach HIGH (step-up) but never CRITICAL: terminating a
    # session needs corroborating context/device/session evidence or a hard override.
    WEIGHTS = {"behavior": 0.70, "context": 0.10, "device": 0.10, "session": 0.10}
    TIERS = [(30, "LOW"), (60, "MEDIUM"), (80, "HIGH"), (100, "CRITICAL")]
    HIGH_CONSECUTIVE_FOR_STEPUP = 2                     # behaviour-only HIGH must persist this many windows
    SESSION_MAX_AGE_H = 8
    LOCK_MINUTES = _env("LOCK_MINUTES", 15, int)
    MAX_FAILED_STEPUPS = 3
