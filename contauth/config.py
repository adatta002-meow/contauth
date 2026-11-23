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

    # Email verification: a new account must confirm a one-time code sent to its email
    # (the "verified Gmail" step) before it can sign in and start enrolling. Set the
    # SMTP_* vars to send real mail (e.g. Gmail SMTP with an app password); with none
    # set, the code is shown on screen in dev mode so the flow still works locally.
    REQUIRE_EMAIL_VERIFICATION = _env("REQUIRE_EMAIL_VERIFICATION", True, lambda v: str(v).lower() != "false")
    EMAIL_CODE_TTL_MIN = _env("EMAIL_CODE_TTL_MIN", 10, int)   # code validity window
    EMAIL_MAX_ATTEMPTS = _env("EMAIL_MAX_ATTEMPTS", 5, int)    # wrong tries before a new code is needed
    EMAIL_RESEND_COOLDOWN_S = _env("EMAIL_RESEND_COOLDOWN_S", 30, int)
    SMTP_HOST = _env("SMTP_HOST", None)
    SMTP_PORT = _env("SMTP_PORT", 587, int)
    SMTP_USER = _env("SMTP_USER", None)
    SMTP_PASSWORD = _env("SMTP_PASSWORD", None)
    SMTP_FROM = _env("SMTP_FROM", None)                        # e.g. "ContAuth <you@gmail.com>"
    SMTP_STARTTLS = _env("SMTP_STARTTLS", True, lambda v: str(v).lower() != "false")

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

    # Sequential, multi-signal decision layer (agent only; see contauth/sequential.py).
    # The agent accumulates per-window anomaly evidence into a 0-100 trust score
    # instead of counting "N HIGH windows in a row": strong anomalies can lock within
    # one window, isolated blips leak away, and every contribution is scaled by signal
    # quality and model confidence so a thin or low-confidence window can't false-lock.
    USE_TRUST_ACCUMULATOR = True
    # Recognise the user by RHYTHM (dimensionless timing ratios) rather than raw speed,
    # so a fast-typing burst is not mistaken for someone else. The on-device personal
    # model scores on the speed-invariant RHYTHM_FEATURES when this is on.
    RHYTHM_MODE = True
    # The CMU keystroke benchmark (reports/keystroke_benchmark.md) shows Isolation Forest
    # outperforms One-Class SVM on real data (EER 8.5% vs 10.7%), so the personal model
    # weights the Isolation Forest member more than an equal blend.
    PERSONAL_IF_WEIGHT = 0.6
    TRUST_ENTER = 50               # risk above which a window adds to the penalty (lower = catches a mismatch sooner)
    TRUST_PENALTY_GAIN = 0.8       # how fast above-threshold windows raise penalty
    TRUST_RECOVERY = 0.5           # how fast clean windows bleed penalty back down
    TRUST_STEPUP_BUDGET = 0.18     # penalty at which a behaviour step-up fires (lower = fewer windows to lock)
    TRUST_TERMINATE_BUDGET = 2.0   # penalty at which corroborated risk terminates
    QUALITY_FULL_EVENTS = 60        # events for a full-quality window
    CONFIDENCE_FLOOR = 0.4          # min model confidence (cold start / unseparable user)
    CONFIDENCE_FULL_MARGIN = 0.35   # genuine-median − tau margin that counts as full confidence
    # The agent will only LOCK on behavioural evidence once it actually recognises
    # you: a personal model exists and separates you from others well enough. Below
    # this confidence it observes and warns instead of locking, so it can't lock you
    # out of your own machine just because it hasn't learned your rhythm yet.
    # Deterministic threats (bot input, replayed windows, session-binding) are NOT
    # gated by this and still act immediately.
    ENFORCE_MIN_CONFIDENCE = 0.55
    # Adaptation: right after the operator signs in (password + verified email) or
    # passes a re-check, we have strong proof it's them. For a short window the agent
    # LEARNS their current behaviour — including fast typing or a different pace — and
    # will not lock on behaviour alone, so a speed change right after login can't lock
    # them out. Deterministic threats (bot input, replay) still act. The profile also
    # keeps absorbing mildly-unusual (MEDIUM) windows while trust is high, so it widens
    # to the user's real range instead of rejecting it.
    ADAPT_AFTER_AUTH_MIN = _env("ADAPT_AFTER_AUTH_MIN", 2, float)   # minutes of learn-and-don't-lock after a sign-in
    ADAPT_ENROLL_MEDIUM = True       # let MEDIUM, clean windows widen the profile
    DRIFT_TRUST_MIN = 75             # trust score above which MEDIUM windows may enroll
    POISON_ADAPT_CAP = 8             # max MEDIUM windows absorbed in a row before a clean LOW is required (anti-poisoning)
    IDLE_RELOCK_MIN = _env("IDLE_RELOCK_MIN", 10, float)   # after this idle gap, drop trust/adaptation so whoever returns must re-prove

    # Desktop sign-in brute-force protection
    AGENT_LOGIN_MAX_TRIES = _env("AGENT_LOGIN_MAX_TRIES", 5, int)
    AGENT_LOGIN_LOCKOUT_MIN = _env("AGENT_LOGIN_LOCKOUT_MIN", 5, float)

    # Anti-spoofing: replay / signal-quality gating (agent, deterministic).
    REPLAY_MAX_SKEW_MS = 5000       # a window whose clock runs backwards > this is rejected
    REPLAY_DUP_HISTORY = 16         # remember this many recent window fingerprints
    MIN_QUALITY_TO_ENROLL = 0.5     # a window must be at least this rich to teach the profile
    MIN_QUALITY_TO_SCORE = 0.2      # below this, observe only (never lock on it)
