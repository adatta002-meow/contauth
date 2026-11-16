"""Zero Trust decision engine (pure functions, no I/O, so it is unit-testable).

    Risk = w1*B + w2*C + w3*D + w4*S       (each component 0-100)

B behaviour  - 100 x (1 - genuineness) from the ML layer, EWMA-smoothed
C context    - network: IP changed mid-session, IP never seen for this user
D device     - user agent / device fingerprint changed mid-session, new device
S session    - sensitive page, session age, failed step-ups

Hard overrides raise the risk to a floor regardless of the weighted sum, for
signals that are deterministic rather than statistical (e.g. the session cookie
is now being used from a different browser).

Tiers (from the Capstone B design):
  LOW 0-30 allow | MEDIUM 31-60 monitor | HIGH 61-80 step-up re-auth | CRITICAL 81-100 terminate + lock
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Signals:
    genuineness: float | None          # None = window had too little activity to judge
    damping: float = 1.0               # <1 during cold start (population model)
    model: str = "population"
    prev_behavior_ewma: float | None = None
    high_streak: int = 0
    ip_changed: bool = False
    ip_new_for_user: bool = False
    ua_changed: bool = False
    device_changed: bool = False
    device_new_for_user: bool = False
    sensitive_page: bool = False
    session_age_h: float = 0.0
    failed_stepups: int = 0
    window_feats: dict = field(default_factory=dict)


def tier_for(risk, tiers):
    for upper, name in tiers:
        if risk <= upper:
            return name
    return tiers[-1][1]


def automation_suspected(f: dict) -> str | None:
    """Cheap tells of scripted input. Humans are never this regular or this fast."""
    if not f:
        return None
    if f.get("events_per_min", 0) > 6000:
        return "event rate above human range"
    # Geometry, not timing: browser timer jitter hides constant velocity, but a script
    # stepping the pointer by the same vector stays visible. Heuristic threshold, set
    # conservatively (the training dataset has no raw trajectories to calibrate it on).
    if f.get("mouse_movement_count", 0) >= 40 and f.get("repeated_step_ratio", 0) >= 0.9:
        return "pointer moved in identical repeated steps"
    if f.get("mouse_movement_count", 0) >= 20 and f.get("avg_mouse_speed_px_s", 0) > 0:
        if f.get("std_mouse_speed_px_s", 0) < 0.01 * f["avg_mouse_speed_px_s"]:
            return "constant-velocity pointer movement"
    if f.get("key_press_count", 0) >= 20 and f.get("std_inter_key_interval_ms") is not None:
        if f["std_inter_key_interval_ms"] < 5:
            return "machine-regular keystroke timing"
    return None


def evaluate(s: Signals, cfg) -> dict:
    w, alpha = cfg["WEIGHTS"], cfg["BEHAVIOR_EWMA_ALPHA"]

    # B: behaviour
    if s.genuineness is None:
        behavior = s.prev_behavior_ewma if s.prev_behavior_ewma is not None else 0.0
        raw_b = None
    else:
        raw_b = 100.0 * (1.0 - min(max(s.genuineness, 0.0), 1.0)) * s.damping
        behavior = raw_b if s.prev_behavior_ewma is None else alpha * raw_b + (1 - alpha) * s.prev_behavior_ewma

    # C: context
    context = max(70.0 if s.ip_changed else 0.0, 30.0 if s.ip_new_for_user else 0.0)
    # D: device
    device = max(100.0 if (s.ua_changed or s.device_changed) else 0.0, 40.0 if s.device_new_for_user else 0.0)
    # S: session
    session = min(100.0, (30.0 if s.sensitive_page else 0.0)
                  + (40.0 if s.session_age_h > cfg["SESSION_MAX_AGE_H"] else 0.0)
                  + 25.0 * s.failed_stepups)

    risk = w["behavior"] * behavior + w["context"] * context + w["device"] * device + w["session"] * session

    overrides = []
    if s.ua_changed or s.device_changed:
        overrides.append(("session_binding_mismatch", 85))
    bot = automation_suspected(s.window_feats)
    if bot:
        overrides.append(("automation_suspected: " + bot, 85))
    if s.ip_changed:
        overrides.append(("ip_changed_mid_session", 61))
    for _, floor in overrides:
        risk = max(risk, floor)
    risk = round(min(risk, 100.0), 1)

    tier = tier_for(risk, cfg["TIERS"])
    high_streak = s.high_streak + 1 if tier == "HIGH" else 0
    if tier == "LOW":
        action = "allow"
    elif tier == "MEDIUM":
        action = "monitor"
    elif tier == "HIGH":
        # statistical evidence must persist; deterministic overrides act at once
        action = "step_up" if (overrides or high_streak >= cfg["HIGH_CONSECUTIVE_FOR_STEPUP"]) else "monitor"
    else:
        action = "terminate"

    # Only clearly trusted, evidence-bearing windows may teach the user's profile.
    clean = not (overrides or s.ip_changed or s.ip_new_for_user or s.device_new_for_user)
    enrollable = bool(raw_b is not None and clean and (tier == "LOW" or (s.model == "population" and tier == "MEDIUM")))

    return {
        "risk": risk,
        "tier": tier,
        "action": action,
        "behavior_ewma": round(behavior, 2),
        "high_streak": high_streak,
        "enrollable": enrollable,
        "components": {
            "behavior": round(behavior, 1), "behavior_raw": None if raw_b is None else round(raw_b, 1),
            "context": context, "device": device, "session": session,
            "model": s.model, "overrides": [o for o, _ in overrides],
        },
    }
