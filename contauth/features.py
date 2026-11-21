"""Behavioral feature definitions shared by the training pipeline and the live system.

The raw columns follow the Capstone B dataset (session_features Main Dataset.csv).
The model only uses *rate and timing* features, because the live system scores
short windows (default 30 s) while the dataset rows are whole sessions. Raw counts
grow with duration and would not be comparable; rates, intervals and ratios are.
"""
from __future__ import annotations

import math
from statistics import mean, pstdev

# An idle gap is any pause of at least this long between consecutive events.
# Inferred from the dataset: no session's mean idle gap is below ~2.1 s.
IDLE_GAP_MS = 2000

# The original 14 features (Capstone B baseline).
BASE_FEATURES = [
    "events_per_min",
    "typing_speed_keys_per_min",
    "avg_inter_key_interval_ms",
    "std_inter_key_interval_ms",
    "avg_mouse_speed_px_s",
    "std_mouse_speed_px_s",
    "avg_inter_click_interval_ms",
    "scroll_rate_per_min",
    "idle_time_ratio",
    # derived from dataset columns (see add_derived_features)
    "mouse_moves_per_min",
    "clicks_per_min",
    "mouse_distance_per_min",
    "idle_gaps_per_min",
    "modifier_key_ratio",
]

# Additional duration-invariant candidates, also computable live from a window.
EXTRA_FEATURES = [
    "cv_inter_key",           # std / mean inter-key interval: rhythm regularity
    "cv_mouse_speed",         # std / mean pointer speed
    "keys_per_mouse_move",    # keyboard vs pointer reliance
    "clicks_per_mouse_move",
    "mean_idle_gap_ms",       # typical pause length
    "max_idle_gap_ratio",     # longest pause / duration
    "px_per_move",            # pointer distance per sampled move
]
ALL_FEATURES = BASE_FEATURES + EXTRA_FEATURES

# Per-keystroke timing. Available only from LIVE capture, because the Capstone
# dataset has no raw key events — so these are used by the on-device PERSONAL
# model, never the dataset-trained population model. Privacy-safe: these are
# hold/gap DURATIONS only; no key identity is ever recorded.
#   dwell  = how long a key is held  (key-down -> its key-up)
#   flight = gap from releasing one key to pressing the next (key-up -> next key-down)
KEYSTROKE_FEATURES = ["avg_dwell_ms", "std_dwell_ms", "avg_flight_ms", "std_flight_ms"]
PERSONAL_FEATURES = ALL_FEATURES + KEYSTROKE_FEATURES

# Columns used by every live model, in input order. Chosen by nested selection
# (contauth/ml/tune.py): the 21-feature set won in all 5 outer splits.
MODEL_FEATURES = ALL_FEATURES

MODIFIER_KEYS = {"Shift", "Control", "Alt", "Meta", "CapsLock", "AltGraph"}


def _per_min(count: float, duration_ms: float) -> float:
    return count / (duration_ms / 60000.0) if duration_ms > 0 else 0.0


def add_derived_features(df):
    """Add the derived rate columns to a dataset DataFrame (in place) and return it."""
    dur = df["session_duration_ms"].clip(lower=1)
    minutes = dur / 60000.0
    df["mouse_moves_per_min"] = df["mouse_movement_count"] / minutes
    df["clicks_per_min"] = df["click_count"] / minutes
    df["mouse_distance_per_min"] = df["total_mouse_distance_px"] / minutes
    df["idle_gaps_per_min"] = df["idle_gap_count"] / minutes
    df["modifier_key_ratio"] = (df["modifier_key_usage_count"] / df["key_press_count"].where(df["key_press_count"] > 0)).clip(upper=1.0)
    df["cv_inter_key"] = df["std_inter_key_interval_ms"] / df["avg_inter_key_interval_ms"].where(df["avg_inter_key_interval_ms"] > 0)
    df["cv_mouse_speed"] = df["std_mouse_speed_px_s"] / df["avg_mouse_speed_px_s"].where(df["avg_mouse_speed_px_s"] > 0)
    df["keys_per_mouse_move"] = df["key_press_count"] / (df["mouse_movement_count"] + 1)
    df["clicks_per_mouse_move"] = df["click_count"] / (df["mouse_movement_count"] + 1)
    df["mean_idle_gap_ms"] = df["total_idle_time_ms"] / df["idle_gap_count"].where(df["idle_gap_count"] > 0)
    df["max_idle_gap_ratio"] = (df["max_idle_gap_ms"] / dur).clip(upper=1.0)
    df["px_per_move"] = df["total_mouse_distance_px"] / (df["mouse_movement_count"] + 1)
    return df


def _ratio(a, b):
    return (a / b) if (a is not None and b) else None


def extract_window_features(events: list[dict], start_ms: float | None = None, end_ms: float | None = None) -> dict:
    """Compute dataset-compatible features from one window of browser events.

    Each event is a dict with at least ``t`` (ms timestamp) and ``type`` in
    {keydown, keyup, mousemove, mousedown, mouseup, click, dblclick, scroll,
    focus, blur, input}. mousemove events carry ``x``/``y``; keydown carries
    ``mod`` (True when the key is a modifier). Key identities are never sent.

    Missing values (no keys typed, fewer than two clicks) are returned as None
    and imputed by the model pipeline, the same way NaNs in the dataset are.
    """
    events = sorted((e for e in events if "t" in e and "type" in e), key=lambda e: e["t"])
    if not events:
        return {}
    t0 = start_ms if start_ms is not None else events[0]["t"]
    t1 = end_ms if end_ms is not None else events[-1]["t"]
    duration = max(t1 - t0, 1.0)

    keydowns = [e for e in events if e["type"] == "keydown"]
    moves = [e for e in events if e["type"] == "mousemove"]
    clicks = [e for e in events if e["type"] == "click"]
    scrolls = [e for e in events if e["type"] == "scroll"]

    # keystroke timing
    key_t = [e["t"] for e in keydowns]
    iki = [b - a for a, b in zip(key_t, key_t[1:]) if b > a]

    # mouse speed between consecutive move samples
    speeds, distance = [], 0.0
    for a, b in zip(moves, moves[1:]):
        d = math.hypot(b.get("x", 0) - a.get("x", 0), b.get("y", 0) - a.get("y", 0))
        distance += d
        dt = b["t"] - a["t"]
        if dt > 0:
            speeds.append(d / (dt / 1000.0))

    # pointer-path regularity (automation tell): consecutive step vectors that are
    # identical in direction and length (within 1 px)
    steps = [(b.get("x", 0) - a.get("x", 0), b.get("y", 0) - a.get("y", 0)) for a, b in zip(moves, moves[1:])]
    steps = [s for s in steps if s != (0, 0)]
    same = sum(1 for (ax, ay), (bx, by) in zip(steps, steps[1:])
               if abs(ax * by - ay * bx) <= max(1.0, 0.02 * math.hypot(ax, ay) * math.hypot(bx, by))
               and abs(math.hypot(ax, ay) - math.hypot(bx, by)) <= 1.0)
    repeated_step_ratio = same / (len(steps) - 1) if len(steps) > 1 else 0.0

    click_t = [e["t"] for e in clicks]
    ici = [b - a for a, b in zip(click_t, click_t[1:]) if b > a]

    # idle gaps: pauses >= IDLE_GAP_MS between consecutive events, plus window edges
    stamps = [t0] + [e["t"] for e in events] + [t1]
    gaps = [b - a for a, b in zip(stamps, stamps[1:]) if b - a >= IDLE_GAP_MS]
    idle_total = float(sum(gaps))

    # per-keystroke timing (live capture only). dwell is carried on each key-up by
    # the agent's capture layer (computed there by pairing a key's own down/up, with
    # the key discarded immediately). flight = release-to-next-press gap, derived here
    # from the key-up/key-down order without any key identity. Pauses (>= IDLE_GAP_MS)
    # are excluded from flight so thinking time doesn't swamp the typing rhythm.
    dwell = [e["dwell"] for e in events
             if e["type"] == "keyup" and isinstance(e.get("dwell"), (int, float)) and 0 < e["dwell"] < 2000]
    flights, last_up = [], None
    for e in events:
        if e["type"] == "keyup":
            last_up = e["t"]
        elif e["type"] == "keydown" and last_up is not None:
            f = e["t"] - last_up
            if 0 < f < IDLE_GAP_MS:
                flights.append(f)
            last_up = None

    mods = sum(1 for e in keydowns if e.get("mod"))
    avg_iki = mean(iki) if iki else None
    std_iki = pstdev(iki) if len(iki) > 1 else None
    avg_spd = mean(speeds) if speeds else 0.0
    std_spd = pstdev(speeds) if len(speeds) > 1 else 0.0

    return {
        "cv_inter_key": _ratio(std_iki, avg_iki),
        "cv_mouse_speed": _ratio(std_spd, avg_spd),
        "keys_per_mouse_move": len(keydowns) / (len(moves) + 1),
        "clicks_per_mouse_move": len(clicks) / (len(moves) + 1),
        "mean_idle_gap_ms": (idle_total / len(gaps)) if gaps else None,
        "max_idle_gap_ratio": min((max(gaps) if gaps else 0.0) / duration, 1.0),
        "px_per_move": distance / (len(moves) + 1),
        "window_duration_ms": duration,
        "total_events": len(events),
        "events_per_min": _per_min(len(events), duration),
        "typing_speed_keys_per_min": _per_min(len(keydowns), duration),
        "avg_inter_key_interval_ms": mean(iki) if iki else None,
        "std_inter_key_interval_ms": pstdev(iki) if len(iki) > 1 else None,
        "avg_mouse_speed_px_s": mean(speeds) if speeds else 0.0,
        "std_mouse_speed_px_s": pstdev(speeds) if len(speeds) > 1 else 0.0,
        "avg_inter_click_interval_ms": mean(ici) if ici else None,
        "scroll_rate_per_min": _per_min(len(scrolls), duration),
        "idle_time_ratio": min(idle_total / duration, 1.0),
        "mouse_moves_per_min": _per_min(len(moves), duration),
        "clicks_per_min": _per_min(len(clicks), duration),
        "mouse_distance_per_min": _per_min(distance, duration),
        "idle_gaps_per_min": _per_min(len(gaps), duration),
        "modifier_key_ratio": (mods / len(keydowns)) if keydowns else None,
        # context counters (not model inputs; used by the policy engine)
        "key_press_count": len(keydowns),
        "mouse_movement_count": len(moves),
        "repeated_step_ratio": repeated_step_ratio,
        "click_count": len(clicks),
        "blur_count": sum(1 for e in events if e["type"] == "blur"),
        "idle_gap_count": len(gaps),
        "max_idle_gap_ms": max(gaps) if gaps else 0.0,
        # per-keystroke timing (personal model only; None when no typing / not captured)
        "avg_dwell_ms": mean(dwell) if dwell else None,
        "std_dwell_ms": pstdev(dwell) if len(dwell) > 1 else None,
        "avg_flight_ms": mean(flights) if flights else None,
        "std_flight_ms": pstdev(flights) if len(flights) > 1 else None,
    }


def vectorize(feats: dict, columns=None) -> list[float]:
    """Model input vector; None becomes NaN for the imputer."""
    return [float("nan") if feats.get(c) is None else float(feats[c]) for c in (columns or MODEL_FEATURES)]
