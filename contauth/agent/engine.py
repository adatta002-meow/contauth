"""The agent's scoring engine — reuses the server's feature, model and policy code.

One window at a time (default 5 s of desktop activity) is turned into the same 21
features as the web/server system, scored against the population model (cold start)
or the user's personal one-class model (Isolation Forest + One-Class SVM), and run
through the identical Zero Trust policy. The only enforcement is a screen lock.

This module does no I/O of its own beyond the Store and the population model file,
and it never touches the screen directly — it returns a decision and lets the
caller (main.py) lock, so it stays unit-testable headless.
"""
from __future__ import annotations

import hashlib
import time
from collections import deque

import joblib
import numpy as np

from contauth.agent.store import Store
from contauth.config import Config
from contauth.features import MODEL_FEATURES, PERSONAL_FEATURES, extract_window_features, vectorize
from contauth.ml import models as M
from contauth.policy import Signals, evaluate
from contauth.sequential import TrustMonitor, model_confidence, signal_quality

CFG = {k: getattr(Config, k) for k in dir(Config) if k.isupper()}


def _trim(feats: dict) -> dict:
    """Store only model inputs + a few context counters; never raw events.
    PERSONAL_FEATURES includes the dwell/flight keystroke-timing features so the
    on-device personal model can use them; the population model uses MODEL_FEATURES."""
    keep = set(PERSONAL_FEATURES) | {"total_events", "key_press_count", "mouse_movement_count",
                                     "repeated_step_ratio", "avg_mouse_speed_px_s", "std_mouse_speed_px_s",
                                     "std_inter_key_interval_ms", "events_per_min"}
    return {k: feats.get(k) for k in keep}


class AuthEngine:
    def __init__(self, store: Store, cfg: dict | None = None, population_path: str | None = None):
        self.store = store
        self.cfg = dict(cfg or CFG)
        self.started = time.time()
        self.ewma = None
        self.high_streak = 0
        self.fails = 0
        self.risk = 0.0
        self.tier = "LOW"
        self.last = None
        self.prof = None           # {"if":..., "ocsvm":..., "tau":..., "med":..., "n":...}
        self.enrolled = store.window_count()
        self._pop = None
        self._pop_path = population_path or self.cfg["POPULATION_MODEL"]
        # sequential, multi-signal decision layer (see contauth/sequential.py)
        self.trust = TrustMonitor(self.cfg) if self.cfg.get("USE_TRUST_ACCUMULATOR") else None
        self.quality = 1.0
        self.confidence = self.cfg.get("CONFIDENCE_FLOOR", 0.4)
        # anti-spoofing: replay protection state (no raw events; feature fingerprints only)
        self._last_t1 = None
        self._recent = deque(maxlen=self.cfg.get("REPLAY_DUP_HISTORY", 16))
        self.replays = 0
        self.low_quality_dropped = 0
        self._adapt_until = 0.0        # learn-and-don't-lock window after a sign-in
        self._train_if_ready()

    # ---- models ----
    def population(self):
        if self._pop is None:
            self._pop = joblib.load(self._pop_path)["scorer"]
        return self._pop

    def _train_if_ready(self):
        # Personal model uses the richer PERSONAL_FEATURES (base 21 + dwell/flight).
        X = np.array([vectorize(f, PERSONAL_FEATURES)
                      for f in self.store.windows(self.cfg["PROFILE_MAX_WINDOWS"])], dtype=float)
        if len(X) < self.cfg["ENROLL_WINDOWS"]:
            self.prof = None
            return None
        iso = M.OneClassScorer(M.isolation_forest()).fit(X, cv=5)
        oc = M.OneClassScorer(M.one_class_svm()).fit(X, cv=5)
        g = (iso.oof_ + oc.oof_) / 2
        self.prof = {"if": iso, "ocsvm": oc, "n": len(X),
                     "tau": float(np.quantile(g, self.cfg["ONECLASS_FRR"])),
                     "med": float(np.median(g)), "at": time.time()}
        self.confidence = model_confidence(self.prof, self.cfg)
        return self.prof

    # ---- anti-spoofing: replay protection (deterministic) ----
    def _fingerprint(self, feats: dict) -> str:
        """Stable hash of a window's rounded model features — no raw events, no
        key identities. Two windows with an identical fingerprint are either a
        replay of recorded activity or a stalled capture; both are rejected."""
        vec = vectorize(feats, MODEL_FEATURES)
        rounded = ",".join("nan" if v != v else f"{v:.3f}" for v in vec)
        return hashlib.sha256(rounded.encode()).hexdigest()[:16]

    def _replay_check(self, feats: dict, t0: float, t1: float) -> str | None:
        """Return a reason string if this window looks replayed/tampered, else None.
          * stale_timestamp — the window clock runs backwards beyond tolerated skew
            (recorded events being re-fed, or a clock glitch): the window is dropped.
          * duplicate_window — an identical feature fingerprint seen very recently:
            a strong replay tell, raised as a step-up-level anti-spoofing override."""
        skew = self.cfg.get("REPLAY_MAX_SKEW_MS", 5000)
        if self._last_t1 is not None and t1 < self._last_t1 - skew:
            return "stale_timestamp"
        if (feats.get("total_events", 0) or 0) >= self.cfg["MIN_EVENTS_PER_WINDOW"]:
            fp = self._fingerprint(feats)
            if fp in self._recent:
                return "duplicate_window"
            self._recent.append(fp)
        self._last_t1 = max(t1, self._last_t1 or t1)
        return None

    def genuineness(self, feats):
        if self.prof is None:
            # cold start: population model, base 21 features (the dataset's feature set)
            x = np.array([vectorize(feats, MODEL_FEATURES)], dtype=float)
            return float(self.population().score(x)[0]), "population", self.cfg["COLD_START_DAMPING"]
        # personal model: richer feature set including dwell/flight
        x = np.array([vectorize(feats, PERSONAL_FEATURES)], dtype=float)
        g = (float(self.prof["if"].score(x)[0]) + float(self.prof["ocsvm"].score(x)[0])) / 2
        return M.calibrated_genuineness(g, self.prof["tau"], self.prof["med"]), "personal", 1.0

    # ---- scoring one window ----
    def score_window(self, events: list[dict], t0: float, t1: float) -> dict:
        feats = extract_window_features(events, t0, t1) or {"total_events": 0, "window_duration_ms": t1 - t0}
        self.quality = quality = signal_quality(feats, self.cfg)

        # Anti-spoofing: reject replayed/tampered windows before they can score or enroll.
        replay = self._replay_check(feats, t0, t1)
        if replay == "stale_timestamp":
            self.low_quality_dropped += 1
            return self._dropped(feats, "replay-dropped", "stale_timestamp")

        # Two independent gates:
        #  * scorable — enough events for the deterministic automation/replay checks
        #    (these run even on "low quality" windows, because a bot's perfectly
        #    regular stream is intentionally low-quality by the behavioural metric).
        #  * enough   — additionally rich enough for the STATISTICAL genuineness score
        #    to be trustworthy; a thin window is observed but never locked on.
        scorable = feats.get("total_events", 0) >= self.cfg["MIN_EVENTS_PER_WINDOW"]
        enough = scorable and quality >= self.cfg.get("MIN_QUALITY_TO_SCORE", 0.2)
        if enough:
            g, model, damp = self.genuineness(feats)
        else:
            g, model, damp = None, "insufficient-activity", 1.0

        sig = Signals(
            genuineness=g, damping=damp, model=model,
            prev_behavior_ewma=self.ewma, high_streak=self.high_streak,
            # On a single trusted machine there is no mid-session IP/device change
            # to detect; behaviour and automation drive the decision.
            ip_changed=False, ip_new_for_user=False, ua_changed=False,
            device_changed=False, device_new_for_user=False,
            sensitive_page=False,
            session_age_h=(time.time() - self.started) / 3600,
            failed_stepups=self.fails,
            window_feats=feats if scorable else {},
        )
        d = evaluate(sig, self.cfg)
        self.ewma = d["behavior_ewma"]
        self.high_streak = d["high_streak"]
        self.risk = d["risk"]
        self.tier = d["tier"]
        d["model"] = model
        d["events"] = feats.get("total_events", 0)
        d["quality"] = quality
        d["confidence"] = self.confidence

        overrides = d["components"]["overrides"]
        # Deterministic terminate-level threats (bot input, session-binding mismatch).
        # Replay is handled separately below as a step-up-level anti-spoofing signal.
        hard_override = bool(overrides)
        behaviour_only = not hard_override

        # Sequential, multi-signal decision: accumulate evidence scaled by signal
        # quality and model confidence instead of counting consecutive HIGH windows.
        if self.trust is not None:
            seq = self.trust.update(d["risk"], quality, self.confidence, hard_override, behaviour_only)
            # never downgrade a terminate that the per-window override already demands
            if not (d["action"] == "terminate" and seq["action"] != "terminate"):
                d["action"] = seq["action"]
            d["trust"] = seq["trust"]
            d["penalty"] = seq["penalty"]
        else:
            d["trust"] = round(max(0.0, 100.0 - d["risk"]), 1)
            d["penalty"] = 0.0

        # Adaptation: for a short window after the operator signs in / re-authenticates,
        # we have strong proof of identity, so behaviour alone must not lock — the agent
        # is still learning the operator's current pace (e.g. fast typing). Deterministic
        # threats (hard_override) are never suppressed.
        adapting = time.time() < self._adapt_until
        if adapting and behaviour_only and d["action"] in ("step_up", "terminate"):
            d["action"] = "monitor"
            d["adapting"] = True

        # Replay: a duplicated behaviour window is a tamper tell. Force at least a
        # step-up (re-auth), but do not escalate straight to terminate on one event.
        if replay == "duplicate_window":
            self.replays += 1
            overrides.append("replay_suspected: duplicate behaviour window")
            if d["action"] in ("allow", "monitor"):
                d["action"] = "step_up"
        self.tier = d["tier"]
        self.last = d

        # Enrollment also requires a genuinely rich window (anti-poisoning). Beyond the
        # policy's own LOW-only rule, the profile ADAPTS to the real user: a clean,
        # mildly-unusual (MEDIUM) window is absorbed while we're adapting after a sign-in
        # or while trust is high — this is how the profile learns the user's fast typing
        # instead of rejecting it. Overrides, replays and thin windows never enroll.
        mild = d["tier"] in ("LOW", "MEDIUM")
        trusted_now = self.trust is not None and self.trust.s.trust >= self.cfg.get("DRIFT_TRUST_MIN", 75)
        adaptive_enroll = (self.cfg.get("ADAPT_ENROLL_MEDIUM", True) and enough and mild
                           and not overrides and (adapting or trusted_now))
        enroll_ok = ((d["enrollable"] or adaptive_enroll)
                     and quality >= self.cfg.get("MIN_QUALITY_TO_ENROLL", 0.5) and replay is None)
        if enroll_ok:
            self.store.add_window(_trim(feats), self.cfg["PROFILE_MAX_WINDOWS"])
            self.enrolled = self.store.window_count()
            trained = self._maybe_retrain()
            if trained:
                d["profile_trained"] = trained["n"]
        return d

    def _dropped(self, feats: dict, model: str, reason: str) -> dict:
        """A window rejected before scoring (replay/tamper). Never locks on its own;
        the caller logs it as a security event."""
        d = {"risk": round(self.risk, 1), "tier": self.tier, "action": "monitor",
             "model": model, "events": feats.get("total_events", 0), "quality": self.quality,
             "confidence": self.confidence, "trust": getattr(self.trust, "s", None) and self.trust.s.trust or 100.0,
             "penalty": 0.0, "behavior_ewma": round(self.ewma or 0.0, 2), "high_streak": self.high_streak,
             "enrollable": False, "dropped": reason,
             "components": {"behavior": round(self.ewma or 0.0, 1), "behavior_raw": None, "context": 0,
                            "device": 0, "session": 0, "model": model, "overrides": []}}
        self.last = d
        return d

    def _maybe_retrain(self):
        n = self.enrolled
        last_n = self.prof["n"] if self.prof else 0
        if (self.prof is None and n >= self.cfg["ENROLL_WINDOWS"]) or \
           (self.prof is not None and n - last_n >= self.cfg["RETRAIN_EVERY"]):
            return self._train_if_ready()
        return None

    # ---- re-auth / reset after a lock ----
    def note_reauth(self):
        """Call after the screen has been locked: reset the behavioural baseline to a
        neutral medium so monitoring resumes cleanly once the user signs back in."""
        self.ewma = 30.0
        self.high_streak = 0
        self.fails = 0
        self.risk = 35.0
        self.tier = "MEDIUM"
        if self.trust is not None:
            self.trust.recover()
        # a fresh session: forget replay history so normal activity is not mistaken
        # for a replay of the pre-lock session
        self._recent.clear()
        self._last_t1 = None

    def reset_profile(self):
        self.store.clear_windows()
        self.prof = None
        self.enrolled = 0
        self.confidence = self.cfg.get("CONFIDENCE_FLOOR", 0.4)
        if self.trust is not None:
            self.trust.recover()

    def note_authenticated(self):
        """Call right after the operator signs in (password + verified email) or passes
        a re-check. Opens an adaptation window: the agent learns the operator's current
        behaviour and will not lock on behaviour alone for a few minutes, so a change of
        pace (e.g. typing fast) right after login cannot lock them out."""
        self._adapt_until = time.time() + self.cfg.get("ADAPT_AFTER_AUTH_MIN", 5) * 60.0
        self.note_reauth()

    def adapting(self) -> bool:
        return time.time() < self._adapt_until

    def enforcement_ready(self) -> bool:
        """Behaviour-based locking is allowed only once the agent actually recognises
        the user: a personal model exists and separates them from others well enough
        (confidence >= ENFORCE_MIN_CONFIDENCE). Before that it observes and warns, so
        it cannot lock the real user out just because it has not learned their rhythm.
        Deterministic threats (bot input, replay, session-binding) are NOT gated here."""
        return self.prof is not None and self.confidence >= self.cfg.get("ENFORCE_MIN_CONFIDENCE", 0.55)

    def status(self) -> dict:
        return {"risk": round(self.risk, 1), "tier": self.tier,
                "model": "personal" if self.prof else "population",
                "enrolled": self.enrolled, "need": self.cfg["ENROLL_WINDOWS"],
                "profile_n": self.prof["n"] if self.prof else 0,
                "threshold": round(self.prof["tau"], 4) if self.prof else None,
                "trust": round(self.trust.s.trust, 1) if self.trust else round(max(0.0, 100.0 - self.risk), 1),
                "quality": round(self.quality, 2),
                "confidence": round(self.confidence, 2),
                "replays": self.replays,
                "adapting": self.adapting()}
