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

import time

import joblib
import numpy as np

from contauth.agent.store import Store
from contauth.config import Config
from contauth.features import MODEL_FEATURES, extract_window_features, vectorize
from contauth.ml import models as M
from contauth.policy import Signals, evaluate

CFG = {k: getattr(Config, k) for k in dir(Config) if k.isupper()}


def _trim(feats: dict) -> dict:
    """Store only model inputs + a few context counters; never raw events."""
    keep = set(MODEL_FEATURES) | {"total_events", "key_press_count", "mouse_movement_count",
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
        self._train_if_ready()

    # ---- models ----
    def population(self):
        if self._pop is None:
            self._pop = joblib.load(self._pop_path)["scorer"]
        return self._pop

    def _train_if_ready(self):
        X = np.array([vectorize(f) for f in self.store.windows(self.cfg["PROFILE_MAX_WINDOWS"])], dtype=float)
        if len(X) < self.cfg["ENROLL_WINDOWS"]:
            self.prof = None
            return None
        iso = M.OneClassScorer(M.isolation_forest()).fit(X, cv=5)
        oc = M.OneClassScorer(M.one_class_svm()).fit(X, cv=5)
        g = (iso.oof_ + oc.oof_) / 2
        self.prof = {"if": iso, "ocsvm": oc, "n": len(X),
                     "tau": float(np.quantile(g, self.cfg["ONECLASS_FRR"])),
                     "med": float(np.median(g)), "at": time.time()}
        return self.prof

    def genuineness(self, feats):
        x = np.array([vectorize(feats)], dtype=float)
        if self.prof is None:
            return float(self.population().score(x)[0]), "population", self.cfg["COLD_START_DAMPING"]
        g = (float(self.prof["if"].score(x)[0]) + float(self.prof["ocsvm"].score(x)[0])) / 2
        return M.calibrated_genuineness(g, self.prof["tau"], self.prof["med"]), "personal", 1.0

    # ---- scoring one window ----
    def score_window(self, events: list[dict], t0: float, t1: float) -> dict:
        feats = extract_window_features(events, t0, t1) or {"total_events": 0, "window_duration_ms": t1 - t0}
        enough = feats.get("total_events", 0) >= self.cfg["MIN_EVENTS_PER_WINDOW"]
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
            window_feats=feats if enough else {},
        )
        d = evaluate(sig, self.cfg)
        self.ewma = d["behavior_ewma"]
        self.high_streak = d["high_streak"]
        self.risk = d["risk"]
        self.tier = d["tier"]
        d["model"] = model
        d["events"] = feats.get("total_events", 0)
        self.last = d

        if d["enrollable"]:
            self.store.add_window(_trim(feats), self.cfg["PROFILE_MAX_WINDOWS"])
            self.enrolled = self.store.window_count()
            trained = self._maybe_retrain()
            if trained:
                d["profile_trained"] = trained["n"]
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

    def reset_profile(self):
        self.store.clear_windows()
        self.prof = None
        self.enrolled = 0

    def status(self) -> dict:
        return {"risk": round(self.risk, 1), "tier": self.tier,
                "model": "personal" if self.prof else "population",
                "enrolled": self.enrolled, "need": self.cfg["ENROLL_WINDOWS"],
                "profile_n": self.prof["n"] if self.prof else 0,
                "threshold": round(self.prof["tau"], 4) if self.prof else None}
