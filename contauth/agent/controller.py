"""Glue between capture, engine and enforcement — kept free of any GUI so it can be
unit-tested headless. The UI and the simulator both drive a Controller.

Daily-use safety: on a real machine you do not want surprise lock-outs, so the
controller supports three guards (all off by default, set by main.py / a config):
  * warm-up   — for the first N minutes after launch, a behaviour-only step-up only
                WARNS (logs) instead of locking; deterministic threats (a bot, a
                cookie replay) still lock immediately.
  * cooldown  — after a lock, suppress another lock for a few seconds so you are not
                locked again the instant you start typing to sign back in.
  * monitor-only — never lock at all; only log what it would have done. Good for
                living with the agent for a few days before letting it enforce.
"""
from __future__ import annotations

import time

from contauth.agent.engine import AuthEngine
from contauth.agent.lock import lock_screen


class Controller:
    def __init__(self, engine: AuthEngine, store, lock_fn=None, face_fn=None, logger=None,
                 warmup_s: float = 0.0, cooldown_s: float = 0.0, monitor_only: bool = False,
                 clock=time.time):
        self.engine = engine
        self.store = store
        self.lock_fn = lock_fn or lock_screen
        self.face_fn = face_fn            # optional: () -> bool, confirms presence
        self.logger = logger or (lambda *a: None)
        self.paused = False
        self.locks = 0
        self.last = None
        self.warmup_s = warmup_s
        self.cooldown_s = cooldown_s
        self.monitor_only = monitor_only
        self._clock = clock
        self.started = clock()
        self._last_lock = -1e12

    def _log(self, kind, severity, detail):
        self.store.log(kind, severity, detail)
        self.logger(kind, severity, detail)

    def process_window(self, events, t0, t1) -> dict:
        """Score one window and enforce. Returns the decision dict."""
        if self.paused:
            return {"tier": "PAUSED", "action": "paused", "risk": 0}
        d = self.engine.score_window(events, t0, t1)
        self.last = d
        if d.get("profile_trained"):
            self._log("profile_trained", "info", f"personal model trained on {d['profile_trained']} windows")
        if d["action"] == "step_up":
            self._enforce(d, "warning", "behaviour no longer matches your profile")
        elif d["action"] == "terminate":
            reason = "; ".join(d["components"]["overrides"]) or "critical behavioural risk"
            self._enforce(d, "critical", reason)
        return d

    def _enforce(self, d, severity, reason):
        now = self._clock()
        # monitor-only: observe, never lock.
        if self.monitor_only:
            self._log("would_lock", severity, f"monitor-only: would lock ({reason})")
            self.engine.note_reauth()
            return
        # warm-up: hold off on behaviour-only step-ups, but still stop real threats.
        if severity != "critical" and (now - self.started) < self.warmup_s:
            self._log("warn_only", "warning", f"warm-up grace: would lock ({reason}) — holding off")
            self.engine.note_reauth()
            return
        # cooldown: don't re-lock the instant the user starts signing back in.
        if self.cooldown_s and (now - self._last_lock) < self.cooldown_s:
            self._log("lock_suppressed", "info", f"within cooldown; not re-locking ({reason})")
            self.engine.note_reauth()
            return
        # optional camera second factor: a confirmed face grants a short grace period
        # instead of locking. Anything else -> lock and re-auth via the OS.
        if self.face_fn is not None and severity != "critical":
            self._log("face_check", "info", "asking for a camera presence check")
            try:
                if self.face_fn():
                    self._log("face_confirmed", "info", "presence confirmed; session continues")
                    self.engine.note_reauth()
                    return
            except Exception as e:
                self._log("face_error", "warning", f"face check failed: {e}")
        self._log("lock_screen", severity, f"locking the screen ({reason})")
        self.locks += 1
        self._last_lock = now
        self.lock_fn(logger=lambda m: self.logger("lock", "info", m))
        # After locking, the OS login is the re-authentication. Reset the baseline so
        # monitoring resumes cleanly when the real user signs back in.
        self.engine.note_reauth()

    def pause(self, on: bool):
        self.paused = on
        self._log("paused" if on else "resumed", "info", "monitoring paused" if on else "monitoring resumed")

    def reset_profile(self):
        self.engine.reset_profile()
        self._log("profile_reset", "info", "profile cleared; enrollment restarts")
