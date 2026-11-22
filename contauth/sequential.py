"""Sequential, multi-signal decision layer for the continuous-auth agent.

The per-window risk in ``policy.evaluate`` answers one question: how anomalous is
*this* window? That is a near-binary verdict per window, and the original agent
turned it into a lock with a brittle rule — "N HIGH windows in a row". This module
replaces that with a proper risk-based, evidence-accumulating decision:

  * signal_quality(feats)  — how much evidence a window actually carries (events,
    both input modalities, non-degenerate). Thin windows can't drive a lock alone.
  * model_confidence(prof) — how well the enrolled model separates this user from
    others. When the personal model is near chance for a hard-to-model user, the
    agent leans on deterministic signals instead of locking on weak behaviour.
  * TrustMonitor          — a leaky penalty integrator (a 0–100 "trust" score).
    Strong anomalies accumulate fast and can step up within one window; isolated
    blips leak away; weak-but-persistent drift still trips. Every contribution is
    scaled by quality × confidence, so a thin or low-confidence window cannot cause
    a false lock on its own.

All pure functions / small state objects, no I/O — unit-testable headless. The
shared ``policy.evaluate`` is deliberately left unchanged so the web/server system
and its calibration keep their exact behaviour.
"""
from __future__ import annotations

from dataclasses import dataclass


def signal_quality(feats: dict, cfg: dict) -> float:
    """0..1 estimate of how much verification evidence a window carries.

    1.0 = a rich window with plenty of keyboard *and* mouse activity. Low values
    mean the window is sparse or one-dimensional, so its genuineness score is
    noisy and must count for less in the decision (and never enroll)."""
    if not feats:
        return 0.0
    n = feats.get("total_events", 0) or 0
    min_ev = cfg.get("MIN_EVENTS_PER_WINDOW", 15)
    target = cfg.get("QUALITY_FULL_EVENTS", max(min_ev * 4, 60))
    # evidence volume, saturating at `target`
    vol = min(1.0, n / target) if target else 0.0
    # modality coverage: windows with both keys and mouse are far more informative
    keys = feats.get("key_press_count", 0) or 0
    moves = feats.get("mouse_movement_count", 0) or 0
    modalities = (1 if keys > 0 else 0) + (1 if moves > 0 else 0)
    cover = {0: 0.0, 1: 0.6, 2: 1.0}[modalities]
    # degenerate-stream penalty: an almost perfectly repeated pointer path, or a
    # single event type, carries little genuine behavioural signal
    degen = 1.0
    if feats.get("mouse_movement_count", 0) >= 20 and feats.get("repeated_step_ratio", 0) >= 0.98:
        degen = 0.3
    return round(max(0.0, min(1.0, vol * cover * degen)), 4)


def model_confidence(prof: dict | None, cfg: dict) -> float:
    """0..1 confidence in the enrolled personal model's ability to tell this user
    apart. Derived from the held-out separation between the user's typical score
    (median) and their decision threshold (tau): a wide margin => confident model;
    a margin near zero (the model can barely separate this user) => low confidence,
    so the sequential layer stays conservative instead of locking on weak evidence.
    Cold start (no personal model) returns the configured floor."""
    floor = cfg.get("CONFIDENCE_FLOOR", 0.4)
    if not prof:
        return floor
    med, tau = prof.get("med"), prof.get("tau")
    if med is None or tau is None:
        return floor
    margin = max(0.0, float(med) - float(tau))          # 0 (useless) .. ~0.5 (strong)
    span = cfg.get("CONFIDENCE_FULL_MARGIN", 0.35)
    return round(floor + (1.0 - floor) * min(1.0, margin / span), 4)


@dataclass
class TrustState:
    penalty: float = 0.0          # accumulated anomaly evidence (0 .. terminate budget)
    trust: float = 100.0          # 0..100, for display: 100 = fully trusted
    stepups: int = 0              # consecutive step-ups without a clean recovery


class TrustMonitor:
    """Leaky evidence accumulator that turns a stream of per-window risks into a
    stable lock decision. See module docstring."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.enter = next((u for u, name in cfg["TIERS"] if name == "MEDIUM"), 60)  # HIGH boundary
        self.gain = cfg.get("TRUST_PENALTY_GAIN", 0.6)
        self.leak = cfg.get("TRUST_RECOVERY", 0.5)
        self.stepup_budget = cfg.get("TRUST_STEPUP_BUDGET", 0.25)
        self.terminate_budget = cfg.get("TRUST_TERMINATE_BUDGET", 2.0)
        self.s = TrustState()

    def _trust_pct(self) -> float:
        return round(max(0.0, 100.0 * (1.0 - self.s.penalty / self.stepup_budget)), 1)

    def update(self, risk: float, quality: float, confidence: float,
               hard_override: bool, behaviour_only: bool) -> dict:
        """Fold one window's verdict into the accumulator and return the sequential
        decision. `hard_override` = a deterministic threat (bot/replay/binding) that
        must act at once; `behaviour_only` = the risk is statistical, so it may step
        up but never terminate on its own (matches the engine's trust model)."""
        span = max(1.0, 100.0 - self.enter)
        if risk > self.enter:
            self.s.penalty += self.gain * (risk - self.enter) / span * max(0.0, quality) * max(0.0, confidence)
        else:
            self.s.penalty = max(0.0, self.s.penalty - self.leak * (self.enter - risk) / self.enter)
        self.s.penalty = min(self.s.penalty, self.terminate_budget)
        self.s.trust = self._trust_pct()

        if hard_override:
            action = "terminate"
        elif self.s.penalty >= self.terminate_budget and not behaviour_only:
            action = "terminate"
        elif self.s.penalty >= self.stepup_budget:
            action = "step_up"
        elif risk <= self.enter:
            action = "allow" if risk <= self.cfg["TIERS"][0][0] else "monitor"
        else:
            action = "monitor"   # over HIGH boundary but not yet enough accumulated evidence

        if action in ("step_up", "terminate"):
            self.s.stepups += 1
        return {"action": action, "penalty": round(self.s.penalty, 4),
                "trust": self.s.trust, "stepups": self.s.stepups}

    def recover(self):
        """After a successful re-auth: clear the accumulated penalty and restore trust."""
        self.s = TrustState()
