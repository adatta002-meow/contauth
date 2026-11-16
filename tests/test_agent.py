"""Tests for the desktop agent — all headless, with synthetic events.

The event streams here are fixtures that exercise code paths (enrollment, the
policy branches, the lock action). They are never used to train a shipped model or
to report any metric.
"""
import random
import time

import numpy as np
import pytest

from contauth.agent.capture import Capture
from contauth.agent.controller import Controller
from contauth.agent.engine import CFG, AuthEngine
from contauth.agent.lock import lock_command
from contauth.agent.store import Store

POP = str(__import__("pathlib").Path(__file__).resolve().parents[1] / "models" / "population.joblib")


def cfg(**over):
    c = dict(CFG)
    c.update({"ENROLL_WINDOWS": 12, "RETRAIN_EVERY": 8, "WINDOW_MS": 5000})
    c.update(over)
    return c


def human(rnd, t0):
    ev, t = [], t0
    for _ in range(rnd.randint(30, 55)):
        t += rnd.randint(70, 260)
        ev.append({"t": t, "type": "keydown", "mod": rnd.random() < 0.1})
    x = y = 600
    for _ in range(rnd.randint(50, 90)):
        t += rnd.randint(10, 40)
        x += rnd.randint(-30, 30); y += rnd.randint(-25, 25)
        ev.append({"t": t, "type": "mousemove", "x": x, "y": y})
    for _ in range(rnd.randint(2, 5)):
        t += rnd.randint(400, 1500)
        ev.append({"t": t, "type": "click"})
    return ev, t0, t0 + 5000


# ---- store ----
def test_store_roundtrip(tmp_path):
    s = Store(tmp_path / "a.db")
    s.add_window({"events_per_min": 10.0}, cap=50)
    s.set("hello", {"x": 1})
    s.log("login", "info", "started")
    assert s.window_count() == 1
    assert s.get("hello") == {"x": 1}
    assert s.events()[0]["kind"] == "login"


def test_store_rolling_cap(tmp_path):
    s = Store(tmp_path / "b.db")
    for i in range(70):
        s.add_window({"i": i}, cap=50)
    assert s.window_count() == 50


# ---- lock selection (no actual locking) ----
def test_lock_command_per_platform():
    assert lock_command("win32") == "LockWorkStation"
    assert lock_command("darwin")[0] in ("/System/Library/CoreServices/Menu Extras/User.menu/Contents/Resources/CGSession", "pmset")
    # linux returns a list or None depending on what's installed; both are valid
    assert lock_command("linux") is None or isinstance(lock_command("linux"), list)


# ---- engine ----
def test_engine_enrolls_and_scores(tmp_path):
    s = Store(tmp_path / "e.db")
    eng = AuthEngine(s, cfg=cfg(), population_path=POP)
    rnd = random.Random(1)
    actions = []
    for k in range(20):
        d = eng.score_window(*human(rnd, k * 5000))
        actions.append(d["action"])
    assert eng.prof is not None and eng.enrolled >= 12
    assert all(a in ("allow", "monitor") for a in actions)
    assert eng.status()["model"] == "personal"


def test_engine_bot_terminates(tmp_path):
    eng = AuthEngine(Store(tmp_path / "f.db"), cfg=cfg(), population_path=POP)
    bot = [{"t": i * 20, "type": "mousemove", "x": 100 + 6 * i, "y": 300} for i in range(150)]
    d = eng.score_window(bot, 0, 5000)
    assert d["action"] == "terminate" and "automation" in " ".join(d["components"]["overrides"])


def test_engine_insufficient_activity_keeps_score(tmp_path):
    eng = AuthEngine(Store(tmp_path / "g.db"), cfg=cfg(), population_path=POP)
    eng.ewma = 20.0
    d = eng.score_window([{"t": 1, "type": "keydown"}], 0, 5000)  # 1 event < MIN
    assert d["model"] == "insufficient-activity" and d["components"]["behavior"] == 20.0


def test_reset_profile(tmp_path):
    s = Store(tmp_path / "h.db")
    eng = AuthEngine(s, cfg=cfg(), population_path=POP)
    rnd = random.Random(2)
    for k in range(14):
        eng.score_window(*human(rnd, k * 5000))
    assert eng.prof is not None
    eng.reset_profile()
    assert eng.prof is None and eng.enrolled == 0 and s.window_count() == 0


# ---- controller + enforcement ----
def test_controller_locks_on_bot(tmp_path):
    s = Store(tmp_path / "i.db")
    eng = AuthEngine(s, cfg=cfg(), population_path=POP)
    calls = []
    c = Controller(eng, s, lock_fn=lambda logger=None: calls.append("lock"))
    bot = [{"t": i * 20, "type": "mousemove", "x": 100 + 6 * i, "y": 300} for i in range(150)]
    c.process_window(bot, 0, 5000)
    assert calls == ["lock"] and c.locks == 1
    assert any(e["kind"] == "lock_screen" and e["severity"] == "critical" for e in s.events())


def test_controller_face_grants_grace(tmp_path):
    s = Store(tmp_path / "j.db")
    eng = AuthEngine(s, cfg=cfg(), population_path=POP)
    locks = []
    # force a behaviour-only HIGH step-up (not a critical override) via a crafted state
    c = Controller(eng, s, lock_fn=lambda logger=None: locks.append(1), face_fn=lambda: True)
    eng.ewma = 100.0  # prime so the next below-threshold window is HIGH
    d = {"action": "step_up", "tier": "HIGH", "components": {"overrides": []}}
    c._enforce(d, "warning", "test")
    assert locks == [] and any(e["kind"] == "face_confirmed" for e in s.events())


def test_controller_pause_skips(tmp_path):
    s = Store(tmp_path / "k.db")
    eng = AuthEngine(s, cfg=cfg(), population_path=POP)
    c = Controller(eng, s, lock_fn=lambda logger=None: None)
    c.pause(True)
    d = c.process_window([{"t": i, "type": "mousemove", "x": i, "y": 0} for i in range(50)], 0, 5000)
    assert d["action"] == "paused"


# ---- capture privacy ----
def test_capture_records_timing_not_keys():
    cap = Capture()

    class FakeKey:
        name = "a"  # a normal character key reports no modifier name match... but 'a' is not in the set
    cap._on_press(FakeKey())
    (e,) = cap.drain()
    assert set(e) == {"t", "type", "mod"}      # only timing + modifier flag
    assert e["type"] == "keydown" and e["mod"] is False
    assert "key" not in e and "char" not in e and "vk" not in e


def test_capture_modifier_flag():
    cap = Capture()

    class Shift:
        name = "shift"
    cap._on_press(Shift())
    assert cap.drain()[0]["mod"] is True


def test_capture_move_throttled():
    cap = Capture(move_sample_ms=1000)
    cap._on_move(0, 0)
    cap._on_move(5, 5)  # within the throttle window -> dropped
    assert len(cap.drain()) == 1
