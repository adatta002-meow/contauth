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


# ---- auto-start installer ----
from contauth.agent import autostart as AS


def test_autostart_install_windows(tmp_path):
    base = tmp_path / "Startup"
    path = AS.install(exe="C:\\apps\\ContAuth.exe", platform="win32", base=base)
    assert path.exists() and path.name == "ContAuth.cmd"
    body = path.read_text()
    assert "ContAuth.exe" in body and "start" in body.lower()
    assert AS.status("win32", base) is True
    assert AS.uninstall("win32", base) is True
    assert AS.status("win32", base) is False


def test_autostart_macos_plist(tmp_path):
    path = AS.install(exe="/Applications/ContAuth.app/ContAuth", platform="darwin", base=tmp_path)
    assert path.suffix == ".plist" and "com.contauth.agent" in path.read_text()
    assert "RunAtLoad" in path.read_text()


def test_autostart_linux_desktop(tmp_path):
    path = AS.install(platform="linux", base=tmp_path, extra="--window-ms 5000")
    assert path.suffix == ".desktop"
    body = path.read_text()
    assert "contauth.agent" in body and "--window-ms 5000" in body


def test_autostart_uninstall_missing(tmp_path):
    assert AS.uninstall("linux", tmp_path) is False


# ---- daily-use safety: warm-up, cooldown, monitor-only, config ----
def _bot_window():
    return [{"t": i * 20, "type": "mousemove", "x": 100 + 6 * i, "y": 300} for i in range(150)], 0, 5000


def test_monitor_only_never_locks(tmp_path):
    s = Store(tmp_path / "mo.db")
    eng = AuthEngine(s, cfg=cfg(), population_path=POP)
    locks = []
    c = Controller(eng, s, lock_fn=lambda logger=None: locks.append(1), monitor_only=True)
    c.process_window(*_bot_window())
    assert locks == [] and c.locks == 0
    assert any(e["kind"] == "would_lock" for e in s.events())


def test_warmup_warns_on_behaviour_but_bot_still_locks(tmp_path):
    s = Store(tmp_path / "wu.db")
    eng = AuthEngine(s, cfg=cfg(), population_path=POP)
    clk = [1000.0]
    locks = []
    c = Controller(eng, s, lock_fn=lambda logger=None: locks.append(1),
                   warmup_s=300.0, clock=lambda: clk[0])
    # behaviour-only step-up during warm-up -> warn only, no lock
    c._enforce({"components": {"overrides": []}}, "warning", "behaviour")
    assert locks == [] and any(e["kind"] == "warn_only" for e in s.events())
    # a critical threat during warm-up still locks
    c._enforce({"components": {"overrides": ["automation"]}}, "critical", "bot")
    assert locks == [1]


def test_cooldown_suppresses_relock(tmp_path):
    s = Store(tmp_path / "cd.db")
    eng = AuthEngine(s, cfg=cfg(), population_path=POP)
    clk = [1000.0]
    locks = []
    c = Controller(eng, s, lock_fn=lambda logger=None: locks.append(1),
                   cooldown_s=30.0, clock=lambda: clk[0])
    c._enforce({"components": {"overrides": ["automation"]}}, "critical", "bot")
    assert locks == [1]
    clk[0] += 5  # within cooldown
    c._enforce({"components": {"overrides": ["automation"]}}, "critical", "bot")
    assert locks == [1] and any(e["kind"] == "lock_suppressed" for e in s.events())
    clk[0] += 40  # past cooldown
    c._enforce({"components": {"overrides": ["automation"]}}, "critical", "bot")
    assert locks == [1, 1]


def test_config_file_overrides(tmp_path):
    import json
    from contauth.agent.main import build
    cfgfile = tmp_path / "c.json"
    cfgfile.write_text(json.dumps({"enroll_windows": 25, "high_consecutive": 3,
                                   "warmup_minutes": 7, "monitor_only": True}))

    class A:
        config = str(cfgfile); window_ms = None; enroll = None; high_consecutive = None
        warmup_min = None; cooldown_sec = None; monitor_only = False; face = False
        dry_run = True; data_dir = str(tmp_path / "d.db"); population = POP
    store, engine, controller, c = build(A())
    assert c["ENROLL_WINDOWS"] == 25 and c["HIGH_CONSECUTIVE_FOR_STEPUP"] == 3
    assert controller.monitor_only is True and controller.warmup_s == 420.0
    store.close()


def test_agent_fast_defaults(tmp_path):
    """The built app should enroll quickly out of the box (no flags)."""
    from contauth.agent.main import build, AGENT_DEFAULTS, DEFAULT_WARMUP_MIN

    class A:
        config = None; window_ms = None; enroll = None; high_consecutive = None
        warmup_min = None; cooldown_sec = None; monitor_only = False; face = False
        dry_run = True; data_dir = str(tmp_path / "d.db"); population = POP
    store, engine, controller, c = build(A())
    assert c["WINDOW_MS"] == 3000 and c["ENROLL_WINDOWS"] == 8
    assert c["ENROLL_WINDOWS"] * c["WINDOW_MS"] / 1000 <= 30  # enrolls within 30 s
    assert controller.warmup_s == DEFAULT_WARMUP_MIN * 60
    store.close()


# ---- keystroke-dynamics features (dwell/flight) ----
from contauth.agent.capture import Capture
from contauth.features import KEYSTROKE_FEATURES, MODEL_FEATURES, PERSONAL_FEATURES, extract_window_features


def test_capture_emits_dwell_without_key_identity():
    cap = Capture()

    class K:
        name = "x"          # a normal character key (not a modifier)
    k = K()
    cap._on_press(k)
    import time as _t; _t.sleep(0.01)
    cap._on_release(k)
    evs = cap.drain()
    down, up = evs[0], evs[1]
    assert down["type"] == "keydown" and up["type"] == "keyup"
    assert "dwell" in up and up["dwell"] > 0          # hold time measured
    # privacy: neither event carries the key, its char or vk
    for e in evs:
        assert "key" not in e and "char" not in e and "vk" not in e
    assert cap._down == {}                            # transient pairing dict is cleared


def test_capture_ignores_autorepeat_for_dwell():
    cap = Capture()

    class K:
        name = "y"
    k = K()
    cap._on_press(k); cap._on_press(k)   # auto-repeat: second press must not reset hold start
    assert len(cap._down) == 1


def test_personal_feature_set_extends_base():
    assert all(f in PERSONAL_FEATURES for f in KEYSTROKE_FEATURES)
    assert len(PERSONAL_FEATURES) == len(MODEL_FEATURES) + 4


def test_engine_personal_model_uses_keystroke_features(tmp_path):
    s = Store(tmp_path / "ks.db")
    eng = AuthEngine(s, cfg=cfg(), population_path=POP)
    rnd = random.Random(7)

    def typed_window(t0):
        ev, t = [], t0
        for i in range(40):
            ev.append({"t": t, "type": "keydown", "mod": i % 11 == 0})
            hold = 80 + rnd.randint(0, 40)
            ev.append({"t": t + hold, "type": "keyup", "dwell": hold})   # live dwell
            t += hold + 40 + rnd.randint(0, 30)
        return ev, t0, t0 + 5000

    for k in range(14):
        eng.score_window(*typed_window(k * 5000))
    # a personal profile trained, and its training matrix has the extended width
    assert eng.prof is not None
    import numpy as _np
    from contauth.features import vectorize
    X = _np.array([vectorize(f, PERSONAL_FEATURES) for f in s.windows(60)], dtype=float)
    assert X.shape[1] == len(PERSONAL_FEATURES)
    # the stored windows actually carry dwell values (not all NaN)
    dwell_col = X[:, PERSONAL_FEATURES.index("avg_dwell_ms")]
    assert _np.isfinite(dwell_col).any()


# ---- sequential, multi-signal decision layer (item 1) ----
from contauth.sequential import TrustMonitor, model_confidence, signal_quality


def test_signal_quality_rich_vs_thin():
    rnd = random.Random(3)
    rich, s, e = human(rnd, 0)
    fq = extract_window_features(rich, s, e)
    assert signal_quality(fq, cfg()) > 0.8                      # both modalities, many events
    thin = extract_window_features([{"t": 1, "type": "keydown"}, {"t": 2, "type": "keydown"}], 0, 5000)
    assert signal_quality(thin, cfg()) < 0.3                    # a couple of keystrokes only
    bot = extract_window_features([{"t": i*20, "type": "mousemove", "x": 100+6*i, "y": 300} for i in range(150)], 0, 5000)
    assert signal_quality(bot, cfg()) < 0.5                     # degenerate repeated path


def test_model_confidence_tracks_separation():
    c = cfg()
    assert model_confidence(None, c) == c["CONFIDENCE_FLOOR"]           # cold start
    strong = model_confidence({"med": 0.7, "tau": 0.2}, c)
    weak = model_confidence({"med": 0.30, "tau": 0.28}, c)             # barely separable user
    assert strong > weak and weak <= 0.6


def test_trust_monitor_strong_anomaly_steps_up_faster_than_weak():
    tm = TrustMonitor(cfg())
    # one strongly anomalous, high-quality, confident window is enough
    assert tm.update(risk=92, quality=1.0, confidence=1.0, hard_override=False, behaviour_only=True)["action"] == "step_up"
    tm2 = TrustMonitor(cfg())
    first = tm2.update(risk=70, quality=1.0, confidence=1.0, hard_override=False, behaviour_only=True)
    second = tm2.update(risk=70, quality=1.0, confidence=1.0, hard_override=False, behaviour_only=True)
    assert first["action"] == "monitor" and second["action"] == "step_up"   # weak evidence must persist


def test_trust_monitor_low_quality_cannot_false_lock():
    tm = TrustMonitor(cfg())
    # same strong risk but a thin / low-confidence window: must not step up alone
    out = tm.update(risk=92, quality=0.2, confidence=0.4, hard_override=False, behaviour_only=True)
    assert out["action"] in ("allow", "monitor")


def test_trust_monitor_leaks_and_recovers():
    tm = TrustMonitor(cfg())
    tm.update(risk=70, quality=1.0, confidence=1.0, hard_override=False, behaviour_only=True)
    tm.update(risk=5, quality=1.0, confidence=1.0, hard_override=False, behaviour_only=True)  # clean window
    assert tm.s.penalty < 0.15                                   # penalty bled back down
    tm.update(risk=70, quality=1.0, confidence=1.0, hard_override=False, behaviour_only=True)
    tm.recover()
    assert tm.s.penalty == 0.0 and tm.s.trust == 100.0


def test_trust_behaviour_only_never_terminates():
    tm = TrustMonitor(cfg())
    out = {"action": "monitor"}
    for _ in range(50):                                          # relentless high behaviour risk
        out = tm.update(risk=100, quality=1.0, confidence=1.0, hard_override=False, behaviour_only=True)
    assert out["action"] == "step_up"                           # escalates to re-auth, never terminate


# ---- anti-spoofing: replay protection (item 2) ----
def test_engine_rejects_duplicate_replayed_window(tmp_path):
    eng = AuthEngine(Store(tmp_path / "rp.db"), cfg=cfg(), population_path=POP)
    rnd = random.Random(9)
    ev, s, e = human(rnd, 0)
    eng.score_window(ev, s, e)                                   # first time: accepted
    d = eng.score_window(list(ev), s, e)                         # identical window replayed
    assert d["dropped"] is None if "dropped" in d else True
    assert "replay_suspected" in " ".join(d["components"]["overrides"])
    assert d["action"] == "step_up" and eng.replays == 1


def test_engine_drops_stale_timestamp_window(tmp_path):
    eng = AuthEngine(Store(tmp_path / "st.db"), cfg=cfg(), population_path=POP)
    rnd = random.Random(10)
    eng.score_window(*human(rnd, 1_000_000))                     # advances the clock
    d = eng.score_window(*human(rnd, 0))                         # window from far in the past
    assert d.get("dropped") == "stale_timestamp" and d["action"] == "monitor"


def test_engine_thin_window_is_observed_not_locked(tmp_path):
    eng = AuthEngine(Store(tmp_path / "tw.db"), cfg=cfg(), population_path=POP)
    eng.ewma = 100.0                                             # prime high behaviour risk
    # a window with a few keystrokes only: below the quality-to-score gate
    d = eng.score_window([{"t": i*300, "type": "keydown"} for i in range(16)], 0, 5000)
    assert d["action"] in ("allow", "monitor")                  # never locks on a thin window


# ---- privacy: at-rest encryption + user-controlled deletion (item 4) ----
import sqlite3 as _sqlite3


def test_store_encrypts_features_at_rest(tmp_path):
    s = Store(tmp_path / "enc.db")
    if not s.encrypted:
        pytest.skip("cryptography not installed in this environment")
    s.add_window({"events_per_min": 123.0, "avg_dwell_ms": 91.0}, cap=50)
    s.log("probe", "info", "secret-detail-string")
    # read the raw bytes straight from sqlite, bypassing the vault
    raw = _sqlite3.connect(str(tmp_path / "enc.db"))
    feat_blob = raw.execute("SELECT features FROM windows").fetchone()[0]
    detail_blob = raw.execute("SELECT detail FROM events").fetchone()[0]
    assert feat_blob.startswith("enc:v1:") and "events_per_min" not in feat_blob
    assert detail_blob.startswith("enc:v1:") and "secret-detail-string" not in detail_blob
    # but the vault round-trips transparently
    assert s.windows(10)[0]["events_per_min"] == 123.0
    assert s.events()[0]["detail"] == "secret-detail-string"


def test_store_wipe_removes_all_user_data(tmp_path):
    s = Store(tmp_path / "wipe.db")
    for i in range(5):
        s.add_window({"i": i}, cap=50)
    s.log("x", "info", "y")
    s.set("k", "v")
    s.wipe()
    assert s.window_count() == 0 and s.events() == [] and s.get("k") is None
    if s.encrypted is False:
        return
    assert not (tmp_path / "wipe.key").exists()         # crypto-erase removed the key


def test_store_export_summary_shows_no_text_stored(tmp_path):
    s = Store(tmp_path / "exp.db")
    s.add_window({"events_per_min": 1.0}, cap=50)
    summ = s.export_summary()
    assert summ["profile_windows"] == 1 and summ["stores_keystrokes_or_text"] is False
    assert "no key identities" in summ["stored_fields"]


# ---- robust recovery (item 2) ----
def test_recovery_escalates_after_repeated_locks(tmp_path):
    s = Store(tmp_path / "re.db")
    eng = AuthEngine(s, cfg=cfg(MAX_FAILED_STEPUPS=3), population_path=POP)
    c = Controller(eng, s, lock_fn=lambda logger=None: None)
    for _ in range(3):
        c._enforce({"components": {"overrides": ["automation"]}}, "critical", "bot")
    assert c.escalated and any(e["kind"] == "recovery_escalation" for e in s.events())


def test_scoring_error_does_not_crash_agent(tmp_path):
    s = Store(tmp_path / "er.db")
    eng = AuthEngine(s, cfg=cfg(), population_path=POP)
    c = Controller(eng, s, lock_fn=lambda logger=None: None)
    eng.score_window = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
    d = c.process_window([{"t": 1, "type": "keydown"}], 0, 5000)
    assert d["action"] == "monitor" and c.errors == 1           # degrades gracefully
    assert any(e["kind"] == "score_error" for e in s.events())
