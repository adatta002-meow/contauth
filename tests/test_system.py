"""Tests for features, the Zero Trust engine, and attack scenarios end to end.

Event streams here are test fixtures that exercise code paths (timing maths,
policy branches). They are never used for training or reported metrics.
"""
import math
import re

import pandas as pd
import pytest

from contauth import create_app
from contauth.config import Config
from contauth.features import MODEL_FEATURES, add_derived_features, extract_window_features
from contauth.policy import Signals, evaluate

CFG = {k: getattr(Config, k) for k in dir(Config) if k.isupper()}
UA = "Mozilla/5.0 (X11; Linux x86_64) TestBrowser/1.0"


# features
def test_window_features_basic_maths():
    ev = [
        {"t": 0, "type": "keydown"}, {"t": 100, "type": "keydown"}, {"t": 300, "type": "keydown", "mod": True},
        {"t": 400, "type": "mousemove", "x": 0, "y": 0}, {"t": 500, "type": "mousemove", "x": 30, "y": 40},
        {"t": 600, "type": "click"}, {"t": 5600, "type": "click"},
    ]
    f = extract_window_features(ev, 0, 6000)
    assert f["avg_inter_key_interval_ms"] == 150
    assert f["avg_mouse_speed_px_s"] == pytest.approx(500.0)  # 50 px in 100 ms
    assert f["avg_inter_click_interval_ms"] == 5000
    assert f["idle_gap_count"] == 1 and f["idle_time_ratio"] == pytest.approx(5000 / 6000)
    assert f["modifier_key_ratio"] == pytest.approx(1 / 3)
    assert f["events_per_min"] == pytest.approx(7 / 0.1)


def test_live_features_match_dataset_columns():
    df = add_derived_features(pd.read_csv("data/session_features.csv"))
    assert set(MODEL_FEATURES) <= set(df.columns)
    f = extract_window_features([{"t": 0, "type": "keydown"}, {"t": 10, "type": "keydown"}], 0, 1000)
    assert set(MODEL_FEATURES) <= set(f)


# policy
def sig(**kw):
    base = dict(genuineness=0.5, damping=1.0, model="personal-oneclass")
    base.update(kw)
    return Signals(**base)


def test_typical_behaviour_is_low():
    assert evaluate(sig(genuineness=0.6), CFG)["tier"] == "LOW"


def test_behaviour_alone_never_terminates():
    d = evaluate(sig(genuineness=0.0, prev_behavior_ewma=100), CFG)
    assert d["tier"] == "HIGH" and d["risk"] == pytest.approx(70)


def test_stepup_needs_persistent_behaviour_evidence():
    first = evaluate(sig(genuineness=0.0, prev_behavior_ewma=100), CFG)
    assert first["action"] == "monitor"
    second = evaluate(sig(genuineness=0.0, prev_behavior_ewma=100, high_streak=first["high_streak"]), CFG)
    assert second["action"] == "step_up"


def test_ip_change_steps_up_immediately():
    d = evaluate(sig(ip_changed=True), CFG)
    assert d["tier"] == "HIGH" and d["action"] == "step_up"


def test_bot_input_is_critical():
    f = {"mouse_movement_count": 50, "avg_mouse_speed_px_s": 800.0, "std_mouse_speed_px_s": 0.0, "events_per_min": 200}
    d = evaluate(sig(window_feats=f), CFG)
    assert d["action"] == "terminate"


def test_anomalous_windows_never_enroll():
    assert not evaluate(sig(genuineness=0.6, ip_new_for_user=True), CFG)["enrollable"]
    assert evaluate(sig(genuineness=0.6), CFG)["enrollable"]


# end to end
@pytest.fixture
def client(tmp_path):
    app = create_app({"DATABASE": str(tmp_path / "t.db"), "TESTING": True, "SECRET_KEY": "test", "ENROLL_WINDOWS": 5, "RETRAIN_EVERY": 5, "REQUIRE_EMAIL_VERIFICATION": False})
    c = app.test_client()
    c.environ_base.update({"HTTP_USER_AGENT": UA, "REMOTE_ADDR": "10.0.0.1"})
    return c


def signin(c, user="alice"):
    c.post("/register", data={"username": user, "password": "correct horse"})
    r = c.post("/login", data={"username": user, "password": "correct horse", "fp": "1920x1080|24|Asia/Dhaka|en|Linux|8"})
    assert r.status_code == 302
    page = c.get("/app").get_data(as_text=True)
    return re.search(r'name="csrf-token" content="([^"]+)"', page).group(1)


def human_window(t0, jitter=0):
    """Irregular, human-like timing fixture (deterministic pseudo-variation)."""
    ev, t = [], t0
    for i in range(40):
        t += 120 + (i * 37 + jitter) % 170
        ev.append({"t": t, "type": "keydown", "mod": i % 9 == 0})
    for i in range(60):
        t += 15 + (i * 13 + jitter) % 40
        ev.append({"t": t, "type": "mousemove", "x": 10 * i + (i * 7) % 23, "y": 5 * i + (i * 11) % 17})
    for i in range(4):
        t += 900 + (i * 211) % 700
        ev.append({"t": t, "type": "click"})
    return ev, t0, t0 + 30000


def post_window(c, csrf, ev, s, e, page="/app/notes", headers=None):
    h = {"X-CSRF-Token": csrf}
    h.update(headers or {})
    return c.post("/api/behavior", json={"start": s, "end": e, "events": ev, "page": page}, headers=h)


def test_normal_use_stays_open_and_enrolls(client):
    csrf = signin(client)
    for k in range(6):
        ev, s, e = human_window(1_000_000 + k * 30000, jitter=k)
        r = post_window(client, csrf, ev, s, e)
        assert r.status_code == 200 and r.json["action"] in ("allow", "monitor")
    assert "Personal profile active" in client.get("/app").get_data(as_text=True)


def test_csrf_required(client):
    signin(client)
    ev, s, e = human_window(0)
    assert post_window(client, "wrong", ev, s, e).status_code == 403


def test_stolen_cookie_in_other_browser_is_terminated(client):
    signin(client)
    r = client.get("/app", headers={"User-Agent": "AttackerBrowser/9.9"})
    assert r.status_code == 302 and "/login" in r.headers["Location"]
    # the victim's session is now dead too, and the account is locked
    assert client.get("/app").status_code == 302
    r = client.post("/login", data={"username": "alice", "password": "correct horse"})
    assert "locked" in r.get_data(as_text=True)


def test_ip_change_forces_step_up_then_password_restores(client):
    csrf = signin(client)
    ev, s, e = human_window(0)
    r = post_window(client, csrf, ev, s, e)
    client.environ_base["REMOTE_ADDR"] = "203.0.113.9"
    r = post_window(client, csrf, ev, s + 30000, e + 30000)
    assert r.json["action"] == "step_up"
    assert "/reauth" in client.get("/app/settings").headers["Location"]
    client.post("/reauth", data={"csrf": csrf, "password": "correct horse"})
    assert client.get("/app/notes").status_code == 200


def test_scripted_input_terminates_session(client):
    csrf = signin(client)
    ev = [{"t": i * 20, "type": "mousemove", "x": i * 10, "y": 0} for i in range(100)]
    r = post_window(client, csrf, ev, 0, 30000)
    assert r.json["action"] == "terminate"
    assert client.get("/app").status_code == 302


def test_three_failed_stepups_lock_account(client):
    csrf = signin(client)
    client.environ_base["REMOTE_ADDR"] = "203.0.113.9"
    ev, s, e = human_window(0)
    post_window(client, csrf, ev, s, e)
    for _ in range(3):
        client.post("/reauth", data={"csrf": csrf, "password": "nope"})
    assert client.get("/app").status_code == 302


def test_admin_pages_need_admin(client):
    signin(client)
    assert client.get("/admin").status_code == 403


# calibration (model improvement)
import numpy as np

from contauth import profiles
from contauth.ml import models as Mm


def test_threshold_lands_on_high_tier():
    g = Mm.calibrated_genuineness(0.42, tau=0.42)
    d = evaluate(sig(genuineness=g, prev_behavior_ewma=100 * (1 - g)), CFG)
    assert d["tier"] == "HIGH"
    g_above = Mm.calibrated_genuineness(0.60, tau=0.42)
    assert evaluate(sig(genuineness=g_above, prev_behavior_ewma=100 * (1 - g_above)), CFG)["tier"] != "HIGH"


def test_far_threshold_hits_target():
    imp = np.linspace(0, 1, 1001)
    t = Mm.far_threshold(imp, 0.10)
    assert (imp >= t).mean() <= 0.10


def test_oof_impostor_users_are_held_out():
    rng = np.random.default_rng(0)
    X = rng.normal(size=(60, 3))
    y = np.r_[np.ones(20), np.zeros(40)]
    groups = np.r_[["self"] * 20, ["a"] * 10, ["b"] * 10, ["c"] * 10, ["d"] * 10]
    s = Mm.oof_by_group(Mm.tuned_supervised(), X, y, groups)
    assert not np.isnan(s).any()


def test_supervised_profile_calibrates(client, monkeypatch):
    monkeypatch.setattr(profiles, "MIN_OTHER_WINDOWS", 5)
    csrf_b = signin(client, "bob")
    for k in range(6):
        ev, s, e = human_window(k * 30000, jitter=50 + k)
        post_window(client, csrf_b, ev, s, e)
    client.post("/logout", data={"csrf": csrf_b})
    csrf = signin(client, "carol")
    for k in range(7):
        ev, s, e = human_window(k * 30000, jitter=k)
        r = post_window(client, csrf, ev, s, e)
    assert r.json["model"] == "personal-supervised"


def test_unload_beacon_with_other_ua_is_dropped_not_fatal(client):
    csrf = signin(client)
    ev, s, e = human_window(0)
    r = client.post(f"/api/behavior?beacon=1&csrf={csrf}", json={"start": s, "end": e, "events": ev, "page": "/app"},
                    headers={"User-Agent": "SomethingElse/1"})
    assert r.status_code == 204
    assert client.get("/app").status_code == 200  # session survives


def test_normal_request_with_other_ua_still_terminates(client):
    csrf = signin(client)
    ev, s, e = human_window(0)
    r = post_window(client, csrf, ev, s, e, headers={"User-Agent": "SomethingElse/1"})
    assert r.status_code == 401
    assert client.get("/app").status_code == 302


def test_jittered_timing_bot_is_caught_by_geometry(client):
    csrf = signin(client)
    # identical 6-px steps, irregular timing (as a real script with timer jitter produces)
    ev, t = [], 0
    for i in range(120):
        t += 18 + (i * 7) % 11
        ev.append({"t": t, "type": "mousemove", "x": 100 + 6 * i, "y": 300})
    r = post_window(client, csrf, ev, 0, 30000)
    assert r.json["action"] == "terminate"


def test_curved_human_path_is_not_flagged():
    ev, t = [], 0
    for i in range(120):
        t += 15 + (i * 13) % 30
        ev.append({"t": t, "type": "mousemove", "x": int(400 + 200 * math.cos(i / 15) + (i * 7) % 5), "y": int(300 + 120 * math.sin(i / 11))})
    f = extract_window_features(ev, 0, 30000)
    assert f["repeated_step_ratio"] < 0.5
    from contauth.policy import automation_suspected
    assert automation_suspected(f) is None


def test_typical_score_maps_to_low_tier():
    g = Mm.calibrated_genuineness(0.5, tau=0.3, median=0.5)
    d = evaluate(sig(genuineness=g, prev_behavior_ewma=100 * (1 - g)), CFG)
    assert d["tier"] == "LOW"


def test_admin_bootstrap_and_proxy_ip(tmp_path):
    app = create_app({"DATABASE": str(tmp_path / "p.db"), "SECRET_KEY": "t", "TESTING": True,
                      "BEHIND_PROXY": True, "ADMIN_USER": "root", "ADMIN_PASSWORD": "rootpass1"})
    c = app.test_client()
    c.environ_base.update({"HTTP_USER_AGENT": UA, "REMOTE_ADDR": "10.9.9.9", "HTTP_X_FORWARDED_FOR": "198.51.100.7"})
    c.post("/login", data={"username": "root", "password": "rootpass1", "fp": "x"})
    assert c.get("/admin").status_code == 200
    assert "198.51.100.7" in c.get("/admin").get_data(as_text=True)


# ---- email (Gmail) verification gate ----
def vclient(tmp_path):
    app = create_app({"DATABASE": str(tmp_path / "v.db"), "TESTING": True, "SECRET_KEY": "test",
                      "REQUIRE_EMAIL_VERIFICATION": True})
    c = app.test_client()
    c.environ_base.update({"HTTP_USER_AGENT": UA, "REMOTE_ADDR": "10.0.0.1"})
    return app, c


def test_registration_requires_email(tmp_path):
    _, c = vclient(tmp_path)
    r = c.post("/register", data={"username": "dave", "password": "correct horse"})  # no email
    assert b"valid email" in r.data                      # rejected, stays on register


def test_email_verification_gates_login_and_enrollment(tmp_path):
    app, c = vclient(tmp_path)
    r = c.post("/register", data={"username": "dave", "email": "dave@gmail.com", "password": "correct horse"})
    assert r.status_code == 302 and "/verify" in r.headers["Location"]
    # cannot sign in until verified — bounced to the verify page
    r = c.post("/login", data={"username": "dave", "password": "correct horse", "fp": "x"})
    assert "/verify" in r.headers["Location"]
    # a wrong code is rejected
    assert b"Incorrect code" in c.post("/verify", data={"code": "000000"}).data
    # the real (dev-mode) code verifies the account
    code = app.config["_DEV_CODES"]["dave@gmail.com"]
    r = c.post("/verify", data={"code": code})
    assert r.status_code == 302 and "/login" in r.headers["Location"]
    # now sign-in works and lands in the protected app (enrollment can begin)
    r = c.post("/login", data={"username": "dave", "password": "correct horse", "fp": "x"})
    assert r.status_code == 302 and "/app" in r.headers["Location"]


def test_expired_code_is_rejected(tmp_path):
    app, c = vclient(tmp_path)
    c.post("/register", data={"username": "erin", "email": "erin@gmail.com", "password": "correct horse"})
    code = app.config["_DEV_CODES"]["erin@gmail.com"]
    with app.app_context():
        from contauth.db import get_db
        get_db().execute("UPDATE email_codes SET expires_at=? WHERE user_id=(SELECT id FROM users WHERE username='erin')",
                         (0,)); get_db().commit()
    assert b"expired" in c.post("/verify", data={"code": code}).data
