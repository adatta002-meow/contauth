"""Continuous Authentication for Web Sessions using Behavioral Biometrics and Zero Trust Controls."""
# Flask and the server-only modules are imported lazily inside create_app so that
# `import contauth` (used by the desktop agent and the ML pipeline) does not require
# Flask. The web server behaves exactly as before — create_app() still builds it.
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import time
from functools import wraps

from contauth.config import Config

SENSITIVE_PATHS = ("/app/settings", "/admin")
MAX_EVENTS_PER_BATCH = 20000
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _bootstrap_admin(app):
    """Create the admin from CA_ADMIN_USER / CA_ADMIN_PASSWORD if it doesn't exist.
    Hosts without shell access (e.g. Render's free tier) can't run `flask create-admin`."""
    from contauth.db import get_db
    from werkzeug.security import generate_password_hash
    user, pw = app.config.get("ADMIN_USER"), app.config.get("ADMIN_PASSWORD")
    if not user or not pw:
        return
    db = get_db()
    if db.execute("SELECT 1 FROM users WHERE username=?", (user,)).fetchone() is None:
        # admins are created out of band and are verified by definition
        db.execute("INSERT INTO users (username, password_hash, role, email_verified, created_at) VALUES (?,?,?,1,?)",
                   (user, generate_password_hash(pw), "admin", time.time()))
        db.commit()


def create_app(overrides: dict | None = None) -> "Flask":
    import click
    from flask import (Flask, abort, flash, g, jsonify, redirect, render_template,
                       request, session, url_for)
    from werkzeug.security import check_password_hash, generate_password_hash

    from contauth import email as emailer
    from contauth import profiles
    from contauth.db import close_db, get_db, init_db, log_event
    from contauth.features import extract_window_features
    from contauth.policy import Signals, evaluate

    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(Config)
    if overrides:
        app.config.update(overrides)
    app.teardown_appcontext(close_db)
    if app.config.get("BEHIND_PROXY"):
        # Hosted behind one reverse proxy (Render, Railway, Fly, nginx): take the
        # client IP and scheme from the proxy's X-Forwarded-* headers. Without this
        # every visitor looks like the proxy, and the IP-change check misfires.
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    with app.app_context():
        init_db()
        _bootstrap_admin(app)

    # helpers
    def cfg():
        return app.config

    def client_ip():
        # Behind a reverse proxy, configure werkzeug ProxyFix rather than trusting headers here.
        return request.remote_addr or "?"

    def device_hash(fp: str, ua: str) -> str:
        return hashlib.sha256((fp + "|" + ua).encode()).hexdigest()[:16]

    def end_session(sid, status, reason, severity="warning", lock_user=False):
        db = get_db()
        row = db.execute("SELECT user_id FROM sessions WHERE id=?", (sid,)).fetchone()
        db.execute("UPDATE sessions SET status=?, end_reason=? WHERE id=?", (status, reason, sid))
        if lock_user and row:
            db.execute("UPDATE users SET locked_until=? WHERE id=?", (time.time() + cfg()["LOCK_MINUTES"] * 60, row["user_id"]))
        db.commit()
        log_event("session_" + status, severity, session_id=sid, user_id=row["user_id"] if row else None,
                  reason=reason, account_locked=lock_user)

    def issue_code(user_id, email):
        """Generate a 6-digit code, store only its hash, and email it. In dev mode
        (no SMTP configured) the plaintext is stashed so the page can show it. Returns
        True when real mail was sent."""
        code = f"{secrets.randbelow(1000000):06d}"
        db = get_db()
        db.execute(
            "INSERT INTO email_codes (user_id, code_hash, expires_at, attempts, sent_at) VALUES (?,?,?,0,?) "
            "ON CONFLICT(user_id) DO UPDATE SET code_hash=excluded.code_hash, expires_at=excluded.expires_at, "
            "attempts=0, sent_at=excluded.sent_at",
            (user_id, generate_password_hash(code), time.time() + cfg()["EMAIL_CODE_TTL_MIN"] * 60, time.time()),
        )
        db.commit()
        sent = False
        try:
            sent = emailer.send_code(cfg(), email, code)
        except Exception as e:
            log_event("email_send_failed", "warning", user_id=user_id, error=str(e)[:160])
        if sent:
            log_event("email_code_sent", session_id=None, user_id=user_id)
        else:
            app.config.setdefault("_DEV_CODES", {})[email] = code   # dev mode only
        return sent

    def current():
        """Load and validate the server-side session on every request."""
        if "cur" in g:
            return g.cur
        g.cur = None
        sid = session.get("sid")
        if not sid:
            return None
        db = get_db()
        row = db.execute(
            "SELECT s.*, u.username, u.role, u.locked_until FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=?", (sid,)
        ).fetchone()
        if row is None or row["status"] in ("terminated", "ended"):
            session.clear()
            return None
        # Session binding: the cookie must keep arriving from the same browser.
        ua = request.headers.get("User-Agent", "")
        if ua != row["user_agent"]:
            if request.endpoint == "behavior" and request.args.get("beacon") == "1":
                # Best-effort unload beacon: some environments (automation, privacy
                # extensions) send these with a different UA. Discard the data, but
                # never let a beacon end a session.
                log_event("beacon_ua_mismatch_dropped", "info", session_id=sid, user_id=row["user_id"])
                g.beacon_dropped = True
                return None
            end_session(sid, "terminated", "user agent changed mid-session (possible cookie theft)", "critical", lock_user=True)
            session.clear()
            return None
        db.execute("UPDATE sessions SET last_seen=? WHERE id=?", (time.time(), sid))
        db.commit()
        g.cur = row
        return row

    def login_required(view):
        @wraps(view)
        def wrapped(*a, **kw):
            cur = current()
            if cur is None:
                return redirect(url_for("login", next=request.path))
            if cur["status"] == "step_up" and request.endpoint not in ("reauth", "logout", "behavior"):
                return redirect(url_for("reauth", next=request.path))
            return view(*a, **kw)
        return wrapped

    def sensitive(view):
        """Zero Trust: sensitive operations need a currently LOW or MEDIUM tier."""
        @wraps(view)
        def wrapped(*a, **kw):
            cur = current()
            if cur is not None and cur["tier"] in ("HIGH", "CRITICAL"):
                log_event("sensitive_blocked", "warning", session_id=cur["id"], user_id=cur["user_id"], path=request.path, tier=cur["tier"])
                get_db().execute("UPDATE sessions SET status='step_up' WHERE id=?", (cur["id"],))
                get_db().commit()
                return redirect(url_for("reauth", next=request.path))
            return view(*a, **kw)
        return wrapped

    def admin_required(view):
        @wraps(view)
        @login_required
        def wrapped(*a, **kw):
            if current()["role"] != "admin":
                abort(403)
            return view(*a, **kw)
        return wrapped

    def check_csrf(token):
        cur = current()
        if cur is None or not token or not hmac.compare_digest(token, cur["csrf"]):
            abort(403)

    @app.before_request
    def csrf_forms():
        if request.method == "POST" and request.endpoint not in ("login", "register", "behavior", "verify", "verify_resend"):
            check_csrf(request.form.get("csrf"))

    @app.context_processor
    def inject():
        return {"cur": current(), "window_ms": cfg()["WINDOW_MS"]}

    # authentication
    @app.route("/")
    def index():
        return redirect(url_for("app_home") if current() else url_for("login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        require = cfg()["REQUIRE_EMAIL_VERIFICATION"]
        if request.method == "POST":
            u = request.form.get("username", "").strip()
            p = request.form.get("password", "")
            em = request.form.get("email", "").strip().lower()
            if not (3 <= len(u) <= 32) or not u.replace("_", "").isalnum():
                flash("Username: 3-32 letters, digits or underscores.")
            elif require and not EMAIL_RE.match(em):
                flash("Enter a valid email address — we'll send a verification code to it.")
            elif len(p) < 8:
                flash("Password must be at least 8 characters.")
            else:
                try:
                    db = get_db()
                    verified = 0 if (require and em) else 1
                    cur = db.execute("INSERT INTO users (username, password_hash, email, email_verified, created_at) VALUES (?,?,?,?,?)",
                                     (u, generate_password_hash(p), em or None, verified, time.time()))
                    db.commit()
                    uid = cur.lastrowid
                    log_event("user_registered", user_id=uid, detail_user=u)
                    if require and em:
                        sent = issue_code(uid, em)
                        session["pending_uid"] = uid
                        if sent:
                            flash(f"We emailed a 6-digit code to {em}. Enter it to verify your account.")
                        else:
                            flash(f"Dev mode (no email server configured): your code is {app.config['_DEV_CODES'][em]}.")
                        return redirect(url_for("verify"))
                    flash("Account created. Sign in.")
                    return redirect(url_for("login"))
                except Exception:
                    flash("That username is taken.")
        return render_template("register.html", require_email=require)

    @app.route("/verify", methods=["GET", "POST"])
    def verify():
        uid = session.get("pending_uid")
        if not uid:
            return redirect(url_for("login"))
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        if user is None:
            session.pop("pending_uid", None)
            return redirect(url_for("register"))
        if user["email_verified"]:
            session.pop("pending_uid", None)
            flash("Your email is already verified. Sign in.")
            return redirect(url_for("login"))
        if request.method == "POST":
            code = request.form.get("code", "").strip()
            rec = db.execute("SELECT * FROM email_codes WHERE user_id=?", (uid,)).fetchone()
            if rec is None or rec["expires_at"] < time.time():
                flash("That code has expired. Request a new one.")
            elif rec["attempts"] >= cfg()["EMAIL_MAX_ATTEMPTS"]:
                flash("Too many incorrect attempts. Request a new code.")
            elif check_password_hash(rec["code_hash"], code):
                db.execute("UPDATE users SET email_verified=1 WHERE id=?", (uid,))
                db.execute("DELETE FROM email_codes WHERE user_id=?", (uid,))
                db.commit()
                app.config.get("_DEV_CODES", {}).pop(user["email"], None)
                log_event("email_verified", user_id=uid)
                session.pop("pending_uid", None)
                flash("Email verified. You can sign in now.")
                return redirect(url_for("login"))
            else:
                db.execute("UPDATE email_codes SET attempts=attempts+1 WHERE user_id=?", (uid,))
                db.commit()
                log_event("email_code_wrong", "warning", user_id=uid)
                flash("Incorrect code. Check the digits and try again.")
        dev_code = None if emailer.smtp_configured(cfg()) else app.config.get("_DEV_CODES", {}).get(user["email"])
        return render_template("verify.html", email=user["email"], dev_code=dev_code)

    @app.route("/verify/resend", methods=["POST"])
    def verify_resend():
        uid = session.get("pending_uid")
        if not uid:
            return redirect(url_for("login"))
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        if user and not user["email_verified"] and user["email"]:
            rec = db.execute("SELECT sent_at FROM email_codes WHERE user_id=?", (uid,)).fetchone()
            if rec and time.time() - rec["sent_at"] < cfg()["EMAIL_RESEND_COOLDOWN_S"]:
                flash("Please wait a few seconds before requesting another code.")
            else:
                issue_code(uid, user["email"])
                flash("A new code is on its way.")
        return redirect(url_for("verify"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        reason = request.args.get("reason")
        if request.method == "POST":
            db = get_db()
            u = request.form.get("username", "").strip()
            user = db.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
            if user and user["locked_until"] > time.time():
                mins = int((user["locked_until"] - time.time()) // 60) + 1
                log_event("login_blocked_locked", "warning", user_id=user["id"])
                flash(f"Account temporarily locked after a security event. Try again in {mins} min.")
            elif user and check_password_hash(user["password_hash"], request.form.get("password", "")):
                # Email-verification gate: an unverified account cannot start a session
                # (and therefore cannot enroll). Re-issue a code and send them to verify.
                if cfg()["REQUIRE_EMAIL_VERIFICATION"] and not user["email_verified"]:
                    session["pending_uid"] = user["id"]
                    if user["email"]:
                        issue_code(user["id"], user["email"])
                    log_event("login_unverified", "warning", user_id=user["id"])
                    flash("Please verify your email first — we've sent you a fresh code.")
                    return redirect(url_for("verify"))
                ua = request.headers.get("User-Agent", "")
                ip = client_ip()
                dev = device_hash(request.form.get("fp", ""), ua)
                known = {(r["kind"], r["value"]) for r in db.execute("SELECT kind, value FROM known_devices WHERE user_id=?", (user["id"],))}
                new_ip, new_dev = ("ip", ip) not in known, ("device", dev) not in known
                first_login = not known
                sid = secrets.token_urlsafe(32)
                db.execute(
                    "INSERT INTO sessions (id, user_id, csrf, created_at, last_seen, ip, user_agent, device_hash, new_ip, new_device) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (sid, user["id"], secrets.token_urlsafe(24), time.time(), time.time(), ip, ua, dev,
                     int(new_ip and not first_login), int(new_dev and not first_login)),
                )
                for kind, val in (("ip", ip), ("device", dev)):
                    db.execute("INSERT OR IGNORE INTO known_devices VALUES (?,?,?,?)", (user["id"], kind, val, time.time()))
                db.commit()
                session.clear()
                session["sid"] = sid
                log_event("login_success", session_id=sid, user_id=user["id"], ip=ip, new_ip=new_ip and not first_login,
                          new_device=new_dev and not first_login)
                nxt = request.args.get("next", "")
                return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else url_for("app_home"))
            else:
                log_event("login_failed", "warning", user_id=user["id"] if user else None, attempted=u)
                flash("Wrong username or password.")
        return render_template("login.html", reason=reason)

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        end_session(current()["id"], "ended", "user logout", "info")
        session.clear()
        return redirect(url_for("login"))

    @app.route("/reauth", methods=["GET", "POST"])
    @login_required
    def reauth():
        cur = current()
        if request.method == "POST":
            db = get_db()
            user = db.execute("SELECT * FROM users WHERE id=?", (cur["user_id"],)).fetchone()
            if check_password_hash(user["password_hash"], request.form.get("password", "")):
                # Proven identity: clear the step-up and reset behaviour risk to a neutral start.
                db.execute("UPDATE sessions SET status='active', tier='MEDIUM', risk=35, behavior_ewma=30, high_streak=0, "
                           "stepups=stepups+1, failed_stepups=0 WHERE id=?", (cur["id"],))
                db.commit()
                log_event("stepup_passed", session_id=cur["id"], user_id=cur["user_id"])
                nxt = request.args.get("next", "")
                return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else url_for("app_home"))
            fails = cur["failed_stepups"] + 1
            db.execute("UPDATE sessions SET failed_stepups=? WHERE id=?", (fails, cur["id"]))
            db.commit()
            log_event("stepup_failed", "warning", session_id=cur["id"], user_id=cur["user_id"], attempt=fails)
            if fails >= cfg()["MAX_FAILED_STEPUPS"]:
                end_session(cur["id"], "terminated", "too many failed step-up attempts", "critical", lock_user=True)
                session.clear()
                return redirect(url_for("login", reason="terminated"))
            flash(f"Password incorrect. {cfg()['MAX_FAILED_STEPUPS'] - fails} attempt(s) left before the session is closed.")
        return render_template("reauth.html")

    # the protected demo portal
    @app.route("/app")
    @login_required
    def app_home():
        cur = current()
        prof = get_db().execute("SELECT n_windows, trained_at FROM profiles WHERE user_id=?", (cur["user_id"],)).fetchone()
        enrolled = get_db().execute("SELECT COUNT(*) FROM windows WHERE user_id=? AND enrollable=1", (cur["user_id"],)).fetchone()[0]
        return render_template("app_home.html", profile=prof, enrolled=enrolled, need=cfg()["ENROLL_WINDOWS"])

    @app.route("/app/notes", methods=["GET", "POST"])
    @login_required
    def notes():
        cur, db = current(), get_db()
        if request.method == "POST":
            t, b = request.form.get("title", "").strip()[:200], request.form.get("body", "").strip()[:10000]
            if t and b:
                db.execute("INSERT INTO notes (user_id, title, body, created_at) VALUES (?,?,?,?)", (cur["user_id"], t, b, time.time()))
                db.commit()
            return redirect(url_for("notes"))
        rows = db.execute("SELECT * FROM notes WHERE user_id=? ORDER BY id DESC", (cur["user_id"],)).fetchall()
        return render_template("notes.html", notes=rows)

    @app.route("/app/settings", methods=["GET", "POST"])
    @login_required
    @sensitive
    def settings():
        cur, db = current(), get_db()
        if request.method == "POST":
            user = db.execute("SELECT * FROM users WHERE id=?", (cur["user_id"],)).fetchone()
            if not check_password_hash(user["password_hash"], request.form.get("old", "")):
                flash("Current password is wrong.")
            elif len(request.form.get("new", "")) < 8:
                flash("New password must be at least 8 characters.")
            else:
                db.execute("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash(request.form["new"]), cur["user_id"]))
                db.commit()
                log_event("password_changed", session_id=cur["id"], user_id=cur["user_id"])
                flash("Password changed.")
        return render_template("settings.html")

    # behaviour ingestion + scoring
    @app.route("/api/behavior", methods=["POST"])
    def behavior():
        cur = current()
        if g.get("beacon_dropped"):
            return "", 204
        if cur is None:
            return jsonify(error="no session"), 401
        check_csrf(request.headers.get("X-CSRF-Token") or request.args.get("csrf"))
        data = request.get_json(silent=True, force=True) or {}
        events = data.get("events") or []
        if not isinstance(events, list) or len(events) > MAX_EVENTS_PER_BATCH:
            return jsonify(error="bad batch"), 400
        events = [e for e in events if isinstance(e, dict) and isinstance(e.get("t"), (int, float)) and isinstance(e.get("type"), str)]
        start, end = data.get("start"), data.get("end")
        if not isinstance(start, (int, float)) or not isinstance(end, (int, float)) or end <= start:
            return jsonify(error="bad window"), 400
        page = str(data.get("page", ""))[:200]

        feats = extract_window_features(events, start, end) or {"total_events": 0, "window_duration_ms": end - start}
        enough = feats.get("total_events", 0) >= cfg()["MIN_EVENTS_PER_WINDOW"]
        if enough:
            g_val, model, damping = profiles.genuineness(cur["user_id"], feats, cfg())
        else:
            g_val, model, damping = None, "insufficient-activity", 1.0

        ip = client_ip()
        sig = Signals(
            genuineness=g_val, damping=damping, model=model,
            prev_behavior_ewma=cur["behavior_ewma"], high_streak=cur["high_streak"],
            ip_changed=ip != cur["ip"], ip_new_for_user=bool(cur["new_ip"]),
            ua_changed=False,  # enforced per request in current(); a change never reaches here
            device_new_for_user=bool(cur["new_device"]),
            sensitive_page=page.startswith(SENSITIVE_PATHS),
            session_age_h=(time.time() - cur["created_at"]) / 3600,
            failed_stepups=cur["failed_stepups"],
            window_feats=feats if enough else {},
        )
        d = evaluate(sig, cfg())

        db = get_db()
        db.execute(
            "INSERT INTO windows (session_id, user_id, start_ms, end_ms, page, features, components, behavior, risk, tier, action, model, enrollable, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (cur["id"], cur["user_id"], start, end, page, json.dumps(feats), json.dumps(d["components"]),
             d["components"]["behavior"], d["risk"], d["tier"], d["action"], model, int(d["enrollable"]), time.time()),
        )
        db.execute("UPDATE sessions SET risk=?, tier=?, behavior_ewma=?, high_streak=?, windows_scored=windows_scored+1 WHERE id=?",
                   (d["risk"], d["tier"], d["behavior_ewma"], d["high_streak"], cur["id"]))
        db.commit()

        resp = {"risk": d["risk"], "tier": d["tier"], "action": d["action"], "model": model}
        if d["action"] == "terminate":
            reason = "; ".join(d["components"]["overrides"]) or "critical risk score"
            end_session(cur["id"], "terminated", reason, "critical", lock_user=True)
            session.clear()
            resp["redirect"] = url_for("login", reason="terminated")
        elif d["action"] == "step_up":
            db.execute("UPDATE sessions SET status='step_up' WHERE id=?", (cur["id"],))
            db.commit()
            log_event("stepup_required", "warning", session_id=cur["id"], user_id=cur["user_id"], risk=d["risk"],
                      overrides=d["components"]["overrides"])
            resp["redirect"] = url_for("reauth", next=page if page.startswith("/") else "/app")
        elif d["tier"] == "MEDIUM" and cur["tier"] == "LOW":
            log_event("risk_elevated", "info", session_id=cur["id"], user_id=cur["user_id"], risk=d["risk"])
        if d["enrollable"]:
            profiles.maybe_retrain(cur["user_id"], cfg())
        return jsonify(resp)

    # admin
    def overview_data():
        db = get_db()
        sessions = [dict(r) for r in db.execute(
            "SELECT s.id, s.status, s.risk, s.tier, s.windows_scored, s.created_at, s.last_seen, s.ip, s.stepups, s.end_reason, u.username "
            "FROM sessions s JOIN users u ON u.id=s.user_id ORDER BY (s.status='active' OR s.status='step_up') DESC, s.last_seen DESC LIMIT 50")]
        for s in sessions:
            s["spark"] = [r[0] for r in db.execute(
                "SELECT risk FROM (SELECT id, risk FROM windows WHERE session_id=? ORDER BY id DESC LIMIT 30) ORDER BY id", (s["id"],))]
        events = [dict(r) for r in db.execute(
            "SELECT e.*, u.username FROM events e LEFT JOIN users u ON u.id=e.user_id ORDER BY e.id DESC LIMIT 25")]
        counts = {
            "active": db.execute("SELECT COUNT(*) FROM sessions WHERE status IN ('active','step_up')").fetchone()[0],
            "step_up": db.execute("SELECT COUNT(*) FROM sessions WHERE status='step_up'").fetchone()[0],
            "terminated_24h": db.execute("SELECT COUNT(*) FROM events WHERE kind='session_terminated' AND ts>?", (time.time() - 86400,)).fetchone()[0],
            "windows_24h": db.execute("SELECT COUNT(*) FROM windows WHERE created_at>?", (time.time() - 86400,)).fetchone()[0],
            "profiles": db.execute("SELECT COUNT(*) FROM profiles").fetchone()[0],
        }
        return {"sessions": sessions, "events": events, "counts": counts, "now": time.time()}

    @app.route("/admin")
    @admin_required
    def admin_overview():
        return render_template("admin/overview.html", data=overview_data())

    @app.route("/admin/api/overview")
    @admin_required
    def admin_api_overview():
        return jsonify(overview_data())

    def session_data(sid):
        db = get_db()
        s = db.execute("SELECT s.*, u.username FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=?", (sid,)).fetchone()
        if s is None:
            abort(404)
        wins = []
        for r in db.execute("SELECT * FROM windows WHERE session_id=? ORDER BY id", (sid,)):
            w = dict(r)
            w["components"] = json.loads(w["components"] or "{}")
            f = json.loads(w["features"])
            w["features"] = {k: f.get(k) for k in ("total_events", "typing_speed_keys_per_min", "avg_mouse_speed_px_s", "idle_time_ratio", "clicks_per_min")}
            wins.append(w)
        ev = [dict(r) for r in db.execute("SELECT * FROM events WHERE session_id=? ORDER BY id", (sid,))]
        s = dict(s)
        s.pop("csrf", None)
        return {"session": s, "windows": wins, "events": ev}

    @app.route("/admin/session/<sid>")
    @admin_required
    def admin_session(sid):
        return render_template("admin/session.html", data=session_data(sid))

    @app.route("/admin/api/session/<sid>")
    @admin_required
    def admin_api_session(sid):
        return jsonify(session_data(sid))

    @app.route("/admin/session/<sid>/terminate", methods=["POST"])
    @admin_required
    def admin_terminate(sid):
        end_session(sid, "terminated", f"terminated by admin {current()['username']}", "warning",
                    lock_user=request.form.get("lock") == "1")
        return redirect(url_for("admin_session", sid=sid))

    @app.route("/admin/events")
    @admin_required
    def admin_events():
        sev = request.args.get("severity")
        q = "SELECT e.*, u.username FROM events e LEFT JOIN users u ON u.id=e.user_id"
        rows = get_db().execute(q + (" WHERE e.severity=?" if sev else "") + " ORDER BY e.id DESC LIMIT 500", ((sev,) if sev else ())).fetchall()
        return render_template("admin/events.html", events=rows, severity=sev)

    @app.route("/admin/users")
    @admin_required
    def admin_users():
        rows = get_db().execute(
            "SELECT u.id, u.username, u.role, u.locked_until, u.created_at, p.n_windows, p.trained_at, "
            "(SELECT COUNT(*) FROM windows w WHERE w.user_id=u.id AND w.enrollable=1) AS enrolled "
            "FROM users u LEFT JOIN profiles p ON p.user_id=u.id ORDER BY u.id").fetchall()
        return render_template("admin/users.html", users=rows, now=time.time(), need=cfg()["ENROLL_WINDOWS"])

    @app.route("/admin/users/<int:uid>/unlock", methods=["POST"])
    @admin_required
    def admin_unlock(uid):
        get_db().execute("UPDATE users SET locked_until=0 WHERE id=?", (uid,))
        get_db().commit()
        log_event("account_unlocked", user_id=uid, by=current()["username"])
        return redirect(url_for("admin_users"))

    @app.route("/admin/users/<int:uid>/reset-profile", methods=["POST"])
    @admin_required
    def admin_reset_profile(uid):
        profiles.reset_profile(uid)
        log_event("profile_reset", user_id=uid, by=current()["username"])
        return redirect(url_for("admin_users"))

    @app.template_filter("ts")
    def ts_filter(v):
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(v)) if v else "—"

    @app.template_filter("fromjson")
    def fromjson(v):
        try:
            return json.loads(v) if v else {}
        except Exception:
            return {}

    # CLI
    @app.cli.command("create-admin")
    @click.argument("username")
    @click.password_option()
    def create_admin(username, password):
        """Create (or promote) an admin account."""
        db = get_db()
        if db.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
            db.execute("UPDATE users SET role='admin', password_hash=? WHERE username=?", (generate_password_hash(password), username))
        else:
            db.execute("INSERT INTO users (username, password_hash, role, created_at) VALUES (?,?,?,?)",
                       (username, generate_password_hash(password), "admin", time.time()))
        db.commit()
        click.echo(f"Admin '{username}' ready.")

    return app
