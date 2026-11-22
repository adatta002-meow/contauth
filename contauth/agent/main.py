"""ContAuth desktop agent — continuous authentication for the whole machine.

Usage:
    python -m contauth.agent                       # run the agent (status window opens)
    python -m contauth.agent --config my.json      # load settings from a JSON file
    python -m contauth.agent --monitor-only        # never lock; just observe + log
    python -m contauth.agent --dry-run             # log the lock instead of locking
    python -m contauth.agent --face                # consented camera presence check
    python -m contauth.agent --simulate            # demo without global hooks
    python -m contauth.agent --headless --simulate # no window (CI / servers)

The agent watches your typing and mouse rhythm across the desktop, scores it every
few seconds with the model trained on 705 real sessions, and locks the screen when
the behaviour stops matching your enrolled profile — the OS login then re-verifies
you. It stores only aggregated features (never keystrokes or text) in a local file,
and the status window lets you pause or quit at any time.

Daily-use safety (so it does not lock you out by surprise):
  * a warm-up grace period after launch (behaviour-only step-ups just warn),
  * a cooldown so it will not re-lock while you are signing back in,
  * --monitor-only to live with it for a few days before it enforces.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time

from contauth.agent.controller import Controller
from contauth.agent.engine import CFG, AuthEngine
from contauth.agent.store import Store

# Settings a JSON config may set, mapped to internal keys. CLI flags override these.
CONFIG_KEYS = {
    "window_ms": ("WINDOW_MS", int),
    "enroll_windows": ("ENROLL_WINDOWS", int),
    "retrain_every": ("RETRAIN_EVERY", int),
    "oneclass_frr": ("ONECLASS_FRR", float),
    "high_consecutive": ("HIGH_CONSECUTIVE_FOR_STEPUP", int),
}

# The agent runs with short windows and fast enrollment by default, so a user is
# protected within about half a minute of launching it. (The web/server config
# defaults are tuned differently — the agent overrides them here.) Enrollment time
# = ENROLL_WINDOWS * WINDOW_MS; 8 * 3 s = 24 s.
AGENT_DEFAULTS = {"WINDOW_MS": 3000, "ENROLL_WINDOWS": 12, "RETRAIN_EVERY": 10}
DEFAULT_WARMUP_MIN = 2.0  # warm-up before a behaviour step-up can lock; recognition
                          # gate (ENFORCE_MIN_CONFIDENCE) then holds off locking until
                          # the model actually knows you, so normal typing won't lock you out


def resolve_population(path: str) -> str:
    """When running as a PyInstaller one-file build, the model is unpacked into the
    temporary bundle dir (sys._MEIPASS). Prefer that copy; fall back to `path`."""
    bundled = getattr(sys, "_MEIPASS", None)
    if bundled:
        cand = os.path.join(bundled, "population.joblib")
        if os.path.exists(cand):
            return cand
    return path


def _simulator(cap, rnd):
    """Inject human-like events into the capture buffer (demo without global hooks)."""
    t = time.time() * 1000.0
    for _ in range(rnd.randint(28, 50)):
        t += rnd.randint(70, 260)
        cap._push({"t": t, "type": "keydown", "mod": rnd.random() < 0.1})
    x = y = 600
    for _ in range(rnd.randint(50, 90)):
        t += rnd.randint(10, 40)
        x += rnd.randint(-30, 30); y += rnd.randint(-25, 25)
        cap._push({"t": t, "type": "mousemove", "x": x, "y": y})
    for _ in range(rnd.randint(2, 5)):
        t += rnd.randint(400, 1500)
        cap._push({"t": t, "type": "click"})


def load_config(path: str | None) -> dict:
    if not path:
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def build(args):
    conf = load_config(args.config)
    if args.dry_run or conf.get("dry_run"):
        os.environ["CA_AGENT_DRY_RUN"] = "1"

    cfg = dict(CFG)
    cfg.update(AGENT_DEFAULTS)
    for key, (internal, cast) in CONFIG_KEYS.items():
        if conf.get(key) is not None:
            cfg[internal] = cast(conf[key])
    if args.window_ms is not None:
        cfg["WINDOW_MS"] = args.window_ms
    if args.enroll is not None:
        cfg["ENROLL_WINDOWS"] = args.enroll
    if args.high_consecutive is not None:
        cfg["HIGH_CONSECUTIVE_FOR_STEPUP"] = args.high_consecutive

    warmup_min = args.warmup_min if args.warmup_min is not None else conf.get("warmup_minutes", DEFAULT_WARMUP_MIN)
    cooldown_s = args.cooldown_sec if args.cooldown_sec is not None else conf.get("lock_cooldown_seconds", 20)
    monitor_only = args.monitor_only or bool(conf.get("monitor_only"))
    use_face = args.face or bool(conf.get("face"))

    store = Store(args.data_dir)
    engine = AuthEngine(store, cfg=cfg, population_path=resolve_population(args.population))

    face_fn = None
    if use_face:
        from contauth.agent import face
        if face.available():
            face_fn = lambda: face.confirm_presence(logger=lambda m: print("[face]", m))  # noqa: E731
        else:
            print("Face check requested but OpenCV/camera unavailable; continuing without it.")

    controller = Controller(engine, store, face_fn=face_fn,
                            warmup_s=float(warmup_min) * 60.0, cooldown_s=float(cooldown_s),
                            monitor_only=monitor_only)
    return store, engine, controller, cfg


def run_headless(args):
    """No GUI: used for the --simulate demo in CI and for servers. Runs N windows."""
    store, engine, controller, cfg = build(args)
    rnd = random.Random(args.seed)
    controller.logger = lambda k, s, d: print(f"  [{s}] {k}: {d}")
    mode = "monitor-only" if controller.monitor_only else "enforcing"
    print(f"Agent (headless, simulate, {mode}). window={cfg['WINDOW_MS']}ms enroll={cfg['ENROLL_WINDOWS']} "
          f"warmup={controller.warmup_s:.0f}s cooldown={controller.cooldown_s:.0f}s")
    from contauth.agent.capture import Capture
    cap = Capture()
    for i in range(args.windows):
        if i == args.bot_at:
            for k in range(150):
                cap._push({"t": k * 20, "type": "mousemove", "x": 100 + 6 * k, "y": 300})
        else:
            _simulator(cap, rnd)
        t1 = time.time() * 1000.0
        d = controller.process_window(cap.drain(), t1 - cfg["WINDOW_MS"], t1)
        s = engine.status()
        print(f"w{i:2d} {d['tier']:9s} {d['action']:9s} risk={d['risk']:5.1f} model={s['model']} enrolled={s['enrolled']}")
    print(f"Locks issued: {controller.locks}")
    store.close()


def run_gui(args):
    store, engine, controller, cfg = build(args)
    from contauth.agent.capture import Capture
    from contauth.agent.ui import StatusWindow
    cap = Capture()
    rnd = random.Random(args.seed)
    win = StatusWindow(controller, on_quit=lambda: (cap.stop(), store.close()))
    win._simulate = bool(args.simulate)
    controller.logger = lambda k, s, d: win.add_log(k, s, d)

    if controller.monitor_only:
        win.add_log("mode", "info", "monitor-only: will observe and log, never lock")
    if args.simulate:
        win.add_log("mode", "info", "simulate: synthetic activity, global hooks OFF")
    else:
        try:
            cap.start()
            win.add_log("capture", "info", "monitoring the desktop — timing only, never keystrokes")
        except Exception as e:
            win.add_log("capture_error", "warning", f"could not start global hooks: {e}. Try --simulate.")
    if controller.warmup_s and not controller.monitor_only:
        w = controller.warmup_s
        human = f"{w/60:.0f} min" if w >= 60 else f"{int(w)} s"
        win.add_log("warmup", "info", f"warm-up grace: {human} before it will lock")

    def tick():
        try:
            if args.simulate and not controller.paused:
                _simulator(cap, rnd)
            t1 = time.time() * 1000.0
            controller.process_window(cap.drain(), t1 - cfg["WINDOW_MS"], t1)
            win.refresh()
        finally:
            win.root.after(cfg["WINDOW_MS"], tick)

    win.refresh()
    win.root.after(cfg["WINDOW_MS"], tick)
    win.mainloop()


def main(argv=None):
    ap = argparse.ArgumentParser(description="ContAuth continuous-authentication desktop agent")
    ap.add_argument("--config", default=None, help="JSON settings file (see agent-config.example.json)")
    ap.add_argument("--window-ms", type=int, default=None, dest="window_ms")
    ap.add_argument("--enroll", type=int, default=None, help="clean windows before a personal profile is built")
    ap.add_argument("--high-consecutive", type=int, default=None, dest="high_consecutive",
                    help="HIGH windows in a row before locking (2 default; 3 is gentler)")
    ap.add_argument("--warmup-min", type=float, default=None, dest="warmup_min",
                    help="minutes after launch during which behaviour step-ups only warn (default 2)")
    ap.add_argument("--cooldown-sec", type=float, default=None, dest="cooldown_sec",
                    help="seconds to suppress re-locking after a lock (default 20)")
    ap.add_argument("--monitor-only", action="store_true", help="never lock; only log what it would do")
    ap.add_argument("--data-dir", default=None, help="SQLite file path (default: per-user app data)")
    ap.add_argument("--population", default=CFG["POPULATION_MODEL"])
    ap.add_argument("--face", action="store_true", help="consented camera presence check on step-up")
    ap.add_argument("--dry-run", action="store_true", help="log the lock instead of locking")
    ap.add_argument("--simulate", action="store_true", help="feed synthetic activity instead of real hooks")
    ap.add_argument("--headless", action="store_true", help="no window (runs a fixed number of windows)")
    ap.add_argument("--windows", type=int, default=20, help="headless: how many windows to run")
    ap.add_argument("--bot-at", type=int, default=-1, help="headless: inject a bot window at this index")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--export", action="store_true", help="print what the agent stores about you (JSON) and exit")
    ap.add_argument("--wipe", action="store_true", help="delete all your data (profile, events) and exit")
    ap.add_argument("--yes", action="store_true", help="skip the confirmation prompt for --wipe")
    args = ap.parse_args(argv)
    if args.export:
        return run_export(args)
    if args.wipe:
        return run_wipe(args)
    if args.headless:
        args.simulate = True
        run_headless(args)
    else:
        run_gui(args)


def run_export(args):
    """User-controlled transparency: show exactly what is stored on this device."""
    store = Store(args.data_dir)
    summ = store.export_summary()
    store.close()
    print(json.dumps(summ, indent=2))
    print("\nNo keystrokes, characters or text are ever stored — only aggregated timing "
          "features per window. Run --wipe to delete everything.")
    return 0


def run_wipe(args):
    """User-controlled deletion: erase the profile, event log and encryption key."""
    store = Store(args.data_dir)
    summ = store.export_summary()
    print(f"This will permanently delete {summ['profile_windows']} profile window(s) and "
          f"{summ['event_log_entries']} event(s) at {summ['db_path']},\nand destroy the encryption key "
          f"so any residual ciphertext is unrecoverable.")
    if not args.yes:
        try:
            if input("Type 'wipe' to confirm: ").strip().lower() != "wipe":
                print("Cancelled.")
                store.close()
                return 1
        except EOFError:
            print("Cancelled (no confirmation).")
            store.close()
            return 1
    store.wipe()
    store.close()
    print("Done. Your behavioural profile and history have been erased; enrollment restarts next launch.")
    return 0


if __name__ == "__main__":
    main()
