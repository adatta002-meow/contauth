"""ContAuth desktop agent — continuous authentication for the whole machine.

Usage:
    python -m contauth.agent                 # run the agent (needs a display + input access)
    python -m contauth.agent --window-ms 5000
    python -m contauth.agent --face          # add a consented camera presence check
    python -m contauth.agent --dry-run       # never actually lock; log the lock instead
    python -m contauth.agent --simulate      # demo without global hooks: synthetic activity
    python -m contauth.agent --headless --simulate   # no window (CI / servers)

The agent watches your typing and mouse rhythm across the desktop, scores it every
few seconds with the model trained on 705 real sessions, and locks the screen when
the behaviour stops matching your enrolled profile — the OS login then re-verifies
you. It stores only aggregated features (never keystrokes or text) in a local file,
and the status window lets you pause or quit at any time.
"""
from __future__ import annotations

import argparse
import math
import os
import random
import time

from contauth.agent.controller import Controller
from contauth.agent.engine import CFG, AuthEngine
from contauth.agent.store import Store


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


def build(args):
    if args.dry_run:
        os.environ["CA_AGENT_DRY_RUN"] = "1"
    cfg = dict(CFG)
    cfg["WINDOW_MS"] = args.window_ms
    if args.enroll:
        cfg["ENROLL_WINDOWS"] = args.enroll
    store = Store(args.data_dir)
    engine = AuthEngine(store, cfg=cfg, population_path=args.population)
    face_fn = None
    if args.face:
        from contauth.agent import face
        if face.available():
            face_fn = lambda: face.confirm_presence(logger=lambda m: print("[face]", m))  # noqa: E731
        else:
            print("Face check requested but OpenCV/camera unavailable; continuing without it.")
    controller = Controller(engine, store, face_fn=face_fn)
    return store, engine, controller, cfg


def run_headless(args):
    """No GUI: used for the --simulate demo in CI and for servers. Runs N windows."""
    store, engine, controller, cfg = build(args)
    rnd = random.Random(args.seed)
    controller.logger = lambda k, s, d: print(f"  [{s}] {k}: {d}")
    print(f"Agent (headless, simulate). window={cfg['WINDOW_MS']}ms enroll={cfg['ENROLL_WINDOWS']}")
    from contauth.agent.capture import Capture
    cap = Capture()
    n = args.windows
    for i in range(n):
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
    controller.logger = lambda k, s, d: win.add_log(k, s, d)

    if args.simulate:
        win.add_log("mode", "info", "simulate: synthetic activity, global hooks OFF")
    else:
        try:
            cap.start()
            win.add_log("capture", "info", "monitoring the desktop — timing only, never keystrokes")
        except Exception as e:
            win.add_log("capture_error", "warning", f"could not start global hooks: {e}. Try --simulate.")

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
    ap.add_argument("--window-ms", type=int, default=5000, dest="window_ms")
    ap.add_argument("--enroll", type=int, default=12, help="clean windows before a personal profile is built")
    ap.add_argument("--data-dir", default=None, help="SQLite file path (default: per-user app data)")
    ap.add_argument("--population", default=CFG["POPULATION_MODEL"])
    ap.add_argument("--face", action="store_true", help="consented camera presence check on step-up")
    ap.add_argument("--dry-run", action="store_true", help="log the lock instead of locking")
    ap.add_argument("--simulate", action="store_true", help="feed synthetic activity instead of real hooks")
    ap.add_argument("--headless", action="store_true", help="no window (runs a fixed number of windows)")
    ap.add_argument("--windows", type=int, default=20, help="headless: how many windows to run")
    ap.add_argument("--bot-at", type=int, default=-1, help="headless: inject a bot window at this index")
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args(argv)
    if args.headless:
        args.simulate = True
        run_headless(args)
    else:
        run_gui(args)


if __name__ == "__main__":
    main()
