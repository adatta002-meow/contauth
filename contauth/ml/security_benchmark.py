"""Security & performance benchmark for the continuous-auth agent.

Produces reports/security_benchmark.{json,md}. Every number here is a real
measurement, and the report says exactly how each was obtained and what is NOT
measured:

  * Detection accuracy (FAR / FRR / EER / ROC-AUC) — read from the real-data
    user-verification benchmark (reports/benchmark.json, produced by
    contauth.ml.train on the Capstone dataset). Not recomputed here.
  * Decision latency — measured directly: time to extract features and score one
    window, cold start (population model) and enrolled (personal model), p50/p95/mean.
    Synthetic event streams drive the code path; the timings are of the real code.
  * CPU / memory — this process's RSS growth and CPU time over a scoring run
    (psutil), reported as the agent's steady-state footprint.
  * Reliability — windows pushed through the full controller, counting errors and
    locks; error rate over the run.
  * Spoof resistance — NOT quantified. The replay / signal-quality / automation
    defences are deterministic and unit-tested, but their real false-accept rate
    against live presentation or replay attacks needs a spoof dataset we do not have.
    The report states this instead of inventing a number.
"""
from __future__ import annotations

import argparse
import json
import platform
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path

from contauth.agent.engine import CFG, AuthEngine
from contauth.agent.store import Store

ROOT = Path(__file__).resolve().parents[2]


def _rng_window(rnd, t0, dur_ms):
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
    return ev, t0, t0 + dur_ms


def measure_latency(tmp_path, population, window_ms=3000, n=120):
    import random
    rnd = random.Random(0)
    cfg = dict(CFG); cfg.update({"ENROLL_WINDOWS": 10, "RETRAIN_EVERY": 10, "WINDOW_MS": window_ms})
    store = Store(tmp_path / "lat.db", encrypt=True)
    eng = AuthEngine(store, cfg=cfg, population_path=population)

    cold, warm, retrain = [], [], []
    for i in range(n):
        ev, s, e = _rng_window(rnd, i * window_ms, window_ms)
        had_prof = eng.prof is not None
        t = time.perf_counter()
        d = eng.score_window(ev, s, e)
        dt = (time.perf_counter() - t) * 1000.0
        if d.get("profile_trained"):      # periodic retrain spike: timed separately
            retrain.append(dt)
        elif had_prof:
            warm.append(dt)
        else:
            cold.append(dt)
    store.close()

    def stats(xs):
        if not xs:
            return None
        xs = sorted(xs)
        p = lambda q: xs[min(len(xs) - 1, int(q * len(xs)))]  # noqa: E731
        return {"n": len(xs), "mean_ms": round(statistics.mean(xs), 3),
                "p50_ms": round(p(0.50), 3), "p95_ms": round(p(0.95), 3), "max_ms": round(max(xs), 3)}
    return {"cold_start_population_model": stats(cold), "enrolled_personal_model": stats(warm),
            "periodic_retrain": stats(retrain)}


def measure_footprint(tmp_path, population, n=200):
    try:
        import os

        import psutil
    except Exception:
        return {"available": False, "note": "psutil not installed; run `pip install psutil` to measure CPU/RAM"}
    import random
    proc = psutil.Process(os.getpid())
    rnd = random.Random(1)
    cfg = dict(CFG); cfg.update({"ENROLL_WINDOWS": 10, "RETRAIN_EVERY": 10, "WINDOW_MS": 3000})
    store = Store(tmp_path / "fp.db", encrypt=True)
    eng = AuthEngine(store, cfg=cfg, population_path=population)
    proc.cpu_percent(None)                       # prime the CPU-percent window
    rss0 = proc.memory_info().rss
    ct0 = proc.cpu_times()
    t0 = time.perf_counter()
    for i in range(n):
        eng.score_window(*_rng_window(rnd, i * 3000, 3000))
    wall = time.perf_counter() - t0
    ct1 = proc.cpu_times()
    rss1 = proc.memory_info().rss
    store.close()
    cpu_s = (ct1.user - ct0.user) + (ct1.system - ct0.system)
    return {"available": True, "windows": n, "wall_s": round(wall, 2),
            "rss_after_mb": round(rss1 / 1e6, 1), "rss_growth_mb": round((rss1 - rss0) / 1e6, 1),
            "cpu_seconds": round(cpu_s, 2), "cpu_ms_per_window": round(cpu_s / n * 1000, 2),
            "cpu_percent_one_core": round(100 * cpu_s / wall, 1) if wall else None}


def measure_reliability(tmp_path, population, n=300):
    import random

    from contauth.agent.controller import Controller
    rnd = random.Random(2)
    cfg = dict(CFG); cfg.update({"ENROLL_WINDOWS": 10, "RETRAIN_EVERY": 10, "WINDOW_MS": 3000})
    store = Store(tmp_path / "rel.db", encrypt=True)
    eng = AuthEngine(store, cfg=cfg, population_path=population)
    c = Controller(eng, store, lock_fn=lambda logger=None: None, monitor_only=True)
    locks = 0
    for i in range(n):
        d = c.process_window(*_rng_window(rnd, i * 3000, 3000))
        if d.get("action") in ("step_up", "terminate"):
            locks += 1
    store.close()
    return {"windows": n, "errors": c.errors, "error_rate": round(c.errors / n, 4),
            "enforcement_actions_on_genuine_stream": locks,
            "false_lock_rate_on_genuine_stream": round(locks / n, 4)}


def load_detection(reports: Path) -> dict:
    f = reports / "benchmark.json"
    if not f.exists():
        return {"available": False, "note": "run `python -m contauth.ml.train` first to produce real-data FAR/FRR/EER"}
    b = json.loads(f.read_text())
    best = max(b["summary"].items(), key=lambda kv: kv[1]["roc_auc"])
    return {"available": True, "dataset_sha256": b["meta"]["dataset_sha256"][:16],
            "users": len(b["users"]), "models": b["summary"], "best_model": best[0]}


def write_markdown(path: Path, rep: dict):
    m, det = rep["meta"], rep["detection_accuracy"]
    L = [f"# Security & performance benchmark", "",
         f"Generated {m['generated_utc']} on {m['python']} / {m['platform']}.", "",
         "Every figure below is a measurement, with its method stated. Read it with the "
         "limitations at the end — in particular, spoof resistance is **not** quantified here.", ""]

    L += ["## 1. Detection accuracy (real Capstone data)", ""]
    if det.get("available"):
        L += [f"From `reports/benchmark.json` (dataset SHA-256 `{det['dataset_sha256']}…`, "
              f"{det['users']} users, impostors unseen in training).", "",
              "| Model | Accuracy | FAR | FRR | EER | ROC-AUC |", "|---|---|---|---|---|---|"]
        for name, s in det["models"].items():
            L.append(f"| {name} | {s['accuracy']*100:.1f}% | {s['far']*100:.1f}% | {s['frr']*100:.1f}% | "
                     f"{s['eer']*100:.1f}% | {s['roc_auc']:.3f} |")
        L += ["", f"Best ROC-AUC: **{det['best_model']}**. These are session-level; the live agent "
              "scores short windows, which are noisier. Per-user thresholds and the FAR/FRR trade-off "
              "are in `reports/tuning.md`."]
    else:
        L += [f"_Not available: {det['note']}._"]

    lat = rep["latency"]
    L += ["", "## 2. Decision latency (measured)", "",
          "Time to extract features and score one window on this machine.", "",
          "| Path | n | mean | p50 | p95 | max |", "|---|---|---|---|---|---|"]
    for label, key in [("Cold start (population model)", "cold_start_population_model"),
                       ("Enrolled (personal model), scoring", "enrolled_personal_model"),
                       ("Periodic model retrain", "periodic_retrain")]:
        s = lat.get(key)
        if s:
            L.append(f"| {label} | {s['n']} | {s['mean_ms']} ms | {s['p50_ms']} ms | {s['p95_ms']} ms | {s['max_ms']} ms |")
    L += ["", "Per-window scoring is a few milliseconds — negligible next to the window length "
          "(seconds), so the detection delay the user experiences is set by the window size, not "
          "computation. The retrain row is the occasional background profile refresh (every "
          f"{CFG.get('RETRAIN_EVERY', 20)} enrolled windows by default), not per-window cost."]

    fp = rep["footprint"]
    L += ["", "## 3. CPU & memory (measured)", ""]
    if fp.get("available"):
        L += [f"- Resident memory after {fp['windows']} windows: **{fp['rss_after_mb']} MB** "
              f"(growth {fp['rss_growth_mb']} MB).",
              f"- CPU: **{fp['cpu_ms_per_window']} ms/window** "
              f"(~{fp['cpu_percent_one_core']}% of one core while actively scoring).",
              "- Between windows the agent is idle (it sleeps for the window interval), so steady-state "
              "CPU is a small fraction of the above."]
    else:
        L += [f"_Not available: {fp['note']}._"]

    rel = rep["reliability"]
    L += ["", "## 4. Reliability (measured)", "",
          f"- {rel['windows']} windows through the full controller: **{rel['errors']} errors** "
          f"(error rate {rel['error_rate']}).",
          f"- Enforcement actions on a genuine (non-attack) stream: "
          f"{rel['enforcement_actions_on_genuine_stream']} "
          f"(false-lock rate {rel['false_lock_rate_on_genuine_stream']}).",
          "- A scoring failure degrades to 'observe, do not lock' rather than crashing or locking blindly."]

    L += ["", "## 5. Spoof resistance — NOT quantified", "",
          "The agent includes deterministic anti-spoofing: replay/duplicate-window rejection, "
          "stale-timestamp rejection, signal-quality gating, and automation (bot-input) detection. "
          "These are unit-tested for correctness. **Their real false-accept rate against live "
          "presentation or replay attacks is not measured**, because the Capstone dataset contains no "
          "spoof or attack samples. Reporting a spoof-resistance percentage here would be fabricated. "
          "To measure it, run this harness against a labelled spoof/replay dataset.", "",
          "## Limitations", "",
          "- Latency, CPU and memory are from this machine; they will differ on the target device.",
          "- Detection metrics are session-level on one dataset; live windowed performance is lower and noisier.",
          "- The genuine-stream false-lock rate uses synthetic human-like windows to exercise the pipeline; "
          "it is a pipeline sanity check, not a field false-lock rate.", ""]
    path.write_text("\n".join(L) + "\n", encoding="utf-8")


def main(argv=None):
    import tempfile
    ap = argparse.ArgumentParser(description="Security & performance benchmark for the ContAuth agent")
    ap.add_argument("--population", default=CFG["POPULATION_MODEL"])
    ap.add_argument("--reports", default=str(ROOT / "reports"))
    a = ap.parse_args(argv)
    reports = Path(a.reports); reports.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        print("Measuring detection accuracy (from real-data benchmark)…")
        detection = load_detection(reports)
        print("Measuring decision latency…")
        latency = measure_latency(tmp, a.population)
        print("Measuring CPU & memory…")
        footprint = measure_footprint(tmp, a.population)
        print("Measuring reliability…")
        reliability = measure_reliability(tmp, a.population)

    rep = {
        "meta": {"generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
                 "python": "Python " + platform.python_version(),
                 "platform": platform.platform()},
        "detection_accuracy": detection,
        "latency": latency,
        "footprint": footprint,
        "reliability": reliability,
        "spoof_resistance": {"quantified": False,
                             "reason": "no spoof/replay attack dataset; defences are unit-tested but unmeasured in the field"},
    }
    (reports / "security_benchmark.json").write_text(json.dumps(rep, indent=2), encoding="utf-8")
    write_markdown(reports / "security_benchmark.md", rep)
    print(f"Wrote {reports/'security_benchmark.md'} and .json")
    return rep


if __name__ == "__main__":
    main()
