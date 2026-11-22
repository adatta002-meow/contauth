# Security & performance benchmark

Generated 2026-11-22 16:27 UTC on Python 3.13.18 / Linux-6.18.44-fc-v726-x86_64-with-glibc2.39.

Every figure below is a measurement, with its method stated. Read it with the limitations at the end — in particular, spoof resistance is **not** quantified here.

## 1. Detection accuracy (real Capstone data)

From `reports/benchmark.json` (dataset SHA-256 `e6b279c4ed027a65…`, 10 users, impostors unseen in training).

| Model | Accuracy | FAR | FRR | EER | ROC-AUC |
|---|---|---|---|---|---|
| Logistic Regression | 70.3% | 30.5% | 21.1% | 24.9% | 0.795 |
| Random Forest | 83.0% | 15.7% | 42.3% | 26.8% | 0.786 |
| Isolation Forest | 31.9% | 71.9% | 6.2% | 28.5% | 0.753 |
| One-Class SVM | 81.0% | 17.7% | 44.5% | 31.1% | 0.696 |
| Hybrid (RF+IF+OCSVM) | 86.1% | 12.1% | 45.6% | 25.2% | 0.802 |
| Tuned ET+LR vote (live model) | 76.2% | 23.8% | 27.7% | 25.3% | 0.807 |

Best ROC-AUC: **Tuned ET+LR vote (live model)**. These are session-level; the live agent scores short windows, which are noisier. Per-user thresholds and the FAR/FRR trade-off are in `reports/tuning.md`.

## 2. Decision latency (measured)

Time to extract features and score one window on this machine.

| Path | n | mean | p50 | p95 | max |
|---|---|---|---|---|---|
| Cold start (population model) | 9 | 24.711 ms | 15.275 ms | 96.496 ms | 96.496 ms |
| Enrolled (personal model), scoring | 108 | 13.752 ms | 14.119 ms | 17.029 ms | 19.482 ms |
| Periodic model retrain | 3 | 1301.064 ms | 1298.91 ms | 1361.659 ms | 1361.659 ms |

Per-window scoring is a few milliseconds — negligible next to the window length (seconds), so the detection delay the user experiences is set by the window size, not computation. The retrain row is the occasional background profile refresh (every 20 enrolled windows by default), not per-window cost.

## 3. CPU & memory (measured)

- Resident memory after 200 windows: **176.9 MB** (growth 0.3 MB).
- CPU: **41.85 ms/window** (~98.7% of one core while actively scoring).
- Between windows the agent is idle (it sleeps for the window interval), so steady-state CPU is a small fraction of the above.

## 4. Reliability (measured)

- 300 windows through the full controller: **0 errors** (error rate 0.0).
- Enforcement actions on a genuine (non-attack) stream: 0 (false-lock rate 0.0).
- A scoring failure degrades to 'observe, do not lock' rather than crashing or locking blindly.

## 5. Spoof resistance — NOT quantified

The agent includes deterministic anti-spoofing: replay/duplicate-window rejection, stale-timestamp rejection, signal-quality gating, and automation (bot-input) detection. These are unit-tested for correctness. **Their real false-accept rate against live presentation or replay attacks is not measured**, because the Capstone dataset contains no spoof or attack samples. Reporting a spoof-resistance percentage here would be fabricated. To measure it, run this harness against a labelled spoof/replay dataset.

## Limitations

- Latency, CPU and memory are from this machine; they will differ on the target device.
- Detection metrics are session-level on one dataset; live windowed performance is lower and noisier.
- The genuine-stream false-lock rate uses synthetic human-like windows to exercise the pipeline; it is a pipeline sanity check, not a field false-lock rate.

