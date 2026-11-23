# Limitations register

An honest account of the system's weaknesses: what was found and fixed in this pass,
and what remains (with the reason it isn't solved here). Written to be used directly in
the Capstone report.

## Fixed in this hardening pass

| # | Limitation | Fix |
|---|---|---|
| 1 | **Sign-in could be brute-forced** — the desktop password login had no attempt limit. | Failed-attempt tracking with a cooldown lockout after N tries (`AGENT_LOGIN_MAX_TRIES`, `AGENT_LOGIN_LOCKOUT_MIN`). A correct password clears it. |
| 2 | **Profile poisoning via drift** — a sustained "mildly unusual" (MEDIUM) stream could keep widening the profile, so a different person could gradually overwrite it. | Anti-poisoning cap: only a bounded run of MEDIUM windows is absorbed before a clean LOW window is required again (`POISON_ADAPT_CAP`). |
| 3 | **Stale trust across an idle gap** — trust and the post-login learning grace persisted if the operator walked away, so a different person who sat down inherited them. | Idle re-lock: after a long idle gap (`IDLE_RELOCK_MIN`) trust drops to a watchful state, the learning grace closes, and replay history clears, so whoever returns must re-prove at full sensitivity. |
| 4 | **No raw-keystroke dataset to benchmark on** — the keystroke-dynamics work (dwell/flight, rhythm) could not be measured, only property-tested. | Added the **CMU Keystroke Dynamics Benchmark** (51 subjects, 400 reps, raw per-key timings; `data/cmu/`, provenance + SHA-256 + source link). Built `contauth/ml/keystroke_benchmark.py`, which reports real FAR/FRR/EER/AUC and reproduces the paper's published 9.6% EER (sanity check). |
| 5 | **Keystroke accuracy only measured on leaky session-level data (~25% EER)** | On the clean CMU data the agent's Isolation Forest model scores **EER 8.52% / ROC-AUC 0.965**; Scaled-Manhattan 9.60% (matches literature). Hold, digraph and flight features each contribute, with the full set best — the evidence for the keystroke-feature design. |
| 6 | **Ensemble blended Isolation Forest and One-Class SVM 50/50** despite IF being stronger. | The benchmark shows IF (8.5% EER) beats OCSVM (10.7%), so the personal model now weights IF more (`PERSONAL_IF_WEIGHT`). |

All six are covered by tests (`tests/test_agent.py`) and/or a reproducible benchmark
(`reports/keystroke_benchmark.md`).

## Known remaining limitations (not solvable in code alone)

- **Keystroke accuracy is now measured, but is still probabilistic.** On the clean CMU
  benchmark the model reaches EER ≈ 8.5% / AUC ≈ 0.965 — strong, and in line with the
  published literature, but not a perfect hard gate. The live free-text agent will run
  a bit higher than this fixed-text benchmark. *To push further:* fuse mouse-trajectory
  dynamics and free-text digraph features.

- **Spoof resistance still unquantified.** The replay / signal-quality / automation
  defences are unit-tested, but their real false-accept rate against live presentation
  or replay attacks needs a labelled spoof/replay dataset, which we do not have. The
  report states this instead of inventing a number.

- **Free-text vs fixed-text gap.** The CMU benchmark is a fixed password; the live agent
  monitors free typing. The benchmark validates the method, detector choice and feature
  groups on real data, but a free-text multi-user collection would be needed to put an
  exact number on the *live* agent. *To solve:* collect a consented free-text dataset.

- **Single operator per device.** The agent verifies "is this the enrolled owner?",
  not "which of several enrolled users is this". *To solve:* multi-profile enrolment and
  identification (a feature addition, not a bug).

- **Not tamper-resistant.** The agent is deliberately visible and user-stoppable (Pause /
  close), and the at-rest encryption key sits next to the database, so it protects
  against casual inspection, not against an attacker already running as the same OS user.
  Real tamper-resistance needs OS-level privileges (a service/driver) and full-disk
  encryption — out of scope for a user-space app, and a different threat model.

- **Detection latency.** A behavioural mismatch locks in ~3 windows (~9 s at 3 s windows);
  it cannot stop a sub-second data grab. It is defence-in-depth alongside idle-lock,
  disk encryption and the OS login, not a replacement for them.

- **Dev-mode email code is shown on screen.** Without SMTP configured the verification
  code is displayed locally (so the flow works offline), which is not real verification.
  *To solve:* configure SMTP (documented in `DEPLOY.md`) so the code is emailed.
