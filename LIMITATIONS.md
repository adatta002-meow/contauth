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

All three are covered by unit tests (`tests/test_agent.py`).

## Known remaining limitations (not solvable in code alone)

- **Detection is statistical, not perfect.** On the real Capstone data the behavioural
  model separates genuine vs impostor users at ROC-AUC ≈ 0.80 / EER ≈ 25% per window —
  strong for some users, near chance for one. It is a second layer, not a hard gate.
  *To improve:* needs a richer dataset (see below), digraph/key-pair features, and mouse
  trajectory dynamics. Can't be benchmarked on the current dataset.

- **Can't quantify the keystroke-rhythm or spoof-resistance gains.** The Capstone dataset
  is session-level with no raw per-keystroke events and no spoof/attack samples, so the
  dwell/flight, rhythm-invariance and anti-spoofing work is validated by property tests,
  not by a before/after FAR/FRR. *To solve:* the CMU Keystroke Dynamics Benchmark
  (raw key timings) for keystroke accuracy; a labelled spoof/replay set for spoofing.

- **Dataset has a recording-condition leak.** Parts of the source data are trivially
  separable by acquisition artefacts rather than behaviour, which inflates any metric
  computed on it. *To solve:* collect or obtain a cleaner, single-condition dataset.

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
