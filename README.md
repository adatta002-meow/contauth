# ContAuth: Continuous Authentication for Web Sessions

Capstone B (CSE400B) system: *Continuous Authentication for Web Sessions Using Behavioral Biometrics and Zero Trust Controls.*

A Flask + SQLite web app that keeps checking, every 30 seconds, that the person using a session is the person who logged in, and responds through a four-tier Zero Trust policy.

```
Browser (capture.js)          Flask app                         ML layer                 SQLite
 keystroke timing  ─┐   POST /api/behavior                 population baseline       users, sessions
 pointer movement   ├─► every 30 s  ─► feature extraction ─► (Capstone B dataset)  ─► windows (+features)
 clicks, scroll     │                  (features.py)        personal model + per-   profiles, devices
 idle, focus       ─┘                        │              user threshold (ET+LR)    events (audit)
                                             ▼
                              Zero Trust engine (policy.py)
                Risk = 0.70·B + 0.10·C + 0.10·D + 0.10·S  + hard overrides
            LOW ≤30 allow · MEDIUM ≤60 monitor · HIGH ≤80 step-up · CRITICAL terminate + lock
```

## Run it

To put it on the internet, see **[DEPLOY.md](DEPLOY.md)** (free Render deploy, about 10 minutes).


```bash
pip install -r requirements.txt
python -m contauth.ml.train                 # trains + writes reports/benchmark.md (~1 min)
python -m contauth.ml.tune                  # optional: nested model selection, reports/tuning.md (~10 min)
flask --app contauth create-admin admin     # prompts for a password
CA_SECRET_KEY=change-me flask --app contauth run
```

Open http://127.0.0.1:5000, register a normal user, and use **Notes** for a few minutes (typing notes generates the behaviour). The admin at `/admin` sees sessions, the risk timeline per window, and the security event log.

Docker: `docker build -t contauth . && docker run -p 8000:8000 -e CA_SECRET_KEY=change-me -v contauth-data:/srv/instance contauth`

Tests: `python -m pytest -q` (25 tests, including attack scenarios and calibration).

## What each layer does

| Layer | File | Role |
|---|---|---|
| Capture | `contauth/static/js/capture.js` | Records event timings + pointer coordinates. Never keys, text or form values. Sends a batch every 30 s and applies the returned decision. |
| Features | `contauth/features.py` | One definition shared by training and live scoring. 21 rate/timing/ratio features (the original 14 plus 7 chosen by nested selection), 2 s idle threshold (inferred from the dataset). |
| ML | `contauth/ml/`, `contauth/profiles.py` | Cold start: population Isolation Forest trained on the 705 dataset sessions. After 20 accepted windows: personal Isolation Forest + One-Class SVM. Once other users are enrolled: tuned ExtraTrees + logistic-regression vote against them. Each personal model gets its own decision threshold calibrated on held-out enrollment data (`OPERATING_FAR`, `ONECLASS_FRR`); a score below it lands exactly in the HIGH tier. Retrains every 20 new accepted windows (handles drift). |
| Zero Trust | `contauth/policy.py` | Weighted risk + hard overrides + tiers. Pure functions, unit-tested. |
| Enforcement | `contauth/__init__.py` | Session binding, step-up re-authentication, sensitive-route guard, termination, account lock, audit log, admin dashboard. |

## Risk components

| | Signal | Value |
|---|---|---|
| **B** behaviour | 100 × (1 − genuineness), EWMA-smoothed across windows | 0–100 (cold start capped at 50) |
| **C** context | IP changed mid-session 70 · IP new for this user 30 | 0–100 |
| **D** device | User agent/device changed mid-session 100 · new device 40 | 0–100 |
| **S** session | Sensitive page 30 · session older than 8 h 40 · each failed step-up 25 | 0–100 |

**Hard overrides** (deterministic signals, not statistics): browser changed mid-session → 85 (terminate); scripted input (constant pointer velocity, machine-regular keystrokes, inhuman event rate) → 85 (terminate); IP changed mid-session → 61 (step-up).

**Design choices worth defending in the viva**

- Behaviour alone can reach HIGH (step-up) but never CRITICAL. Killing a session needs corroboration, which keeps statistical false rejects from locking real users out.
- A behaviour-only HIGH must persist for 2 consecutive windows before step-up (cuts false rejects). Deterministic overrides act at once.
- Only clean, low-risk windows train the profile. Anomalous or post-alert windows never enter it, so an attacker cannot teach the model.
- Windows with fewer than 15 events carry no behavioural evidence and keep the previous score rather than being judged.

## Attack scenarios covered (see `tests/test_system.py`)

| Scenario | Detection | Response |
|---|---|---|
| A1/A3 Session hijacking, cookie theft (cookie replayed from another browser) | Session binding: user agent mismatch on the next request | Terminate, lock account 15 min, critical event |
| A2 Replay from another network | IP changed mid-session | Immediate step-up; protected pages blocked until password |
| A4 Insider at an unlocked workstation | Behaviour diverges from personal profile over consecutive windows | Step-up re-authentication; 3 failures → terminate + lock |
| A5 Bot / scripted input | Automation heuristics | Terminate + lock |

## Measured performance (honest)

Per-user verification, 10 users, test impostors never seen in training, 5 splits. Every model and threshold choice was made on training data only (`reports/tuning.md`).

| | ROC-AUC | EER |
|---|---|---|
| Original: Random Forest, 14 features | 0.767 | 28.1% |
| **Improved: nested-selected, 21 features** | **0.800** | **25.6%** |

FAR/FRR trade-off with per-user calibrated thresholds (measured on unseen impostors):

| Target FAR | Test FAR | Test FRR (per session) |
|---|---|---|
| 1% | 1.6% | 76.2% |
| 5% | 5.1% | 60.3% |
| **10% (live default)** | **9.2%** | **48.2%** |
| 20% | 18.5% | 35.5% |
| EER point | 25.4% | 27.3% |

Calibrated thresholds hit their FAR targets on unseen people, so `CA_OPERATING_FAR` is a reliable dial. Per-session FRR is high at strict settings. In the live system a false reject costs one password re-entry, only after 2 consecutive below-threshold windows, and never ends the session. One user (`31eed1`) stays near chance in this feature space.

`reports/benchmark.md` has all six models on the original splits (the live model: AUC 0.807, EER 25.3%).

None of this reproduces the 95.5% / 0.983 in the Capstone B report or the 96.7% in the earlier slides. The dataset's figshare and `v0`/`v1` portions are separable with 100% accuracy, because they were recorded differently. Any label tied to the source would score near-perfectly without measuring identity. See `DATA_PROVENANCE.md`.

## Known limitations

- **Dataset granularity.** Training rows are whole sessions; live scoring uses 30-second windows. The population baseline is therefore coarse (cold-start sessions sit at ~35 risk, MEDIUM/monitor). Real discrimination comes from the personal profile built from the user's own windows.
- **Mobile networks change IPs.** On mobile carriers, the IP override will cause extra step-ups. Relax it to a context score only (`policy.py`) if needed.
- **Behind a reverse proxy**, wrap the app in werkzeug `ProxyFix` so `remote_addr` is the client's address.
- Step-up is password re-entry. TOTP/WebAuthn would be the production choice.
- Set `CA_SECRET_KEY` and `CA_COOKIE_SECURE=true` (HTTPS) outside development.
