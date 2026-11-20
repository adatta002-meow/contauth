# ContAuth desktop agent

Continuous authentication for the **whole machine**, not just one web page. The
agent watches your typing and mouse rhythm across the desktop, scores it every few
seconds with the same model and Zero Trust engine as the web/server system, and
**locks the screen** when the behaviour stops matching your enrolled profile — the
operating system's login then re-verifies you.

It reuses the project's existing code unchanged: `contauth/features.py` (the 21
features), `contauth/ml/models.py` (the models), `contauth/policy.py` (the Zero
Trust engine) and `models/population.joblib` (the model trained on 705 real
sessions). Scores are therefore identical to the server.

```
Global hooks (pynput)        AuthEngine                      Enforcement
 keystroke timing  ─┐   every 5 s   ─► features.py (21 feats)   ── LOW  → allow
 pointer moves      ├─► drain buffer ─► population / personal   ── MED  → monitor
 clicks, scroll    ─┘                   Isolation Forest + OCSVM ── HIGH → lock screen (re-auth via OS)
                                        policy.py (Risk=…)       ── CRIT → lock + alert
            Local SQLite: aggregated windows + event log (no keystrokes, no text)
                     Tk status window: live risk, progress, Pause / Reset / Quit
```

## Run it

```bash
pip install -r requirements.txt -r requirements-agent.txt
python -m contauth.ml.train            # once, builds models/population.joblib

python -m contauth.agent               # start the agent (status window opens)
python -m contauth.agent --dry-run     # same, but log the lock instead of locking
python -m contauth.agent --simulate    # demo with synthetic activity, no global hooks
python -m contauth.agent --face        # add a consented camera presence check on step-up
python -m contauth.agent --headless --simulate --bot-at 16   # no window; CI/demo
```

On Windows and macOS this just works. On Linux you may need `sudo apt install
python3-tk`, and global input hooks need an X/Wayland session.

## Privacy — what it records and what it never does

**Records:** the *timing* of key events, a per-key "is this a modifier" flag, and
mouse coordinates/clicks/scrolls. Only the 21 aggregated features of each 5-second
window are written to a local SQLite file.

**Never does:** it does not record which keys you press or any text (it is not a
keylogger); it does not read files, photos or passwords; it does not use the camera
or microphone unless you pass `--face`, and then only in a visible window; it does
not see other apps or tabs; and it never shuts down, signs out destructively, or
changes anything on the device. Its single action is to **lock the screen**, exactly
like a screensaver timeout. The status window is always visible and the agent can be
paused or quit at any time — a hidden, unstoppable agent would be spyware; this is
the opposite by design.

## How enforcement works

| Tier | Risk | Action |
|---|---|---|
| LOW | ≤30 | allow |
| MEDIUM | ≤60 | monitor more closely |
| HIGH | ≤80 | **lock the screen** — you sign back in with your OS password |
| CRITICAL | >80 | lock + a critical event (e.g. scripted input detected) |

Behaviour alone can reach HIGH (a lock), never CRITICAL — the same rule as the rest
of the system. With `--face`, a HIGH step-up first opens a visible camera window and
a confirmed face grants a short grace period instead of locking; CRITICAL always
locks. After any lock the behavioural baseline resets to neutral, so monitoring
resumes cleanly once the real user signs back in.

## Data location

`%LOCALAPPDATA%\ContAuth\agent.db` (Windows), `~/Library/Application Support/ContAuth`
(macOS), `~/.local/share/contauth` (Linux), or pass `--data-dir`. The trained model
is **retrained from the stored feature windows at startup**, so it always matches the
installed scikit-learn — no pickled model is shipped or loaded from disk.

## Limitations (good viva talking points)

- Enforcement is a screen lock. It verifies continuously but relies on the OS login
  to re-authenticate; it does not replace the OS password.
- The `--face` factor detects face **presence**, not identity. Per-user face
  recognition is a natural next step.
- Keystroke/mouse dynamics need a few windows (~1 min) to enroll; during cold start
  the shared population model is used at half weight, so the agent stays at MEDIUM
  and only monitors.

## Daily use on your own device

For real everyday use you want it to protect the machine without locking you out by
surprise. Three guards make that safe (all tunable in a config file):

- **Warm-up** — for the first few minutes after launch, a behaviour-only step-up
  just *warns*; a bot or a stolen-cookie signal still locks immediately.
- **Cooldown** — after a lock it won't lock again for a few seconds, so typing your
  password to sign back in doesn't trigger another lock.
- **Monitor-only** — `--monitor-only` never locks, it only logs what it *would* do.
  Run this for a few days first to see how often it would have acted, then switch
  enforcement on once you trust it.

Recommended first run (watch, don't enforce):

```bash
python -m contauth.agent --monitor-only
```

Then enforce with gentle settings via a config file (copy
`agent-config.example.json` to `agent-config.json` and edit):

```bash
python -m contauth.agent --config agent-config.json
```

The example config enrolls in about 24 s (8 windows x 3 s), requires **3** HIGH windows in a row
(gentler than the default 2), gives a 30-second warm-up and a 30-second cooldown.

### Start it automatically on login

```bash
python -m contauth.agent.autostart install        # start on next login
python -m contauth.agent.autostart status
python -m contauth.agent.autostart uninstall
```

The entry is a plain, visible file you can also delete by hand (Startup folder on
Windows, a LaunchAgent on macOS, an autostart `.desktop` on Linux). Auto-start only
saves you from launching it each time — the window still opens and you can pause or
quit whenever you like.

### Make it a double-click app

To turn it into a single `ContAuth.exe` (Windows) or binary (macOS/Linux) with the
model bundled inside, see **[packaging/README.md](../../packaging/README.md)**.
PyInstaller builds for the OS it runs on, so build the `.exe` on Windows.
