# ContAuth agent — Windows quick start

Build the double-click app and run it on your Windows laptop. You need **Python
3.10+** installed (tick "Add Python to PATH" in the installer).

## 1. Get the code

```bat
git clone https://github.com/adatta002-meow/contauth
cd contauth
```

(Already cloned? Just `cd contauth` then `git pull`.)

## 2. Build ContAuth.exe (one command)

```bat
packaging\build_windows.bat
```

This installs the dependencies, trains the model if needed, and produces
**`dist\ContAuth.exe`** — one file, no console window, the model bundled inside.
First build takes a few minutes.

> Prefer not to build an .exe? You can skip this and just run
> `python -m contauth.agent` after `pip install -r requirements.txt -r requirements-agent.txt`.

## 3. Try it safely first (no locking)

Double-click `dist\ContAuth.exe`, or from the terminal run it in monitor-only mode:

```bat
python -m contauth.agent --monitor-only
```

Type and use your laptop for about half a minute (it enrolls in ~24 s). The status window shows your risk and
the event log, and logs "would lock" instead of locking. This shows how it behaves
on your real usage before it can lock you.

## 4. Turn on enforcement (gentle settings)

```bat
copy agent-config.example.json agent-config.json
python -m contauth.agent --config agent-config.json
```

Now it locks the screen when behaviour stops matching you (5-minute warm-up,
3 bad windows in a row, 30-second cooldown). To test the lock safely without being
locked out, add `--dry-run` and watch the log say "would lock".

## 5. Start it automatically on login

```bat
python -m contauth.agent.autostart install --exe "%cd%\dist\ContAuth.exe"
python -m contauth.agent.autostart status
python -m contauth.agent.autostart uninstall
```

(Omit `--exe` to auto-start `python -m contauth.agent` instead of the built app.)

## Notes

- Windows SmartScreen may warn about an unsigned app the first time — that's normal
  for a self-built exe. Click "More info" → "Run anyway". Code-signing is out of
  scope for a capstone.
- Your data (enrolled windows + event log) lives in `%LOCALAPPDATA%\ContAuth` and is
  kept between runs, so you enroll once.
- It records only typing/mouse **timing**, never the keys you press.
- Pause or quit anytime from the status window.
