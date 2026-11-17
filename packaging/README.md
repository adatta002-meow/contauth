# Packaging the desktop agent

Turn the agent into a single double-click app and (optionally) start it on login.
You run these steps once, on the machine where the app will be used, because
PyInstaller builds a binary for the operating system it runs on — it does not
cross-compile, so a Windows `.exe` must be built on Windows.

## Windows — build `ContAuth.exe`

From the repository root:

```bat
packaging\build_windows.bat
```

That installs the dependencies, trains the model if needed, and produces
**`dist\ContAuth.exe`** — one file, no console window, with the trained model
bundled inside. Double-click it to run the agent.

Manual equivalent:

```bat
pip install -r requirements.txt -r requirements-agent.txt pyinstaller
python -m contauth.ml.train
pyinstaller packaging\agent.spec --noconfirm
```

## macOS / Linux — build a binary

```bash
pip install -r requirements.txt -r requirements-agent.txt pyinstaller
python -m contauth.ml.train
pyinstaller packaging/agent.spec --noconfirm   # -> dist/ContAuth
```

## Start on login (auto-start)

After building, point the auto-start installer at the executable:

```bat
python -m contauth.agent.autostart install --exe "%cd%\dist\ContAuth.exe"
```

Without `--exe` it auto-starts `python -m contauth.agent` instead (use this if you
did not build an `.exe`). You can pass agent flags too:

```bat
python -m contauth.agent.autostart install --exe "...\ContAuth.exe" --args "--window-ms 5000"
```

Check or remove it:

```bat
python -m contauth.agent.autostart status
python -m contauth.agent.autostart uninstall
```

The auto-start entry is a plain, visible file you can also delete by hand:

| OS | File |
|---|---|
| Windows | `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\ContAuth.cmd` |
| macOS | `~/Library/LaunchAgents/com.contauth.agent.plist` |
| Linux | `~/.config/autostart/contauth.desktop` |

Auto-start only saves you from launching the agent each time; the status window
still opens, and you can pause or quit it whenever you want.

## Notes

- First launch after login enrolls from scratch unless the per-user data file
  already holds your windows; the data lives in `%LOCALAPPDATA%\ContAuth` and is
  kept between runs.
- Antivirus / SmartScreen may warn about an unsigned executable the first time —
  that is expected for a self-built app. Code-signing is out of scope for a capstone.
- To demo without building anything, skip all of this and run
  `python -m contauth.agent` (or `--simulate`).
