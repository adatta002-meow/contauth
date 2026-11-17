"""Install or remove a login auto-start entry for the agent.

    python -m contauth.agent.autostart install            # start on next login
    python -m contauth.agent.autostart install --exe C:\\path\\ContAuth.exe
    python -m contauth.agent.autostart uninstall
    python -m contauth.agent.autostart status

The entry is a plain, visible file the user can see and delete by hand:
  * Windows : a .cmd in the Startup folder
      %APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\ContAuth.cmd
  * macOS   : a LaunchAgent  ~/Library/LaunchAgents/com.contauth.agent.plist
  * Linux   : an autostart   ~/.config/autostart/contauth.desktop

Nothing here hides the agent or makes it unstoppable — auto-start only saves the
user from launching it each time; they can still pause or quit it, or remove this
entry. When no --exe is given it launches `python -m contauth.agent`.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

APP = "ContAuth"


def _launch_command(exe: str | None, extra: str = "") -> str:
    if exe:
        return f'"{exe}" {extra}'.strip()
    py = Path(sys.executable).name  # pythonw.exe on Windows avoids a console window
    if sys.platform.startswith("win"):
        pyw = str(Path(sys.executable).with_name("pythonw.exe"))
        exe_py = pyw if Path(pyw).exists() else sys.executable
        return f'"{exe_py}" -m contauth.agent {extra}'.strip()
    return f'"{sys.executable}" -m contauth.agent {extra}'.strip()


def entry_path(platform: str | None = None, base: str | os.PathLike | None = None) -> Path:
    """Where the auto-start file lives. `base` overrides the parent dir (for tests)."""
    p = platform or sys.platform
    if base is not None:
        base = Path(base)
    if p.startswith("win"):
        root = base or (Path(os.environ.get("APPDATA", Path.home())) /
                        "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup")
        return root / f"{APP}.cmd"
    if p == "darwin":
        root = base or (Path.home() / "Library" / "LaunchAgents")
        return root / "com.contauth.agent.plist"
    root = base or (Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "autostart")
    return root / "contauth.desktop"


def _contents(platform: str, cmd: str) -> str:
    if platform.startswith("win"):
        # `start "" /min` launches minimized and returns immediately at login.
        return f'@echo off\r\nstart "" /min {cmd}\r\n'
    if platform == "darwin":
        import shlex
        args = "".join(f"    <string>{a}</string>\n" for a in shlex.split(cmd))
        return ('<?xml version="1.0" encoding="UTF-8"?>\n'
                '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
                '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
                '<plist version="1.0"><dict>\n'
                '  <key>Label</key><string>com.contauth.agent</string>\n'
                f'  <key>ProgramArguments</key><array>\n{args}  </array>\n'
                '  <key>RunAtLoad</key><true/>\n'
                '</dict></plist>\n')
    return ("[Desktop Entry]\nType=Application\nName=ContAuth agent\n"
            f"Exec={cmd}\nX-GNOME-Autostart-enabled=true\nTerminal=false\n")


def install(exe: str | None = None, platform: str | None = None, base=None, extra: str = "") -> Path:
    p = platform or sys.platform
    path = entry_path(p, base)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_contents(p, _launch_command(exe, extra)), encoding="utf-8")
    if not p.startswith("win"):
        try:
            os.chmod(path, 0o644)
        except Exception:
            pass
    return path


def uninstall(platform: str | None = None, base=None) -> bool:
    path = entry_path(platform or sys.platform, base)
    if path.exists():
        path.unlink()
        return True
    return False


def status(platform: str | None = None, base=None) -> bool:
    return entry_path(platform or sys.platform, base).exists()


def main(argv=None):
    ap = argparse.ArgumentParser(description="Install/remove the ContAuth agent login auto-start")
    ap.add_argument("action", choices=["install", "uninstall", "status"])
    ap.add_argument("--exe", default=None, help="path to ContAuth.exe (omit to use python -m contauth.agent)")
    ap.add_argument("--args", default="", help="extra arguments to pass to the agent, e.g. '--window-ms 5000'")
    a = ap.parse_args(argv)
    if a.action == "install":
        path = install(exe=a.exe, extra=a.args)
        print(f"Auto-start installed: {path}")
        print("The agent will launch at your next login. Remove it with: "
              "python -m contauth.agent.autostart uninstall")
    elif a.action == "uninstall":
        print("Auto-start removed." if uninstall() else "No auto-start entry was installed.")
    else:
        print("Auto-start is " + ("ON" if status() else "OFF") + f" ({entry_path()})")


if __name__ == "__main__":
    main()
