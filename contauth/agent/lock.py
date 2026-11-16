"""Locking the workstation — the agent's only enforcement action.

The agent NEVER shuts down, signs out destructively, deletes, or changes anything
on the device. Its single response to a failed behavioural check is to lock the
screen, exactly like a screensaver timeout, so the real user re-authenticates with
their normal OS password. That is the whole point: trust is re-established by the
operating system's own login, not by this program.

Set CA_AGENT_DRY_RUN=1 to log the lock instead of performing it (used in tests and
for a safe demo).
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys


def _is_dry_run() -> bool:
    return os.environ.get("CA_AGENT_DRY_RUN", "").lower() in ("1", "true", "yes")


def lock_command(platform: str | None = None) -> list[str] | str | None:
    """Return the lock mechanism for a platform without running it.

    Windows -> the string "LockWorkStation" (a user32 call, handled in lock()).
    macOS / Linux -> an argv list for subprocess, or None if no tool is found.
    """
    p = platform or sys.platform
    if p.startswith("win"):
        return "LockWorkStation"
    if p == "darwin":
        cg = "/System/Library/CoreServices/Menu Extras/User.menu/Contents/Resources/CGSession"
        if os.path.exists(cg):
            return [cg, "-suspend"]
        return ["pmset", "displaysleepnow"]
    # Linux / other Unix: try the common session lockers in order of reliability.
    for cmd in (["loginctl", "lock-session"],
                ["xdg-screensaver", "lock"],
                ["gnome-screensaver-command", "-l"],
                ["dm-tool", "lock"],
                ["xset", "s", "activate"]):
        if shutil.which(cmd[0]):
            return cmd
    return None


def lock_screen(logger=None) -> bool:
    """Lock the workstation. Returns True if a lock was issued (or dry-run)."""
    cmd = lock_command()
    say = logger or (lambda *a: None)
    if _is_dry_run():
        say(f"[dry-run] would lock the screen via: {cmd}")
        return True
    if cmd is None:
        say("No screen-lock tool found on this system; cannot lock.")
        return False
    try:
        if cmd == "LockWorkStation":
            import ctypes
            ctypes.windll.user32.LockWorkStation()
        else:
            subprocess.run(cmd, check=False, timeout=10)
        say("Screen locked. The user must sign back in with their OS password.")
        return True
    except Exception as e:  # pragma: no cover - platform specific
        say(f"Could not lock the screen: {e}")
        return False
