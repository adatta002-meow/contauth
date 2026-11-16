"""System-wide behaviour capture via global input hooks (pynput).

PRIVACY — read this first. This module hooks global keyboard and mouse events so
the agent can keep verifying the user across the whole desktop, not just one app.
It is NOT a keylogger and must never become one:

  * It records only the TIMESTAMP of each key event and a single boolean, "was this
    a modifier key" (Shift/Ctrl/Alt/...). It does NOT record which key was pressed,
    the character, or any text. The key object from pynput is inspected only to set
    that boolean and is then discarded.
  * For the mouse it records timing, cursor coordinates, clicks and scrolls.
  * Nothing captured here is ever written to disk as-is: only the aggregated 21
    features of a 5-second window are stored, and those contain no key identities.

The listeners run on pynput's own background threads and simply append timing
events to a shared buffer that the engine drains once per window.
"""
from __future__ import annotations

import threading
import time

# Names of modifier keys as pynput reports them (Key.<name>), used only to set the
# "mod" boolean. We never store the key itself.
_MODIFIER_NAMES = {"shift", "shift_r", "shift_l", "ctrl", "ctrl_l", "ctrl_r",
                   "alt", "alt_l", "alt_r", "alt_gr", "cmd", "cmd_l", "cmd_r", "caps_lock"}


class Capture:
    def __init__(self, move_sample_ms: int = 20, max_buffer: int = 40000):
        self._buf: list[dict] = []
        self._lock = threading.Lock()
        self._last_move = 0.0
        self.move_sample_ms = move_sample_ms
        self.max_buffer = max_buffer
        self._kb = None
        self._ms = None
        self.running = False

    def _push(self, e: dict):
        with self._lock:
            if len(self._buf) < self.max_buffer:
                self._buf.append(e)

    def drain(self) -> list[dict]:
        """Return and clear the buffered events (called once per window)."""
        with self._lock:
            b = self._buf
            self._buf = []
        return b

    # ---- keyboard: timing + modifier boolean ONLY ----
    def _is_modifier(self, key) -> bool:
        name = getattr(key, "name", None) or getattr(key, "_name_", None)
        return bool(name and name in _MODIFIER_NAMES)

    def _on_press(self, key):
        # The only thing we take from `key` is whether it is a modifier. The key's
        # character/vk is never read or stored. `key` goes out of scope immediately.
        self._push({"t": time.time() * 1000.0, "type": "keydown", "mod": self._is_modifier(key)})

    def _on_release(self, key):
        self._push({"t": time.time() * 1000.0, "type": "keyup"})

    # ---- mouse ----
    def _on_move(self, x, y):
        t = time.time() * 1000.0
        if t - self._last_move < self.move_sample_ms:
            return
        self._last_move = t
        self._push({"t": t, "type": "mousemove", "x": int(x), "y": int(y)})

    def _on_click(self, x, y, button, pressed):
        self._push({"t": time.time() * 1000.0, "type": "mousedown" if pressed else "mouseup"})
        if not pressed:
            self._push({"t": time.time() * 1000.0, "type": "click"})

    def _on_scroll(self, x, y, dx, dy):
        self._push({"t": time.time() * 1000.0, "type": "scroll"})

    def start(self):
        """Start the global listeners. Imports pynput lazily so the rest of the
        package imports on headless machines without a display."""
        from pynput import keyboard, mouse  # lazy: needs an input backend
        self._kb = keyboard.Listener(on_press=self._on_press, on_release=self._on_release)
        self._ms = mouse.Listener(on_move=self._on_move, on_click=self._on_click, on_scroll=self._on_scroll)
        self._kb.start()
        self._ms.start()
        self.running = True

    def stop(self):
        for l in (self._kb, self._ms):
            try:
                if l:
                    l.stop()
            except Exception:
                pass
        self.running = False
