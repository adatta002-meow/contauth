"""The agent's local dashboard (Tkinter, standard library).

Redesigned to make the four things that matter legible at a glance:
  * TRUST      — a 0-100 trust score (the sequential engine's live confidence that
                 the person at the keyboard is you), with a colour band.
  * PROTECTION — one plain-language status line: Protected / Watching / Re-auth
                 needed / Locked / Paused / Monitor-only.
  * HEALTH     — monitoring health tiles: capture on, model state + enrollment,
                 live signal quality, model confidence, encryption at rest.
  * EVENTS     — the security event log, colour-coded by severity.

The agent is deliberately visible and user-controlled: Pause, Reset, "My data"
(what's stored / delete it) and Quit are always on screen. A hidden agent you
cannot see or stop would be spyware; this one is neither.
"""
from __future__ import annotations

import time

# colour system (dark, high-contrast)
C = {"bg": "#0a1222", "panel": "#111f36", "panel2": "#0e1a2e", "ink": "#eaf1fb",
     "mut": "#8ca3c0", "line": "#1d2f4d", "good": "#1f9d57", "warn": "#c98a16",
     "bad": "#d4570f", "crit": "#d23b3b", "idle": "#51657f", "accent": "#3d7dff"}

# trust bands -> colour + label
def _trust_band(trust, protection):
    if protection in ("PAUSED", "MONITOR-ONLY"):
        return C["idle"]
    if trust >= 70:
        return C["good"]
    if trust >= 45:
        return C["warn"]
    if trust >= 25:
        return C["bad"]
    return C["crit"]


SEV_COLOR = {"info": C["mut"], "warning": C["warn"], "critical": C["crit"]}


class StatusWindow:
    def __init__(self, controller, on_quit):
        import tkinter as tk
        self.tk = tk
        self.controller = controller
        self.store = getattr(controller, "store", None)
        self.on_quit = on_quit
        self.root = tk.Tk()
        self.root.title("ContAuth — continuous authentication")
        self.root.geometry("500x660")
        self.root.minsize(460, 600)
        self.root.configure(bg=C["bg"])

        # ---- header ----
        head = tk.Frame(self.root, bg=C["bg"]); head.pack(fill="x", padx=18, pady=(16, 6))
        tk.Label(head, text="ContAuth", font=("Segoe UI", 18, "bold"), bg=C["bg"], fg=C["ink"]).pack(side="left")
        self.enc = tk.Label(head, text="", font=("Segoe UI", 9), bg=C["bg"], fg=C["mut"])
        self.enc.pack(side="right")
        tk.Label(self.root, text="Verifies you continuously by your typing and mouse rhythm — timing only, never the keys you press.",
                 font=("Segoe UI", 9), bg=C["bg"], fg=C["mut"], wraplength=460, justify="left").pack(anchor="w", padx=18)

        # ---- trust meter + protection status ----
        card = tk.Frame(self.root, bg=C["panel"]); card.pack(fill="x", padx=18, pady=12)
        left = tk.Frame(card, bg=C["panel"]); left.pack(side="left", padx=(18, 10), pady=16)
        tk.Label(left, text="TRUST", font=("Segoe UI", 9, "bold"), bg=C["panel"], fg=C["mut"]).pack(anchor="w")
        self.trust = tk.Label(left, text="--", font=("Segoe UI", 46, "bold"), bg=C["panel"], fg=C["ink"])
        self.trust.pack(anchor="w")
        self.bar_bg = tk.Frame(left, bg=C["line"], height=8, width=150); self.bar_bg.pack(anchor="w", pady=(2, 0))
        self.bar_bg.pack_propagate(False)
        self.bar = tk.Frame(self.bar_bg, bg=C["good"], height=8, width=0); self.bar.pack(side="left")

        right = tk.Frame(card, bg=C["panel"]); right.pack(side="left", fill="both", expand=True, pady=16)
        self.status = tk.Label(right, text="starting", font=("Segoe UI", 13, "bold"), bg=C["idle"], fg="#fff", padx=12, pady=4)
        self.status.pack(anchor="w")
        self.substatus = tk.Label(right, text="", font=("Segoe UI", 10), bg=C["panel"], fg=C["mut"],
                                  wraplength=230, justify="left")
        self.substatus.pack(anchor="w", pady=(8, 0))
        self.risk = tk.Label(right, text="", font=("Segoe UI", 9), bg=C["panel"], fg=C["mut"])
        self.risk.pack(anchor="w", pady=(6, 0))

        # ---- monitoring health tiles ----
        tk.Label(self.root, text="MONITORING HEALTH", font=("Segoe UI", 9, "bold"),
                 bg=C["bg"], fg=C["mut"]).pack(anchor="w", padx=18, pady=(2, 4))
        grid = tk.Frame(self.root, bg=C["bg"]); grid.pack(fill="x", padx=18)
        self.tiles = {}
        specs = [("capture", "Capture"), ("model", "Model"), ("enroll", "Enrollment"),
                 ("quality", "Signal quality"), ("confidence", "Model confidence"), ("spoof", "Anti-spoofing")]
        for i, (key, label) in enumerate(specs):
            cell = tk.Frame(grid, bg=C["panel2"], highlightbackground=C["line"], highlightthickness=1)
            cell.grid(row=i // 3, column=i % 3, sticky="nsew", padx=3, pady=3)
            grid.grid_columnconfigure(i % 3, weight=1)
            tk.Label(cell, text=label.upper(), font=("Segoe UI", 7, "bold"), bg=C["panel2"], fg=C["mut"]).pack(anchor="w", padx=8, pady=(6, 0))
            v = tk.Label(cell, text="—", font=("Segoe UI", 11, "bold"), bg=C["panel2"], fg=C["ink"])
            v.pack(anchor="w", padx=8, pady=(0, 6))
            self.tiles[key] = v

        # ---- controls ----
        btns = tk.Frame(self.root, bg=C["bg"]); btns.pack(fill="x", padx=18, pady=(10, 2))
        self.pause_btn = tk.Button(btns, text="Pause", width=9, command=self._toggle_pause)
        self.pause_btn.pack(side="left")
        tk.Button(btns, text="Reset profile", width=12, command=self._reset).pack(side="left", padx=6)
        tk.Button(btns, text="My data", width=9, command=self._data).pack(side="left")
        tk.Button(btns, text="Quit", width=7, command=self._quit).pack(side="right")

        # ---- security events ----
        tk.Label(self.root, text="SECURITY EVENTS", font=("Segoe UI", 9, "bold"),
                 bg=C["bg"], fg=C["mut"]).pack(anchor="w", padx=18, pady=(12, 2))
        self.log = tk.Text(self.root, height=11, bg=C["panel"], fg=C["ink"], font=("Consolas", 9),
                           relief="flat", wrap="word", state="disabled", padx=10, pady=8)
        self.log.pack(fill="both", expand=True, padx=18, pady=(0, 16))
        for sev, col in SEV_COLOR.items():
            self.log.tag_config(sev, foreground=col)
        self.root.protocol("WM_DELETE_WINDOW", self._quit)

    # ---- controls ----
    def _toggle_pause(self):
        self.controller.pause(not self.controller.paused)
        self.pause_btn.config(text="Resume" if self.controller.paused else "Pause")

    def _reset(self):
        from tkinter import messagebox
        if messagebox.askyesno("Reset profile", "Clear your enrolled profile and restart enrollment?"):
            self.controller.reset_profile()

    def _data(self):
        """Transparency + deletion: show what's stored and offer to erase it."""
        from tkinter import messagebox
        if not self.store:
            return
        s = self.store.export_summary()
        msg = (f"Profile windows stored: {s['profile_windows']}\n"
               f"Event log entries: {s['event_log_entries']}\n"
               f"Encrypted at rest: {'yes (AES-256-GCM)' if s['encrypted_at_rest'] else 'no'}\n"
               f"Stores keystrokes or text: NO\n\n"
               f"What is stored: {s['stored_fields']}.\n\n"
               f"Delete everything now? (profile, events, and the encryption key)")
        if messagebox.askyesno("Your data", msg):
            self.store.wipe()
            self.controller.engine.reset_profile()
            self.add_log("data_wiped", "info", "all stored data erased at your request")

    def _quit(self):
        self.on_quit()
        self.root.destroy()

    # ---- log + refresh ----
    def add_log(self, kind, severity, detail):
        self.log.config(state="normal")
        ts = time.strftime("%H:%M:%S")
        self.log.insert("1.0", f"{ts}  {kind.replace('_', ' ')}  —  {detail}\n", severity if severity in SEV_COLOR else "info")
        self.log.delete("200.0", "end")
        self.log.config(state="disabled")

    def _protection(self, s, paused):
        if paused:
            return "PAUSED", C["idle"], "Monitoring is paused — you are not being verified."
        if getattr(self.controller, "monitor_only", False):
            return "MONITOR-ONLY", C["idle"], "Observing and logging only — it will not lock the screen."
        last = self.controller.last or {}
        action = last.get("action")
        if action == "terminate":
            return "LOCKING", C["crit"], "Critical anomaly — locking the screen for re-authentication."
        if action == "step_up":
            return "RE-AUTH NEEDED", C["bad"], "Behaviour stopped matching your profile — re-authentication required."
        if s["trust"] >= 70:
            return "PROTECTED", C["good"], "Behaviour matches your profile. You are verified."
        return "WATCHING", C["warn"], "Gathering evidence — trust is below the comfortable range."

    def refresh(self):
        s = self.controller.engine.status()
        paused = self.controller.paused
        label, col, sub = self._protection(s, paused)

        trust = 0 if paused else s["trust"]
        self.trust.config(text="II" if paused else str(round(trust)))
        band = _trust_band(trust, label)
        self.bar.config(bg=band, width=int(150 * max(0, min(100, trust)) / 100))
        self.status.config(text=label, bg=col)
        self.substatus.config(text=sub)
        self.risk.config(text=f"Risk {s['risk']}   ·   tier {self.controller.engine.tier}")
        self.enc.config(text=("🔒 encrypted at rest" if (self.store and self.store.encrypted) else "unencrypted store"))

        # health tiles
        cap_on = "paused" if paused else ("simulate" if getattr(self, "_simulate", False) else "on")
        self.tiles["capture"].config(text=cap_on, fg=C["mut"] if paused else C["good"])
        self.tiles["model"].config(text=s["model"])
        self.tiles["enroll"].config(
            text=(f"{s['enrolled']}/{s['need']}" if not s["profile_n"] else f"{s['profile_n']} win"))
        q = s.get("quality", 0)
        self.tiles["quality"].config(text=f"{q:.2f}", fg=C["good"] if q >= 0.5 else C["warn"])
        self.tiles["confidence"].config(text=f"{s.get('confidence', 0):.2f}")
        reps = s.get("replays", 0)
        self.tiles["spoof"].config(text=("OK" if reps == 0 else f"{reps} flag"),
                                   fg=C["good"] if reps == 0 else C["bad"])

    def mainloop(self):
        self.root.mainloop()
