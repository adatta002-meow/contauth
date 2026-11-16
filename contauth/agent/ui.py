"""A small, always-visible status window (Tkinter, standard library).

The agent is deliberately not hidden: this window shows the live risk, the model
state, the enrollment progress and a running event log, and it carries the Pause,
Reset and Quit controls. A background authentication agent the user cannot see or
stop would be spyware; this one is visible and stoppable by design.
"""
from __future__ import annotations

import time

TIER_COLORS = {"LOW": "#1f8a52", "MEDIUM": "#b07a00", "HIGH": "#d4570f",
               "CRITICAL": "#c42828", "PAUSED": "#5b6b80"}


class StatusWindow:
    def __init__(self, controller, on_quit):
        import tkinter as tk
        from tkinter import ttk
        self.tk = tk
        self.controller = controller
        self.on_quit = on_quit
        self.root = tk.Tk()
        self.root.title("ContAuth — continuous authentication agent")
        self.root.geometry("460x560")
        self.root.configure(bg="#0b1728")
        C = {"bg": "#0b1728", "panel": "#12233c", "ink": "#e7eef8", "mut": "#93a6bd"}

        tk.Label(self.root, text="ContAuth agent", font=("Segoe UI", 16, "bold"),
                 bg=C["bg"], fg=C["ink"]).pack(anchor="w", padx=16, pady=(14, 0))
        tk.Label(self.root, text="Measures your typing and mouse timing only — never the keys you press.",
                 font=("Segoe UI", 9), bg=C["bg"], fg=C["mut"], wraplength=430, justify="left").pack(anchor="w", padx=16)

        meter = tk.Frame(self.root, bg=C["panel"]); meter.pack(fill="x", padx=16, pady=12)
        self.risk = tk.Label(meter, text="--", font=("Segoe UI", 40, "bold"), bg=C["panel"], fg=C["ink"])
        self.risk.pack(side="left", padx=(16, 8), pady=12)
        side = tk.Frame(meter, bg=C["panel"]); side.pack(side="left", pady=12)
        self.tier = tk.Label(side, text="starting", font=("Segoe UI", 12, "bold"), bg="#5b6b80", fg="#fff", padx=10)
        self.tier.pack(anchor="w")
        self.model = tk.Label(side, text="", font=("Segoe UI", 10), bg=C["panel"], fg=C["mut"])
        self.model.pack(anchor="w", pady=(6, 0))
        self.enroll = tk.Label(side, text="", font=("Segoe UI", 10), bg=C["panel"], fg=C["mut"])
        self.enroll.pack(anchor="w")

        btns = tk.Frame(self.root, bg=C["bg"]); btns.pack(fill="x", padx=16)
        self.pause_btn = tk.Button(btns, text="Pause", width=10, command=self._toggle_pause)
        self.pause_btn.pack(side="left")
        tk.Button(btns, text="Reset profile", width=12, command=self._reset).pack(side="left", padx=6)
        tk.Button(btns, text="Quit", width=8, command=self._quit).pack(side="right")

        tk.Label(self.root, text="Security events", font=("Segoe UI", 10, "bold"),
                 bg=C["bg"], fg=C["mut"]).pack(anchor="w", padx=16, pady=(14, 2))
        self.log = tk.Text(self.root, height=14, bg=C["panel"], fg=C["ink"], font=("Consolas", 9),
                           relief="flat", wrap="word", state="disabled")
        self.log.pack(fill="both", expand=True, padx=16, pady=(0, 14))
        self.root.protocol("WM_DELETE_WINDOW", self._quit)

    def _toggle_pause(self):
        self.controller.pause(not self.controller.paused)
        self.pause_btn.config(text="Resume" if self.controller.paused else "Pause")

    def _reset(self):
        self.controller.reset_profile()

    def _quit(self):
        self.on_quit()
        self.root.destroy()

    def add_log(self, kind, severity, detail):
        self.log.config(state="normal")
        ts = time.strftime("%H:%M:%S")
        self.log.insert("1.0", f"{ts}  {kind.replace('_', ' ')}  —  {detail}\n")
        self.log.delete("200.0", "end")
        self.log.config(state="disabled")

    def refresh(self):
        s = self.controller.engine.status()
        paused = self.controller.paused
        self.risk.config(text="II" if paused else str(round(s["risk"])))
        t = "PAUSED" if paused else s["tier"]
        self.tier.config(text=t.lower() + (" risk" if not paused else ""), bg=TIER_COLORS.get(t, "#5b6b80"))
        self.model.config(text=f"Model: {s['model']}" + (f" ({s['profile_n']} windows)" if s["profile_n"] else ""))
        self.enroll.config(text=(f"Enrolling {s['enrolled']}/{s['need']}" if not s["profile_n"]
                                 else f"Threshold {s['threshold']}"))

    def mainloop(self):
        self.root.mainloop()
