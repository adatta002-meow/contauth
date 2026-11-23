"""Sign-in window shown before the agent starts monitoring.

Three states, chosen automatically:
  * register — first run: set an email + password.
  * verify   — email not yet confirmed: enter the 6-digit code (emailed if SMTP is
               configured, otherwise shown on screen in dev mode).
  * login    — returning run: enter the password.

On success the window closes and the agent begins capturing and comparing behaviour.
Standard-library Tkinter only, so it bundles into the one-file exe.
"""
from __future__ import annotations

from contauth import email as emailer
from contauth.agent import account

C = {"bg": "#0a1222", "panel": "#111f36", "ink": "#eaf1fb", "mut": "#8ca3c0",
     "line": "#1d2f4d", "accent": "#3d7dff", "bad": "#d4570f", "good": "#1f9d57"}


class AuthWindow:
    def __init__(self, store, cfg):
        import tkinter as tk
        self.tk = tk
        self.store = store
        self.cfg = cfg
        self.ok = False
        self.root = tk.Tk()
        self.root.title("ContAuth — sign in")
        self.root.geometry("420x430")
        self.root.configure(bg=C["bg"])
        self.body = tk.Frame(self.root, bg=C["bg"])
        self.body.pack(fill="both", expand=True, padx=22, pady=20)
        self.root.protocol("WM_DELETE_WINDOW", self._cancel)
        self._route()

    # ---- helpers ----
    def _clear(self):
        for w in self.body.winfo_children():
            w.destroy()

    def _title(self, text, sub=""):
        self.tk.Label(self.body, text="ContAuth", font=("Segoe UI", 18, "bold"), bg=C["bg"], fg=C["ink"]).pack(anchor="w")
        self.tk.Label(self.body, text=text, font=("Segoe UI", 12, "bold"), bg=C["bg"], fg=C["ink"]).pack(anchor="w", pady=(10, 0))
        if sub:
            self.tk.Label(self.body, text=sub, font=("Segoe UI", 9), bg=C["bg"], fg=C["mut"],
                          wraplength=360, justify="left").pack(anchor="w", pady=(2, 8))

    def _field(self, label, show=None):
        self.tk.Label(self.body, text=label, font=("Segoe UI", 9), bg=C["bg"], fg=C["mut"]).pack(anchor="w", pady=(8, 2))
        e = self.tk.Entry(self.body, show=show or "", font=("Segoe UI", 11), bg=C["panel"], fg=C["ink"],
                          insertbackground=C["ink"], relief="flat")
        e.pack(fill="x", ipady=5)
        return e

    def _err(self):
        self._err_lbl = self.tk.Label(self.body, text="", font=("Segoe UI", 9), bg=C["bg"], fg=C["bad"],
                                      wraplength=360, justify="left")
        self._err_lbl.pack(anchor="w", pady=(8, 0))

    def _button(self, text, cmd):
        b = self.tk.Button(self.body, text=text, command=cmd, font=("Segoe UI", 11, "bold"),
                           bg=C["accent"], fg="#fff", relief="flat", activebackground="#2f66d8", cursor="hand2")
        b.pack(fill="x", ipady=7, pady=(14, 0))
        return b

    def _route(self):
        if not account.exists(self.store):
            self._screen_register()
        elif not account.is_verified(self.store):
            self._screen_verify(reissue=True)
        else:
            self._screen_login()

    # ---- screens ----
    def _screen_register(self):
        self._clear()
        self._title("Create your account", "Register with your email and a password. "
                    "You'll verify the email with a 6-digit code, then the agent starts learning your "
                    "typing and mouse rhythm.")
        self.e_email = self._field("Email (Gmail)")
        self.e_pw = self._field("Password (8+ characters)", show="•")
        self.e_pw2 = self._field("Repeat password", show="•")
        self._err()
        self._button("Create account", self._do_register)

    def _do_register(self):
        email = self.e_email.get().strip().lower()
        pw, pw2 = self.e_pw.get(), self.e_pw2.get()
        if "@" not in email or "." not in email.split("@")[-1]:
            self._err_lbl.config(text="Enter a valid email address."); return
        if len(pw) < 8:
            self._err_lbl.config(text="Password must be at least 8 characters."); return
        if pw != pw2:
            self._err_lbl.config(text="The two passwords don't match."); return
        account.register(self.store, email, pw)
        self.store.log("account_registered", "info", email)
        self._screen_verify(reissue=True)

    def _screen_verify(self, reissue=False):
        self._clear()
        a = account.get_account(self.store)
        email = a["email"] if a else ""
        dev_code = None
        if reissue:
            code = account.issue_code(self.store)
            sent = False
            try:
                sent = emailer.send_code(self.cfg, email, code)
            except Exception as e:
                self.store.log("email_send_failed", "warning", str(e)[:120])
            if not sent:
                dev_code = code
            self.store.log("email_code_sent" if sent else "email_code_devmode", "info", email)
        self._title("Verify your email", f"Enter the 6-digit code for {email}.")
        if dev_code:
            self.tk.Label(self.body, text=f"Demo mode (no email server configured): your code is {dev_code}",
                          font=("Segoe UI", 10, "bold"), bg=C["panel"], fg=C["ink"], wraplength=360,
                          justify="left", padx=10, pady=8).pack(fill="x", pady=(6, 0))
        self.e_code = self._field("Verification code")
        self._err()
        self._button("Verify & start", self._do_verify)
        self.tk.Button(self.body, text="Send a new code", command=lambda: self._screen_verify(reissue=True),
                       font=("Segoe UI", 9), bg=C["bg"], fg=C["mut"], relief="flat", cursor="hand2").pack(pady=(10, 0))

    def _do_verify(self):
        res = account.check_code(self.store, self.e_code.get().strip())
        if res == "ok":
            self.store.log("email_verified", "info", "email verified")
            self._success()
        elif res == "expired":
            self._err_lbl.config(text="That code expired. Click 'Send a new code'.")
        elif res == "locked":
            self._err_lbl.config(text="Too many attempts. Click 'Send a new code'.")
        else:
            self._err_lbl.config(text="Incorrect code. Check the digits and try again.")

    def _screen_login(self):
        self._clear()
        a = account.get_account(self.store)
        self._title("Welcome back", f"Signed in as {a['email']}. Enter your password to start monitoring.")
        self.e_pw = self._field("Password", show="•")
        self._err()
        self._button("Sign in", self._do_login)
        self.e_pw.bind("<Return>", lambda e: self._do_login())

    def _do_login(self):
        rem = account.login_locked_for(self.store)
        if rem > 0:
            self._err_lbl.config(text=f"Too many wrong passwords. Try again in ~{int(rem // 60) + 1} min.")
            return
        if account.check_password(self.store, self.e_pw.get()):
            account.record_login_result(self.store, True)
            self.store.log("login_success", "info", "operator signed in")
            self._success()
        else:
            account.record_login_result(self.store, False,
                                        self.cfg.get("AGENT_LOGIN_MAX_TRIES", 5),
                                        self.cfg.get("AGENT_LOGIN_LOCKOUT_MIN", 5) * 60)
            self.store.log("login_failed", "warning", "wrong password")
            rem = account.login_locked_for(self.store)
            self._err_lbl.config(text="Wrong password." + (f" Locked for ~{int(rem // 60) + 1} min." if rem > 0 else ""))

    # ---- exit ----
    def _success(self):
        self.ok = True
        self.root.destroy()

    def _cancel(self):
        self.ok = False
        self.root.destroy()

    def run(self) -> bool:
        self.root.mainloop()
        return self.ok
