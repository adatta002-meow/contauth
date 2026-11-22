"""Sending the one-time verification code by email.

Real mail goes out over SMTP when SMTP_HOST/SMTP_FROM are configured (e.g. Gmail
SMTP with an app password). With nothing configured the app runs in *dev mode*: no
mail is sent and the code is surfaced on screen, so the verification flow still works
end to end on a laptop with no mail server. send_code() reports which happened so the
caller can show the code only in dev mode and never leak it when real mail was sent.
"""
from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage


def smtp_configured(cfg) -> bool:
    return bool(cfg.get("SMTP_HOST") and cfg.get("SMTP_FROM"))


def send_code(cfg, to: str, code: str) -> bool:
    """Send the code to `to`. Returns True if real mail was sent, False in dev mode
    (no SMTP configured). Raises on a genuine SMTP failure so the caller can report it."""
    if not smtp_configured(cfg):
        return False
    ttl = cfg.get("EMAIL_CODE_TTL_MIN", 10)
    msg = EmailMessage()
    msg["Subject"] = "Your ContAuth verification code"
    msg["From"] = cfg["SMTP_FROM"]
    msg["To"] = to
    msg.set_content(
        f"Your ContAuth verification code is: {code}\n\n"
        f"It expires in {ttl} minutes. If you did not request this, ignore this email."
    )
    host, port = cfg["SMTP_HOST"], int(cfg.get("SMTP_PORT", 587))
    with smtplib.SMTP(host, port, timeout=20) as s:
        if cfg.get("SMTP_STARTTLS", True):
            s.starttls(context=ssl.create_default_context())
        if cfg.get("SMTP_USER"):
            s.login(cfg["SMTP_USER"], cfg["SMTP_PASSWORD"])
        s.send_message(msg)
    return True
