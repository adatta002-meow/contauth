"""Optional second factor: a consented camera presence check (OpenCV).

Off by default. Enabled with `--face`. When a step-up is triggered, instead of
locking blindly the agent can open a VISIBLE camera window and confirm a face is
present before giving the session a short grace period; if no face appears within
the timeout, it locks. The window is always shown, so the user can see exactly
when the camera is on — the agent never uses the camera silently.

This module detects face PRESENCE (a liveness/second-factor signal), not identity.
Matching a specific person's face is a natural extension and is noted as future
work in the report. OpenCV is an optional dependency; if it is missing or there is
no camera, the agent logs that and falls back to locking.
"""
from __future__ import annotations

import time


def available() -> bool:
    try:
        import cv2  # noqa: F401
        return True
    except Exception:
        return False


def confirm_presence(timeout_s: float = 6.0, logger=None) -> bool:
    """Open a visible camera window; return True if a face is seen before timeout.

    Returns False on any error (no camera, no OpenCV, user closed the window), so
    the caller treats "couldn't confirm" the same as "not confirmed" and locks.
    """
    say = logger or (lambda *a: None)
    try:
        import cv2
    except Exception:
        say("OpenCV not installed; cannot run the face check.")
        return False
    cascade_path = cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
    clf = cv2.CascadeClassifier(cascade_path)
    cam = cv2.VideoCapture(0)
    if not cam.isOpened():
        say("No camera available; cannot run the face check.")
        return False
    win = "ContAuth — confirm it's you (press Esc to cancel)"
    found = False
    t_end = time.time() + timeout_s
    try:
        while time.time() < t_end:
            ok, frame = cam.read()
            if not ok:
                break
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            faces = clf.detectMultiScale(gray, 1.2, 5, minSize=(80, 80))
            for (x, y, w, h) in faces:
                cv2.rectangle(frame, (x, y), (x + w, y + h), (0, 200, 120), 2)
            cv2.putText(frame, "Confirming presence..." if not len(faces) else "Face detected",
                        (16, 32), cv2.FONT_HERSHEY_SIMPLEX, 0.8, (255, 255, 255), 2)
            cv2.imshow(win, frame)
            if len(faces):
                found = True
                cv2.waitKey(400)
                break
            if cv2.waitKey(30) == 27:  # Esc
                break
    finally:
        cam.release()
        cv2.destroyAllWindows()
    say("Face confirmed." if found else "No face confirmed.")
    return found
