/*
 * Behavioral capture for continuous authentication.
 * Records event TIMINGS and pointer coordinates only. It never records which key
 * was pressed, typed text or form values. Every WINDOW_MS it sends one batch to
 * the server and applies the Zero Trust decision that comes back.
 */
(function () {
  "use strict";
  const meta = (n) => document.querySelector(`meta[name="${n}"]`)?.content;
  const ENDPOINT = meta("ca-endpoint") || "/api/behavior";
  const CSRF = meta("csrf-token");
  const WINDOW_MS = parseInt(meta("ca-window-ms") || "30000", 10);
  const MOVE_SAMPLE_MS = 20; // at most ~50 mousemove samples per second
  const MODIFIERS = new Set(["Shift", "Control", "Alt", "Meta", "CapsLock", "AltGraph"]);

  let buffer = [];
  let windowStart = Date.now();
  let lastMove = 0;
  let sending = false;

  const push = (e) => { if (buffer.length < 20000) buffer.push(e); };
  const now = () => Date.now();

  document.addEventListener("keydown", (ev) => {
    if (ev.repeat) return; // auto-repeat is not human rhythm
    push({ t: now(), type: "keydown", mod: MODIFIERS.has(ev.key) });
  }, true);
  document.addEventListener("keyup", () => push({ t: now(), type: "keyup" }), true);
  document.addEventListener("mousemove", (ev) => {
    const t = now();
    if (t - lastMove < MOVE_SAMPLE_MS) return;
    lastMove = t;
    push({ t, type: "mousemove", x: ev.screenX, y: ev.screenY });
  }, { capture: true, passive: true });
  for (const type of ["mousedown", "mouseup", "click", "dblclick"]) {
    document.addEventListener(type, () => push({ t: now(), type }), true);
  }
  window.addEventListener("scroll", () => push({ t: now(), type: "scroll" }), { capture: true, passive: true });
  window.addEventListener("focus", () => push({ t: now(), type: "focus" }));
  window.addEventListener("blur", () => push({ t: now(), type: "blur" }));
  document.addEventListener("input", () => push({ t: now(), type: "input" }), true);

  function applyDecision(d) {
    const badge = document.getElementById("ca-badge");
    if (badge && d.risk !== undefined) {
      badge.dataset.tier = d.tier;
      badge.textContent = `Trust: ${d.tier.toLowerCase()} risk (${Math.round(d.risk)})`;
    }
    if (d.action === "step_up") window.location.href = d.redirect || "/reauth";
    if (d.action === "terminate") window.location.href = d.redirect || "/login?reason=terminated";
  }

  async function flush(final) {
    if (sending && !final) return;
    const end = now();
    const payload = JSON.stringify({ start: windowStart, end, events: buffer, page: location.pathname });
    buffer = [];
    windowStart = end;
    if (final) {
      // page is unloading: fire-and-forget
      navigator.sendBeacon?.(ENDPOINT + "?beacon=1&csrf=" + encodeURIComponent(CSRF || ""), new Blob([payload], { type: "application/json" }));
      return;
    }
    sending = true;
    try {
      const r = await fetch(ENDPOINT, {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": CSRF || "" },
        body: payload,
      });
      if (r.status === 401) { window.location.href = "/login?reason=expired"; return; }
      if (r.ok) applyDecision(await r.json());
    } catch (_) { /* network blip: next window will carry on */ }
    finally { sending = false; }
  }

  setInterval(() => flush(false), WINDOW_MS);
  document.addEventListener("visibilitychange", () => { if (document.visibilityState === "hidden") flush(true); });
})();
