"""Per-user behavioural profiles: enrollment, training and scoring.

Before a user has ENROLL_WINDOWS accepted windows, behaviour is scored against
the population baseline trained offline on the Capstone B dataset (damped, since
it only knows "typical human", not "this human"). After enrollment each user gets
a personal model with a per-user calibrated decision threshold:
  * supervised (tuned ExtraTrees + LR vote, genuine vs other enrolled users),
    threshold set at OPERATING_FAR on out-of-fold scores of unseen other users;
  * until enough other users exist: Isolation Forest + One-Class SVM on the
    user's own windows, threshold set at ONECLASS_FRR on out-of-fold scores.
The calibrated threshold maps to the HIGH tier (models.calibrated_genuineness).
"""
from __future__ import annotations

import io
import json
import threading
import time

import joblib
import numpy as np

from contauth.db import get_db, log_event
from contauth.features import MODEL_FEATURES, vectorize
from contauth.ml import models as M

MIN_OTHER_WINDOWS = 30
_lock = threading.Lock()
_population = None
_cache: dict[int, tuple[float, dict]] = {}


def population(path):
    global _population
    with _lock:
        if _population is None:
            _population = joblib.load(path)
    return _population


def _dump(obj) -> bytes:
    buf = io.BytesIO()
    joblib.dump(obj, buf)
    return buf.getvalue()


def _load(blob: bytes):
    return joblib.load(io.BytesIO(blob))


def enrollable_matrix(user_id, limit):
    rows = get_db().execute(
        "SELECT features FROM windows WHERE user_id=? AND enrollable=1 ORDER BY id DESC LIMIT ?", (user_id, limit)
    ).fetchall()
    return np.array([vectorize(json.loads(r["features"])) for r in rows], dtype=float)


def train_profile(user_id, cfg):
    X = enrollable_matrix(user_id, cfg["PROFILE_MAX_WINDOWS"])
    if len(X) < cfg["ENROLL_WINDOWS"]:
        return None
    iso = M.OneClassScorer(M.isolation_forest()).fit(X, cv=5)
    oc = M.OneClassScorer(M.one_class_svm()).fit(X, cv=5)
    oof_g = (iso.oof_ + oc.oof_) / 2
    prof = {"if": iso, "ocsvm": oc, "n": len(X),
            "tau_oneclass": float(np.quantile(oof_g, cfg["ONECLASS_FRR"])),
            "med_oneclass": float(np.median(oof_g)), "med_sup": None,
            "sup": None, "tau_sup": None, "est": {}}
    others = get_db().execute(
        "SELECT user_id, features FROM windows WHERE user_id<>? AND enrollable=1 ORDER BY id DESC LIMIT ?",
        (user_id, cfg["PROFILE_MAX_WINDOWS"] * 3),
    ).fetchall()
    if len(others) >= MIN_OTHER_WINDOWS:
        Xo = np.array([vectorize(json.loads(r["features"])) for r in others], dtype=float)
        Xa = np.vstack([X, Xo])
        y = np.r_[np.ones(len(X)), np.zeros(len(Xo))]
        groups = np.r_[["self"] * len(X), [str(r["user_id"]) for r in others]]
        oof = M.oof_by_group(M.tuned_supervised(), Xa, y, groups)
        ok = ~np.isnan(oof)
        if ok[y == 0].any() and ok[y == 1].any():
            tau = M.far_threshold(oof[ok & (y == 0)], cfg["OPERATING_FAR"])
            prof["tau_sup"] = tau
            prof["med_sup"] = float(np.median(oof[ok & (y == 1)]))
            prof["est"] = {"far": float((oof[ok & (y == 0)] >= tau).mean()),
                           "frr": float((oof[ok & (y == 1)] < tau).mean()),
                           "other_users": int(len(set(groups[y == 0])))}
            prof["sup"] = M.tuned_supervised().fit(Xa, y)
    now = time.time()
    db = get_db()
    db.execute(
        "INSERT INTO profiles (user_id, model, n_windows, trained_at) VALUES (?,?,?,?) "
        "ON CONFLICT(user_id) DO UPDATE SET model=excluded.model, n_windows=excluded.n_windows, trained_at=excluded.trained_at",
        (user_id, _dump(prof), len(X), now),
    )
    db.commit()
    _cache[user_id] = (now, prof)
    log_event("profile_trained", user_id=user_id, windows=len(X), supervised=prof["sup"] is not None,
              tau=round(prof["tau_sup"] if prof["sup"] is not None else prof["tau_oneclass"], 4),
              **{f"est_{k}": round(v, 3) if isinstance(v, float) else v for k, v in prof["est"].items()})
    return prof


def get_profile(user_id):
    row = get_db().execute("SELECT model, trained_at FROM profiles WHERE user_id=?", (user_id,)).fetchone()
    if row is None:
        _cache.pop(user_id, None)
        return None
    cached = _cache.get(user_id)
    if cached and cached[0] == row["trained_at"]:
        return cached[1]
    prof = _load(row["model"])
    _cache[user_id] = (row["trained_at"], prof)
    return prof


def genuineness(user_id, feats, cfg):
    """Returns (g in [0,1], model_name, damping). g ~0.5 typical, ~0 unlike anything seen."""
    x = np.array([vectorize(feats)], dtype=float)
    prof = get_profile(user_id)
    if prof is not None and "med_oneclass" not in prof:  # profile from an older version: rebuild
        prof = train_profile(user_id, cfg)
    if prof is None:
        pop = population(cfg["POPULATION_MODEL"])["scorer"]
        return float(pop.score(x)[0]), "population", cfg["COLD_START_DAMPING"]
    if prof.get("sup") is not None:
        p = float(prof["sup"].predict_proba(x)[0, 1])
        return M.calibrated_genuineness(p, prof["tau_sup"], prof.get("med_sup")), "personal-supervised", 1.0
    g = (float(prof["if"].score(x)[0]) + float(prof["ocsvm"].score(x)[0])) / 2
    return M.calibrated_genuineness(g, prof["tau_oneclass"], prof.get("med_oneclass")), "personal-oneclass", 1.0


def maybe_retrain(user_id, cfg):
    """Train at enrollment; afterwards refresh on a rolling window of the latest
    accepted windows every RETRAIN_EVERY new ones (handles behavioural drift)."""
    db = get_db()
    row = db.execute("SELECT trained_at FROM profiles WHERE user_id=?", (user_id,)).fetchone()
    since = row["trained_at"] if row else 0
    n_new = db.execute(
        "SELECT COUNT(*) FROM windows WHERE user_id=? AND enrollable=1 AND created_at>?", (user_id, since)
    ).fetchone()[0]
    if (row is None and n_new >= cfg["ENROLL_WINDOWS"]) or (row is not None and n_new >= cfg["RETRAIN_EVERY"]):
        return train_profile(user_id, cfg)
    return None


def reset_profile(user_id):
    db = get_db()
    db.execute("DELETE FROM profiles WHERE user_id=?", (user_id,))
    db.execute("UPDATE windows SET enrollable=0 WHERE user_id=?", (user_id,))
    db.commit()
    _cache.pop(user_id, None)
