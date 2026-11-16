"""Training pipeline: offline user-verification benchmark + population baseline.

Usage:  python -m contauth.ml.train [--data data/session_features.csv]

Outputs
  models/population.joblib  - human-behaviour baseline used for cold-start scoring
  reports/benchmark.json    - all metrics, per user and averaged
  reports/benchmark.md      - human-readable results table
"""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score, roc_curve

from contauth.features import MODEL_FEATURES, add_derived_features
from contauth.ml import models as M

ROOT = Path(__file__).resolve().parents[2]
MIN_SESSIONS_PER_USER = 20
GENUINE_TRAIN_FRAC = 0.7
SEEDS = [0, 1, 2, 3, 4]
ONE_CLASS_ACCEPT = 0.05  # accept if at or above the 5th percentile of genuine training scores


def load_dataset(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    add_derived_features(df)
    # Subject identity is only recoverable for the figshare portion: ux_<user>_s<n>
    df["user"] = df["session_id"].str.extract(r"^ux_([0-9a-f]+)_s\d+$")[0]
    return df


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rates(y_true, accept):
    """y_true: 1 genuine, 0 impostor. accept: bool predictions."""
    y_true, accept = np.asarray(y_true), np.asarray(accept, bool)
    imp, gen = y_true == 0, y_true == 1
    far = accept[imp].mean() if imp.any() else np.nan
    frr = (~accept[gen]).mean() if gen.any() else np.nan
    acc = (accept == gen).mean()
    return acc, far, frr


def eer(y_true, score):
    fpr, tpr, _ = roc_curve(y_true, score)
    fnr = 1 - tpr
    i = np.nanargmin(np.abs(fnr - fpr))
    return float((fpr[i] + fnr[i]) / 2)


def evaluate_user(df, user, seed):
    """Leave-impostors-out protocol: test impostors are users never seen in training."""
    rng = np.random.default_rng(seed)
    X_all = df[MODEL_FEATURES].to_numpy(float)
    is_u = (df["user"] == user).to_numpy()

    gen_idx = rng.permutation(np.flatnonzero(is_u))
    n_tr = int(round(len(gen_idx) * GENUINE_TRAIN_FRAC))
    gen_tr, gen_te = gen_idx[:n_tr], gen_idx[n_tr:]

    others = df.loc[~is_u & df["user"].notna(), "user"].unique()
    others = rng.permutation(others)
    half = len(others) // 2
    imp_train_users, imp_test_users = set(others[:half]), set(others[half:])
    imp_tr = np.flatnonzero(df["user"].isin(imp_train_users).to_numpy())
    imp_te = np.flatnonzero(df["user"].isin(imp_test_users).to_numpy())

    X_tr = X_all[np.r_[gen_tr, imp_tr]]
    y_tr = np.r_[np.ones(len(gen_tr)), np.zeros(len(imp_tr))]
    X_te = X_all[np.r_[gen_te, imp_te]]
    y_te = np.r_[np.ones(len(gen_te)), np.zeros(len(imp_te))]

    scores = {}
    lr = M.logistic_regression(seed).fit(X_tr, y_tr)
    scores["Logistic Regression"] = (lr.predict_proba(X_te)[:, 1], 0.5)
    rf = M.random_forest(seed).fit(X_tr, y_tr)
    rf_p = rf.predict_proba(X_te)[:, 1]
    scores["Random Forest"] = (rf_p, 0.5)
    iso = M.OneClassScorer(M.isolation_forest(seed)).fit(X_all[gen_tr])
    if_s = iso.score(X_te)
    scores["Isolation Forest"] = (if_s, ONE_CLASS_ACCEPT)
    oc = M.OneClassScorer(M.one_class_svm()).fit(X_all[gen_tr])
    oc_s = oc.score(X_te)
    scores["One-Class SVM"] = (oc_s, ONE_CLASS_ACCEPT)
    scores["Hybrid (RF+IF+OCSVM)"] = (M.hybrid_score(rf_p, if_s, oc_s), 0.5)
    tuned = M.tuned_supervised(seed).fit(X_tr, y_tr)
    scores["Tuned ET+LR vote (live model)"] = (tuned.predict_proba(X_te)[:, 1], 0.5)

    out = {}
    for name, (s, thr) in scores.items():
        acc, far, frr = rates(y_te, s >= thr)
        out[name] = {"accuracy": acc, "far": far, "frr": frr, "eer": eer(y_te, s), "roc_auc": roc_auc_score(y_te, s)}
    importances = rf.named_steps["clf"].feature_importances_
    return out, importances, {"genuine_train": len(gen_tr), "genuine_test": len(gen_te), "impostor_train": len(imp_tr), "impostor_test": len(imp_te)}


def run_benchmark(df):
    counts = df["user"].value_counts()
    users = sorted(counts[counts >= MIN_SESSIONS_PER_USER].index)
    per_user, imps, sizes = {}, [], {}
    for u in users:
        runs = []
        for seed in SEEDS:
            r, imp, sz = evaluate_user(df, u, seed)
            runs.append(r)
            imps.append(imp)
            sizes[u] = sz
        per_user[u] = {m: {k: float(np.mean([run[m][k] for run in runs])) for k in runs[0][m]} for m in runs[0]}
    model_names = list(next(iter(per_user.values())).keys())
    summary = {}
    for m in model_names:
        summary[m] = {}
        for k in ["accuracy", "far", "frr", "eer", "roc_auc"]:
            vals = [per_user[u][m][k] for u in users]
            summary[m][k] = float(np.mean(vals))
            summary[m][k + "_std"] = float(np.std(vals))
    fi = pd.Series(np.mean(imps, axis=0), index=MODEL_FEATURES).sort_values(ascending=False)
    return users, per_user, summary, fi, sizes


def train_population(df, seed=0):
    """Isolation Forest over all 705 real sessions: a 'normal human behaviour' baseline.
    Used only for cold start, before a user has an enrolled profile."""
    X = df[MODEL_FEATURES].to_numpy(float)
    return M.OneClassScorer(M.isolation_forest(seed)).fit(X)


def write_markdown(path, meta, users, summary, fi, sizes):
    lines = [
        "# User-verification benchmark",
        "",
        f"Generated {meta['generated_utc']} from `{meta['dataset_file']}` (SHA-256 `{meta['dataset_sha256'][:16]}…`).",
        "",
        f"Protocol: one verifier per user ({len(users)} users with ≥{MIN_SESSIONS_PER_USER} sessions, figshare portion). "
        f"{int(GENUINE_TRAIN_FRAC*100)}% of the user's sessions train, the rest test. Other users are split in half: "
        "one half are training impostors, the other half are **unseen** test impostors. "
        f"Averaged over {len(SEEDS)} random splits, then over users (± is std across users).",
        "",
        "| Model | Accuracy | FAR | FRR | EER | ROC-AUC |",
        "|---|---|---|---|---|---|",
    ]
    for m, s in summary.items():
        lines.append(
            f"| {m} | {s['accuracy']*100:.1f}% ± {s['accuracy_std']*100:.1f} | {s['far']*100:.1f}% | {s['frr']*100:.1f}% | "
            f"{s['eer']*100:.1f}% | {s['roc_auc']:.3f} ± {s['roc_auc_std']:.3f} |"
        )
    lines += ["", "## Random Forest feature importance (mean over all runs)", "", "| Feature | Importance |", "|---|---|"]
    lines += [f"| {k} | {v:.3f} |" for k, v in fi.items()]
    lines += ["", "## Split sizes per user (one seed)", "", "| User | Genuine train | Genuine test | Impostor train | Impostor test |", "|---|---|---|---|---|"]
    lines += [f"| {u} | {s['genuine_train']} | {s['genuine_test']} | {s['impostor_train']} | {s['impostor_test']} |" for u, s in sizes.items()]
    lines += [
        "",
        "Notes",
        "- Accuracy is balanced by neither class; impostor sessions outnumber genuine ones, so read it together with FAR/FRR/EER.",
        "- These numbers come from this pipeline only. They are not the figures quoted in earlier slides or the report.",
        "- Session-level features; the live system scores 30-second windows, which are noisier.",
        f"- All models here use the {len(MODEL_FEATURES)}-feature live set. The nested comparison against the original 14-feature model, "
        "and the FAR/FRR operating points, are in `tuning.md`.",
        "- Rows use a fixed 0.5 threshold; the live system calibrates a per-user threshold instead (see `tuning.md`).",
    ]
    Path(path).write_text("\n".join(lines) + "\n")


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=str(ROOT / "data" / "session_features.csv"))
    ap.add_argument("--models", default=str(ROOT / "models"))
    ap.add_argument("--reports", default=str(ROOT / "reports"))
    a = ap.parse_args(argv)
    data, mdir, rdir = Path(a.data), Path(a.models), Path(a.reports)
    mdir.mkdir(exist_ok=True, parents=True)
    rdir.mkdir(exist_ok=True, parents=True)

    df = load_dataset(data)
    meta = {
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "dataset_file": data.name,
        "dataset_sha256": sha256(data),
        "rows": int(len(df)),
        "variants": df["dataset_variant"].value_counts().to_dict(),
        "features": MODEL_FEATURES,
    }
    print(f"Loaded {len(df)} sessions: {meta['variants']}")

    users, per_user, summary, fi, sizes = run_benchmark(df)
    for m, s in summary.items():
        print(f"{m:24s} acc {s['accuracy']:.3f}  FAR {s['far']:.3f}  FRR {s['frr']:.3f}  EER {s['eer']:.3f}  AUC {s['roc_auc']:.3f}")

    pop = train_population(df)
    joblib.dump({"scorer": pop, "features": MODEL_FEATURES, "meta": meta}, mdir / "population.joblib")

    (rdir / "benchmark.json").write_text(json.dumps(
        {"meta": meta, "users": users, "summary": summary, "per_user": per_user, "feature_importance": fi.to_dict()}, indent=2))
    write_markdown(rdir / "benchmark.md", meta, users, summary, fi, sizes)
    print(f"Saved {mdir/'population.joblib'} and reports in {rdir}")


if __name__ == "__main__":
    main()
