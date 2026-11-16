"""Nested model selection + FAR/FRR threshold calibration on the Capstone B dataset.

Usage:  python -m contauth.ml.tune

Leakage rules (the point of this script):
  * OUTER split per (user, seed) is identical to train.py: 70% of the user's
    sessions + half of the other users train; the remaining sessions + the
    other half of users (never seen) test.
  * Every choice is made on the OUTER TRAINING part only:
      - model/feature configuration: chosen by mean AUC on an INNER validation
        split (held-out genuine sessions + held-out impostor *users*), averaged
        over all users for that seed (one global choice per seed);
      - feature selection (top-k) happens inside the pipeline, fit on fit-data only;
      - decision thresholds: from out-of-fold scores on the outer training part,
        with impostors grouped by user so OOF impostors are unseen users.
  * The outer test set is scored once, with everything already frozen.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import numpy as np
from sklearn.base import clone
from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.feature_selection import SelectFromModel
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from sklearn.pipeline import Pipeline

from contauth.features import ALL_FEATURES, BASE_FEATURES
from contauth.ml import models as M
from contauth.ml.train import GENUINE_TRAIN_FRAC, MIN_SESSIONS_PER_USER, ROOT, SEEDS, eer, load_dataset, rates, sha256

FAR_TARGETS = [0.01, 0.05, 0.10, 0.20]


# candidate grid
SoftVote = M.SoftVote


def _clf(name, seed):
    return {
        "LR C=0.1": LogisticRegression(C=0.1, max_iter=3000, class_weight="balanced"),
        "LR C=1": LogisticRegression(C=1.0, max_iter=3000, class_weight="balanced"),
        "RF (current)": RandomForestClassifier(300, min_samples_leaf=2, class_weight="balanced", random_state=seed, n_jobs=-1),
        "ET leaf3": ExtraTreesClassifier(250, min_samples_leaf=3, class_weight="balanced", random_state=seed, n_jobs=-1),
        "ET leaf5 mf0.5": ExtraTreesClassifier(250, min_samples_leaf=5, max_features=0.5, class_weight="balanced", random_state=seed, n_jobs=-1),
        "HGB d3": HistGradientBoostingClassifier(max_depth=3, learning_rate=0.05, max_iter=200, class_weight="balanced", random_state=seed),
    }[name]


def make(feature_set, model, seed):
    cols = BASE_FEATURES if feature_set == "base14" else ALL_FEATURES
    steps = [("prep", M.preprocessor())]
    if feature_set == "all21 top12":
        steps.append(("select", SelectFromModel(
            ExtraTreesClassifier(150, min_samples_leaf=3, class_weight="balanced", random_state=seed, n_jobs=-1),
            max_features=12, threshold=-np.inf)))
    if model == "ET+LR vote":
        est = SoftVote([Pipeline(steps + [("clf", _clf("ET leaf3", seed))]), Pipeline(steps + [("clf", _clf("LR C=0.1", seed))])])
    else:
        est = Pipeline(steps + [("clf", _clf(model, seed))])
    return cols, est


FEATURE_SETS = ["base14", "all21", "all21 top12"]
MODELS = ["LR C=0.1", "LR C=1", "RF (current)", "ET leaf3", "ET leaf5 mf0.5", "HGB d3", "ET+LR vote"]
CONFIGS = [(f, m) for f in FEATURE_SETS for m in MODELS]


# splits
def outer_split(df, user, seed):
    """Byte-identical to train.evaluate_user's split, so results are comparable."""
    rng = np.random.default_rng(seed)
    is_u = (df["user"] == user).to_numpy()
    gen = rng.permutation(np.flatnonzero(is_u))
    n = int(round(len(gen) * GENUINE_TRAIN_FRAC))
    others = rng.permutation(df.loc[~is_u & df["user"].notna(), "user"].unique())
    h = len(others) // 2
    return gen[:n], gen[n:], list(others[:h]), list(others[h:])


def inner_split(df, gen_tr, imp_users, seed):
    rng = np.random.default_rng(1000 + seed)
    g = rng.permutation(gen_tr)
    k = int(round(len(g) * 0.75))
    u = list(rng.permutation(imp_users))
    h = max(1, len(u) // 2)
    fit_imp = np.flatnonzero(df["user"].isin(u[:h]).to_numpy())
    val_imp = np.flatnonzero(df["user"].isin(u[h:]).to_numpy())
    return g[:k], g[k:], fit_imp, val_imp


def oof_scores(df, X, est, gen_tr, imp_tr):
    """Out-of-fold scores on the outer training part; impostor folds grouped by user."""
    idx = np.r_[gen_tr, imp_tr]
    y = np.r_[np.ones(len(gen_tr)), np.zeros(len(imp_tr))]
    # Explicit folds: genuine sessions spread over all folds; each impostor user
    # sits wholly in one fold (round-robin), so OOF impostors are unseen users and
    # every training fold contains both classes.
    imp_users = list(dict.fromkeys(df["user"].to_numpy()[imp_tr]))
    k = min(5, len(imp_users))
    ufold = {u: i % k for i, u in enumerate(imp_users)}
    fold = np.r_[np.arange(len(gen_tr)) % k, [ufold[u] for u in df["user"].to_numpy()[imp_tr]]]
    s = np.empty(len(idx))
    for f in range(k):
        tr, te = fold != f, fold == f
        s[te] = clone(est).fit(X[idx[tr]], y[tr]).predict_proba(X[idx[te]])[:, 1]
    return s, y


def thresholds_from(scores, y):
    imp, gen = np.sort(scores[y == 0]), scores[y == 1]
    out = {}
    for t in FAR_TARGETS:
        # smallest threshold whose OOF FAR <= target
        k = int(np.ceil((1 - t) * len(imp))) - 1
        out[f"FAR<={int(t*100)}%"] = float(imp[min(max(k, 0), len(imp) - 1)]) + 1e-9
    cand = np.unique(scores)
    far = np.array([(imp >= c).mean() for c in cand])
    frr = np.array([(gen < c).mean() for c in cand])
    out["EER point"] = float(cand[np.argmin(np.abs(far - frr))])
    return out


def main():
    data = ROOT / "data" / "session_features.csv"
    df = load_dataset(data)
    counts = df["user"].value_counts()
    users = sorted(counts[counts >= MIN_SESSIONS_PER_USER].index)
    Xs = {fs: df[BASE_FEATURES if fs == "base14" else ALL_FEATURES].to_numpy(float) for fs in FEATURE_SETS}
    t_start = time.time()

    chosen, inner_table, results = {}, {}, []
    for seed in SEEDS:
        # 1) inner selection: one global configuration per seed
        inner = {c: [] for c in CONFIGS}
        splits = {u: outer_split(df, u, seed) for u in users}
        for u in users:
            gen_tr, _, imp_tr_users, _ = splits[u]
            g_fit, g_val, i_fit, i_val = inner_split(df, gen_tr, imp_tr_users, seed)
            y_fit = np.r_[np.ones(len(g_fit)), np.zeros(len(i_fit))]
            y_val = np.r_[np.ones(len(g_val)), np.zeros(len(i_val))]
            for c in CONFIGS:
                _, est = make(*c, seed)
                X = Xs[c[0]]
                est.fit(X[np.r_[g_fit, i_fit]], y_fit)
                inner[c].append(roc_auc_score(y_val, est.predict_proba(X[np.r_[g_val, i_val]])[:, 1]))
        means = {c: float(np.mean(v)) for c, v in inner.items()}
        best = max(means, key=means.get)
        chosen[seed] = best
        inner_table[seed] = {f"{c[0]} | {c[1]}": v for c, v in means.items()}
        print(f"seed {seed}: chose {best} (inner AUC {means[best]:.3f})  [{time.time()-t_start:.0f}s]", flush=True)

        # 2) per user: calibrate thresholds on OOF scores, refit, score outer test once
        for u in users:
            gen_tr, gen_te, imp_tr_users, imp_te_users = splits[u]
            imp_tr = np.flatnonzero(df["user"].isin(imp_tr_users).to_numpy())
            imp_te = np.flatnonzero(df["user"].isin(imp_te_users).to_numpy())
            X = Xs[best[0]]
            _, est = make(*best, seed)
            oof, y_oof = oof_scores(df, X, est, gen_tr, imp_tr)
            thr = thresholds_from(oof, y_oof)
            final = clone(est).fit(X[np.r_[gen_tr, imp_tr]], np.r_[np.ones(len(gen_tr)), np.zeros(len(imp_tr))])
            y_te = np.r_[np.ones(len(gen_te)), np.zeros(len(imp_te))]
            s_te = final.predict_proba(X[np.r_[gen_te, imp_te]])[:, 1]
            # baseline on the same outer split: the currently shipped RF
            _, base = make("base14", "RF (current)", seed)
            Xb = Xs["base14"]
            base.fit(Xb[np.r_[gen_tr, imp_tr]], np.r_[np.ones(len(gen_tr)), np.zeros(len(imp_tr))])
            s_b = base.predict_proba(Xb[np.r_[gen_te, imp_te]])[:, 1]
            row = {"user": u, "seed": seed, "config": " | ".join(best),
                   "auc": roc_auc_score(y_te, s_te), "eer": eer(y_te, s_te),
                   "baseline_auc": roc_auc_score(y_te, s_b), "baseline_eer": eer(y_te, s_b), "points": {}}
            for name, t in thr.items():
                acc, far, frr = rates(y_te, s_te >= t)
                row["points"][name] = {"threshold": t, "far": far, "frr": frr, "accuracy": acc}
            acc, far, frr = rates(y_te, s_te >= 0.5)
            row["points"]["fixed 0.5"] = {"threshold": 0.5, "far": far, "frr": frr, "accuracy": acc}
            results.append(row)
        print(f"  seed {seed} scored  [{time.time()-t_start:.0f}s]", flush=True)

    # aggregate: mean over seeds per user, then mean over users
    def agg(key_fn):
        per_user = [np.mean([key_fn(r) for r in results if r["user"] == u]) for u in users]
        return float(np.mean(per_user)), float(np.std(per_user))

    summary = {
        "auc": agg(lambda r: r["auc"]), "eer": agg(lambda r: r["eer"]),
        "baseline_auc": agg(lambda r: r["baseline_auc"]), "baseline_eer": agg(lambda r: r["baseline_eer"]),
        "points": {p: {k: agg(lambda r, p=p, k=k: r["points"][p][k]) for k in ("far", "frr", "accuracy")}
                   for p in results[0]["points"]},
    }
    per_user = {u: {"auc": float(np.mean([r["auc"] for r in results if r["user"] == u])),
                    "baseline_auc": float(np.mean([r["baseline_auc"] for r in results if r["user"] == u]))} for u in users}

    out = {"dataset_sha256": sha256(data), "seeds": SEEDS, "users": users, "configs_searched": [" | ".join(c) for c in CONFIGS],
           "chosen_per_seed": {s: " | ".join(c) for s, c in chosen.items()}, "inner_auc": inner_table,
           "summary": summary, "per_user": per_user}
    (ROOT / "reports").mkdir(exist_ok=True)
    (ROOT / "reports" / "tuning.json").write_text(json.dumps(out, indent=2))
    print(json.dumps({"chosen": out["chosen_per_seed"], "auc": summary["auc"], "baseline_auc": summary["baseline_auc"],
                      "eer": summary["eer"], "baseline_eer": summary["baseline_eer"]}, indent=1))
    for p, v in summary["points"].items():
        print(f"{p:12s} FAR {v['far'][0]:.3f}  FRR {v['frr'][0]:.3f}  acc {v['accuracy'][0]:.3f}")
    print(f"done in {time.time()-t_start:.0f}s")
    write_report()


def write_report(path_json=None, path_md=None):
    """Render reports/tuning.md from reports/tuning.json (no recomputation)."""
    pj = Path(path_json or ROOT / "reports" / "tuning.json")
    pm = Path(path_md or ROOT / "reports" / "tuning.md")
    t = json.loads(pj.read_text())
    s = t["summary"]
    seeds = list(t["inner_auc"])
    avg = {c: float(np.mean([t["inner_auc"][k][c] for k in seeds])) for c in t["configs_searched"]}
    L = [
        "# Model improvement: nested selection and threshold calibration",
        "",
        f"Dataset SHA-256 `{t['dataset_sha256'][:16]}…`. {len(t['users'])} users, {len(seeds)} outer splits, "
        "test impostors never seen in training. Every choice below was made on training data only; "
        "the outer test sets were scored once, after everything was frozen.",
        "",
        "## Headline (outer test, mean ± std across users)",
        "",
        "| | ROC-AUC | EER |",
        "|---|---|---|",
        f"| Before: Random Forest, 14 features | {s['baseline_auc'][0]:.3f} ± {s['baseline_auc'][1]:.3f} | {s['baseline_eer'][0]*100:.1f}% |",
        f"| After: nested-selected model, 21 features | **{s['auc'][0]:.3f}** ± {s['auc'][1]:.3f} | **{s['eer'][0]*100:.1f}%** |",
        "",
        "## FAR / FRR operating points (per-user thresholds calibrated on training data)",
        "",
        "| Target | Test FAR | Test FRR | Accuracy |",
        "|---|---|---|---|",
    ]
    for name, v in s["points"].items():
        L.append(f"| {name} | {v['far'][0]*100:.1f}% | {v['frr'][0]*100:.1f}% | {v['accuracy'][0]*100:.1f}% |")
    L += [
        "",
        "FRR here is per **session**. The live system only steps up after two consecutive below-threshold windows, "
        "and a false reject costs a password re-entry, not a lockout. The live default is `OPERATING_FAR = 0.10`.",
        "",
        "## Configuration chosen in each outer split (inner validation only)",
        "",
        "| Split | Chosen |",
        "|---|---|",
    ] + [f"| {k} | {v.replace(' | ', ', ')} |" for k, v in t["chosen_per_seed"].items()] + [
        "",
        "## Inner-validation AUC, averaged over splits (top 8 of 21)",
        "",
        "| Configuration | Inner AUC |",
        "|---|---|",
    ] + [f"| {c.replace(' | ', ', ')} | {v:.3f} |" for c, v in sorted(avg.items(), key=lambda x: -x[1])[:8]] + [
        "",
        "The 21-feature set was selected in every split. The model family varied (differences are small), "
        "so the live system uses the best average on inner validation: ExtraTrees + logistic regression soft vote.",
        "",
        "## Per user (outer test ROC-AUC)",
        "",
        "| User | Before | After |",
        "|---|---|---|",
    ] + [f"| {u} | {v['baseline_auc']:.3f} | {v['auc']:.3f} |" for u, v in sorted(t["per_user"].items(), key=lambda x: -x[1]["auc"])] + [
        "",
        "User `31eed1` stays near chance: with these features their sessions are indistinguishable from other users'. "
        "The model is honest about this rather than overfitting.",
    ]
    pm.write_text("\n".join(L) + "\n")
    return pm


if __name__ == "__main__":
    import sys
    write_report() if "--report-only" in sys.argv else main()
