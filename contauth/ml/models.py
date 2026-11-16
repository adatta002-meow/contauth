"""Model building blocks shared by offline training and the live system."""
from __future__ import annotations

import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline, make_pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler
from sklearn.svm import OneClassSVM


def _log1p_nonneg(x):
    return np.log1p(np.clip(x, 0, None))


def preprocessor() -> Pipeline:
    """Median imputation -> log1p (features are heavy-tailed, non-negative) -> z-score."""
    return make_pipeline(
        SimpleImputer(strategy="median", keep_empty_features=True),
        FunctionTransformer(_log1p_nonneg),
        StandardScaler(),
    )


def logistic_regression(seed=0):
    return Pipeline([("prep", preprocessor()), ("clf", LogisticRegression(max_iter=2000, class_weight="balanced", random_state=seed))])


def random_forest(seed=0):
    return Pipeline([("prep", preprocessor()), ("clf", RandomForestClassifier(n_estimators=300, min_samples_leaf=2, class_weight="balanced", random_state=seed, n_jobs=-1))])


class SoftVote:
    """Average of predicted probabilities from several pipelines."""

    def __init__(self, members):
        self.members = members

    def fit(self, X, y):
        from sklearn.base import clone
        self.fitted_ = [clone(m).fit(X, y) for m in self.members]
        return self

    def predict_proba(self, X):
        return np.mean([m.predict_proba(X) for m in self.fitted_], axis=0)

    def get_params(self, deep=False):
        return {"members": self.members}

    def set_params(self, **p):
        self.__dict__.update(p)
        return self


def tuned_supervised(seed=0):
    """Winner of the nested search (reports/tuning.md): ExtraTrees + L2 logistic
    regression, soft vote, on the 21-feature set."""
    from sklearn.ensemble import ExtraTreesClassifier
    et = Pipeline([("prep", preprocessor()), ("clf", ExtraTreesClassifier(250, min_samples_leaf=3, class_weight="balanced", random_state=seed, n_jobs=-1))])
    lr = Pipeline([("prep", preprocessor()), ("clf", LogisticRegression(C=0.1, max_iter=3000, class_weight="balanced"))])
    return SoftVote([et, lr])


def isolation_forest(seed=0):
    return Pipeline([("prep", preprocessor()), ("clf", IsolationForest(n_estimators=300, contamination="auto", random_state=seed))])


def one_class_svm():
    return Pipeline([("prep", preprocessor()), ("clf", OneClassSVM(kernel="rbf", gamma="scale", nu=0.1))])


class GenuineCDF:
    """Turns a one-class decision score into P(score <= s | genuine), estimated on
    the genuine training scores. 0 = far less normal than anything seen in
    training, 0.5 = typical. Makes one-class scores comparable to probabilities."""

    def __init__(self, scores):
        self.ref = np.sort(np.asarray(scores, dtype=float))

    def __call__(self, s):
        s = np.atleast_1d(np.asarray(s, dtype=float))
        return np.searchsorted(self.ref, s, side="right") / max(len(self.ref), 1)


class OneClassScorer:
    """Fit on one class only; score() returns a [0,1] genuineness value."""

    def __init__(self, pipe):
        self.pipe = pipe
        self.cdf = None

    def fit(self, X, cv: int = 0):
        """cv > 1: calibrate the CDF on out-of-fold scores. With small enrollment
        sets, in-sample scores are optimistic and would inflate false rejects."""
        X = np.asarray(X, dtype=float)
        cv = min(cv, len(X) // 2) if cv else 0
        if cv >= 2:
            from sklearn.base import clone
            from sklearn.model_selection import KFold
            oof = np.empty(len(X))
            for tr, te in KFold(cv, shuffle=True, random_state=0).split(X):
                oof[te] = clone(self.pipe).fit(X[tr]).decision_function(X[te])
            self.pipe.fit(X)
            self.cdf = GenuineCDF(oof)
            self.oof_ = self.cdf(oof)  # held-out genuineness of the user's own windows
        else:
            self.pipe.fit(X)
            self.cdf = GenuineCDF(self.pipe.decision_function(X))
            self.oof_ = self.cdf(self.pipe.decision_function(X))  # in-sample: optimistic, only for tiny sets
        return self

    def score(self, X):
        return self.cdf(self.pipe.decision_function(X))


def far_threshold(impostor_scores, target_far):
    """Smallest threshold whose empirical FAR on these impostor scores is <= target."""
    imp = np.sort(np.asarray(impostor_scores, dtype=float))
    k = int(np.ceil((1 - target_far) * len(imp))) - 1
    return float(imp[min(max(k, 0), len(imp) - 1)]) + 1e-9


def oof_by_group(est, X, y, groups, k=5):
    """Out-of-fold probabilities. Positives spread over all folds; each negative
    group (impostor user) sits wholly in one fold, so OOF negatives are unseen people.
    Falls back to per-row folds when there are fewer than 2 negative groups."""
    from sklearn.base import clone
    X, y, groups = np.asarray(X, float), np.asarray(y), np.asarray(groups)
    neg_groups = list(dict.fromkeys(groups[y == 0]))
    k = max(2, min(k, len(neg_groups))) if len(neg_groups) >= 2 else 5
    gfold = {g: i % k for i, g in enumerate(neg_groups)}
    fold = np.empty(len(y), dtype=int)
    n_pos = n_neg = 0
    for i in range(len(y)):
        if y[i] == 1:
            fold[i] = n_pos % k
            n_pos += 1
        else:
            fold[i] = gfold[groups[i]] if len(neg_groups) >= 2 else n_neg % k
            n_neg += 1
    s = np.empty(len(y))
    for f in range(k):
        tr, te = fold != f, fold == f
        if te.any() and len(np.unique(y[tr])) == 2:
            s[te] = clone(est).fit(X[tr], y[tr]).predict_proba(X[te])[:, 1]
        else:
            s[te] = np.nan
    return s


TAU_ANCHOR = 0.13     # threshold -> behaviour risk 87 -> total ~61: HIGH tier
MEDIAN_ANCHOR = 0.65  # the user's typical score -> behaviour risk 35 -> total ~25: LOW tier


def calibrated_genuineness(score, tau, median=None):
    """Piecewise-linear map with two per-user anchors fitted on held-out enrollment data:
      decision threshold tau      -> 0.13 (lands exactly on the HIGH tier)
      user's median genuine score -> 0.65 (a typical window is LOW risk)
    So: score < tau => HIGH (step-up once it persists); typical behaviour => LOW.
    The FAR/FRR operating point therefore directly controls when step-ups happen."""
    s = float(np.clip(score, 0.0, 1.0))
    tau = float(np.clip(tau, 1e-6, 1 - 2e-6))
    if s < tau:
        return TAU_ANCHOR * s / tau
    m = median if (median is not None and tau < median < 1) else (tau + 1) / 2
    if s < m:
        return TAU_ANCHOR + (MEDIAN_ANCHOR - TAU_ANCHOR) * (s - tau) / (m - tau)
    return MEDIAN_ANCHOR + (1 - MEDIAN_ANCHOR) * (s - m) / (1 - m)


HYBRID_WEIGHTS = {"rf": 0.6, "if": 0.2, "ocsvm": 0.2}


def hybrid_score(rf_prob, if_score, ocsvm_score):
    w = HYBRID_WEIGHTS
    return w["rf"] * np.asarray(rf_prob) + w["if"] * np.asarray(if_score) + w["ocsvm"] * np.asarray(ocsvm_score)
