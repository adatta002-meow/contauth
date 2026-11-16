# Model improvement: nested selection and threshold calibration

Dataset SHA-256 `e6b279c4ed027a65…`. 10 users, 5 outer splits, test impostors never seen in training. Every choice below was made on training data only; the outer test sets were scored once, after everything was frozen.

## Headline (outer test, mean ± std across users)

| | ROC-AUC | EER |
|---|---|---|
| Before: Random Forest, 14 features | 0.767 ± 0.137 | 28.1% |
| After: nested-selected model, 21 features | **0.800** ± 0.134 | **25.6%** |

## FAR / FRR operating points (per-user thresholds calibrated on training data)

| Target | Test FAR | Test FRR | Accuracy |
|---|---|---|---|
| FAR<=1% | 1.6% | 76.2% | 93.9% |
| FAR<=5% | 5.1% | 60.3% | 91.6% |
| FAR<=10% | 9.2% | 48.2% | 88.3% |
| FAR<=20% | 18.5% | 35.5% | 80.5% |
| EER point | 25.4% | 27.3% | 74.6% |
| fixed 0.5 | 19.2% | 34.4% | 80.2% |

FRR here is per **session**. The live system only steps up after two consecutive below-threshold windows, and a false reject costs a password re-entry, not a lockout. The live default is `OPERATING_FAR = 0.10`.

## Configuration chosen in each outer split (inner validation only)

| Split | Chosen |
|---|---|
| 0 | all21, ET leaf3 |
| 1 | all21, ET+LR vote |
| 2 | all21, RF (current) |
| 3 | all21, ET+LR vote |
| 4 | all21, ET leaf3 |

## Inner-validation AUC, averaged over splits (top 8 of 21)

| Configuration | Inner AUC |
|---|---|
| all21, ET+LR vote | 0.814 |
| all21, ET leaf3 | 0.808 |
| all21, RF (current) | 0.802 |
| all21, ET leaf5 mf0.5 | 0.802 |
| all21, LR C=1 | 0.798 |
| all21, LR C=0.1 | 0.797 |
| base14, ET+LR vote | 0.795 |
| base14, LR C=1 | 0.791 |

The 21-feature set was selected in every split. The model family varied (differences are small), so the live system uses the best average on inner validation: ExtraTrees + logistic regression soft vote.

## Per user (outer test ROC-AUC)

| User | Before | After |
|---|---|---|
| 53c064 | 0.989 | 0.991 |
| 7189e6 | 0.942 | 0.956 |
| 0720c3 | 0.771 | 0.863 |
| e88647 | 0.793 | 0.862 |
| 35258a | 0.829 | 0.845 |
| 2c7489 | 0.786 | 0.802 |
| 3433fe | 0.719 | 0.748 |
| 344ae7 | 0.728 | 0.735 |
| 50e2a5 | 0.625 | 0.702 |
| 31eed1 | 0.486 | 0.495 |

User `31eed1` stays near chance: with these features their sessions are indistinguishable from other users'. The model is honest about this rather than overfitting.
