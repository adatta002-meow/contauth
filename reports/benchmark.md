# User-verification benchmark

Generated 2026-11-11 05:47 UTC from `session_features.csv` (SHA-256 `e6b279c4ed027a65…`).

Protocol: one verifier per user (10 users with ≥20 sessions, figshare portion). 70% of the user's sessions train, the rest test. Other users are split in half: one half are training impostors, the other half are **unseen** test impostors. Averaged over 5 random splits, then over users (± is std across users).

| Model | Accuracy | FAR | FRR | EER | ROC-AUC |
|---|---|---|---|---|---|
| Logistic Regression | 70.3% ± 16.7 | 30.5% | 21.1% | 24.9% | 0.795 ± 0.139 |
| Random Forest | 83.0% ± 10.6 | 15.7% | 42.3% | 26.8% | 0.786 ± 0.135 |
| Isolation Forest | 31.9% ± 26.1 | 71.9% | 6.2% | 28.5% | 0.753 ± 0.117 |
| One-Class SVM | 81.0% ± 12.3 | 17.7% | 44.5% | 31.1% | 0.696 ± 0.081 |
| Hybrid (RF+IF+OCSVM) | 86.1% ± 9.1 | 12.1% | 45.6% | 25.2% | 0.802 ± 0.122 |
| Tuned ET+LR vote (live model) | 76.2% ± 14.6 | 23.8% | 27.7% | 25.3% | 0.807 ± 0.137 |

## Random Forest feature importance (mean over all runs)

| Feature | Importance |
|---|---|
| clicks_per_mouse_move | 0.067 |
| px_per_move | 0.065 |
| clicks_per_min | 0.063 |
| cv_mouse_speed | 0.063 |
| idle_gaps_per_min | 0.061 |
| avg_mouse_speed_px_s | 0.059 |
| std_mouse_speed_px_s | 0.056 |
| mouse_distance_per_min | 0.053 |
| typing_speed_keys_per_min | 0.051 |
| keys_per_mouse_move | 0.049 |
| scroll_rate_per_min | 0.049 |
| mouse_moves_per_min | 0.049 |
| events_per_min | 0.049 |
| avg_inter_click_interval_ms | 0.048 |
| idle_time_ratio | 0.042 |
| mean_idle_gap_ms | 0.042 |
| cv_inter_key | 0.042 |
| max_idle_gap_ratio | 0.037 |
| avg_inter_key_interval_ms | 0.029 |
| std_inter_key_interval_ms | 0.025 |
| modifier_key_ratio | 0.000 |

## Split sizes per user (one seed)

| User | Genuine train | Genuine test | Impostor train | Impostor test |
|---|---|---|---|---|
| 0720c3 | 14 | 6 | 356 | 283 |
| 2c7489 | 59 | 26 | 337 | 237 |
| 31eed1 | 57 | 24 | 199 | 379 |
| 3433fe | 48 | 21 | 161 | 429 |
| 344ae7 | 63 | 27 | 248 | 321 |
| 35258a | 30 | 13 | 426 | 190 |
| 50e2a5 | 31 | 13 | 426 | 189 |
| 53c064 | 82 | 35 | 188 | 354 |
| 7189e6 | 24 | 10 | 308 | 317 |
| e88647 | 33 | 14 | 350 | 262 |

Notes
- Accuracy is balanced by neither class; impostor sessions outnumber genuine ones, so read it together with FAR/FRR/EER.
- These numbers come from this pipeline only. They are not the figures quoted in earlier slides or the report.
- Session-level features; the live system scores 30-second windows, which are noisier.
- All models here use the 21-feature live set. The nested comparison against the original 14-feature model, and the FAR/FRR operating points, are in `tuning.md`.
- Rows use a fixed 0.5 threshold; the live system calibrates a per-user threshold instead (see `tuning.md`).
