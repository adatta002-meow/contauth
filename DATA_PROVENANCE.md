# Data provenance

## Training data

| Item | Value |
|---|---|
| File | `data/session_features.csv` |
| Origin | Google Drive file "session_features Main Dataset.csv" (Capstone B shared drive, last modified 2026-08-03) |
| Integrity | SHA-256 recorded in `reports/benchmark.json` at every training run |
| Rows | 705 sessions, 27 columns, one row per session (aggregate features, no raw events) |
| Labels | None in the file. Labels are derived, see below |

Composition by `dataset_variant`:

| Variant | Sessions | Subject identity | Used for |
|---|---|---|---|
| `ux_figshare` | 659 | Yes: `ux_<6-hex user id>_s<n>`, 18 users (12 with ≥16 sessions, 6 with 1) | Benchmark + population baseline |
| `v1` | 36 | Not recorded | Population baseline only |
| `v0` | 10 | Not recorded | Population baseline only |

**Original source of the `ux_figshare` portion: not confirmed.** The variant name says it came from figshare, but no DOI, citation or license is stored with the file. A possible match, *not verified*, is "A dataset of interactions and emotions for website user experience evaluation" (PMC article PMC12624104). Confirm against your Capstone B notebook or report bibliography and record the DOI and license here before publication.

**`v0` / `v1`: origin not documented in the file.** They look like a separate in-house collection (sessions of 9–33 min, versus minutes to hours for figshare). Record who collected them and under what consent.

## How labels are derived

User verification, one model per user: a user's own sessions are *genuine*; every other user's sessions are *impostor*. Only users with ≥20 sessions get a verifier (10 users). No rows are synthesised, resampled or altered.

## Known dataset caveat

A Random Forest separates `ux_figshare` from `v0`/`v1` with 100% accuracy, because the two sources were recorded under different conditions. Any experiment whose labels correlate with the source will report inflated accuracy. The benchmark here avoids this by building every comparison inside the figshare portion.

## Data the live system collects

The browser sends event **timings and coordinates only**: never which key was pressed, never typed text, never form values. Key events carry one boolean, "is a modifier key". Stored in `instance/contauth.db` (SQLite).
