# CMU Keystroke Dynamics Benchmark — data provenance

**File:** `DSL-StrongPasswordData.csv` (saved here as `DSL.csv`)
**Source (canonical):** https://www.cs.cmu.edu/~keystroke/
**Direct URL used:** https://www.cs.cmu.edu/~keystroke/DSL-StrongPasswordData.csv
**Downloaded:** 2026-11-23
**SHA-256:** `b11d23538b1865fa6ecf4e8b78567caa312e9c1027604bb022fcc6ad7eaa7a33`

**Citation (required by the authors):**
Kevin S. Killourhy and Roy A. Maxion. "Comparing Anomaly-Detection Algorithms for
Keystroke Dynamics." In *Proc. 39th Annual International Conference on Dependable
Systems and Networks (DSN-2009)*, pp. 125–134, 2009. IEEE.

**Contents:** 51 subjects, each typing the password `.tie5Roanl` 400 times (8 sessions
× 50 repetitions). 20,400 rows. 31 raw timing features per repetition:
- `H.<key>` — hold time (dwell) of each key (11 keys incl. Return)
- `DD.<k1>.<k2>` — key-down to key-down latency of each adjacent key pair (digraph, 10)
- `UD.<k1>.<k2>` — key-up to key-down latency of each pair (flight time, 10)

**Why it's here:** the Capstone dataset is session-level with no raw per-keystroke
events, so the keystroke-dynamics work (dwell/flight, digraphs, rhythm) could not be
benchmarked on it. This dataset has raw key timings and is the standard reference
benchmark, so it lets us report real FAR/FRR/EER/AUC and reproduce published results.
It is a single-condition, clean collection (no acquisition leak).

**License/usage:** published by the authors for public research use with the citation
above. Not redistributed for commercial use.
