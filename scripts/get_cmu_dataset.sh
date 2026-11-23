#!/usr/bin/env bash
# Download the CMU Keystroke Dynamics Benchmark (Killourhy & Maxion, DSN-2009).
# Source: https://www.cs.cmu.edu/~keystroke/   (cite the paper; research use)
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p data/cmu
curl -sS -L --max-time 60 -o data/cmu/DSL.csv \
  "https://www.cs.cmu.edu/~keystroke/DSL-StrongPasswordData.csv"
echo "Saved data/cmu/DSL.csv"
sha256sum data/cmu/DSL.csv
echo "Expected: b11d23538b1865fa6ecf4e8b78567caa312e9c1027604bb022fcc6ad7eaa7a33"
