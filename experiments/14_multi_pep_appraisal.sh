#!/usr/bin/env bash
set -euo pipefail

RESULT_DIR="experiments/results"
RAW="$RESULT_DIR/14_multi_pep_appraisal_raw.txt"
mkdir -p "$RESULT_DIR"

go test ./verifier \
  -run '^$' \
  -bench '^BenchmarkConcurrentPEPAppraisal' \
  -benchmem \
  -benchtime="${BENCHTIME:-1s}" \
  -count="${COUNT:-10}" | tee "$RAW"

echo "raw=$RAW"
