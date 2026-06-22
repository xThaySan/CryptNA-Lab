#!/usr/bin/env bash
set -euo pipefail

RESULT_DIR="experiments/results"
RAW="$RESULT_DIR/06_history_microbench_raw.txt"
CSV="$RESULT_DIR/06_history_microbench.csv"
BENCHTIME="${BENCHTIME:-1s}"
COUNT="${COUNT:-10}"

mkdir -p "$RESULT_DIR"

echo "[1] run history-bound microbenchmarks"
go test ./common/attest ./verifier \
  -run '^$' \
  -bench 'Benchmark(Hash|Verify)' \
  -benchmem \
  -benchtime="$BENCHTIME" \
  -count="$COUNT" | tee "$RAW"

echo "[2] convert Go benchmark output to CSV"
python3 - <<'PY' "$RAW" "$CSV"
import csv
import re
import sys
from pathlib import Path

raw = Path(sys.argv[1])
out = Path(sys.argv[2])
rows = []
current_pkg = ""
bench_re = re.compile(r'^(Benchmark\S+)-\d+\s+\d+\s+([0-9.]+)\s+ns/op\s+([0-9.]+)\s+B/op\s+([0-9.]+)\s+allocs/op')
for line in raw.read_text().splitlines():
    if line.startswith('pkg:'):
        current_pkg = line.split(':', 1)[1].strip()
        continue
    m = bench_re.match(line)
    if not m:
        continue
    name, ns, bytes_op, allocs = m.groups()
    rows.append({
        'package': current_pkg,
        'benchmark': name,
        'ns_per_op': float(ns),
        'us_per_op': float(ns) / 1000.0,
        'ms_per_op': float(ns) / 1_000_000.0,
        'bytes_per_op': float(bytes_op),
        'allocs_per_op': float(allocs),
    })

with out.open('w', newline='') as f:
    fields = ['package', 'benchmark', 'ns_per_op', 'us_per_op', 'ms_per_op', 'bytes_per_op', 'allocs_per_op']
    w = csv.DictWriter(f, fieldnames=fields)
    w.writeheader()
    for r in rows:
        w.writerow(r)

print(f"rows={len(rows)} csv={out}")
if not rows:
    raise SystemExit('no benchmark rows parsed')
PY

echo "raw=$RAW"
echo "csv=$CSV"
