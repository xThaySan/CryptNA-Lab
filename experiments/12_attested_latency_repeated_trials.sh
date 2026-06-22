#!/usr/bin/env bash
set -euo pipefail

TRIALS="${TRIALS:-10}"
N="${N:-1000}"
WARMUP="${WARMUP:-20}"
RESULT_DIR="experiments/results"
RAW_DIR="$RESULT_DIR/12_trials_raw"
PER_TRIAL="$RESULT_DIR/12_attested_latency_repeated_trials.csv"
AGG="$RESULT_DIR/12_attested_latency_repeated_trials_aggregate.csv"
STATUS="$RESULT_DIR/12_attested_latency_repeated_trials_status.csv"

mkdir -p "$RAW_DIR"
rm -f "$PER_TRIAL" "$AGG" "$STATUS"
rm -f "$RAW_DIR"/*.csv
echo "trial,status" > "$STATUS"

for trial in $(seq 1 "$TRIALS"); do
  if [ $((trial % 2)) -eq 1 ]; then
    order="baseline-first"
  else
    order="history-first"
  fi
  echo "[trial=$trial/$TRIALS] paired dry-run comparison order=$order"
  set +e
  N="$N" WARMUP="$WARMUP" CASE_ORDER="$order" PEP_STATE_PERSISTENCE=0 \
    ./experiments/07_attested_latency_compare.sh
  status=$?
  set -e
  echo "$trial,$status" >> "$STATUS"
  if [ "$status" -ne 0 ]; then
    echo "trial $trial failed with status $status; stopping the paired campaign" >&2
    exit "$status"
  fi
  cp "$RESULT_DIR/07_attested_latency_compare_summary.csv" "$RAW_DIR/summary_trial_${trial}.csv"
  cp "$RESULT_DIR/07_baseline_handshake_latency_raw.csv" "$RAW_DIR/baseline_trial_${trial}.csv"
  cp "$RESULT_DIR/07_history_bound_handshake_latency_raw.csv" "$RAW_DIR/history_bound_trial_${trial}.csv"

  python3 - <<'PY' "$RESULT_DIR/07_attested_latency_compare_summary.csv" "$PER_TRIAL" "$trial"
import csv, sys
from pathlib import Path
src, out, trial = Path(sys.argv[1]), Path(sys.argv[2]), int(sys.argv[3])
rows = list(csv.DictReader(src.open()))
if {r['case'] for r in rows} != {'baseline', 'history_bound'}:
    raise SystemExit('paired comparison is incomplete')
if {r['pep_state_persistence'] for r in rows} != {'disabled'}:
    raise SystemExit('official paired comparison must disable PEP JSON state persistence')
fields = ['trial'] + list(rows[0])
with out.open('a', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=fields)
    if out.stat().st_size == 0:
        writer.writeheader()
    for row in rows:
        writer.writerow({'trial': trial, **row})
PY
done

python3 - <<'PY' "$PER_TRIAL" "$AGG" "$TRIALS" "$N" "$WARMUP"
import csv, statistics, sys
from pathlib import Path
src, out = Path(sys.argv[1]), Path(sys.argv[2])
trials_requested, n, warmup = map(int, sys.argv[3:6])
rows = list(csv.DictReader(src.open()))
by_trial = {}
for row in rows:
    by_trial.setdefault(int(row['trial']), {})[row['case']] = row
if len(by_trial) != trials_requested or any(set(v) != {'baseline', 'history_bound'} for v in by_trial.values()):
    raise SystemExit('one or more paired trials are incomplete')
persistence = {row['pep_state_persistence'] for row in rows}
if persistence != {'disabled'}:
    raise SystemExit(f'unexpected PEP state persistence modes: {sorted(persistence)}')
metrics = ['avg_ms', 'median_ms', 'p95_ms', 'p99_ms']
output = []
for metric in metrics:
    baseline = [float(by_trial[t]['baseline'][metric]) for t in sorted(by_trial)]
    history = [float(by_trial[t]['history_bound'][metric]) for t in sorted(by_trial)]
    deltas = [h-b for b,h in zip(baseline, history)]
    for group, values in [('baseline', baseline), ('history_bound', history), ('paired_delta_ms', deltas)]:
        output.append({
            'group': group, 'metric': metric, 'trials': len(values),
            'N_per_trial': n, 'warmup_per_case': warmup,
            'pep_state_persistence': 'disabled',
            'mean': statistics.mean(values), 'median': statistics.median(values),
            'min': min(values), 'max': max(values),
            'stdev': statistics.stdev(values) if len(values) > 1 else 0.0,
        })
fields = ['group','metric','trials','N_per_trial','warmup_per_case','pep_state_persistence','mean','median','min','max','stdev']
with out.open('w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()
    for row in output:
        writer.writerow({k: f'{v:.6f}' if isinstance(v, float) else v for k,v in row.items()})
print(out.read_text())
PY

echo "per_trial=$PER_TRIAL"
echo "aggregate=$AGG"
echo "status=$STATUS"
