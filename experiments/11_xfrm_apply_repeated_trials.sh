#!/usr/bin/env bash
set -euo pipefail

TRIALS="${TRIALS:-5}"
N="${N:-50}"
RESULT_DIR="experiments/results"
mkdir -p "$RESULT_DIR"

PER_TRIAL="$RESULT_DIR/11_xfrm_apply_repeated_trials.csv"
OVERHEAD="$RESULT_DIR/11_xfrm_apply_repeated_trials_overhead.csv"
AGG="$RESULT_DIR/11_xfrm_apply_repeated_trials_aggregate.csv"
STATUS="$RESULT_DIR/11_xfrm_apply_repeated_trials_status.csv"
RAW_DIR="$RESULT_DIR/11_trials_raw"
mkdir -p "$RAW_DIR"

rm -f "$PER_TRIAL" "$OVERHEAD" "$AGG" "$STATUS"
rm -f "$RAW_DIR"/*.csv
echo "trial,status" > "$STATUS"

for t in $(seq 1 "$TRIALS"); do
  if [ $((t % 2)) -eq 1 ]; then
    order="baseline-first"
  else
    order="history-first"
  fi
  echo "[trial=$t/$TRIALS] run XFRM apply comparison with N=$N order=$order"
  rm -f "$RESULT_DIR/10_xfrm_apply_latency_compare_summary.csv"
  set +e
  N="$N" CASE_ORDER="$order" ./experiments/10_xfrm_apply_latency_compare.sh
  status=$?
  set -e
  echo "$t,$status" >> "$STATUS"

  if [ "$status" -ne 0 ]; then
    echo "[trial=$t/$TRIALS] comparison script returned status $status; excluding the trial" >&2
    continue
  fi

  if [ ! -f "$RESULT_DIR/10_xfrm_apply_latency_compare_summary.csv" ]; then
    echo "[trial=$t/$TRIALS] missing comparison summary, skipping trial aggregation" >&2
    continue
  fi

  cp "$RESULT_DIR/10_xfrm_apply_latency_compare_summary.csv" "$RAW_DIR/10_xfrm_apply_latency_compare_summary_trial_${t}.csv"
  [ -f "$RESULT_DIR/10_baseline_xfrm_apply_latency_raw.csv" ] && cp "$RESULT_DIR/10_baseline_xfrm_apply_latency_raw.csv" "$RAW_DIR/10_baseline_xfrm_apply_latency_raw_trial_${t}.csv"
  [ -f "$RESULT_DIR/10_history_bound_xfrm_apply_latency_raw.csv" ] && cp "$RESULT_DIR/10_history_bound_xfrm_apply_latency_raw.csv" "$RAW_DIR/10_history_bound_xfrm_apply_latency_raw_trial_${t}.csv"

  python3 - <<'PY' "$RESULT_DIR/10_xfrm_apply_latency_compare_summary.csv" "$PER_TRIAL" "$t"
import csv, sys
from pathlib import Path
src = Path(sys.argv[1])
out = Path(sys.argv[2])
trial = sys.argv[3]
rows = list(csv.DictReader(src.open()))
if not rows:
    raise SystemExit(0)
fields = ['trial'] + list(rows[0].keys())
write_header = not out.exists()
with out.open('a', newline='') as f:
    w = csv.DictWriter(f, fieldnames=fields)
    if write_header:
        w.writeheader()
    for r in rows:
        rr = {'trial': trial}
        rr.update(r)
        w.writerow(rr)
PY

done

python3 - <<'PY' "$PER_TRIAL" "$OVERHEAD" "$AGG" "$TRIALS" "$N" "$STATUS"
import csv, statistics, sys
from collections import defaultdict
from pathlib import Path
per_trial = Path(sys.argv[1])
overhead_out = Path(sys.argv[2])
agg_out = Path(sys.argv[3])
trials_requested = int(sys.argv[4])
N = int(sys.argv[5])
status_path = Path(sys.argv[6])
if not per_trial.exists():
    raise SystemExit(f'no per-trial summary generated: {per_trial}')
rows = list(csv.DictReader(per_trial.open()))
if not rows:
    raise SystemExit(f'empty per-trial summary: {per_trial}')
metrics = ['avg_ms', 'median_ms', 'p95_ms', 'p99_ms', 'min_ms', 'max_ms']
by_trial = defaultdict(dict)
for r in rows:
    by_trial[r['trial']][r['case']] = r

overhead_rows = []
for trial, cases in sorted(by_trial.items(), key=lambda kv: int(kv[0])):
    if 'baseline' not in cases or 'history_bound' not in cases:
        continue
    base = cases['baseline']
    hb = cases['history_bound']
    for m in metrics:
        bv = float(base[m]); hv = float(hb[m])
        delta = hv - bv
        pct = (delta / bv * 100.0) if bv else 0.0
        overhead_rows.append({
            'trial': trial,
            'metric': m,
            'baseline_apply': bv,
            'history_bound_apply': hv,
            'delta_ms': delta,
            'delta_percent': pct,
        })

with overhead_out.open('w', newline='') as f:
    fields = ['trial', 'metric', 'baseline_apply', 'history_bound_apply', 'delta_ms', 'delta_percent']
    w = csv.DictWriter(f, fieldnames=fields)
    w.writeheader()
    for r in overhead_rows:
        w.writerow({k: f'{v:.3f}' if isinstance(v, float) else v for k, v in r.items()})

agg_rows = []
# Per-case aggregate across trial summaries.
for case in ['baseline', 'history_bound']:
    case_rows = [r for r in rows if r['case'] == case]
    if not case_rows:
        continue
    success_rates = []
    for r in case_rows:
        runs = int(float(r['runs']))
        ok = int(float(r['ok']))
        success_rates.append((ok / runs * 100.0) if runs else 0.0)
    agg_rows.append({
        'group': case,
        'metric': 'success_rate_percent',
        'trials': len(success_rates),
        'N_per_trial': N,
        'mean': statistics.mean(success_rates),
        'median': statistics.median(success_rates),
        'min': min(success_rates),
        'max': max(success_rates),
        'stdev': statistics.stdev(success_rates) if len(success_rates) > 1 else 0.0,
    })
    for m in metrics:
        vals = [float(r[m]) for r in case_rows]
        agg_rows.append({
            'group': case,
            'metric': m,
            'trials': len(vals),
            'N_per_trial': N,
            'mean': statistics.mean(vals),
            'median': statistics.median(vals),
            'min': min(vals),
            'max': max(vals),
            'stdev': statistics.stdev(vals) if len(vals) > 1 else 0.0,
        })
# Aggregate overhead across trials.
for m in metrics:
    vals = [float(r['delta_ms']) for r in overhead_rows if r['metric'] == m]
    pcts = [float(r['delta_percent']) for r in overhead_rows if r['metric'] == m]
    if vals:
        agg_rows.append({
            'group': 'overhead_delta_ms',
            'metric': m,
            'trials': len(vals),
            'N_per_trial': N,
            'mean': statistics.mean(vals),
            'median': statistics.median(vals),
            'min': min(vals),
            'max': max(vals),
            'stdev': statistics.stdev(vals) if len(vals) > 1 else 0.0,
        })
    if pcts:
        agg_rows.append({
            'group': 'overhead_delta_percent',
            'metric': m,
            'trials': len(pcts),
            'N_per_trial': N,
            'mean': statistics.mean(pcts),
            'median': statistics.median(pcts),
            'min': min(pcts),
            'max': max(pcts),
            'stdev': statistics.stdev(pcts) if len(pcts) > 1 else 0.0,
        })

# Script status aggregate. stdev column stores failed script invocations for compactness.
if status_path.exists():
    status_rows = list(csv.DictReader(status_path.open()))
    failed_scripts = sum(1 for r in status_rows if r.get('status') not in ('0', 0))
    agg_rows.append({
        'group': 'script',
        'metric': 'completed_trials',
        'trials': len(status_rows),
        'N_per_trial': N,
        'mean': len(by_trial),
        'median': len(by_trial),
        'min': len(by_trial),
        'max': trials_requested,
        'stdev': failed_scripts,
    })

with agg_out.open('w', newline='') as f:
    fields = ['group', 'metric', 'trials', 'N_per_trial', 'mean', 'median', 'min', 'max', 'stdev']
    w = csv.DictWriter(f, fieldnames=fields)
    w.writeheader()
    for r in agg_rows:
        w.writerow({k: f'{v:.3f}' if isinstance(v, float) else v for k, v in r.items()})

print(f'per_trial={per_trial}')
print(f'overhead={overhead_out}')
print(f'aggregate={agg_out}')
print(f'status={status_path}')
if failed_scripts or len(by_trial) != trials_requested:
    raise SystemExit(
        f'incomplete XFRM campaign: completed={len(by_trial)}/{trials_requested}, '
        f'failed_script_invocations={failed_scripts}'
    )
PY
