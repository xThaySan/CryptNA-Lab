#!/usr/bin/env bash
set -euo pipefail

N="${N:-50}"
WARMUP="${WARMUP:-3}"
CASE_ORDER="${CASE_ORDER:-baseline-first}"
RESULT_DIR="experiments/results"
mkdir -p "$RESULT_DIR"

summarize_csv() {
  local raw_path="$1"
  local summary_path="$2"
  local name="$3"
  local attestation="$4"
  python3 - <<'PY' "$raw_path" "$summary_path" "$name" "$attestation"
import csv, statistics, sys
from pathlib import Path
raw_path = Path(sys.argv[1])
summary_path = Path(sys.argv[2])
case = sys.argv[3]
attestation = sys.argv[4]
rows = list(csv.DictReader(raw_path.open()))
ok = [r for r in rows if r['status'] == 'ok']
failed = [r for r in rows if r['status'] != 'ok']
if not ok:
    raise SystemExit(f'no successful runs for {case}')
values = sorted(float(r['duration_ms']) for r in ok)
def pct(vals, p):
    k = (len(vals)-1) * p / 100.0
    lo = int(k)
    hi = min(lo + 1, len(vals)-1)
    if lo == hi:
        return vals[lo]
    return vals[lo] * (1 - (k - lo)) + vals[hi] * (k - lo)
summary = {
    'case': case,
    'attestation_enabled': attestation,
    'xfrm_mode': 'apply',
    'case_order': __import__('os').environ.get('CRYPTNA_BENCH_CASE_ORDER', 'baseline-first'),
    'runs': len(rows),
    'warmup_runs': int(__import__('os').environ.get('CRYPTNA_BENCH_WARMUP', '0')),
    'ok': len(ok),
    'failed': len(failed),
    'avg_ms': statistics.mean(values),
    'median_ms': statistics.median(values),
    'min_ms': min(values),
    'max_ms': max(values),
    'p95_ms': pct(values, 95),
    'p99_ms': pct(values, 99),
}
with summary_path.open('w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=summary.keys())
    w.writeheader()
    w.writerow({k: f'{v:.3f}' if isinstance(v, float) else v for k, v in summary.items()})
print(','.join(summary.keys()))
print(','.join(f'{summary[k]:.3f}' if isinstance(summary[k], float) else str(summary[k]) for k in summary))
if failed:
    raise SystemExit(f'{case}: {len(failed)} failed runs; result is invalid')
PY
}


cleanup_xfrm() {
  docker exec cryptna-client ip xfrm policy flush >/dev/null 2>&1 || true
  docker exec cryptna-client ip xfrm state flush >/dev/null 2>&1 || true
  docker exec cryptna-pep ip xfrm policy flush >/dev/null 2>&1 || true
  docker exec cryptna-pep ip xfrm state flush >/dev/null 2>&1 || true
}

run_case() {
  local name="$1"
  local attestation="$2"
  local raw="/tmp/${name}_xfrm_apply_latency.csv"
  local host_raw="$RESULT_DIR/10_${name}_xfrm_apply_latency_raw.csv"
  local summary="$RESULT_DIR/10_${name}_xfrm_apply_latency_summary.csv"

  echo "[case=$name] start lab attestation=$attestation XFRM_MODE=apply"
  docker compose down -v --remove-orphans >/dev/null
  PEP_ATTESTATION_ENABLED="$attestation" \
  XFRM_MODE=apply \
  CRYPTNA_DEBUG=0 \
  SA_LIFETIME_SECONDS=3600 \
  SESSION_REAPER_INTERVAL_SECONDS=3600 \
  VERIFIER_TOKEN_TTL_SECONDS=3600 \
  VERIFIER_REQUIRED_OBSERVER_PROFILE=posthoc \
    docker compose up -d --build >/dev/null

  ./scripts/wait_lab_ready.sh

  echo "[case=$name] cleanup stale XFRM state"
  cleanup_xfrm

  if [ "$WARMUP" -gt 0 ]; then
    echo "[case=$name] run $WARMUP unmeasured warm-up handshakes"
    docker exec -e XFRM_MODE=apply -e CRYPTNA_DEBUG=0 cryptna-client \
      /app/client bench-handshake -n "$WARMUP" -out "/tmp/${name}_xfrm_warmup.csv" >/dev/null
  fi

  echo "[case=$name] run $N sequential handshakes with real XFRM apply"
  set +e
  docker exec -e XFRM_MODE=apply -e CRYPTNA_DEBUG=0 cryptna-client \
    /app/client bench-handshake -n "$N" -out "$raw"
  local bench_status=$?
  set -e
  if [ "$bench_status" -ne 0 ]; then
    echo "[case=$name] benchmark command returned status $bench_status; attempting to keep partial CSV results" >&2
  fi

  docker cp "cryptna-client:$raw" "$host_raw"
  summarize_csv "$host_raw" "$summary" "$name" "$attestation"

  echo "[case=$name] cleanup XFRM state after run"
  cleanup_xfrm
}

rm -f "$RESULT_DIR/10_xfrm_apply_latency_compare_summary.csv"
export CRYPTNA_BENCH_WARMUP="$WARMUP"
export CRYPTNA_BENCH_CASE_ORDER="$CASE_ORDER"

case "$CASE_ORDER" in
  baseline-first)
    run_case baseline 0
    run_case history_bound 1
    ;;
  history-first)
    run_case history_bound 1
    run_case baseline 0
    ;;
  *)
    echo "invalid CASE_ORDER=$CASE_ORDER (expected baseline-first or history-first)" >&2
    exit 1
    ;;
esac

COMBINED="$RESULT_DIR/10_xfrm_apply_latency_compare_summary.csv"
head -n 1 "$RESULT_DIR/10_baseline_xfrm_apply_latency_summary.csv" > "$COMBINED"
tail -n +2 "$RESULT_DIR/10_baseline_xfrm_apply_latency_summary.csv" >> "$COMBINED"
tail -n +2 "$RESULT_DIR/10_history_bound_xfrm_apply_latency_summary.csv" >> "$COMBINED"

echo "summary=$COMBINED"
cat "$COMBINED"
