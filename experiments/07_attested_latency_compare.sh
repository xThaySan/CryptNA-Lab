#!/usr/bin/env bash
set -euo pipefail

N="${N:-200}"
RESULT_DIR="experiments/results"
mkdir -p "$RESULT_DIR"

run_case() {
  local name="$1"
  local attestation="$2"
  local raw="/tmp/${name}_handshake_latency.csv"
  local host_raw="$RESULT_DIR/07_${name}_handshake_latency_raw.csv"
  local summary="$RESULT_DIR/07_${name}_handshake_latency_summary.csv"

  echo "[case=$name] start lab attestation=$attestation"
  docker compose down -v --remove-orphans >/dev/null
  PEP_ATTESTATION_ENABLED="$attestation" \
  XFRM_MODE=dry-run \
  CRYPTNA_DEBUG=0 \
  SA_LIFETIME_SECONDS=3600 \
  SESSION_REAPER_INTERVAL_SECONDS=60 \
  VERIFIER_TOKEN_TTL_SECONDS=3600 \
    docker compose up -d --build >/dev/null

  echo "[case=$name] run $N sequential dry-run handshakes"
  docker exec -e XFRM_MODE=dry-run -e CRYPTNA_DEBUG=0 cryptna-client \
    /app/client bench-handshake -n "$N" -out "$raw"

  docker cp "cryptna-client:$raw" "$host_raw"

  python3 - <<'PY' "$host_raw" "$summary" "$name" "$attestation"
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
    'runs': len(rows),
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
    raise SystemExit(f'{case}: {len(failed)} failed runs')
PY
}

run_case baseline 0
run_case history_bound 1

COMBINED="$RESULT_DIR/07_attested_latency_compare_summary.csv"
head -n 1 "$RESULT_DIR/07_baseline_handshake_latency_summary.csv" > "$COMBINED"
tail -n +2 "$RESULT_DIR/07_baseline_handshake_latency_summary.csv" >> "$COMBINED"
tail -n +2 "$RESULT_DIR/07_history_bound_handshake_latency_summary.csv" >> "$COMBINED"

echo "summary=$COMBINED"
cat "$COMBINED"
