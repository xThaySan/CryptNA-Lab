#!/usr/bin/env bash
set -euo pipefail

N="${N:-1000}"
RATES="${RATES:-10 50 100}"

RESULT_DIR="experiments/results"
mkdir -p "$RESULT_DIR"

SUMMARY="$RESULT_DIR/03_pdp_load_rates_valid_summary.csv"
echo "scenario,target_rate_sps,runs,ok,failed,duration_s,achieved_sps,avg_ms,median_ms,min_ms,max_ms,p95_ms" > "$SUMMARY"

echo "[1] start lab in dry-run mode"
docker compose down -v --remove-orphans >/dev/null
XFRM_MODE=dry-run CRYPTNA_DEBUG=0 SA_LIFETIME_SECONDS=30 SESSION_REAPER_INTERVAL_SECONDS=5 \
  docker compose up -d --build >/dev/null

for RATE in $RATES; do
  echo
  echo "[2] valid SPA load test at ${RATE} SPA/s"

  docker compose up -d --force-recreate pdp pep client >/dev/null
  sleep 2

  CONTAINER_OUT="/tmp/pdp_load_valid_${RATE}.csv"
  RAW="$RESULT_DIR/03_pdp_load_rates_valid_${RATE}sps.csv"

  docker exec -e XFRM_MODE=dry-run -e CRYPTNA_DEBUG=0 cryptna-client \
    /app/client bench-handshake-rate \
      -n "$N" \
      -rate-sps "$RATE" \
      -out "$CONTAINER_OUT"

  docker cp "cryptna-client:$CONTAINER_OUT" "$RAW" >/dev/null

  python3 - <<'PY' "$RAW" "$SUMMARY" "$RATE"
import csv
import statistics
import sys
from pathlib import Path

raw = Path(sys.argv[1])
summary = Path(sys.argv[2])
rate = sys.argv[3]

rows = list(csv.DictReader(raw.open()))
ok = [r for r in rows if r["status"] == "ok"]
failed = [r for r in rows if r["status"] != "ok"]

if not rows:
    raise SystemExit("empty CSV")
if not ok:
    raise SystemExit("no successful runs")

values = sorted(float(r["duration_ms"]) for r in ok)

def percentile(xs, p):
    k = (len(xs) - 1) * p / 100.0
    lo = int(k)
    hi = min(lo + 1, len(xs) - 1)
    if lo == hi:
        return xs[lo]
    return xs[lo] * (hi - k) + xs[hi] * (k - lo)

last = max(float(r["start_offset_ms"]) + float(r["duration_ms"]) for r in rows)
duration_s = last / 1000.0
achieved_sps = len(ok) / duration_s if duration_s > 0 else 0.0

line = {
    "scenario": "valid_spa",
    "target_rate_sps": rate,
    "runs": len(rows),
    "ok": len(ok),
    "failed": len(failed),
    "duration_s": duration_s,
    "achieved_sps": achieved_sps,
    "avg_ms": statistics.mean(values),
    "median_ms": statistics.median(values),
    "min_ms": min(values),
    "max_ms": max(values),
    "p95_ms": percentile(values, 95),
}

with summary.open("a", newline="") as f:
    w = csv.DictWriter(f, fieldnames=[
        "scenario","target_rate_sps","runs","ok","failed","duration_s",
        "achieved_sps","avg_ms","median_ms","min_ms","max_ms","p95_ms"
    ])
    w.writerow({
        k: f"{v:.3f}" if isinstance(v, float) else v
        for k, v in line.items()
    })

print(
    f"valid_spa rate={rate} runs={line['runs']} ok={line['ok']} failed={line['failed']} "
    f"achieved_sps={line['achieved_sps']:.2f} avg_ms={line['avg_ms']:.3f} "
    f"median_ms={line['median_ms']:.3f} p95_ms={line['p95_ms']:.3f}"
)

if failed:
    raise SystemExit(f"{len(failed)} failed runs")
PY
done

echo
echo "summary=$SUMMARY"
column -s, -t "$SUMMARY" || cat "$SUMMARY"
