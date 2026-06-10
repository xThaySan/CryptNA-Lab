#!/usr/bin/env bash
set -euo pipefail

N="${N:-100}"
RATES="${RATES:-10 50 100}"
SCENARIOS="${SCENARIOS:-valid wrong-psk random}"

RESULT_DIR="experiments/results"
mkdir -p "$RESULT_DIR"

SUMMARY="$RESULT_DIR/04_pdp_internal_processing_rates_summary.csv"
echo "scenario,target_rate_sps,events,authorized_or_dropped,duration_s,achieved_sps,avg_ms,median_ms,min_ms,max_ms,p95_ms" > "$SUMMARY"

echo "[1] start lab in dry-run mode"
docker compose down -v --remove-orphans >/dev/null
XFRM_MODE=dry-run CRYPTNA_DEBUG=0 SA_LIFETIME_SECONDS=30 SESSION_REAPER_INTERVAL_SECONDS=5 \
  docker compose up -d --build >/dev/null

for SCENARIO in $SCENARIOS; do
  for RATE in $RATES; do
    echo
    echo "[2] PDP internal scenario=${SCENARIO} rate=${RATE} SPA/s n=${N}"

    docker compose up -d --force-recreate pdp pep client >/dev/null
    sleep 2

    docker exec cryptna-pdp wget -qO- http://localhost:8080/metrics/spa/reset >/dev/null

    SAFE_SCENARIO="$(echo "$SCENARIO" | tr '-' '_')"
    CLIENT_OUT="/tmp/pdp_load_${SAFE_SCENARIO}_${RATE}.csv"
    PDP_RAW="$RESULT_DIR/04_pdp_internal_${SAFE_SCENARIO}_${RATE}sps.csv"

    docker exec -e XFRM_MODE=dry-run -e CRYPTNA_DEBUG=0 cryptna-client \
      /app/client bench-handshake-rate \
        -scenario "$SCENARIO" \
        -n "$N" \
        -rate-sps "$RATE" \
        -timeout-ms 100 \
        -out "$CLIENT_OUT" >/dev/null

    docker exec cryptna-pdp wget -qO- http://localhost:8080/metrics/spa/raw > "$PDP_RAW"

    python3 - <<'PY' "$PDP_RAW" "$SUMMARY" "$RATE" "$SCENARIO" "$N"
import csv
import statistics
import sys
from pathlib import Path

raw = Path(sys.argv[1])
summary = Path(sys.argv[2])
rate = sys.argv[3]
scenario = sys.argv[4]
expected_n = int(sys.argv[5])

rows = list(csv.DictReader(raw.open()))
rows = [r for r in rows if r["scenario"] == scenario]

if not rows:
    raise SystemExit(f"no PDP metric rows for scenario={scenario}")

values = sorted(float(r["duration_us"]) / 1000.0 for r in rows)

def percentile(xs, p):
    k = (len(xs) - 1) * p / 100.0
    lo = int(k)
    hi = min(lo + 1, len(xs) - 1)
    if lo == hi:
        return xs[lo]
    return xs[lo] * (hi - k) + xs[hi] * (k - lo)

starts = [int(r["start_unix_ns"]) for r in rows]
ends = [
    int(r["start_unix_ns"]) + int(r["duration_us"]) * 1000
    for r in rows
]

duration_s = (max(ends) - min(starts)) / 1_000_000_000
achieved_sps = len(rows) / duration_s if duration_s > 0 else 0.0

ok_outcomes = {
    "valid": "authorized",
    "wrong-psk": "drop_invalid_payload",
    "random": "drop_invalid_header",
}

expected_outcome = ok_outcomes.get(scenario)
matching = [r for r in rows if r["outcome"] == expected_outcome] if expected_outcome else rows

line = {
    "scenario": scenario,
    "target_rate_sps": rate,
    "events": len(rows),
    "authorized_or_dropped": len(matching),
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
        "scenario","target_rate_sps","events","authorized_or_dropped","duration_s",
        "achieved_sps","avg_ms","median_ms","min_ms","max_ms","p95_ms"
    ])
    w.writerow({
        k: f"{v:.3f}" if isinstance(v, float) else v
        for k, v in line.items()
    })

print(
    f"{scenario} rate={rate} events={line['events']} matched={line['authorized_or_dropped']} "
    f"achieved_sps={line['achieved_sps']:.2f} avg_ms={line['avg_ms']:.3f} "
    f"median_ms={line['median_ms']:.3f} p95_ms={line['p95_ms']:.3f}"
)

if len(rows) != expected_n:
    raise SystemExit(f"expected {expected_n} PDP events, got {len(rows)}")
if len(matching) != expected_n:
    raise SystemExit(f"expected {expected_n} expected outcomes, got {len(matching)}")
PY
  done
done

echo
echo "summary=$SUMMARY"
column -s, -t "$SUMMARY" || cat "$SUMMARY"
