#!/usr/bin/env bash
set -euo pipefail

N="${N:-100}"
RATES="${RATES:-10 50 100}"
SCENARIOS="${SCENARIOS:-valid wrong-psk random}"

RESULT_DIR="experiments/results"
mkdir -p "$RESULT_DIR"

SUMMARY="$RESULT_DIR/05_pdp_cpu_cost_summary.csv"
echo "scenario,target_rate_sps,events,cpu_delta_ms,cpu_ms_per_spa,wall_duration_s,pdp_cpu_percent,avg_processing_ms,median_processing_ms,p95_processing_ms" > "$SUMMARY"

read_pdp_cpu_us() {
  docker exec cryptna-pdp sh -c '
    if [ -r /sys/fs/cgroup/cpu.stat ]; then
      awk "/^usage_usec / {print \$2}" /sys/fs/cgroup/cpu.stat
    elif [ -r /sys/fs/cgroup/cpuacct/cpuacct.usage ]; then
      awk "{print int(\$1 / 1000)}" /sys/fs/cgroup/cpuacct/cpuacct.usage
    else
      echo "0"
    fi
  '
}

echo "[1] start lab in dry-run mode"
docker compose down -v --remove-orphans >/dev/null
XFRM_MODE=dry-run CRYPTNA_DEBUG=0 SA_LIFETIME_SECONDS=30 SESSION_REAPER_INTERVAL_SECONDS=5 \
  docker compose up -d --build >/dev/null

for SCENARIO in $SCENARIOS; do
  for RATE in $RATES; do
    echo
    echo "[2] PDP CPU scenario=${SCENARIO} rate=${RATE} SPA/s n=${N}"

    docker compose up -d --force-recreate pdp pep client >/dev/null
    sleep 2

    docker exec cryptna-pdp wget -qO- http://localhost:8080/metrics/spa/reset >/dev/null

    SAFE_SCENARIO="$(echo "$SCENARIO" | tr '-' '_')"
    CLIENT_OUT="/tmp/pdp_cpu_${SAFE_SCENARIO}_${RATE}.csv"
    PDP_RAW="$RESULT_DIR/05_pdp_cpu_${SAFE_SCENARIO}_${RATE}sps_raw.csv"

    CPU_BEFORE="$(read_pdp_cpu_us)"
    WALL_BEFORE_NS="$(date +%s%N)"

    docker exec -e XFRM_MODE=dry-run -e CRYPTNA_DEBUG=0 cryptna-client \
      /app/client bench-handshake-rate \
        -scenario "$SCENARIO" \
        -n "$N" \
        -rate-sps "$RATE" \
        -timeout-ms 100 \
        -out "$CLIENT_OUT" >/dev/null

    WALL_AFTER_NS="$(date +%s%N)"
    CPU_AFTER="$(read_pdp_cpu_us)"

    docker exec cryptna-pdp wget -qO- http://localhost:8080/metrics/spa/raw > "$PDP_RAW"

    python3 - <<'PY' "$PDP_RAW" "$SUMMARY" "$SCENARIO" "$RATE" "$N" "$CPU_BEFORE" "$CPU_AFTER" "$WALL_BEFORE_NS" "$WALL_AFTER_NS"
import csv
import statistics
import sys
from pathlib import Path

raw = Path(sys.argv[1])
summary = Path(sys.argv[2])
scenario = sys.argv[3]
rate = sys.argv[4]
expected_n = int(sys.argv[5])
cpu_before_us = int(sys.argv[6])
cpu_after_us = int(sys.argv[7])
wall_before_ns = int(sys.argv[8])
wall_after_ns = int(sys.argv[9])

rows = list(csv.DictReader(raw.open()))
rows = [r for r in rows if r["scenario"] == scenario]

if len(rows) != expected_n:
    raise SystemExit(f"expected {expected_n} PDP events for {scenario}, got {len(rows)}")

values = sorted(float(r["duration_us"]) / 1000.0 for r in rows)

def percentile(xs, p):
    k = (len(xs) - 1) * p / 100.0
    lo = int(k)
    hi = min(lo + 1, len(xs) - 1)
    if lo == hi:
        return xs[lo]
    return xs[lo] * (hi - k) + xs[hi] * (k - lo)

cpu_delta_us = cpu_after_us - cpu_before_us
if cpu_delta_us <= 0:
    raise SystemExit(f"invalid CPU delta: before={cpu_before_us} after={cpu_after_us}")

cpu_delta_ms = cpu_delta_us / 1000.0
cpu_ms_per_spa = cpu_delta_ms / len(rows)

wall_duration_s = (wall_after_ns - wall_before_ns) / 1_000_000_000.0
pdp_cpu_percent = (cpu_delta_us / 1_000_000.0) / wall_duration_s * 100.0 if wall_duration_s > 0 else 0.0

line = {
    "scenario": scenario,
    "target_rate_sps": rate,
    "events": len(rows),
    "cpu_delta_ms": cpu_delta_ms,
    "cpu_ms_per_spa": cpu_ms_per_spa,
    "wall_duration_s": wall_duration_s,
    "pdp_cpu_percent": pdp_cpu_percent,
    "avg_processing_ms": statistics.mean(values),
    "median_processing_ms": statistics.median(values),
    "p95_processing_ms": percentile(values, 95),
}

with summary.open("a", newline="") as f:
    w = csv.DictWriter(f, fieldnames=[
        "scenario",
        "target_rate_sps",
        "events",
        "cpu_delta_ms",
        "cpu_ms_per_spa",
        "wall_duration_s",
        "pdp_cpu_percent",
        "avg_processing_ms",
        "median_processing_ms",
        "p95_processing_ms",
    ])
    w.writerow({
        k: f"{v:.3f}" if isinstance(v, float) else v
        for k, v in line.items()
    })

print(
    f"{scenario} rate={rate} events={len(rows)} "
    f"cpu_ms_per_spa={cpu_ms_per_spa:.3f} "
    f"pdp_cpu_percent={pdp_cpu_percent:.2f}% "
    f"avg_processing_ms={statistics.mean(values):.3f}"
)
PY
  done
done

echo
echo "summary=$SUMMARY"
column -s, -t "$SUMMARY" || cat "$SUMMARY"
