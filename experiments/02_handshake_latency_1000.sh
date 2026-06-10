#!/usr/bin/env bash
set -euo pipefail

N="${N:-1000}"
RESULT_DIR="experiments/results"
RAW="$RESULT_DIR/02_handshake_latency_raw.csv"
SUMMARY="$RESULT_DIR/02_handshake_latency_summary.csv"
TMP_IN_CONTAINER="/tmp/handshake_latency.csv"

mkdir -p "$RESULT_DIR"

echo "[1] start lab in control-plane benchmark mode"
docker compose down -v --remove-orphans >/dev/null
XFRM_MODE=dry-run CRYPTNA_DEBUG=0 SA_LIFETIME_SECONDS=3600 SESSION_REAPER_INTERVAL_SECONDS=60 \
  docker compose up -d --build >/dev/null

echo "[2] run $N sequential handshakes inside client container"
docker exec -e XFRM_MODE=dry-run -e CRYPTNA_DEBUG=0 cryptna-client \
  /app/client bench-handshake -n "$N" -out "$TMP_IN_CONTAINER"

echo "[3] collect raw CSV"
docker cp "cryptna-client:$TMP_IN_CONTAINER" "$RAW"

echo "[4] compute summary"
python3 - <<'PY' "$RAW" "$SUMMARY"
import csv
import statistics
import sys
from pathlib import Path

raw_path = Path(sys.argv[1])
summary_path = Path(sys.argv[2])

rows = list(csv.DictReader(raw_path.open()))
ok = [r for r in rows if r["status"] == "ok"]
failed = [r for r in rows if r["status"] != "ok"]

if not ok:
    raise SystemExit("no successful run in benchmark CSV")

values = sorted(float(r["duration_ms"]) for r in ok)

def percentile(sorted_values, pct):
    k = (len(sorted_values) - 1) * pct / 100.0
    lo = int(k)
    hi = min(lo + 1, len(sorted_values) - 1)
    if lo == hi:
        return sorted_values[lo]
    frac = k - lo
    return sorted_values[lo] * (1 - frac) + sorted_values[hi] * frac

summary = {
    "runs": len(rows),
    "ok": len(ok),
    "failed": len(failed),
    "avg_ms": statistics.mean(values),
    "median_ms": statistics.median(values),
    "min_ms": min(values),
    "max_ms": max(values),
    "p95_ms": percentile(values, 95),
}

with summary_path.open("w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(summary.keys()))
    w.writeheader()
    w.writerow({k: f"{v:.3f}" if isinstance(v, float) else v for k, v in summary.items()})

print("runs,ok,failed,avg_ms,median_ms,min_ms,max_ms,p95_ms")
print(",".join(str(summary[k]) if not isinstance(summary[k], float) else f"{summary[k]:.3f}" for k in summary))

if failed:
    raise SystemExit(f"benchmark has {len(failed)} failed runs")
PY

echo "raw=$RAW"
echo "summary=$SUMMARY"
