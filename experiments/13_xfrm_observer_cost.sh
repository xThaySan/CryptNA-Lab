#!/usr/bin/env bash
set -euo pipefail

N="${N:-30}"
WARMUP="${WARMUP:-3}"
RESULT_DIR="experiments/results"
OUT="$RESULT_DIR/13_xfrm_observer_cost.csv"
mkdir -p "$RESULT_DIR"
rm -f "$OUT"

run_case() {
  local name="$1"
  local observer="$2"
  local required="$3"
  shift 3
  local compose_args=("$@")
  local log_file="$RESULT_DIR/13_${name}_pep.log"
  local bench_file="/tmp/${name}_observer_bench.csv"

  docker compose "${compose_args[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  XFRM_MODE=apply \
  PEP_ATTESTATION_ENABLED=1 \
  XFRM_OBSERVER="$observer" \
  XFRM_EBPF_STRICT=1 \
  VERIFIER_REQUIRED_OBSERVER_PROFILE="$required" \
  SA_LIFETIME_SECONDS=3600 \
  VERIFIER_TOKEN_TTL_SECONDS=3600 \
    docker compose "${compose_args[@]}" up -d --build >/dev/null
  ./scripts/wait_lab_ready.sh

  if [ "$WARMUP" -gt 0 ]; then
    docker exec cryptna-client /app/client bench-handshake -n "$WARMUP" -out "/tmp/${name}_observer_warmup.csv" >/dev/null
  fi
  docker exec cryptna-client /app/client bench-handshake -n "$N" -out "$bench_file" >/dev/null
  docker logs cryptna-pep >"$log_file" 2>&1

  python3 - <<'PY' "$log_file" "$OUT" "$name" "$observer" "$required" "$N"
import csv, re, statistics, sys
from pathlib import Path
log_path, out = Path(sys.argv[1]), Path(sys.argv[2])
name, observer, required, expected = sys.argv[3], sys.argv[4], sys.argv[5], int(sys.argv[6])
pattern = re.compile(r'xfrm_apply_observed .*posthoc_duration_us=(\d+) .*ebpf_correlation_duration_us=(\d+) .*observer_total_duration_us=(\d+)')
values = [tuple(map(int, m.groups())) for m in map(pattern.search, log_path.read_text(errors='replace').splitlines()) if m]
values = values[-expected:]
if len(values) != expected:
    raise SystemExit(f'{name}: expected {expected} measured observer records, got {len(values)}')
fields = ['case','observer','required_profile','samples','metric','mean_us','median_us','min_us','max_us','stdev_us']
write_header = not out.exists()
with out.open('a', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=fields)
    if write_header: writer.writeheader()
    for index, metric in enumerate(['posthoc_duration','ebpf_correlation_duration','observer_total_duration']):
        series = [row[index] for row in values]
        writer.writerow({
            'case': name, 'observer': observer, 'required_profile': required,
            'samples': len(series), 'metric': metric,
            'mean_us': f'{statistics.mean(series):.3f}',
            'median_us': f'{statistics.median(series):.3f}',
            'min_us': min(series), 'max_us': max(series),
            'stdev_us': f'{statistics.stdev(series) if len(series)>1 else 0:.3f}',
        })
PY
}

run_case posthoc posthoc posthoc -f docker-compose.yml
run_case hybrid hybrid hybrid -f docker-compose.yml -f docker-compose.ebpf.yml

cat "$OUT"
echo "csv=$OUT"
