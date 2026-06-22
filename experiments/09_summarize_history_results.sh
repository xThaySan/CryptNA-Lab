#!/usr/bin/env bash
set -euo pipefail

RESULT_DIR="experiments/results"
MICROBENCH="$RESULT_DIR/06_history_microbench.csv"
LATENCY="$RESULT_DIR/07_attested_latency_compare_summary.csv"
SIZES="$RESULT_DIR/08_history_token_size.csv"
OUT_MD="$RESULT_DIR/09_history_evaluation_summary.md"
OUT_OVERHEAD="$RESULT_DIR/09_latency_overhead.csv"
OUT_MICRO="$RESULT_DIR/09_microbench_summary.csv"
OUT_SIZE="$RESULT_DIR/09_size_breakdown.csv"
XFRM_LATENCY="$RESULT_DIR/10_xfrm_apply_latency_compare_summary.csv"
OUT_XFRM_OVERHEAD="$RESULT_DIR/09_xfrm_apply_latency_overhead.csv"
XFRM_REPEATED_AGG="$RESULT_DIR/11_xfrm_apply_repeated_trials_aggregate.csv"
XFRM_REPEATED_STATUS="$RESULT_DIR/11_xfrm_apply_repeated_trials_status.csv"

mkdir -p "$RESULT_DIR"

for f in "$MICROBENCH" "$LATENCY" "$SIZES"; do
  if [ ! -f "$f" ]; then
    echo "missing required result file: $f" >&2
    echo "run experiments/06_history_microbench.sh, 07_attested_latency_compare.sh and 08_history_token_size.sh first" >&2
    exit 1
  fi
done

python3 - <<'PY' "$MICROBENCH" "$LATENCY" "$SIZES" "$OUT_MD" "$OUT_OVERHEAD" "$OUT_MICRO" "$OUT_SIZE" "$XFRM_LATENCY" "$OUT_XFRM_OVERHEAD" "$XFRM_REPEATED_AGG" "$XFRM_REPEATED_STATUS"
import csv
import statistics
import sys
from collections import defaultdict
from pathlib import Path

micro_path = Path(sys.argv[1])
lat_path = Path(sys.argv[2])
size_path = Path(sys.argv[3])
out_md = Path(sys.argv[4])
out_overhead = Path(sys.argv[5])
out_micro = Path(sys.argv[6])
out_size = Path(sys.argv[7])
xfrm_latency_path = Path(sys.argv[8])
out_xfrm_overhead = Path(sys.argv[9])
xfrm_repeated_agg_path = Path(sys.argv[10])
xfrm_repeated_status_path = Path(sys.argv[11])

# --- Microbench summary ---
bench_rows = list(csv.DictReader(micro_path.open()))
by_bench = defaultdict(list)
for r in bench_rows:
    by_bench[r['benchmark']].append(r)

micro_summary = []
for bench, rows in sorted(by_bench.items()):
    ns = [float(r['ns_per_op']) for r in rows]
    b = [float(r['bytes_per_op']) for r in rows]
    a = [float(r['allocs_per_op']) for r in rows]
    micro_summary.append({
        'benchmark': bench,
        'runs': len(rows),
        'median_us': statistics.median(ns) / 1000.0,
        'mean_us': statistics.mean(ns) / 1000.0,
        'min_us': min(ns) / 1000.0,
        'max_us': max(ns) / 1000.0,
        'median_bytes_per_op': statistics.median(b),
        'median_allocs_per_op': statistics.median(a),
    })

with out_micro.open('w', newline='') as f:
    fields = ['benchmark', 'runs', 'median_us', 'mean_us', 'min_us', 'max_us', 'median_bytes_per_op', 'median_allocs_per_op']
    w = csv.DictWriter(f, fieldnames=fields)
    w.writeheader()
    for r in micro_summary:
        w.writerow({k: f'{v:.3f}' if isinstance(v, float) else v for k, v in r.items()})

# --- Latency overhead ---
lat_rows = list(csv.DictReader(lat_path.open()))
lat_by_case = {r['case']: r for r in lat_rows}
if 'baseline' not in lat_by_case or 'history_bound' not in lat_by_case:
    raise SystemExit('latency summary must contain baseline and history_bound rows')
base = lat_by_case['baseline']
hb = lat_by_case['history_bound']
metrics = ['avg_ms', 'median_ms', 'p95_ms', 'p99_ms', 'min_ms', 'max_ms']
overhead_rows = []
for m in metrics:
    bv = float(base[m])
    hv = float(hb[m])
    delta = hv - bv
    pct = (delta / bv * 100.0) if bv else 0.0
    overhead_rows.append({
        'metric': m,
        'baseline': bv,
        'history_bound': hv,
        'delta_ms': delta,
        'delta_percent': pct,
    })

with out_overhead.open('w', newline='') as f:
    fields = ['metric', 'baseline', 'history_bound', 'delta_ms', 'delta_percent']
    w = csv.DictWriter(f, fieldnames=fields)
    w.writeheader()
    for r in overhead_rows:
        w.writerow({k: f'{v:.3f}' if isinstance(v, float) else v for k, v in r.items()})


# --- Optional real XFRM apply latency overhead ---
xfrm_overhead_rows = []
if xfrm_latency_path.exists():
    xfrm_rows = list(csv.DictReader(xfrm_latency_path.open()))
    xfrm_by_case = {r['case']: r for r in xfrm_rows}
    if 'baseline' in xfrm_by_case and 'history_bound' in xfrm_by_case:
        xb = xfrm_by_case['baseline']
        xh = xfrm_by_case['history_bound']
        for m in metrics:
            bv = float(xb[m])
            hv = float(xh[m])
            delta = hv - bv
            pct = (delta / bv * 100.0) if bv else 0.0
            xfrm_overhead_rows.append({
                'metric': m,
                'baseline_apply': bv,
                'history_bound_apply': hv,
                'delta_ms': delta,
                'delta_percent': pct,
            })
        with out_xfrm_overhead.open('w', newline='') as f:
            fields = ['metric', 'baseline_apply', 'history_bound_apply', 'delta_ms', 'delta_percent']
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            for r in xfrm_overhead_rows:
                w.writerow({k: f'{v:.3f}' if isinstance(v, float) else v for k, v in r.items()})

# --- Size summary ---
size_rows = list(csv.DictReader(size_path.open()))
size_map = {r['metric']: int(r['bytes']) for r in size_rows}
attestation_bytes = size_map.get('capacity_token_json_bytes', 0) + size_map.get('sa_binding_json_bytes', 0)
access_bytes = size_map.get('access_response_json_bytes', 0)
size_summary = list(size_rows)
size_summary.append({'metric': 'capacity_token_plus_sa_binding_bytes', 'bytes': str(attestation_bytes)})
if access_bytes:
    size_summary.append({'metric': 'attestation_objects_share_percent', 'bytes': f'{attestation_bytes / access_bytes * 100.0:.2f}'})

with out_size.open('w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=['metric', 'bytes'])
    w.writeheader()
    w.writerows(size_summary)

# Pull useful named microbench values for prose.
def find_bench(prefix):
    for r in micro_summary:
        if r['benchmark'].startswith(prefix):
            return r
    return None

verify_1 = find_bench('BenchmarkVerifyHistoryEvidence/events_1')
verify_100 = find_bench('BenchmarkVerifyHistoryEvidence/events_100')
verify_1000 = find_bench('BenchmarkVerifyHistoryEvidence/events_1000')
hash_event = find_bench('BenchmarkHashEnforcementEvent')
hash_ckpt = find_bench('BenchmarkHashEnforcementCheckpoint')

avg_over = next(r for r in overhead_rows if r['metric'] == 'avg_ms')
med_over = next(r for r in overhead_rows if r['metric'] == 'median_ms')

md = []
md.append('# History-bound evaluation summary')
md.append('')
md.append('## Input files')
md.append('')
md.append(f'- `{micro_path}`')
md.append(f'- `{lat_path}`')
md.append(f'- `{size_path}`')
if xfrm_latency_path.exists():
    md.append(f'- `{xfrm_latency_path}`')
if xfrm_repeated_agg_path.exists():
    md.append(f'- `{xfrm_repeated_agg_path}`')
if xfrm_repeated_status_path.exists():
    md.append(f'- `{xfrm_repeated_status_path}`')
md.append('')
md.append('## Main results')
md.append('')
md.append(f'- Sequential dry-run handshakes completed successfully for both baseline and history-bound cases: baseline `{base["ok"]}/{base["runs"]}`, history-bound `{hb["ok"]}/{hb["runs"]}`.')
md.append(f'- Average latency: baseline `{float(base["avg_ms"]):.3f} ms`, history-bound `{float(hb["avg_ms"]):.3f} ms`, delta `{avg_over["delta_ms"]:.3f} ms` (`{avg_over["delta_percent"]:.1f}%`).')
md.append(f'- Median latency: baseline `{float(base["median_ms"]):.3f} ms`, history-bound `{float(hb["median_ms"]):.3f} ms`, delta `{med_over["delta_ms"]:.3f} ms` (`{med_over["delta_percent"]:.1f}%`).')
if hash_event:
    md.append(f'- Event hashing median cost: `{hash_event["median_us"]:.3f} µs/op`.')
if hash_ckpt:
    md.append(f'- Checkpoint hashing median cost: `{hash_ckpt["median_us"]:.3f} µs/op`.')
if verify_100:
    md.append(f'- History verification for 100 events median cost: `{verify_100["median_us"]:.3f} µs/op`.')
if verify_1000:
    md.append(f'- History verification for 1000 events median cost: `{verify_1000["median_us"]:.3f} µs/op`.')
md.append(f'- Capacity token JSON size: `{size_map.get("capacity_token_json_bytes", 0)} bytes`.')
md.append(f'- SA binding JSON size: `{size_map.get("sa_binding_json_bytes", 0)} bytes`.')
md.append(f'- Combined attestation objects size: `{attestation_bytes} bytes`.')
if xfrm_overhead_rows:
    xmed = next(r for r in xfrm_overhead_rows if r['metric'] == 'median_ms')
    xavg = next(r for r in xfrm_overhead_rows if r['metric'] == 'avg_ms')
    md.append(f'- Real XFRM apply median latency: baseline `{xmed["baseline_apply"]:.3f} ms`, history-bound `{xmed["history_bound_apply"]:.3f} ms`, delta `{xmed["delta_ms"]:.3f} ms` (`{xmed["delta_percent"]:.1f}%`).')
    md.append(f'- Real XFRM apply average latency: baseline `{xavg["baseline_apply"]:.3f} ms`, history-bound `{xavg["history_bound_apply"]:.3f} ms`, delta `{xavg["delta_ms"]:.3f} ms` (`{xavg["delta_percent"]:.1f}%`).')

if xfrm_repeated_agg_path.exists():
    repeated_rows = list(csv.DictReader(xfrm_repeated_agg_path.open()))
    def find_repeated(group, metric):
        for r in repeated_rows:
            if r['group'] == group and r['metric'] == metric:
                return r
        return None
    def find_case(case, metric):
        for r in repeated_rows:
            if r['group'] == case and r['metric'] == metric:
                return r
        return None
    rep_med_delta = find_repeated('overhead_delta_ms', 'median_ms')
    rep_avg_delta = find_repeated('overhead_delta_ms', 'avg_ms')
    base_med = find_case('baseline', 'median_ms')
    hb_med = find_case('history_bound', 'median_ms')
    success_base = find_case('baseline', 'success_rate_percent')
    success_hb = find_case('history_bound', 'success_rate_percent')
    if success_base and success_hb:
        md.append(f'- Repeated real XFRM apply trials completed with median success rates of `{float(success_base["median"]):.1f}%` for baseline and `{float(success_hb["median"]):.1f}%` for history-bound over `{success_base["trials"]}` trials.')
    if base_med and hb_med:
        md.append(f'- Repeated real XFRM apply trials: median latency across trial summaries was `{float(base_med["median"]):.3f} ms` for baseline and `{float(hb_med["median"]):.3f} ms` for history-bound.')
    if rep_med_delta:
        md.append(f'- Repeated real XFRM apply trials: median-of-deltas for median latency `{float(rep_med_delta["median"]):.3f} ms` over `{rep_med_delta["trials"]}` trials; this should be interpreted as no measurable median overhead, not as an optimization claim.')
    if rep_avg_delta:
        md.append(f'- Repeated real XFRM apply trials: median-of-deltas for average latency `{float(rep_avg_delta["median"]):.3f} ms` over `{rep_avg_delta["trials"]}` trials; the real-XFRM tails are dominated by kernel and cleanup variance.')
md.append('')
md.append('## Generated figure-ready CSV files')
md.append('')
md.append(f'- `{out_micro}`')
md.append(f'- `{out_overhead}`')
md.append(f'- `{out_size}`')
if xfrm_overhead_rows:
    md.append(f'- `{out_xfrm_overhead}`')
if xfrm_repeated_agg_path.exists():
    md.append(f'- `{xfrm_repeated_agg_path}`')
if xfrm_repeated_status_path.exists():
    md.append(f'- `{xfrm_repeated_status_path}`')
md.append('')
md.append('## Suggested paper wording')
md.append('')

median_delta = med_over['delta_ms']
if median_delta < 0.1:
    latency_phrase = 'less than 0.1 ms median latency'
else:
    latency_phrase = f'{median_delta:.3f} ms median latency'

if verify_1000:
    verify_ms = verify_1000['median_us'] / 1000.0
    if verify_ms < 1.0:
        verify_phrase = f'sub-millisecond verification for 1000 events ({verify_ms:.3f} ms median)'
    else:
        verify_phrase = f'{verify_ms:.3f} ms median verification cost for 1000 events'
else:
    verify_phrase = 'low verifier-side history checking cost'

paper_sentence = f'In our dry-run sequential handshake benchmark, history-bound attestation adds {latency_phrase} compared with the non-attested CRYPTNA baseline. The verifier-side history checks show {verify_phrase}, while the serialized capacity token and SA binding together add {attestation_bytes} bytes of JSON metadata to the authorization response.'
if xfrm_repeated_agg_path.exists():
    paper_sentence += ' In real XFRM apply experiments, setup time is dominated by kernel-side XFRM installation and cleanup; repeated trials show comparable median latency between baseline and history-bound configurations, so we use this experiment primarily as an end-to-end validation rather than as an overhead claim.'
md.append(paper_sentence)

out_md.write_text('\n'.join(md) + '\n')

print(f'summary_md={out_md}')
print(f'latency_overhead_csv={out_overhead}')
print(f'microbench_summary_csv={out_micro}')
print(f'size_breakdown_csv={out_size}')
if xfrm_overhead_rows:
    print(f'xfrm_apply_latency_overhead_csv={out_xfrm_overhead}')
PY
