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
DRY_REPEATED_AGG="$RESULT_DIR/12_attested_latency_repeated_trials_aggregate.csv"
DRY_REPEATED="$RESULT_DIR/12_attested_latency_repeated_trials.csv"
DRY_REPEATED_STATUS="$RESULT_DIR/12_attested_latency_repeated_trials_status.csv"
OBSERVER_COST="$RESULT_DIR/13_xfrm_observer_cost.csv"
MULTI_PEP_RAW="$RESULT_DIR/14_multi_pep_appraisal_raw.txt"
ENVIRONMENT="$RESULT_DIR/environment.txt"
OUT_MULTI_PEP="$RESULT_DIR/09_multi_pep_summary.csv"

mkdir -p "$RESULT_DIR"
rm -f \
  "$OUT_MD" \
  "$OUT_OVERHEAD" \
  "$OUT_MICRO" \
  "$OUT_SIZE" \
  "$OUT_XFRM_OVERHEAD" \
  "$OUT_MULTI_PEP"

for f in \
  "$MICROBENCH" \
  "$LATENCY" \
  "$SIZES" \
  "$XFRM_REPEATED_AGG" \
  "$XFRM_REPEATED_STATUS" \
  "$DRY_REPEATED_AGG" \
  "$DRY_REPEATED" \
  "$DRY_REPEATED_STATUS" \
  "$OBSERVER_COST" \
  "$MULTI_PEP_RAW" \
  "$ENVIRONMENT"; do
  if [ ! -f "$f" ]; then
    echo "missing required result file: $f" >&2
    echo "the official evaluation campaign is incomplete; rerun the documented workflow before summarizing" >&2
    exit 1
  fi
done

python3 - <<'PY' "$MICROBENCH" "$LATENCY" "$SIZES" "$OUT_MD" "$OUT_OVERHEAD" "$OUT_MICRO" "$OUT_SIZE" "$XFRM_LATENCY" "$OUT_XFRM_OVERHEAD" "$XFRM_REPEATED_AGG" "$XFRM_REPEATED_STATUS" "$DRY_REPEATED_AGG" "$DRY_REPEATED" "$DRY_REPEATED_STATUS" "$OBSERVER_COST" "$MULTI_PEP_RAW" "$ENVIRONMENT" "$OUT_MULTI_PEP"
import csv
import re
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
dry_repeated_agg_path = Path(sys.argv[12])
dry_repeated_path = Path(sys.argv[13])
dry_repeated_status_path = Path(sys.argv[14])
observer_cost_path = Path(sys.argv[15])
multi_pep_raw_path = Path(sys.argv[16])
environment_path = Path(sys.argv[17])
out_multi_pep = Path(sys.argv[18])

expected_trials = 10
expected_dry_n = 1000
expected_dry_warmup = 20

def read_rows(path):
    rows = list(csv.DictReader(path.open()))
    if not rows:
        raise SystemExit(f'empty required result file: {path}')
    return rows

def validate_status(path, expected):
    rows = read_rows(path)
    if len(rows) != expected:
        raise SystemExit(f'{path}: expected {expected} status rows, got {len(rows)}')
    expected_ids = list(range(1, expected + 1))
    trial_ids = [int(row['trial']) for row in rows]
    if trial_ids != expected_ids:
        raise SystemExit(f'{path}: unexpected trial identifiers {trial_ids}')
    failed = [row for row in rows if int(row['status']) != 0]
    if failed:
        raise SystemExit(f'{path}: failed trials present: {failed}')

validate_status(xfrm_repeated_status_path, expected_trials)
validate_status(dry_repeated_status_path, expected_trials)

dry_trial_rows = read_rows(dry_repeated_path)
dry_by_trial = defaultdict(dict)
for row in dry_trial_rows:
    dry_by_trial[int(row['trial'])][row['case']] = row
if sorted(dry_by_trial) != list(range(1, expected_trials + 1)):
    raise SystemExit('dry-run repeated campaign does not contain all expected trials')
for trial, cases in dry_by_trial.items():
    if set(cases) != {'baseline', 'history_bound'}:
        raise SystemExit(f'dry-run trial {trial} is not a complete pair')
    for case, row in cases.items():
        if row.get('pep_state_persistence') != 'disabled':
            raise SystemExit(f'dry-run trial {trial}/{case} did not use the declared authorization-path configuration')
        if int(row['runs']) != expected_dry_n or int(row['warmup_runs']) != expected_dry_warmup:
            raise SystemExit(f'dry-run trial {trial}/{case} has unexpected run or warm-up count')
        if int(row['failed']) != 0 or int(row['ok']) != expected_dry_n:
            raise SystemExit(f'dry-run trial {trial}/{case} contains failed handshakes')

dry_rows = read_rows(dry_repeated_agg_path)
dry_index = {(row['group'], row['metric']): row for row in dry_rows}
for group in ('baseline', 'history_bound', 'paired_delta_ms'):
    for metric in ('avg_ms', 'median_ms', 'p95_ms', 'p99_ms'):
        row = dry_index.get((group, metric))
        if row is None:
            raise SystemExit(f'missing dry-run aggregate row {group}/{metric}')
        if row.get('pep_state_persistence') != 'disabled':
            raise SystemExit(f'invalid dry-run persistence metadata for {group}/{metric}')
        if int(row['trials']) != expected_trials or int(row['N_per_trial']) != expected_dry_n or int(row['warmup_per_case']) != expected_dry_warmup:
            raise SystemExit(f'invalid dry-run aggregate metadata for {group}/{metric}')

# --- Microbench summary ---
bench_rows = read_rows(micro_path)
by_bench = defaultdict(list)
for r in bench_rows:
    by_bench[r['benchmark']].append(r)
if any(len(rows) != expected_trials for rows in by_bench.values()):
    raise SystemExit('microbenchmark results do not contain ten repetitions per benchmark')

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

# --- Paired dry-run latency overhead ---
# The 07 summary is the final pair from experiment 12. Validate its schema so a
# stale pre-repetition file cannot be silently combined with a new campaign.
lat_rows = read_rows(lat_path)
required_latency_fields = {'case', 'pep_state_persistence', 'case_order', 'runs', 'warmup_runs', 'ok', 'failed'}
if not required_latency_fields.issubset(lat_rows[0]):
    raise SystemExit(f'{lat_path}: stale or incompatible latency summary schema')
lat_by_case = {r['case']: r for r in lat_rows}
if 'baseline' not in lat_by_case or 'history_bound' not in lat_by_case:
    raise SystemExit('latency summary must contain baseline and history_bound rows')
for case in ('baseline', 'history_bound'):
    row = lat_by_case[case]
    if row['pep_state_persistence'] != 'disabled':
        raise SystemExit(f'{lat_path}: final {case} pair did not disable PEP JSON state persistence')
    if int(row['runs']) != expected_dry_n or int(row['warmup_runs']) != expected_dry_warmup or int(row['failed']) != 0:
        raise SystemExit(f'{lat_path}: final {case} pair is incomplete')

metrics = ['avg_ms', 'median_ms', 'p95_ms', 'p99_ms']
overhead_rows = []
for m in metrics:
    bv = float(dry_index[('baseline', m)]['median'])
    hv = float(dry_index[('history_bound', m)]['median'])
    delta = float(dry_index[('paired_delta_ms', m)]['median'])
    pct = (delta / bv * 100.0) if bv else 0.0
    overhead_rows.append({
        'metric': m,
        'pep_state_persistence': 'disabled',
        'baseline': bv,
        'history_bound': hv,
        'delta_ms': delta,
        'delta_percent': pct,
        'trials': expected_trials,
        'N_per_trial': expected_dry_n,
        'warmup_per_case': expected_dry_warmup,
        'delta_stdev_ms': float(dry_index[('paired_delta_ms', m)]['stdev']),
    })

with out_overhead.open('w', newline='') as f:
    fields = ['metric', 'pep_state_persistence', 'baseline', 'history_bound', 'delta_ms', 'delta_percent', 'trials', 'N_per_trial', 'warmup_per_case', 'delta_stdev_ms']
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
size_rows = read_rows(size_path)
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

# --- Concurrent multi-PEP appraisal summary ---
multi_re = re.compile(
    r'^BenchmarkConcurrentPEPAppraisal/peps_(\d+)_events_(\d+)-\d+\s+'
    r'\d+\s+([0-9.]+)\s+ns/op\s+([0-9.]+)\s+B/op\s+([0-9.]+)\s+allocs/op$'
)
multi_values = defaultdict(list)
for line in multi_pep_raw_path.read_text().splitlines():
    match = multi_re.match(line.strip())
    if not match:
        continue
    peps, events, ns_op, bytes_op, allocs_op = match.groups()
    multi_values[(int(peps), int(events))].append((float(ns_op), float(bytes_op), float(allocs_op)))
if sorted(multi_values) != [(1, 100), (10, 100), (100, 100)]:
    raise SystemExit(f'unexpected multi-PEP benchmark groups: {sorted(multi_values)}')

multi_summary = []
for (peps, events), values in sorted(multi_values.items()):
    if len(values) != expected_trials:
        raise SystemExit(f'multi-PEP benchmark peps={peps}: expected ten repetitions, got {len(values)}')
    ns = [value[0] for value in values]
    bytes_op = [value[1] for value in values]
    allocs_op = [value[2] for value in values]
    total_median_us = statistics.median(ns) / 1000.0
    multi_summary.append({
        'peps': peps,
        'events_per_pep': events,
        'runs': len(values),
        'total_median_us': total_median_us,
        'total_mean_us': statistics.mean(ns) / 1000.0,
        'total_min_us': min(ns) / 1000.0,
        'total_max_us': max(ns) / 1000.0,
        'total_stdev_us': statistics.stdev(ns) / 1000.0,
        'median_us_per_pep': total_median_us / peps,
        'median_bytes_per_op': statistics.median(bytes_op),
        'median_allocs_per_op': statistics.median(allocs_op),
    })

with out_multi_pep.open('w', newline='') as f:
    fields = ['peps', 'events_per_pep', 'runs', 'total_median_us', 'total_mean_us', 'total_min_us', 'total_max_us', 'total_stdev_us', 'median_us_per_pep', 'median_bytes_per_op', 'median_allocs_per_op']
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()
    for row in multi_summary:
        writer.writerow({key: f'{value:.3f}' if isinstance(value, float) else value for key, value in row.items()})

# Pull useful named microbench values for prose.
def find_bench(prefix):
    for r in micro_summary:
        if r['benchmark'].startswith(prefix):
            return r
    return None

verify_1 = find_bench('BenchmarkVerifyHistoryEvidence/events_1')
verify_100 = find_bench('BenchmarkVerifyHistoryEvidence/events_100')
verify_1000 = find_bench('BenchmarkVerifyHistoryEvidence/events_1000')
full_100 = find_bench('BenchmarkVerifyFullHistoryAppraisal/events_100')
full_1000 = find_bench('BenchmarkVerifyFullHistoryAppraisal/events_1000')
hash_event = find_bench('BenchmarkHashEnforcementEvent')
hash_ckpt = find_bench('BenchmarkHashEnforcementCheckpoint')

avg_over = next(r for r in overhead_rows if r['metric'] == 'avg_ms')
med_over = next(r for r in overhead_rows if r['metric'] == 'median_ms')
dry_total_per_case = expected_trials * expected_dry_n
dry_base_avg = float(dry_index[('baseline', 'avg_ms')]['median'])
dry_history_avg = float(dry_index[('history_bound', 'avg_ms')]['median'])
dry_base_median = float(dry_index[('baseline', 'median_ms')]['median'])
dry_history_median = float(dry_index[('history_bound', 'median_ms')]['median'])

md = []
md.append('# History-bound evaluation summary')
md.append('')
md.append('## Input files')
md.append('')
md.append(f'- `{micro_path}`')
md.append(f'- `{lat_path}`')
md.append(f'- `{size_path}`')
md.append(f'- `{dry_repeated_path}`')
md.append(f'- `{dry_repeated_agg_path}`')
md.append(f'- `{dry_repeated_status_path}`')
md.append(f'- `{environment_path}`')
if xfrm_latency_path.exists():
    md.append(f'- `{xfrm_latency_path}`')
if xfrm_repeated_agg_path.exists():
    md.append(f'- `{xfrm_repeated_agg_path}`')
if xfrm_repeated_status_path.exists():
    md.append(f'- `{xfrm_repeated_status_path}`')
if observer_cost_path.exists():
    md.append(f'- `{observer_cost_path}`')
if multi_pep_raw_path.exists():
    md.append(f'- `{multi_pep_raw_path}`')
md.append('')
md.append('## Main results')
md.append('')
md.append(f'- Ten paired dry-run trials completed successfully: baseline `{dry_total_per_case}/{dry_total_per_case}`, history-bound `{dry_total_per_case}/{dry_total_per_case}`, with `{expected_dry_warmup}` unmeasured warm-up requests per case and trial.')
md.append('- The paired dry-run benchmark disables PEP JSON state persistence in both cases; it measures the in-memory authorization path and excludes crash-recovery snapshot I/O.')
md.append(f'- Across paired trial summaries, average latency medians were baseline `{dry_base_avg:.3f} ms` and history-bound `{dry_history_avg:.3f} ms`; the median paired delta was `{avg_over["delta_ms"]:.3f} ms` with inter-trial standard deviation `{avg_over["delta_stdev_ms"]:.3f} ms`.')
md.append(f'- Across paired trial summaries, latency medians were baseline `{dry_base_median:.3f} ms` and history-bound `{dry_history_median:.3f} ms`; the median paired delta was `{med_over["delta_ms"]:.3f} ms` (`{med_over["delta_percent"]:.1f}%` relative to the baseline trial-summary median), with inter-trial standard deviation `{med_over["delta_stdev_ms"]:.3f} ms`.')
if hash_event:
    md.append(f'- Event hashing median cost: `{hash_event["median_us"]:.3f} µs/op`.')
if hash_ckpt:
    md.append(f'- Checkpoint hashing median cost: `{hash_ckpt["median_us"]:.3f} µs/op`.')
if verify_100:
    md.append(f'- Cryptographic chain and checkpoint verification for 100 events median cost: `{verify_100["median_us"]:.3f} µs/op`.')
if verify_1000:
    md.append(f'- Cryptographic chain and checkpoint verification for 1000 events median cost: `{verify_1000["median_us"]:.3f} µs/op`.')
if full_100:
    md.append(f'- Full cryptographic and semantic appraisal for 100 events median cost: `{full_100["median_us"]:.3f} µs/op`.')
if full_1000:
    md.append(f'- Full cryptographic and semantic appraisal for 1000 events median cost: `{full_1000["median_us"]:.3f} µs/op`.')
md.append(f'- Capacity token JSON size: `{size_map.get("capacity_token_json_bytes", 0)} bytes`.')
md.append(f'- SA binding JSON size: `{size_map.get("sa_binding_json_bytes", 0)} bytes`.')
md.append(f'- Combined attestation objects size: `{attestation_bytes} bytes`.')
if xfrm_overhead_rows:
    xmed = next(r for r in xfrm_overhead_rows if r['metric'] == 'median_ms')
    xavg = next(r for r in xfrm_overhead_rows if r['metric'] == 'avg_ms')
    md.append(f'- Real XFRM apply median latency: baseline `{xmed["baseline_apply"]:.3f} ms`, history-bound `{xmed["history_bound_apply"]:.3f} ms`, delta `{xmed["delta_ms"]:.3f} ms` (`{xmed["delta_percent"]:.1f}%`).')
    md.append(f'- Real XFRM apply average latency: baseline `{xavg["baseline_apply"]:.3f} ms`, history-bound `{xavg["history_bound_apply"]:.3f} ms`, delta `{xavg["delta_ms"]:.3f} ms` (`{xavg["delta_percent"]:.1f}%`).')

if xfrm_repeated_agg_path.exists():
    repeated_rows = read_rows(xfrm_repeated_agg_path)
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
    required_xfrm_rows = [rep_med_delta, rep_avg_delta, base_med, hb_med, success_base, success_hb]
    if any(row is None for row in required_xfrm_rows):
        raise SystemExit('repeated XFRM aggregate is incomplete')
    if any(int(row['trials']) != expected_trials for row in required_xfrm_rows):
        raise SystemExit('repeated XFRM aggregate does not contain ten completed trials')
    if success_base and success_hb:
        md.append(f'- Repeated real XFRM apply trials completed with median success rates of `{float(success_base["median"]):.1f}%` for baseline and `{float(success_hb["median"]):.1f}%` for history-bound over `{success_base["trials"]}` trials.')
    if base_med and hb_med:
        md.append(f'- Repeated real XFRM apply trials: median latency across trial summaries was `{float(base_med["median"]):.3f} ms` for baseline and `{float(hb_med["median"]):.3f} ms` for history-bound.')
    if rep_med_delta:
        md.append(f'- Repeated real XFRM apply trials: median paired delta for median latency `{float(rep_med_delta["median"]):.3f} ms` with inter-trial standard deviation `{float(rep_med_delta["stdev"]):.3f} ms` over `{rep_med_delta["trials"]}` trials; the magnitude should be interpreted cautiously because kernel and cleanup variance dominate the tails.')
    if rep_avg_delta:
        md.append(f'- Repeated real XFRM apply trials: median paired delta for average latency `{float(rep_avg_delta["median"]):.3f} ms` with inter-trial standard deviation `{float(rep_avg_delta["stdev"]):.3f} ms`.')

observer_rows = read_rows(observer_cost_path)
observer_index = {(row['case'], row['metric']): row for row in observer_rows}
for key in (
    ('posthoc', 'observer_total_duration'),
    ('hybrid', 'posthoc_duration'),
    ('hybrid', 'ebpf_correlation_duration'),
    ('hybrid', 'observer_total_duration'),
):
    if key not in observer_index:
        raise SystemExit(f'missing observer cost row {key}')
posthoc_total = observer_index[('posthoc', 'observer_total_duration')]
hybrid_posthoc = observer_index[('hybrid', 'posthoc_duration')]
hybrid_ebpf = observer_index[('hybrid', 'ebpf_correlation_duration')]
hybrid_total = observer_index[('hybrid', 'observer_total_duration')]
md.append(f'- Standalone posthoc exact XFRM inspection: median `{float(posthoc_total["median_us"]):.3f} µs` total over `{posthoc_total["samples"]}` measured applications.')
md.append(f'- Hybrid XFRM observation: posthoc inspection median `{float(hybrid_posthoc["median_us"]):.3f} µs`, isolated eBPF correlation median `{float(hybrid_ebpf["median_us"]):.3f} µs`, and total observer median `{float(hybrid_total["median_us"]):.3f} µs` over `{hybrid_total["samples"]}` measured applications; separate batches are not used to claim a speedup.')

multi_100 = next(row for row in multi_summary if row['peps'] == 100)
md.append(f'- Concurrent appraisal of 100 independent PEP histories with 100 events each: `{multi_100["total_median_us"] / 1000.0:.3f} ms` median total on the two-vCPU VM (`{multi_100["median_us_per_pep"]:.3f} µs` total-time equivalent per PEP), over `{multi_100["runs"]}` benchmark repetitions.')
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
md.append(f'- `{dry_repeated_agg_path}`')
md.append(f'- `{dry_repeated_status_path}`')
if observer_cost_path.exists():
    md.append(f'- `{observer_cost_path}`')
if multi_pep_raw_path.exists():
    md.append(f'- `{multi_pep_raw_path}`')
md.append(f'- `{out_multi_pep}`')
md.append('')
md.append('## Suggested paper wording')
md.append('')

median_delta = med_over['delta_ms']
latency_phrase = f'a {median_delta:.3f} ms median paired delta in median latency'

if full_1000:
    verify_ms = full_1000['median_us'] / 1000.0
    if verify_ms < 1.0:
        verify_phrase = f'sub-millisecond full cryptographic and semantic appraisal for 1000 events ({verify_ms:.3f} ms median)'
    else:
        verify_phrase = f'{verify_ms:.3f} ms median full cryptographic and semantic appraisal cost for 1000 events'
elif verify_1000:
    verify_ms = verify_1000['median_us'] / 1000.0
    verify_phrase = f'{verify_ms:.3f} ms median cryptographic chain-verification cost for 1000 events (semantic appraisal not measured in this run)'
else:
    verify_phrase = 'a separately measured verifier-side appraisal cost'

paper_sentence = f'Across ten paired dry-run trials of {expected_dry_n} measured handshakes per case, history-bound attestation produced {latency_phrase} compared with the non-attested CRYPTNA baseline. This authorization-path comparison disables PEP JSON state persistence in both cases and excludes crash-recovery snapshot I/O. The verifier measurements show {verify_phrase}, while the serialized capacity token and SA binding together add {attestation_bytes} bytes of JSON metadata to the authorization response.'
if xfrm_repeated_agg_path.exists():
    paper_sentence += f' In real XFRM apply experiments, setup time is dominated by kernel-side installation and cleanup; the median paired delta in median latency was {float(rep_med_delta["median"]):.3f} ms with {float(rep_med_delta["stdev"]):.3f} ms inter-trial standard deviation, so we use this experiment primarily as an end-to-end validation.'
paper_sentence += f' A concurrent local benchmark appraised 100 independent 100-event PEP histories in {multi_100["total_median_us"] / 1000.0:.3f} ms median total on the two-vCPU VM.'
md.append(paper_sentence)

out_md.write_text('\n'.join(md) + '\n')

print(f'summary_md={out_md}')
print(f'latency_overhead_csv={out_overhead}')
print(f'microbench_summary_csv={out_micro}')
print(f'size_breakdown_csv={out_size}')
print(f'multi_pep_summary_csv={out_multi_pep}')
if xfrm_overhead_rows:
    print(f'xfrm_apply_latency_overhead_csv={out_xfrm_overhead}')
PY
