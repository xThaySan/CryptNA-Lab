# History-bound evaluation workflow

Run the experiments from the repository root.

Capture the exact source revision and software/hardware environment first:

```bash
./scripts/capture_environment.sh
```

```bash
./scripts/test_history_negative_unit.sh
./scripts/test_history_hash_chain_unit.sh
./scripts/test_attested_xfrm_end_to_end.sh
./experiments/06_history_microbench.sh
TRIALS=10 N=1000 WARMUP=20 ./experiments/12_attested_latency_repeated_trials.sh
./experiments/08_history_token_size.sh
TRIALS=10 N=50 WARMUP=3 ./experiments/11_xfrm_apply_repeated_trials.sh
N=30 WARMUP=3 ./experiments/13_xfrm_observer_cost.sh
./experiments/14_multi_pep_appraisal.sh
./experiments/09_summarize_history_results.sh
```

The first two scripts validate the negative and structural tests. The measurement
scripts retain raw data for every independent trial. The last script produces
figure-ready CSV files and a short Markdown summary. A trial containing any
failed handshake is rejected rather than partially aggregated. The summary step
also refuses stale single-run files or campaigns with fewer than ten successful
paired trials.

Main output files:

```text
experiments/results/06_history_microbench.csv
experiments/results/07_attested_latency_compare_summary.csv
experiments/results/08_history_token_size.csv
experiments/results/09_microbench_summary.csv
experiments/results/09_latency_overhead.csv
experiments/results/09_size_breakdown.csv
experiments/results/09_multi_pep_summary.csv
experiments/results/09_history_evaluation_summary.md
experiments/results/10_xfrm_apply_latency_compare_summary.csv
experiments/results/11_xfrm_apply_repeated_trials_status.csv
experiments/results/12_attested_latency_repeated_trials.csv
experiments/results/12_attested_latency_repeated_trials_aggregate.csv
experiments/results/12_attested_latency_repeated_trials_status.csv
experiments/results/13_xfrm_observer_cost.csv
experiments/results/14_multi_pep_appraisal_raw.txt
```

Methodology defaults:

- History microbenchmarks use a one-second Go benchmark window and ten independent repetitions.
- Dry-run latency uses ten paired trials, 20 unmeasured warm-up requests per case, and 1000 measured sequential requests per case; case order alternates by trial. Both cases set `PEP_STATE_PERSISTENCE_ENABLED=0`, so this benchmark isolates the in-memory authorization path from the prototype's unoptimized JSON crash-recovery snapshot I/O. Durable PEP state remains enabled by default in normal and end-to-end runs.
- Real XFRM validation uses ten paired trials, three unmeasured warm-up requests per case, and 50 measured requests per case; case order alternates by trial.
- Readiness checks complete before warm-up begins; startup time is not counted.
- The dry-run client pool is a `/16`, so all 1000 assigned inner addresses are syntactically valid and in scope.
- One completed synthetic session occupies six lifecycle events (apply intent, apply observation, activation, expiry, delete intent, and delete observation). Thus the 100- and 1000-event appraisal cases contain 16 and 166 completed lifecycles plus four management events. At a 30-second renewal cadence this is approximately 0.5 and 5.5 completed lifecycles/s per PEP; other renewal cadences scale these rates inversely.
- Keep `VERIFIER_TOKEN_TTL_SECONDS=25` only when explicitly testing checkpoint renewal behavior.

For a diagnostic storage-inclusive pair, run `PEP_STATE_PERSISTENCE=1 ./experiments/07_attested_latency_compare.sh`. That mode exercises the inspectability-oriented full-JSON snapshot implementation and is deliberately excluded from the authorization-path headline; do not combine its results with experiment 12.


## Real XFRM apply latency

`experiments/10_xfrm_apply_latency_compare.sh` measures the same sequential handshake path as experiment 07, but with `XFRM_MODE=apply`. This includes real client-side and PEP-side `ip xfrm` state/policy installation. Use a smaller default run count (`N=50`) because each run creates real kernel XFRM state before cleanup.

Interpretation rule: experiment 07 isolates the in-memory authorization path with dry-run XFRM and PEP JSON persistence disabled in both cases, while experiment 10 includes kernel XFRM installation and durable PEP-state overhead.

## Optional stability run for real XFRM apply

The real XFRM apply experiment is more sensitive to kernel and container scheduling noise than the dry-run authorization benchmark. To avoid overinterpreting a single run, use repeated trials when preparing paper figures:

```bash
TRIALS=10 N=50 WARMUP=3 ./experiments/11_xfrm_apply_repeated_trials.sh
```

This produces:

```text
experiments/results/11_xfrm_apply_repeated_trials.csv
experiments/results/11_xfrm_apply_repeated_trials_overhead.csv
experiments/results/11_xfrm_apply_repeated_trials_aggregate.csv
```

Use the paired aggregate table for reporting, include inter-trial standard
deviation, and treat p95/p99 as exploratory. `BenchmarkVerifyHistoryEvidence`
is the cryptographic chain/checkpoint cost, `BenchmarkVerifyEnforcementPolicy`
is the semantic lifecycle cost, and `BenchmarkVerifyFullHistoryAppraisal` is
the combined Verifier operation; these labels must not be conflated.
