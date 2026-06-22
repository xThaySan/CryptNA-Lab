# History-bound evaluation workflow

Run the experiments from the repository root.

```bash
./scripts/test_history_negative_unit.sh
./scripts/test_history_hash_chain_unit.sh
./experiments/06_history_microbench.sh
N=1000 ./experiments/07_attested_latency_compare.sh
./experiments/08_history_token_size.sh
N=50 ./experiments/10_xfrm_apply_latency_compare.sh
./experiments/09_summarize_history_results.sh
```

The first two scripts validate the negative and structural tests. The next three scripts generate raw measurements. The last script produces figure-ready CSV files and a short Markdown summary.

Main output files:

```text
experiments/results/06_history_microbench.csv
experiments/results/07_attested_latency_compare_summary.csv
experiments/results/08_history_token_size.csv
experiments/results/09_microbench_summary.csv
experiments/results/09_latency_overhead.csv
experiments/results/09_size_breakdown.csv
experiments/results/09_history_evaluation_summary.md
experiments/results/10_xfrm_apply_latency_compare_summary.csv
```

Recommended run counts:

- `N=200` for quick validation.
- `N=1000` or more for paper figures.
- Keep `VERIFIER_TOKEN_TTL_SECONDS=25` when checking checkpoint renewal behavior.


## Real XFRM apply latency

`experiments/10_xfrm_apply_latency_compare.sh` measures the same sequential handshake path as experiment 07, but with `XFRM_MODE=apply`. This includes real client-side and PEP-side `ip xfrm` state/policy installation. Use a smaller default run count (`N=50`) because each run creates real kernel XFRM state before cleanup.

Interpretation rule: experiment 07 isolates the authorization path with dry-run XFRM, while experiment 10 includes kernel XFRM installation overhead.

## Optional stability run for real XFRM apply

The real XFRM apply experiment is more sensitive to kernel and container scheduling noise than the dry-run authorization benchmark. To avoid overinterpreting a single run, use repeated trials when preparing paper figures:

```bash
TRIALS=5 N=50 ./experiments/11_xfrm_apply_repeated_trials.sh
```

This produces:

```text
experiments/results/11_xfrm_apply_repeated_trials.csv
experiments/results/11_xfrm_apply_repeated_trials_overhead.csv
experiments/results/11_xfrm_apply_repeated_trials_aggregate.csv
```

Use the median of medians or the aggregate table for reporting, and treat p95/p99 as exploratory unless enough trials are collected.
