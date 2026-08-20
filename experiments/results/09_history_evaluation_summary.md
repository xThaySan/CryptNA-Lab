# History-bound evaluation summary

## Input files

- `experiments/results/06_history_microbench.csv`
- `experiments/results/07_attested_latency_compare_summary.csv`
- `experiments/results/08_history_token_size.csv`
- `experiments/results/12_attested_latency_repeated_trials.csv`
- `experiments/results/12_attested_latency_repeated_trials_aggregate.csv`
- `experiments/results/12_attested_latency_repeated_trials_status.csv`
- `experiments/results/environment.txt`
- `experiments/results/10_xfrm_apply_latency_compare_summary.csv`
- `experiments/results/11_xfrm_apply_repeated_trials_aggregate.csv`
- `experiments/results/11_xfrm_apply_repeated_trials_status.csv`
- `experiments/results/13_xfrm_observer_cost.csv`
- `experiments/results/14_multi_pep_appraisal_raw.txt`

## Main results

- Ten paired dry-run trials completed successfully: baseline `10000/10000`, history-bound `10000/10000`, with `20` unmeasured warm-up requests per case and trial.
- The paired dry-run benchmark disables PEP JSON state persistence in both cases; it measures the in-memory authorization path and excludes crash-recovery snapshot I/O.
- Across paired trial summaries, average latency medians were baseline `1.018 ms` and history-bound `1.225 ms`; the median paired delta was `0.211 ms` with inter-trial standard deviation `0.105 ms`.
- Across paired trial summaries, latency medians were baseline `0.917 ms` and history-bound `1.088 ms`; the median paired delta was `0.172 ms` (`18.8%` relative to the baseline trial-summary median), with inter-trial standard deviation `0.049 ms`.
- Event hashing median cost: `0.502 µs/op`.
- Checkpoint hashing median cost: `0.607 µs/op`.
- Cryptographic chain and checkpoint verification for 100 events median cost: `93.596 µs/op`.
- Cryptographic chain and checkpoint verification for 1000 events median cost: `676.633 µs/op`.
- Full cryptographic and semantic appraisal for 100 events median cost: `232.331 µs/op`.
- Full cryptographic and semantic appraisal for 1000 events median cost: `2096.530 µs/op`.
- Capacity token JSON size: `618 bytes`.
- SA binding JSON size: `631 bytes`.
- Combined attestation objects size: `1249 bytes`.
- Real XFRM apply median latency: baseline `26.165 ms`, history-bound `30.299 ms`, delta `4.134 ms` (`15.8%`).
- Real XFRM apply average latency: baseline `29.757 ms`, history-bound `33.444 ms`, delta `3.687 ms` (`12.4%`).
- Repeated real XFRM apply trials completed with median success rates of `100.0%` for baseline and `100.0%` for history-bound over `10` trials.
- Repeated real XFRM apply trials: median latency across trial summaries was `25.482 ms` for baseline and `27.504 ms` for history-bound.
- Repeated real XFRM apply trials: median paired delta for median latency `2.155 ms` with inter-trial standard deviation `2.969 ms` over `10` trials; the magnitude should be interpreted cautiously because kernel and cleanup variance dominate the tails.
- Repeated real XFRM apply trials: median paired delta for average latency `1.587 ms` with inter-trial standard deviation `4.287 ms`.
- Standalone posthoc exact XFRM inspection: median `2843.000 µs` total over `30` measured applications.
- Hybrid XFRM observation: posthoc inspection median `2625.000 µs`, isolated eBPF correlation median `4.000 µs`, and total observer median `2638.000 µs` over `30` measured applications; separate batches are not used to claim a speedup.
- Concurrent appraisal of 100 independent PEP histories with 100 events each: `16.037 ms` median total on the two-vCPU VM (`160.373 µs` total-time equivalent per PEP), over `10` benchmark repetitions.

## Generated figure-ready CSV files

- `experiments/results/09_microbench_summary.csv`
- `experiments/results/09_latency_overhead.csv`
- `experiments/results/09_size_breakdown.csv`
- `experiments/results/09_xfrm_apply_latency_overhead.csv`
- `experiments/results/11_xfrm_apply_repeated_trials_aggregate.csv`
- `experiments/results/11_xfrm_apply_repeated_trials_status.csv`
- `experiments/results/12_attested_latency_repeated_trials_aggregate.csv`
- `experiments/results/12_attested_latency_repeated_trials_status.csv`
- `experiments/results/13_xfrm_observer_cost.csv`
- `experiments/results/14_multi_pep_appraisal_raw.txt`
- `experiments/results/09_multi_pep_summary.csv`

## Suggested paper wording

Across ten paired dry-run trials of 1000 measured handshakes per case, history-bound attestation produced a 0.172 ms median paired delta in median latency compared with the non-attested CRYPTNA baseline. This authorization-path comparison disables PEP JSON state persistence in both cases and excludes crash-recovery snapshot I/O. The verifier measurements show 2.097 ms median full cryptographic and semantic appraisal cost for 1000 events, while the serialized capacity token and SA binding together add 1249 bytes of JSON metadata to the authorization response. In real XFRM apply experiments, setup time is dominated by kernel-side installation and cleanup; the median paired delta in median latency was 2.155 ms with 2.969 ms inter-trial standard deviation, so we use this experiment primarily as an end-to-end validation. A concurrent local benchmark appraised 100 independent 100-event PEP histories in 16.037 ms median total on the two-vCPU VM.
