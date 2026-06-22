# CryptNA-Lab: history-bound attested enforcement

This repository is the reproducible Docker Compose lab for the CRYPTNA history-bound attested enforcement prototype. CRYPTNA's SPA, PDP/PIP/PEP separation, service concealment, and dynamic IPsec/NAT-T tunnel are reused from the earlier CRYPTNA prototype. The contribution implemented here is the history-bound PEP authority layer: enforcement events, signed checkpoints, Verifier appraisal, scoped capacity tokens, PEP-signed SA bindings, persistent lifecycle state, and posthoc/eBPF XFRM observation.

## Scope and trust boundary

The lab validates cryptographic continuity and lifecycle semantics for events covered by the configured observer. It does **not** prove that every kernel action was observed, does not attest PDP decision correctness, and does not implement TPM-backed remote attestation. The committed measurement and policy values are software-profile identifiers. The optional eBPF kprobes provide kernel-side corroboration in PEP-controlled transaction windows; they are not complete mediation and run in the privileged PEP container in this prototype.

The repository contains demonstration identities. Replace all committed keys and enrollment files in a real deployment.

## Requirements

- Linux host or VM with Docker Engine and Docker Compose
- Go 1.23 or newer and Python 3 for host-side unit benchmarks and summaries
- `curl`, `jq`, `bash`, and standard GNU utilities
- For eBPF mode: a kernel exposing XFRM kprobe symbols, BTF/tracing filesystems, and permission to run a privileged container

The paper evaluation environment is recorded by `scripts/capture_environment.sh`. The official rerun uses an Ubuntu VM under VMware Workstation Pro 17.6.4 build 24832109 with 2 vCPUs and approximately 3.3 GiB RAM. The capture file records the exact Ubuntu release, kernel, CPU model, Docker/Compose, Go, Python, and iproute2 versions for the result campaign.

## Quick start

Baseline CRYPTNA without history-bound attestation:

```bash
docker compose down -v --remove-orphans
PEP_ATTESTATION_ENABLED=0 XFRM_MODE=dry-run docker compose up -d --build
./scripts/wait_lab_ready.sh
docker exec cryptna-client /app/client
```

History-bound dry-run protocol validation:

```bash
docker compose down -v --remove-orphans
PEP_ATTESTATION_ENABLED=1 \
XFRM_MODE=dry-run \
VERIFIER_REQUIRED_OBSERVER_PROFILE=dry-run \
docker compose up -d --build
./scripts/wait_lab_ready.sh
docker exec cryptna-client /app/client
```

Real XFRM enforcement with exact posthoc inspection:

```bash
docker compose down -v --remove-orphans
PEP_ATTESTATION_ENABLED=1 \
XFRM_MODE=apply \
VERIFIER_REQUIRED_OBSERVER_PROFILE=posthoc \
docker compose up -d --build
./scripts/wait_lab_ready.sh
docker exec cryptna-client /app/client
```

Hybrid posthoc+eBPF mode:

```bash
docker compose -f docker-compose.yml -f docker-compose.ebpf.yml down -v --remove-orphans
PEP_ATTESTATION_ENABLED=1 \
XFRM_MODE=apply \
XFRM_OBSERVER=hybrid \
XFRM_EBPF_STRICT=1 \
VERIFIER_REQUIRED_OBSERVER_PROFILE=hybrid \
docker compose -f docker-compose.yml -f docker-compose.ebpf.yml up -d --build
./scripts/wait_lab_ready.sh
```

## Durable state and reset semantics

`verifier_data` stores accepted checkpoints, active-session state, and the last issued token for idempotent response replay. `pep_data` stores the PEP history, active sessions, and transaction marker. The PEP refuses to start if it detects an interrupted persisted XFRM transaction or if a restored active session no longer has exactly matching kernel state.

The demonstration PEP and Verifier keys are mutually pinned: the Verifier checks `verifier/enrolled_peps.json`, while the PEP verifies tokens with `PEP_VERIFIER_PUBLIC_KEY`. In attested Compose runs, `CLIENT_ATTESTATION_REQUIRED` follows `PEP_ATTESTATION_ENABLED`; removing the attestation objects therefore causes client rejection rather than a baseline fallback.

Removing only one of these volumes intentionally breaks continuity. Use the following only for a full trusted laboratory reset:

```bash
docker compose down -v --remove-orphans
```

## Tests

```bash
./scripts/test_history_hash_chain_unit.sh
./scripts/test_history_negative_unit.sh
./scripts/test_history_recovery_unit.sh
./scripts/test_attested_v1_end_to_end.sh
./scripts/test_attestation_required_missing.sh
./scripts/test_xfrm_end_to_end.sh
./scripts/test_attested_xfrm_end_to_end.sh
./scripts/test_real_multi_client.sh
```

Run the eBPF apply/delete smoke test and retain its log:

```bash
mkdir -p experiments/results
XFRM_EBPF_CHECK_DELETE=1 ./scripts/test_xfrm_ebpf_observer.sh \
  2>&1 | tee experiments/results/xfrm_ebpf_smoke.log
```

## Evaluation

Capture the environment before every official campaign:

```bash
./scripts/capture_environment.sh
```

Then run:

```bash
./experiments/06_history_microbench.sh
TRIALS=10 N=1000 WARMUP=20 ./experiments/12_attested_latency_repeated_trials.sh
./experiments/08_history_token_size.sh
TRIALS=10 N=50 WARMUP=3 ./experiments/11_xfrm_apply_repeated_trials.sh
N=30 WARMUP=3 ./experiments/13_xfrm_observer_cost.sh
./experiments/14_multi_pep_appraisal.sh
./experiments/09_summarize_history_results.sh
```

Generated CSV files and raw logs are written to `experiments/results/`. This directory is intentionally versionable so the exact evidence used by a paper table can be committed with an identified code revision.
The final summarizer stops instead of reusing stale files when either repeated campaign is incomplete.

## Measurement interpretation

- `BenchmarkVerifyHistoryEvidence` measures chain/checkpoint cryptography only.
- `BenchmarkVerifyEnforcementPolicy` measures lifecycle semantics only.
- `BenchmarkVerifyFullHistoryAppraisal` measures both operations on the same delta.
- A completed synthetic session contributes six lifecycle events. The 100- and 1000-event full-appraisal cases represent 16 and 166 completed session lifecycles plus four management events; with a 30-second renewal interval, these correspond to approximately 0.5 and 5.5 completed lifecycles/s per PEP.
- Experiment 12 reports paired independent dry-run trials, with declared unmeasured warm-up runs and alternating baseline/HBAEC execution order.
- Experiment 12 disables PEP JSON state persistence in both paired cases to isolate the in-memory authorization path; normal and end-to-end runs keep durable PEP state enabled. Results from experiment 12 must not be presented as storage-inclusive latency.
- Experiment 13 reports the posthoc lookup and eBPF-correlation components separately from XFRM installation.
- Experiment 14 is a concurrent Verifier appraisal microbenchmark, not a distributed multi-host deployment.

See `ATTESTATION_V1.md`, `EBPF_OBSERVER.md`, and `experiments/HISTORY_BOUND_EVALUATION.md` for protocol and experiment details.

Public artifact: <https://github.com/xThaySan/CryptNA-Lab>
