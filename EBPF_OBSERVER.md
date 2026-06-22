# Optional eBPF XFRM Observer

The lab supports an optional eBPF-backed observation backend for history-bound
enforcement events. The default backend remains `posthoc`, which preserves the
original behavior and portability. The eBPF backend is enabled through a Docker
Compose overlay.

## Modes

- `XFRM_OBSERVER=posthoc`: original post-apply `ip xfrm state/policy` checks.
- `XFRM_OBSERVER=hybrid`: keep posthoc checks and attach eBPF metadata to
  observed events. This is the recommended development mode.
- `XFRM_OBSERVER=ebpf`: strict kernel-side observation. In this mode,
  `xfrm_apply_observed` and `xfrm_delete_observed` are marked successful only if
  the monitor reports matching kernel-side activity.

`XFRM_EBPF_STRICT=1` makes PEP startup fail if the eBPF monitor cannot start.

Additional tuning variables:

- `XFRM_EBPF_LOG_EVENTS=1`: log every raw eBPF event. The default is `0`; the
  PEP still records events internally and logs one summarized observation line per
  apply/delete transaction.
- `XFRM_EBPF_MIN_APPLY_EVENTS`: minimum number of apply-specific kernel events
  required for `ebpf_matched=true` in an apply observation. Default: `2`.
- `XFRM_EBPF_MIN_DELETE_EVENTS`: minimum number of delete-specific kernel events
  required for `ebpf_matched=true` in a delete observation. Default: `2`.
- `XFRM_EBPF_CHECK_DELETE=1`: make the smoke test wait for the session expiry
  path and verify a matched `xfrm_delete_observed` summary.


## Run

The smoke test resets Docker volumes by default because the Verifier stores the
last accepted checkpoint. This avoids false failures when only the PEP container
is recreated. To preserve state during manual debugging, set
`XFRM_EBPF_RESET_LAB=0`.

```bash
XFRM_MODE=apply docker compose -f docker-compose.yml -f docker-compose.ebpf.yml up -d --build
./scripts/test_xfrm_ebpf_observer.sh
```

The overlay builds the PEP image with `bpftrace` and runs the PEP container in
privileged mode with the kernel tracing filesystems mounted. This is intentionally
kept outside the default `docker-compose.yml` so the baseline lab remains usable
on hosts without eBPF support.

## Implementation note

The bpftrace program intentionally avoids process-specific builtins such as
`pid` and `comm`. In some containerized kernels, those builtins expand to helpers
that are rejected for XFRM kprobes. Correlation is instead performed by the PEP:
it opens an observation window immediately before applying or deleting XFRM state
and records all XFRM-related kernel events seen within that window.

## Security interpretation

The eBPF observer improves separation between PEP intent logging and kernel-side
observation. It does not prove complete kernel mediation. The guarantee remains
bounded by the selected probes, the kernel, and the integrity of the monitor
deployment.

## v0.11.5 note

The eBPF smoke test now resets the lab by default before startup. This prevents
Verifier checkpoint persistence from rejecting a freshly recreated PEP with HTTP
403 during repeated test runs.

## v0.11.4 note

The PEP now logs summarized eBPF observation metadata by default and keeps raw
eBPF event logs behind `XFRM_EBPF_LOG_EVENTS=1`. `ebpf_event_count` now counts
only events matching the expected action (`apply` or `delete`), while
`ebpf_total_event_count` records the full observation window. This avoids
presenting unrelated global kprobe activity as a matched PEP transaction.
