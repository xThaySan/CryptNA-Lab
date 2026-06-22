#!/bin/sh
set -eu

# Build a small bpftrace program from the XFRM functions that are actually
# available on the host kernel. This is more robust than using xfrm_state_*
# wildcards, which also capture lookup/walk/timer functions and make the
# observer noisy.
TRACEFS="${TRACEFS:-/sys/kernel/tracing}"
if [ ! -r "$TRACEFS/available_filter_functions" ] && [ -r /sys/kernel/debug/tracing/available_filter_functions ]; then
  TRACEFS="/sys/kernel/debug/tracing"
fi
AVAIL="$TRACEFS/available_filter_functions"
PROGRAM="${XFRM_EBPF_GENERATED_SCRIPT:-/tmp/cryptna_xfrm_monitor.bt}"

if ! command -v bpftrace >/dev/null 2>&1; then
  echo "bpftrace is not installed" >&2
  exit 127
fi

if [ ! -r "$AVAIL" ]; then
  echo "cannot read available kernel functions: $AVAIL" >&2
  exit 2
fi

has_func() {
  grep -Eq "(^|[[:space:]])$1([[:space:]]|$)" "$AVAIL"
}

add_probe() {
  func="$1"
  action="$2"
  if has_func "$func"; then
    printf 'kprobe:%s\n{\n  printf("cryptna_xfrm_event probe=kprobe:%s action=%s\\n");\n}\n\n' "$func" "$func" "$action" >> "$PROGRAM"
    SELECTED="${SELECTED}${SELECTED:+,}kprobe:${func}:${action}"
  fi
}

SELECTED=""
cat > "$PROGRAM" <<'BT'
#!/usr/bin/env bpftrace

BEGIN
{
  printf("cryptna_ebpf_ready monitor=xfrm mode=selected-kprobes\n");
}

BT

# State and policy installation paths observed when iproute2 applies XFRM state.
add_probe xfrm_state_add apply
add_probe xfrm_policy_insert apply
add_probe xfrm_policy_insert_list apply

# State and policy deletion paths vary slightly across kernels. Include the
# common symbols when available, but do not fail if one is missing.
add_probe xfrm_state_delete delete
add_probe xfrm_state_delete_tunnel delete
add_probe xfrm_policy_delete delete
add_probe xfrm_policy_kill delete
add_probe xfrm_policy_destroy delete

if [ -z "$SELECTED" ]; then
  echo "no selected XFRM kprobes are available on this kernel" >&2
  exit 3
fi

echo "cryptna_ebpf_selected probes=$SELECTED" >&2
exec bpftrace -q "$PROGRAM"
