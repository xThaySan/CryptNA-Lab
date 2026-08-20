#!/usr/bin/env bash
set -euo pipefail

COMPOSE_FILES=(-f docker-compose.yml -f docker-compose.ebpf.yml)
RESET_LAB="${XFRM_EBPF_RESET_LAB:-1}"

# The Verifier persists the last accepted checkpoint. Recreating only the PEP
# resets its local history while keeping the Verifier state, which correctly
# causes a 403 on the next capacity request. The smoke test therefore starts
# from a clean lab by default. Set XFRM_EBPF_RESET_LAB=0 only for manual
# debugging when you intentionally preserve Verifier/PEP state.
if [ "$RESET_LAB" = "1" ]; then
  echo "[0] reset lab state"
  docker compose "${COMPOSE_FILES[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
fi

echo "[1] build PEP image with bpftrace support"
docker compose "${COMPOSE_FILES[@]}" build pep >/dev/null

echo "[2] start lab with XFRM apply mode and eBPF observer overlay"
XFRM_MODE=apply \
PEP_ATTESTATION_ENABLED=${PEP_ATTESTATION_ENABLED:-1} \
XFRM_OBSERVER=${XFRM_OBSERVER:-hybrid} \
XFRM_EBPF_STRICT=${XFRM_EBPF_STRICT:-1} \
VERIFIER_REQUIRED_OBSERVER_PROFILE=${VERIFIER_REQUIRED_OBSERVER_PROFILE:-hybrid} \
docker compose "${COMPOSE_FILES[@]}" up -d >/dev/null

./scripts/wait_lab_ready.sh

wait_for_log() {
  pattern="$1"
  timeout_seconds="${2:-30}"
  i=0
  while [ "$i" -lt "$timeout_seconds" ]; do
    if docker logs cryptna-pep 2>&1 | grep -E "$pattern" >/dev/null; then
      docker logs cryptna-pep 2>&1 | grep -E "$pattern" | tail -5
      return 0
    fi
    sleep 1
    i=$((i + 1))
  done
  return 1
}

echo "[3] wait for PEP observer startup"
wait_for_log 'XFRM observer initialized mode=hybrid|XFRM observer initialized mode=ebpf|XFRM observer initialized mode=posthoc|XFRM eBPF observer unavailable|XFRM eBPF monitor ready' 45 || {
  echo "ERROR: PEP did not initialize XFRM observer"
  docker ps --filter name=cryptna-pep
  docker logs cryptna-pep 2>&1 | tail -120
  exit 1
}

echo "[4] cleanup XFRM state before activation"
docker exec cryptna-client ip xfrm policy flush || true
docker exec cryptna-client ip xfrm state flush || true
docker exec cryptna-pep ip xfrm policy flush || true
docker exec cryptna-pep ip xfrm state flush || true

echo "[5] create tunnel"
OUT="$(docker exec cryptna-client /app/client)"
echo "$OUT"
grep -q '"authorized": true' <<<"$OUT"

echo "[6] verify eBPF metadata in PEP logs"
# Hybrid mode is fail-closed in this smoke test: both exact posthoc checks and
# the configured minimum number of eBPF events must match.
wait_for_log 'xfrm_apply_observed observer_source=.*ebpf_matched=true.*ebpf_event_count=[2-9]' 30 || {
  echo "ERROR: no matched eBPF apply observation summary in PEP logs"
  docker logs cryptna-pep 2>&1 | tail -160
  exit 1
}

PEP_LOGS="$(docker logs cryptna-pep 2>&1)"
if grep -q 'Invalid argument' <<<"$PEP_LOGS"; then
  echo "ERROR: bpftrace emitted Invalid argument diagnostics"
  grep -E 'xfrm-ebpf stderr|Invalid argument' <<<"$PEP_LOGS" | tail -80
  exit 1
fi


if ! grep -q 'XFRM eBPF selected probes' <<<"$PEP_LOGS"; then
  echo "ERROR: eBPF monitor did not report selected probes"
  tail -160 <<<"$PEP_LOGS"
  exit 1
fi

if [ "${XFRM_EBPF_CHECK_DELETE:-0}" = "1" ]; then
  echo "[7] wait for matched eBPF delete observation"
  wait_for_log 'xfrm_delete_observed observer_source=.*ebpf_matched=true.*ebpf_event_count=[2-9]' "${XFRM_EBPF_DELETE_TIMEOUT_SECONDS:-90}" || {
    echo "ERROR: no matched eBPF delete observation summary in PEP logs"
    docker logs cryptna-pep 2>&1 | tail -200
    exit 1
  }
fi

echo "XFRM eBPF observer smoke test OK"
