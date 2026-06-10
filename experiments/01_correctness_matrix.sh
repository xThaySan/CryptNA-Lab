#!/usr/bin/env bash
set -euo pipefail

mkdir -p experiments/results
RESULTS="experiments/results/01_correctness_matrix.csv"

echo "scenario,status,script" > "$RESULTS"

run_case() {
  local name="$1"
  local script="$2"

  echo
  echo "=== [$name] $script ==="

  if "$script"; then
    echo "$name,PASS,$script" >> "$RESULTS"
  else
    echo "$name,FAIL,$script" >> "$RESULTS"
    echo "FAILED: $name"
    exit 1
  fi
}

echo "[0] fresh lab start"
docker compose down -v --remove-orphans >/dev/null
XFRM_MODE=apply CRYPTNA_DEBUG=1 docker compose up -d --build >/dev/null

# Network isolation must run before tunnel tests, otherwise installed XFRM routes can make
# direct service checks ambiguous.
run_case "network_isolation" "./scripts/test_network.sh"

# Paper category: invalid traffic.
run_case "invalid_random_and_malformed_spa" "./scripts/test_spa_invalid_packets.sh"

# Paper category: validly-formed but rejected SPAs.
run_case "expired_timestamp" "./scripts/test_spa_timestamp.sh"
run_case "replay_cache" "./scripts/test_replay_no_extra_xfrm.sh"
run_case "wrong_psk_no_xfrm" "./scripts/test_wrong_psk_no_xfrm.sh"

# Extra CRYPTNA-specific authorization check.
run_case "unauthorized_service_no_xfrm" "./scripts/test_unauthorized_no_xfrm.sh"

# Paper category: successful end-to-end handshake.
run_case "successful_end_to_end_xfrm_nat_t" "./scripts/test_xfrm_end_to_end.sh"

# Scalability sanity check beyond the paper's single-client path.
run_case "real_multi_client_xfrm_nat_t" "./scripts/test_real_multi_client.sh"

echo
echo "Correctness matrix OK"
column -s, -t "$RESULTS" || cat "$RESULTS"
