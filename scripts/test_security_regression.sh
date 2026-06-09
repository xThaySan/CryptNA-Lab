#!/usr/bin/env bash
set -euo pipefail

chmod +x scripts/*.sh

echo "=== CRYPTNA security regression suite ==="

echo
echo "[1] SPA invalid packets"
./scripts/test_spa_invalid_packets.sh

echo
echo "[2] SPA corruption"
./scripts/test_spa_corruption.sh

echo
echo "[3] SPA timestamp anti-replay"
./scripts/test_spa_timestamp.sh

echo
echo "[4] SPA replay cache"
./scripts/test_spa_replay.sh

echo
echo "[5] Unauthorized service must not create XFRM"
./scripts/test_unauthorized_no_xfrm.sh

echo
echo "[6] Wrong PSK must not create XFRM"
./scripts/test_wrong_psk_no_xfrm.sh

echo
echo "[7] SPA replay must not create extra XFRM"
./scripts/test_replay_no_extra_xfrm.sh

echo
echo "[8] Service must remain hidden without tunnel"
./scripts/test_service_hidden.sh

echo
echo "=== CRYPTNA security regression suite OK ==="
