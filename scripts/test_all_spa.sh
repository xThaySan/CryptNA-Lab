#!/usr/bin/env bash
set -euo pipefail

./scripts/test_spa.sh
./scripts/test_spa_replay.sh
./scripts/test_spa_timestamp.sh
./scripts/test_spa_invalid_packets.sh
./scripts/test_spa_corruption.sh
./scripts/test_spa_authorization.sh
./scripts/test_spa_wrong_psk.sh
./scripts/test_spa_dos_basic.sh 1000

echo "ALL SPA TESTS OK"
