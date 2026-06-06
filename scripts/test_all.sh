#!/usr/bin/env bash
set -euo pipefail

chmod +x scripts/*.sh

echo "=== CRYPTNA full test suite ==="

echo
echo "[1] SPA nominal"
./scripts/test_spa.sh

echo
echo "[2] SPA security regression"
./scripts/test_security_regression.sh

echo
echo "[3] XFRM end-to-end NAT-T"
./scripts/test_xfrm_end_to_end.sh

echo
echo "[4] PEP XFRM expiry cleanup"
./scripts/test_xfrm_expiry_cleanup.sh

echo
echo "[5] Client XFRM cleanup"
./scripts/test_client_xfrm_cleanup.sh

echo
echo "[6] XFRM multi-session"
./scripts/test_xfrm_multi_session.sh 3

echo
echo "=== CRYPTNA full test suite OK ==="
