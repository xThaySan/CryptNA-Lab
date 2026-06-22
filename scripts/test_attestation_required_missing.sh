#!/usr/bin/env bash
set -euo pipefail

echo "[1] start baseline PEP while client policy requires attestation"
docker compose down -v --remove-orphans >/dev/null 2>&1 || true
PEP_ATTESTATION_ENABLED=0 \
CLIENT_ATTESTATION_REQUIRED=1 \
XFRM_MODE=dry-run \
CRYPTNA_DEBUG=0 \
  docker compose up -d --build >/dev/null
./scripts/wait_lab_ready.sh

echo "[2] client must reject a response without capacity token and SA binding"
docker exec cryptna-client sh -c 'test "$CLIENT_ATTESTATION_REQUIRED" = "1"'
set +e
OUT="$(docker exec -e XFRM_MODE=dry-run cryptna-client /app/client 2>&1)"
RC=$?
set -e

echo "$OUT"
if [ "$RC" -eq 0 ]; then
  echo "ERROR: client accepted a response with missing required attestation" >&2
  exit 1
fi
echo "$OUT" | grep -qi 'attestation required'

echo "Missing required attestation fail-closed test OK"
