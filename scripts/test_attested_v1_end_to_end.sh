#!/usr/bin/env bash
set -euo pipefail

chmod +x scripts/*.sh

echo "[1] start attested V1 lab in dry-run mode"
docker compose down -v --remove-orphans >/dev/null
PEP_ATTESTATION_ENABLED=1 XFRM_MODE=dry-run CRYPTNA_DEBUG=0 VERIFIER_REQUIRED_OBSERVER_PROFILE=dry-run docker compose up -d --build >/dev/null
./scripts/wait_lab_ready.sh

echo "[2] create attested tunnel"
OUT="$(docker exec -e XFRM_MODE=dry-run cryptna-client /app/client)"
grep -q '"authorized": true' <<<"$OUT"
grep -q '"capacity_token"' <<<"$OUT"
grep -q '"sa_binding"' <<<"$OUT"
grep -q '"verifier_signature"' <<<"$OUT"
grep -q '"pep_signature"' <<<"$OUT"

echo "[3] verify PEP session exists"
docker exec cryptna-pep curl -s http://localhost:8080/sessions | jq -e 'length >= 1' >/dev/null

echo "Attested V1 end-to-end test OK"
