#!/usr/bin/env bash
set -euo pipefail

echo "[1] start lab with short SA lifetime"
docker compose down -v --remove-orphans >/dev/null 2>&1 || true
SA_LIFETIME_SECONDS=10 SESSION_REAPER_INTERVAL_SECONDS=2 XFRM_MODE=apply CRYPTNA_DEBUG=1 docker compose up -d --build >/dev/null
./scripts/wait_lab_ready.sh

echo "[2] cleanup existing XFRM state"
docker exec cryptna-client ip xfrm policy flush || true
docker exec cryptna-client ip xfrm state flush || true
docker exec cryptna-pep ip xfrm policy flush || true
docker exec cryptna-pep ip xfrm state flush || true

echo "[3] create tunnel"
OUT="$(docker exec cryptna-client /app/client)"
echo "$OUT"
grep -q '"authorized": true' <<<"$OUT"
grep -q '"sa_lifetime_seconds": 10' <<<"$OUT"

echo "[4] verify PEP session and XFRM exist"
SESSIONS_BEFORE="$(docker exec cryptna-pep curl -s http://localhost:8080/sessions | jq 'length')"
STATES_BEFORE="$(docker exec cryptna-pep ip xfrm state | grep -c '^src ' || true)"
POLICIES_BEFORE="$(docker exec cryptna-pep ip xfrm policy | grep -c '^src ' || true)"

if [ "$SESSIONS_BEFORE" -lt 1 ]; then
  echo "ERROR: expected at least one PEP session before expiry"
  exit 1
fi

if [ "$STATES_BEFORE" -lt 2 ]; then
  echo "ERROR: expected at least 2 PEP states before expiry"
  docker exec cryptna-pep ip xfrm state
  exit 1
fi

if [ "$POLICIES_BEFORE" -lt 2 ]; then
  echo "ERROR: expected at least 2 PEP policies before expiry"
  docker exec cryptna-pep ip xfrm policy
  exit 1
fi

echo "[5] wait for expiry and reaper"
sleep 14

echo "[6] verify PEP session and XFRM were cleaned"
SESSIONS_AFTER="$(docker exec cryptna-pep curl -s http://localhost:8080/sessions | jq 'length')"
STATES_AFTER="$(docker exec cryptna-pep ip xfrm state | grep -c '^src ' || true)"
POLICIES_AFTER="$(docker exec cryptna-pep ip xfrm policy | grep -c '^src ' || true)"

if [ "$SESSIONS_AFTER" -ne 0 ]; then
  echo "ERROR: expected 0 PEP sessions after expiry, got $SESSIONS_AFTER"
  docker exec cryptna-pep curl -s http://localhost:8080/sessions | jq
  exit 1
fi

if [ "$STATES_AFTER" -ne 0 ]; then
  echo "ERROR: expected 0 PEP states after expiry, got $STATES_AFTER"
  docker exec cryptna-pep ip xfrm state
  exit 1
fi

if [ "$POLICIES_AFTER" -ne 0 ]; then
  echo "ERROR: expected 0 PEP policies after expiry, got $POLICIES_AFTER"
  docker exec cryptna-pep ip xfrm policy
  exit 1
fi

echo "[7] verify cleanup logs"
PEP_LOGS="$(docker logs cryptna-pep --tail 100 2>&1)"
grep -q 'session expired, deleting XFRM' <<<"$PEP_LOGS"
grep -q 'deleting XFRM' <<<"$PEP_LOGS"

echo "XFRM expiry cleanup test OK"
