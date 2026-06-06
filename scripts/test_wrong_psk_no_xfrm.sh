#!/usr/bin/env bash
set -euo pipefail

WRONG_PSK="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

echo "[1] start lab"
SA_LIFETIME_SECONDS=60 SESSION_REAPER_INTERVAL_SECONDS=5 XFRM_MODE=apply CRYPTNA_DEBUG=1 docker compose up -d >/dev/null

echo "[2] cleanup existing XFRM state"
docker exec cryptna-client ip xfrm policy flush || true
docker exec cryptna-client ip xfrm state flush || true
docker exec cryptna-pep ip xfrm policy flush || true
docker exec cryptna-pep ip xfrm state flush || true

echo "[3] count PEP sessions before"
SESSIONS_BEFORE="$(docker exec cryptna-pep curl -s http://localhost:8080/sessions | jq 'length')"
STATES_BEFORE="$(docker exec cryptna-pep ip xfrm state | grep -c '^src ' || true)"
POLICIES_BEFORE="$(docker exec cryptna-pep ip xfrm policy | grep -c '^src ' || true)"

echo "sessions_before=$SESSIONS_BEFORE states_before=$STATES_BEFORE policies_before=$POLICIES_BEFORE"

echo "[4] send SPA with wrong PSK"
OUT="$(docker exec cryptna-spa-send /app/spa-send -mode send -psk "$WRONG_PSK")"
echo "$OUT"

if ! echo "$OUT" | grep -q 'timeout/no-response'; then
  echo "ERROR: wrong PSK received a response"
  exit 1
fi

echo "[5] verify no PEP session and no XFRM were created"
SESSIONS_AFTER="$(docker exec cryptna-pep curl -s http://localhost:8080/sessions | jq 'length')"
STATES_AFTER="$(docker exec cryptna-pep ip xfrm state | grep -c '^src ' || true)"
POLICIES_AFTER="$(docker exec cryptna-pep ip xfrm policy | grep -c '^src ' || true)"

echo "sessions_after=$SESSIONS_AFTER states_after=$STATES_AFTER policies_after=$POLICIES_AFTER"

if [ "$SESSIONS_AFTER" != "$SESSIONS_BEFORE" ]; then
  echo "ERROR: wrong PSK changed PEP session count"
  exit 1
fi

if [ "$STATES_AFTER" != "$STATES_BEFORE" ]; then
  echo "ERROR: wrong PSK changed PEP XFRM states"
  docker exec cryptna-pep ip xfrm state
  exit 1
fi

if [ "$POLICIES_AFTER" != "$POLICIES_BEFORE" ]; then
  echo "ERROR: wrong PSK changed PEP XFRM policies"
  docker exec cryptna-pep ip xfrm policy
  exit 1
fi

echo "Wrong PSK no-XFRM test OK"
