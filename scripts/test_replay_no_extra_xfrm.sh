#!/usr/bin/env bash
set -euo pipefail

PACKET="/tmp/spa-replay-xfrm.packet"

echo "[1] start lab"
SA_LIFETIME_SECONDS=60 SESSION_REAPER_INTERVAL_SECONDS=5 XFRM_MODE=apply CRYPTNA_DEBUG=1 docker compose up -d >/dev/null

echo "[2] cleanup existing XFRM state"
docker exec cryptna-client ip xfrm policy flush || true
docker exec cryptna-client ip xfrm state flush || true
docker exec cryptna-pep ip xfrm policy flush || true
docker exec cryptna-pep ip xfrm state flush || true

echo "[3] build SPA packet"
docker exec cryptna-spa-send /app/spa-send -mode build -packet "$PACKET"

echo "[4] first send should create one PEP session"
FIRST="$(docker exec cryptna-spa-send /app/spa-send -mode replay -packet "$PACKET")"
echo "$FIRST"

if ! echo "$FIRST" | grep -q 'response size='; then
  echo "ERROR: first SPA send did not receive a response"
  exit 1
fi

SESSIONS_AFTER_FIRST="$(docker exec cryptna-pep curl -s http://localhost:8080/sessions | jq 'length')"
STATES_AFTER_FIRST="$(docker exec cryptna-pep ip xfrm state | grep -c '^src ' || true)"
POLICIES_AFTER_FIRST="$(docker exec cryptna-pep ip xfrm policy | grep -c '^src ' || true)"

echo "after_first sessions=$SESSIONS_AFTER_FIRST states=$STATES_AFTER_FIRST policies=$POLICIES_AFTER_FIRST"

if [ "$SESSIONS_AFTER_FIRST" -ne 1 ]; then
  echo "ERROR: expected 1 PEP session after first SPA"
  exit 1
fi

if [ "$STATES_AFTER_FIRST" -lt 2 ]; then
  echo "ERROR: expected at least 2 PEP XFRM states after first SPA"
  docker exec cryptna-pep ip xfrm state
  exit 1
fi

if [ "$POLICIES_AFTER_FIRST" -lt 2 ]; then
  echo "ERROR: expected at least 2 PEP XFRM policies after first SPA"
  docker exec cryptna-pep ip xfrm policy
  exit 1
fi

echo "[5] replay same SPA should be silently dropped"
SECOND="$(docker exec cryptna-spa-send /app/spa-send -mode replay -packet "$PACKET")"
echo "$SECOND"

if ! echo "$SECOND" | grep -q 'timeout/no-response'; then
  echo "ERROR: replayed SPA received a response"
  exit 1
fi

echo "[6] verify replay did not create extra PEP session or XFRM"
SESSIONS_AFTER_REPLAY="$(docker exec cryptna-pep curl -s http://localhost:8080/sessions | jq 'length')"
STATES_AFTER_REPLAY="$(docker exec cryptna-pep ip xfrm state | grep -c '^src ' || true)"
POLICIES_AFTER_REPLAY="$(docker exec cryptna-pep ip xfrm policy | grep -c '^src ' || true)"

echo "after_replay sessions=$SESSIONS_AFTER_REPLAY states=$STATES_AFTER_REPLAY policies=$POLICIES_AFTER_REPLAY"

if [ "$SESSIONS_AFTER_REPLAY" != "$SESSIONS_AFTER_FIRST" ]; then
  echo "ERROR: replay changed PEP session count"
  exit 1
fi

if [ "$STATES_AFTER_REPLAY" != "$STATES_AFTER_FIRST" ]; then
  echo "ERROR: replay changed PEP XFRM state count"
  docker exec cryptna-pep ip xfrm state
  exit 1
fi

if [ "$POLICIES_AFTER_REPLAY" != "$POLICIES_AFTER_FIRST" ]; then
  echo "ERROR: replay changed PEP XFRM policy count"
  docker exec cryptna-pep ip xfrm policy
  exit 1
fi

echo "Replay no-extra-XFRM test OK"
