#!/usr/bin/env bash
set -euo pipefail

N="${1:-3}"

echo "[1] ensure lab is up with XFRM apply mode"
XFRM_MODE=apply docker compose up -d >/dev/null

echo "[2] cleanup existing XFRM states/policies"
docker exec cryptna-pep ip xfrm policy flush || true
docker exec cryptna-pep ip xfrm state flush || true

echo "[3] restart PEP to reset in-memory sessions"
XFRM_MODE=apply docker compose up -d --force-recreate pep >/dev/null

echo "[4] create $N CRYPTNA sessions"
for i in $(seq 1 "$N"); do
  echo "activation $i"
  docker exec cryptna-client /app/client >/tmp/cryptna-client-$i.out
  grep -q '"authorized": true' /tmp/cryptna-client-$i.out
done

echo "[5] read PEP sessions"
SESSIONS="$(docker exec cryptna-pep curl -fsS http://localhost:8080/sessions)"
echo "$SESSIONS" | jq .

COUNT="$(echo "$SESSIONS" | jq 'length')"
if [ "$COUNT" -ne "$N" ]; then
  echo "ERROR: expected $N sessions, got $COUNT"
  exit 1
fi

echo "[6] verify unique reqid"
REQID_COUNT="$(echo "$SESSIONS" | jq '[.[].reqid] | unique | length')"
if [ "$REQID_COUNT" -ne "$N" ]; then
  echo "ERROR: reqid are not unique"
  exit 1
fi

echo "[7] verify unique client_inner_ip"
INNER_COUNT="$(echo "$SESSIONS" | jq '[.[].client_inner_ip] | unique | length')"
if [ "$INNER_COUNT" -ne "$N" ]; then
  echo "ERROR: client_inner_ip are not unique"
  exit 1
fi

echo "[8] verify unique client_in_spi and pep_in_spi"
CLIENT_SPI_COUNT="$(echo "$SESSIONS" | jq '[.[].client_in_spi] | unique | length')"
PEP_SPI_COUNT="$(echo "$SESSIONS" | jq '[.[].pep_in_spi] | unique | length')"

if [ "$CLIENT_SPI_COUNT" -ne "$N" ]; then
  echo "ERROR: client_in_spi are not unique"
  exit 1
fi

if [ "$PEP_SPI_COUNT" -ne "$N" ]; then
  echo "ERROR: pep_in_spi are not unique"
  exit 1
fi

echo "[9] verify XFRM state count"
STATE_COUNT="$(docker exec cryptna-pep ip xfrm state | grep -c '^src ' || true)"
EXPECTED_STATES=$((N * 2))

if [ "$STATE_COUNT" -ne "$EXPECTED_STATES" ]; then
  echo "ERROR: expected $EXPECTED_STATES XFRM states, got $STATE_COUNT"
  docker exec cryptna-pep ip xfrm state
  exit 1
fi

echo "[10] verify XFRM policy count"
POLICY_COUNT="$(docker exec cryptna-pep ip xfrm policy | grep -c '^src ' || true)"
EXPECTED_POLICIES=$((N * 2))

if [ "$POLICY_COUNT" -ne "$EXPECTED_POLICIES" ]; then
  echo "ERROR: expected $EXPECTED_POLICIES XFRM policies, got $POLICY_COUNT"
  docker exec cryptna-pep ip xfrm policy
  exit 1
fi

echo "XFRM multi-session test OK"
