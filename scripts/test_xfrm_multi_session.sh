#!/usr/bin/env bash
set -euo pipefail

N="${1:-3}"

echo "[1] start a clean lab with XFRM apply mode"
docker compose down -v --remove-orphans >/dev/null 2>&1 || true
XFRM_MODE=apply docker compose up -d --build >/dev/null
./scripts/wait_lab_ready.sh

echo "[2] cleanup existing XFRM states/policies on client and PEP"
docker exec cryptna-client ip xfrm policy flush || true
docker exec cryptna-client ip xfrm state flush || true
docker exec cryptna-pep ip xfrm policy flush || true
docker exec cryptna-pep ip xfrm state flush || true

echo "[3] create $N CRYPTNA sessions"
for i in $(seq 1 "$N"); do
  echo "activation $i"
  docker exec cryptna-client /app/client >/tmp/cryptna-client-$i.out
  grep -q '"authorized": true' /tmp/cryptna-client-$i.out
  grep -q '"client_inner_ip"' /tmp/cryptna-client-$i.out
  grep -q '"service_ip"' /tmp/cryptna-client-$i.out
done

echo "[4] read PEP sessions"
SESSIONS="$(docker exec cryptna-pep curl -fsS http://localhost:8080/sessions)"
echo "$SESSIONS" | jq .

COUNT="$(echo "$SESSIONS" | jq 'length')"
if [ "$COUNT" -ne "$N" ]; then
  echo "ERROR: expected $N sessions, got $COUNT"
  exit 1
fi

echo "[5] verify unique reqid"
REQID_COUNT="$(echo "$SESSIONS" | jq '[.[].reqid] | unique | length')"
if [ "$REQID_COUNT" -ne "$N" ]; then
  echo "ERROR: reqid are not unique"
  exit 1
fi

echo "[6] verify unique client_inner_ip"
INNER_COUNT="$(echo "$SESSIONS" | jq '[.[].client_inner_ip] | unique | length')"
if [ "$INNER_COUNT" -ne "$N" ]; then
  echo "ERROR: client_inner_ip are not unique"
  exit 1
fi

echo "[7] verify unique client_in_spi and pep_in_spi"
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

echo "[8] verify PEP XFRM state count"
PEP_STATE_COUNT="$(docker exec cryptna-pep ip xfrm state | grep -c '^src ' || true)"
EXPECTED_STATES=$((N * 2))

if [ "$PEP_STATE_COUNT" -ne "$EXPECTED_STATES" ]; then
  echo "ERROR: expected $EXPECTED_STATES PEP XFRM states, got $PEP_STATE_COUNT"
  docker exec cryptna-pep ip xfrm state
  exit 1
fi

echo "[9] verify PEP XFRM policy count"
PEP_POLICY_COUNT="$(docker exec cryptna-pep ip xfrm policy | grep -c '^src ' || true)"
EXPECTED_POLICIES=$((N * 2))

if [ "$PEP_POLICY_COUNT" -ne "$EXPECTED_POLICIES" ]; then
  echo "ERROR: expected $EXPECTED_POLICIES PEP XFRM policies, got $PEP_POLICY_COUNT"
  docker exec cryptna-pep ip xfrm policy
  exit 1
fi

echo "[10] verify client XFRM has at least the latest session installed"
CLIENT_STATE_COUNT="$(docker exec cryptna-client ip xfrm state | grep -c '^src ' || true)"
CLIENT_POLICY_COUNT="$(docker exec cryptna-client ip xfrm policy | grep -c '^src ' || true)"

if [ "$CLIENT_STATE_COUNT" -lt 2 ]; then
  echo "ERROR: expected at least 2 client XFRM states, got $CLIENT_STATE_COUNT"
  docker exec cryptna-client ip xfrm state
  exit 1
fi

if [ "$CLIENT_POLICY_COUNT" -lt 2 ]; then
  echo "ERROR: expected at least 2 client XFRM policies, got $CLIENT_POLICY_COUNT"
  docker exec cryptna-client ip xfrm policy
  exit 1
fi

echo "XFRM multi-session test OK"
