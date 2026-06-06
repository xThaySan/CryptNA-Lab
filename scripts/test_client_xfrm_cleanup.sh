#!/usr/bin/env bash
set -euo pipefail

echo "[1] start lab with short SA lifetime"
SA_LIFETIME_SECONDS=10 SESSION_REAPER_INTERVAL_SECONDS=2 XFRM_MODE=apply CRYPTNA_DEBUG=1 docker compose up -d >/dev/null

echo "[2] cleanup existing XFRM state"
docker exec cryptna-client ip xfrm policy flush || true
docker exec cryptna-client ip xfrm state flush || true
docker exec cryptna-pep ip xfrm policy flush || true
docker exec cryptna-pep ip xfrm state flush || true

echo "[3] create tunnel"
OUT="$(docker exec cryptna-client /app/client)"
echo "$OUT"
echo "$OUT" | grep -q '"authorized": true'
echo "$OUT" | grep -q '"sa_lifetime_seconds": 10'

CLIENT_INNER_IP="$(echo "$OUT" | sed -n 's/.*"client_inner_ip": "\([^"]*\)".*/\1/p' | tail -1)"
SERVICE_IP="$(echo "$OUT" | sed -n 's/.*"service_ip": "\([^"]*\)".*/\1/p' | tail -1)"

if [ -z "$CLIENT_INNER_IP" ] || [ -z "$SERVICE_IP" ]; then
  echo "ERROR: failed to extract tunnel IPs"
  exit 1
fi

echo "client_inner_ip=$CLIENT_INNER_IP"
echo "service_ip=$SERVICE_IP"

echo "[4] verify client XFRM and route exist"
CLIENT_STATES="$(docker exec cryptna-client ip xfrm state | grep -c '^src ' || true)"
CLIENT_POLICIES="$(docker exec cryptna-client ip xfrm policy | grep -c '^src ' || true)"

if [ "$CLIENT_STATES" -lt 2 ]; then
  echo "ERROR: expected client XFRM states before cleanup"
  docker exec cryptna-client ip xfrm state
  exit 1
fi

if [ "$CLIENT_POLICIES" -lt 2 ]; then
  echo "ERROR: expected client XFRM policies before cleanup"
  docker exec cryptna-client ip xfrm policy
  exit 1
fi

docker exec cryptna-client ip route | grep -q "$SERVICE_IP"
docker exec cryptna-client ip addr show lo | grep -q "$CLIENT_INNER_IP"

echo "[5] wait for client cleanup"
sleep 13

echo "[6] verify client XFRM, route and inner IP are cleaned"
CLIENT_STATES_AFTER="$(docker exec cryptna-client ip xfrm state | grep -c '^src ' || true)"
CLIENT_POLICIES_AFTER="$(docker exec cryptna-client ip xfrm policy | grep -c '^src ' || true)"

if [ "$CLIENT_STATES_AFTER" -ne 0 ]; then
  echo "ERROR: expected 0 client XFRM states after cleanup, got $CLIENT_STATES_AFTER"
  docker exec cryptna-client ip xfrm state
  exit 1
fi

if [ "$CLIENT_POLICIES_AFTER" -ne 0 ]; then
  echo "ERROR: expected 0 client XFRM policies after cleanup, got $CLIENT_POLICIES_AFTER"
  docker exec cryptna-client ip xfrm policy
  exit 1
fi

if docker exec cryptna-client ip route | grep -q "$SERVICE_IP"; then
  echo "ERROR: client route to service still exists"
  docker exec cryptna-client ip route
  exit 1
fi

if docker exec cryptna-client ip addr show lo | grep -q "$CLIENT_INNER_IP"; then
  echo "ERROR: client inner IP still exists"
  docker exec cryptna-client ip addr show lo
  exit 1
fi

echo "[7] verify client cleanup log"
docker logs cryptna-client --tail 80 | grep -q 'scheduling local XFRM cleanup'

echo "Client XFRM cleanup test OK"
