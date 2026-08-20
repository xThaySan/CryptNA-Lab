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
OUT="$(docker exec cryptna-client /app/client 2>&1)"
echo "$OUT"
grep -q '"authorized": true' <<<"$OUT"
grep -q '"sa_lifetime_seconds": 10' <<<"$OUT"

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

CLIENT_ROUTES_BEFORE="$(docker exec cryptna-client ip route)"
if ! grep -Fq -- "$SERVICE_IP" <<<"$CLIENT_ROUTES_BEFORE"; then
  echo "ERROR: client route to service was not installed"
  printf '%s\n' "$CLIENT_ROUTES_BEFORE"
  exit 1
fi

CLIENT_LOOPBACK_BEFORE="$(docker exec cryptna-client ip addr show lo)"
if ! grep -Fq -- "$CLIENT_INNER_IP" <<<"$CLIENT_LOOPBACK_BEFORE"; then
  echo "ERROR: client inner IP was not installed"
  printf '%s\n' "$CLIENT_LOOPBACK_BEFORE"
  exit 1
fi

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

CLIENT_ROUTES_AFTER="$(docker exec cryptna-client ip route)"
if grep -Fq -- "$SERVICE_IP" <<<"$CLIENT_ROUTES_AFTER"; then
  echo "ERROR: client route to service still exists"
  printf '%s\n' "$CLIENT_ROUTES_AFTER"
  exit 1
fi

CLIENT_LOOPBACK_AFTER="$(docker exec cryptna-client ip addr show lo)"
if grep -Fq -- "$CLIENT_INNER_IP" <<<"$CLIENT_LOOPBACK_AFTER"; then
  echo "ERROR: client inner IP still exists"
  printf '%s\n' "$CLIENT_LOOPBACK_AFTER"
  exit 1
fi

echo "[7] verify client cleanup log"
grep -q 'scheduling local XFRM cleanup' <<<"$OUT"

echo "Client XFRM cleanup test OK"
