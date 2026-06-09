#!/usr/bin/env bash
set -euo pipefail

chmod +x scripts/*.sh

echo "[1] start lab"
SA_LIFETIME_SECONDS=60 SESSION_REAPER_INTERVAL_SECONDS=5 XFRM_MODE=apply CRYPTNA_DEBUG=1 docker compose up -d --build >/dev/null

echo "[2] reset client and PEP XFRM"
for C in cryptna-client cryptna-client-2; do
  docker exec "$C" ip xfrm policy flush || true
  docker exec "$C" ip xfrm state flush || true
  docker exec "$C" ip route delete 172.22.0.50/32 || true
  docker exec "$C" ip addr flush dev lo scope global || true
done

docker exec cryptna-pep ip xfrm policy flush || true
docker exec cryptna-pep ip xfrm state flush || true

echo "[3] reset PEP sessions"
SA_LIFETIME_SECONDS=60 SESSION_REAPER_INTERVAL_SECONDS=5 XFRM_MODE=apply CRYPTNA_DEBUG=1 docker compose up -d --force-recreate pep >/dev/null
sleep 2

echo "[4] authorize client1"
OUT1="$(docker exec cryptna-client /app/client)"
echo "$OUT1" | grep -q '"authorized": true'

IP1="$(echo "$OUT1" | sed -n 's/.*"client_inner_ip": "\([^"]*\)".*/\1/p' | tail -1)"
SVC1="$(echo "$OUT1" | sed -n 's/.*"service_ip": "\([^"]*\)".*/\1/p' | tail -1)"

echo "[5] authorize client2"
OUT2="$(docker exec cryptna-client-2 /app/client)"
echo "$OUT2" | grep -q '"authorized": true'

IP2="$(echo "$OUT2" | sed -n 's/.*"client_inner_ip": "\([^"]*\)".*/\1/p' | tail -1)"
SVC2="$(echo "$OUT2" | sed -n 's/.*"service_ip": "\([^"]*\)".*/\1/p' | tail -1)"

test -n "$IP1"
test -n "$IP2"
test "$IP1" != "$IP2"

echo "client1_inner_ip=$IP1"
echo "client2_inner_ip=$IP2"

echo "[6] verify two PEP sessions"
SESSIONS="$(docker exec cryptna-pep curl -s http://localhost:8080/sessions)"
echo "$SESSIONS" | jq .

echo "$SESSIONS" | jq -e 'length == 2' >/dev/null
echo "$SESSIONS" | jq -e '[.[].client_outer_ip] | sort == ["172.20.0.10","172.20.0.11"]' >/dev/null

echo "[7] verify service access from both clients"
docker exec cryptna-client curl -sS --max-time 5 --interface "$IP1" "http://$SVC1" | grep -q "Welcome to nginx"
docker exec cryptna-client-2 curl -sS --max-time 5 --interface "$IP2" "http://$SVC2" | grep -q "Welcome to nginx"

echo "Real multi-client NAT-T XFRM test OK"
