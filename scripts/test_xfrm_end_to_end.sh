#!/usr/bin/env bash
set -euo pipefail

echo "[1] ensure lab is up with XFRM apply mode"
XFRM_MODE=apply CRYPTNA_DEBUG=1 docker compose up -d >/dev/null

echo "[2] verify NAT-T listeners"
docker exec cryptna-pep ss -lunp | grep -q ':4500'
docker exec cryptna-client ss -lunp | grep -q ':4500'
echo "OK"

echo "[3] cleanup XFRM state"
docker exec cryptna-client ip xfrm policy flush || true
docker exec cryptna-client ip xfrm state flush || true
docker exec cryptna-pep ip xfrm policy flush || true
docker exec cryptna-pep ip xfrm state flush || true

echo "[4] create CRYPTNA tunnel"
OUT="$(docker exec cryptna-client /app/client)"
echo "$OUT"

echo "$OUT" | grep -q '"authorized": true'

SERVICE_IP="$(echo "$OUT" | sed -n 's/.*"service_ip": "\([^"]*\)".*/\1/p' | tail -1)"
CLIENT_INNER_IP="$(echo "$OUT" | sed -n 's/.*"client_inner_ip": "\([^"]*\)".*/\1/p' | tail -1)"

if [ -z "$SERVICE_IP" ]; then
  echo "ERROR: could not extract service_ip"
  exit 1
fi

if [ -z "$CLIENT_INNER_IP" ]; then
  echo "ERROR: could not extract client_inner_ip"
  exit 1
fi

echo "service_ip=$SERVICE_IP"
echo "client_inner_ip=$CLIENT_INNER_IP"
echo "OK"

echo "[5] verify XFRM installed on client"
CLIENT_STATES="$(docker exec cryptna-client ip xfrm state | grep -c '^src ' || true)"
CLIENT_POLICIES="$(docker exec cryptna-client ip xfrm policy | grep -c '^src ' || true)"

if [ "$CLIENT_STATES" -lt 2 ]; then
  echo "ERROR: expected at least 2 client XFRM states, got $CLIENT_STATES"
  docker exec cryptna-client ip xfrm state
  exit 1
fi

if [ "$CLIENT_POLICIES" -lt 2 ]; then
  echo "ERROR: expected at least 2 client XFRM policies, got $CLIENT_POLICIES"
  docker exec cryptna-client ip xfrm policy
  exit 1
fi
echo "OK"

echo "[6] verify XFRM installed on PEP"
PEP_STATES="$(docker exec cryptna-pep ip xfrm state | grep -c '^src ' || true)"
PEP_POLICIES="$(docker exec cryptna-pep ip xfrm policy | grep -c '^src ' || true)"

if [ "$PEP_STATES" -lt 2 ]; then
  echo "ERROR: expected at least 2 PEP XFRM states, got $PEP_STATES"
  docker exec cryptna-pep ip xfrm state
  exit 1
fi

if [ "$PEP_POLICIES" -lt 2 ]; then
  echo "ERROR: expected at least 2 PEP XFRM policies, got $PEP_POLICIES"
  docker exec cryptna-pep ip xfrm policy
  exit 1
fi
echo "OK"

echo "[7] verify service route back to client tunnel subnet"
docker exec cryptna-service-http ip route | grep -q '10.200.0.0/24 via 172.22.0.40'
echo "OK"

echo "[8] curl service through NAT-T IPsec tunnel"
HTTP_OUT="$(docker exec cryptna-client curl -sS --max-time 5 --interface "$CLIENT_INNER_IP" -D - "http://$SERVICE_IP")"
echo "$HTTP_OUT" | head -20

echo "$HTTP_OUT" | grep -q 'HTTP/1.1 200 OK'
echo "$HTTP_OUT" | grep -q 'Welcome to nginx'
echo "OK"

echo "[9] verify XFRM counters moved"
docker exec cryptna-client ip -s xfrm state
docker exec cryptna-pep ip -s xfrm state

echo "XFRM end-to-end NAT-T test OK"
