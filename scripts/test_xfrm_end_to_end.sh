#!/usr/bin/env bash
set -euo pipefail

echo "[1] ensure lab is up with XFRM apply mode"
XFRM_MODE=apply docker compose up -d >/dev/null

echo "[2] cleanup existing XFRM states/policies"
docker exec cryptna-client ip xfrm policy flush || true
docker exec cryptna-client ip xfrm state flush || true
docker exec cryptna-pep ip xfrm policy flush || true
docker exec cryptna-pep ip xfrm state flush || true

echo "[3] restart PEP to reset sessions"
XFRM_MODE=apply docker compose up -d --force-recreate pep >/dev/null

echo "[4] create one CRYPTNA tunnel"
OUT="$(docker exec cryptna-client /app/client)"
echo "$OUT"
echo "$OUT" | grep -q '"authorized": true'

JSON_OUT="$(printf '%s\n' "$OUT" | sed -n '/^{/,$p' | sed '/^spa_packet_hash:/,$d')"
SERVICE_IP="$(echo "$JSON_OUT" | jq -r '.tunnel.service_ip')"
CLIENT_INNER_IP="$(echo "$JSON_OUT" | jq -r '.tunnel.client_inner_ip')"

if [ -z "$SERVICE_IP" ] || [ "$SERVICE_IP" = "null" ]; then
  echo "ERROR: missing service_ip"
  exit 1
fi
if [ -z "$CLIENT_INNER_IP" ] || [ "$CLIENT_INNER_IP" = "null" ]; then
  echo "ERROR: missing client_inner_ip"
  exit 1
fi

echo "[5] verify XFRM installed on client and PEP"
docker exec cryptna-client ip xfrm state | grep -q '^src '
docker exec cryptna-client ip xfrm policy | grep -q '^src '
docker exec cryptna-pep ip xfrm state | grep -q '^src '
docker exec cryptna-pep ip xfrm policy | grep -q '^src '

echo "[6] verify service has route back to tunnel clients"
docker exec cryptna-service-http ip route | grep -q '10.200.0.0/24 via 172.22.0.40'

echo "[7] try HTTP request through the IPsec tunnel"
docker exec cryptna-client curl -fsS --max-time 5 "http://$SERVICE_IP" >/dev/null

echo "XFRM end-to-end HTTP test OK"
