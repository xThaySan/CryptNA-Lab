#!/usr/bin/env bash
set -euo pipefail

echo "[1] start lab with short SA lifetime"
SA_LIFETIME_SECONDS=10 SESSION_REAPER_INTERVAL_SECONDS=2 XFRM_MODE=apply CRYPTNA_DEBUG=1 docker compose up -d >/dev/null

echo "[2] cleanup existing XFRM state"
docker exec cryptna-client ip xfrm policy flush || true
docker exec cryptna-client ip xfrm state flush || true
docker exec cryptna-pep ip xfrm policy flush || true
docker exec cryptna-pep ip xfrm state flush || true
docker exec cryptna-client ip route delete 172.22.0.50/32 || true
docker exec cryptna-client ip addr flush dev lo scope global || true

echo "[3] service should be unreachable without CRYPTNA tunnel"
if docker exec cryptna-client curl -sS --max-time 3 http://172.22.0.50 >/tmp/cryptna-direct.out 2>&1; then
  echo "ERROR: service is reachable without CRYPTNA tunnel"
  cat /tmp/cryptna-direct.out
  exit 1
fi
echo "OK"

echo "[4] create CRYPTNA tunnel"
OUT="$(docker exec cryptna-client /app/client)"
echo "$OUT"
grep -q '"authorized": true' <<<"$OUT"

CLIENT_INNER_IP="$(echo "$OUT" | sed -n 's/.*"client_inner_ip": "\([^"]*\)".*/\1/p' | tail -1)"
SERVICE_IP="$(echo "$OUT" | sed -n 's/.*"service_ip": "\([^"]*\)".*/\1/p' | tail -1)"

if [ -z "$CLIENT_INNER_IP" ] || [ -z "$SERVICE_IP" ]; then
  echo "ERROR: failed to extract tunnel IPs"
  exit 1
fi

echo "client_inner_ip=$CLIENT_INNER_IP"
echo "service_ip=$SERVICE_IP"

echo "[5] service should be reachable through CRYPTNA tunnel"
HTTP_OUT="$(docker exec cryptna-client curl -sS --max-time 5 --interface "$CLIENT_INNER_IP" -D - "http://$SERVICE_IP")"
echo "$HTTP_OUT" | head -20
grep -q 'HTTP/1.1 200 OK' <<<"$HTTP_OUT"
grep -q 'Welcome to nginx' <<<"$HTTP_OUT"
echo "OK"

echo "[6] wait for tunnel expiry and cleanup"
sleep 13

echo "[7] service should be unreachable again after cleanup"
if docker exec cryptna-client curl -sS --max-time 3 "http://$SERVICE_IP" >/tmp/cryptna-after-cleanup.out 2>&1; then
  echo "ERROR: service is reachable after CRYPTNA tunnel cleanup"
  cat /tmp/cryptna-after-cleanup.out
  exit 1
fi
echo "OK"

echo "Service hiding test OK"
