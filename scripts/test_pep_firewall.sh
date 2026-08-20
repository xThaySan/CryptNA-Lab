#!/usr/bin/env bash
set -euo pipefail

echo "[1] start lab with PEP firewall enabled"
PEP_FIREWALL_ENABLED=1 XFRM_MODE=apply CRYPTNA_DEBUG=1 docker compose up -d --build pep >/dev/null

echo "[2] verify PEP FORWARD policy is DROP"
docker exec cryptna-pep iptables -S FORWARD | grep '^-P FORWARD DROP' >/dev/null

echo "[3] verify only tunnel subnet to service:80 is allowed"
docker exec cryptna-pep iptables -S FORWARD | grep -- '-s 10.200.0.0/16 -d 172.22.0.50/32' >/dev/null
docker exec cryptna-pep iptables -S FORWARD | grep -- '--dport 80' >/dev/null
docker exec cryptna-pep iptables -S FORWARD | grep -- '-s 172.22.0.50/32 -d 10.200.0.0/16' >/dev/null
docker exec cryptna-pep iptables -S FORWARD | grep -- '--sport 80' >/dev/null

echo "[4] create tunnel"
OUT="$(docker exec cryptna-client /app/client)"
echo "$OUT"
grep -q '"authorized": true' <<<"$OUT"

CLIENT_INNER_IP="$(echo "$OUT" | sed -n 's/.*"client_inner_ip": "\([^"]*\)".*/\1/p' | tail -1)"
SERVICE_IP="$(echo "$OUT" | sed -n 's/.*"service_ip": "\([^"]*\)".*/\1/p' | tail -1)"

if [ -z "$CLIENT_INNER_IP" ] || [ -z "$SERVICE_IP" ]; then
  echo "ERROR: failed to extract tunnel IPs"
  exit 1
fi

echo "[5] service should still be reachable through tunnel"
HTTP_OUT="$(docker exec cryptna-client curl -sS --max-time 5 --interface "$CLIENT_INNER_IP" -D - "http://$SERVICE_IP")"
echo "$HTTP_OUT" | head -20
grep -q 'HTTP/1.1 200 OK' <<<"$HTTP_OUT"
grep -q 'Welcome to nginx' <<<"$HTTP_OUT"

echo "PEP firewall test OK"
