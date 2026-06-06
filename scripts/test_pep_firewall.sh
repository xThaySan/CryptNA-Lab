#!/usr/bin/env bash
set -euo pipefail

echo "[1] start lab with PEP firewall enabled"
PEP_FIREWALL_ENABLED=1 XFRM_MODE=apply CRYPTNA_DEBUG=1 docker compose up -d --build pep >/dev/null

echo "[2] verify PEP FORWARD policy is DROP"
docker exec cryptna-pep iptables -S FORWARD | grep -q '^-P FORWARD DROP'

echo "[3] verify only tunnel subnet to service:80 is allowed"
docker exec cryptna-pep iptables -S FORWARD | grep -q -- '-s 10.200.0.0/24 -d 172.22.0.50/32'
docker exec cryptna-pep iptables -S FORWARD | grep -q -- '--dport 80'
docker exec cryptna-pep iptables -S FORWARD | grep -q -- '-s 172.22.0.50/32 -d 10.200.0.0/24'
docker exec cryptna-pep iptables -S FORWARD | grep -q -- '--sport 80'

echo "[4] create tunnel"
OUT="$(docker exec cryptna-client /app/client)"
echo "$OUT"
echo "$OUT" | grep -q '"authorized": true'

CLIENT_INNER_IP="$(echo "$OUT" | sed -n 's/.*"client_inner_ip": "\([^"]*\)".*/\1/p' | tail -1)"
SERVICE_IP="$(echo "$OUT" | sed -n 's/.*"service_ip": "\([^"]*\)".*/\1/p' | tail -1)"

if [ -z "$CLIENT_INNER_IP" ] || [ -z "$SERVICE_IP" ]; then
  echo "ERROR: failed to extract tunnel IPs"
  exit 1
fi

echo "[5] service should still be reachable through tunnel"
HTTP_OUT="$(docker exec cryptna-client curl -sS --max-time 5 --interface "$CLIENT_INNER_IP" -D - "http://$SERVICE_IP")"
echo "$HTTP_OUT" | head -20
echo "$HTTP_OUT" | grep -q 'HTTP/1.1 200 OK'
echo "$HTTP_OUT" | grep -q 'Welcome to nginx'

echo "PEP firewall test OK"
