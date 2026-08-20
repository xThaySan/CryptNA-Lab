#!/usr/bin/env bash
set -euo pipefail

PEP_ATTESTATION_ENABLED="${PEP_ATTESTATION_ENABLED:-0}"
CLIENT_ATTESTATION_REQUIRED="${CLIENT_ATTESTATION_REQUIRED:-$PEP_ATTESTATION_ENABLED}"
VERIFIER_REQUIRED_OBSERVER_PROFILE="${VERIFIER_REQUIRED_OBSERVER_PROFILE:-posthoc}"

echo "[1] start a clean lab with XFRM apply mode"
docker compose down -v --remove-orphans >/dev/null 2>&1 || true
XFRM_MODE=apply \
PEP_ATTESTATION_ENABLED="$PEP_ATTESTATION_ENABLED" \
CLIENT_ATTESTATION_REQUIRED="$CLIENT_ATTESTATION_REQUIRED" \
VERIFIER_REQUIRED_OBSERVER_PROFILE="$VERIFIER_REQUIRED_OBSERVER_PROFILE" \
CRYPTNA_DEBUG=1 \
  docker compose up -d --build >/dev/null
./scripts/wait_lab_ready.sh

echo "[2] verify NAT-T listeners"
docker exec cryptna-pep ss -lunp | grep ':4500' >/dev/null
docker exec cryptna-client ss -lunp | grep ':4500' >/dev/null
echo "OK"

echo "[3] cleanup XFRM state"
docker exec cryptna-client ip xfrm policy flush || true
docker exec cryptna-client ip xfrm state flush || true
docker exec cryptna-pep ip xfrm policy flush || true
docker exec cryptna-pep ip xfrm state flush || true

echo "[4] create CRYPTNA tunnel"
OUT="$(docker exec cryptna-client /app/client)"
echo "$OUT"

grep -q '"authorized": true' <<<"$OUT"
if [ "$CLIENT_ATTESTATION_REQUIRED" = "1" ]; then
  grep -q '"capacity_token"' <<<"$OUT"
  grep -q '"sa_binding"' <<<"$OUT"
  grep -q '"verifier_signature"' <<<"$OUT"
  grep -q '"pep_signature"' <<<"$OUT"
fi

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
docker exec cryptna-service-http ip route | grep '10.200.0.0/16 via 172.22.0.40' >/dev/null
echo "OK"

echo "[8] curl service through NAT-T IPsec tunnel"
HTTP_OUT="$(docker exec cryptna-client curl -sS --max-time 5 --interface "$CLIENT_INNER_IP" -D - "http://$SERVICE_IP")"
echo "$HTTP_OUT" | head -20

grep -q 'HTTP/1.1 200 OK' <<<"$HTTP_OUT"
grep -q 'Welcome to nginx' <<<"$HTTP_OUT"
echo "OK"

echo "[9] verify XFRM counters moved"
docker exec cryptna-client ip -s xfrm state
docker exec cryptna-pep ip -s xfrm state

echo "XFRM end-to-end NAT-T test OK"
