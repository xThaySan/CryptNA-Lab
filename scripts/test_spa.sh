#!/usr/bin/env bash
set -euo pipefail

echo "[1] ensure lab is up"
docker compose up -d >/dev/null

echo "[2] health checks"
docker exec cryptna-pip curl -fsS http://localhost:8080/health >/dev/null
docker exec cryptna-pdp curl -fsS http://localhost:8080/health >/dev/null
docker exec cryptna-pep curl -fsS http://localhost:8080/health >/dev/null
echo "OK"

echo "[3] run client SPA"
OUT="$(docker exec cryptna-client /app/client)"
echo "$OUT"

echo "[4] check client received authorization"
grep -q '"authorized": true' <<<"$OUT"
grep -q '"tunnel"' <<<"$OUT"
grep -q '"pep_in_spi"' <<<"$OUT"
echo "OK"

echo "[5] check PEP stored at least one session"
SESSIONS="$(docker exec cryptna-pep curl -fsS http://localhost:8080/sessions)"
echo "$SESSIONS" | jq .

COUNT="$(echo "$SESSIONS" | jq 'length')"
if [ "$COUNT" -lt 1 ]; then
  echo "ERROR: no session stored in PEP"
  exit 1
fi
echo "OK"

echo "SPA nominal test OK"
