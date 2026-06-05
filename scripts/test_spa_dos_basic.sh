#!/usr/bin/env bash
set -euo pipefail

COUNT="${1:-1000}"

echo "[1] record PEP session count"
BEFORE="$(docker exec cryptna-pep curl -fsS http://localhost:8080/sessions | jq 'length')"
echo "sessions before=$BEFORE"

echo "[2] send $COUNT random UDP packets without waiting"
docker exec cryptna-spa-send /app/spa-send -mode random -count "$COUNT" -random-size 128 -wait=false >/dev/null

echo "[3] PDP should still be alive"
docker exec cryptna-pdp curl -fsS http://localhost:8080/health >/dev/null

echo "[4] PEP session count should not increase"
AFTER="$(docker exec cryptna-pep curl -fsS http://localhost:8080/sessions | jq 'length')"
echo "sessions after=$AFTER"

if [ "$BEFORE" != "$AFTER" ]; then
  echo "ERROR: random packets created PEP sessions"
  exit 1
fi

echo "SPA basic DoS test OK"
