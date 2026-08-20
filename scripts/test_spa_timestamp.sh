#!/usr/bin/env bash
set -euo pipefail

echo "[1] ensure lab is up"
docker compose up -d >/dev/null

echo "[2] fresh SPA should be accepted"
FRESH="$(docker exec cryptna-spa-send /app/spa-send -mode send)"
echo "$FRESH"

if ! grep -q "response size=" <<<"$FRESH"; then
  echo "ERROR: fresh SPA was not accepted"
  exit 1
fi

echo "[3] expired SPA should be silently dropped"
EXPIRED="$(docker exec cryptna-spa-send /app/spa-send -mode send -timestamp-offset -30s)"
echo "$EXPIRED"

if ! grep -q "timeout/no-response" <<<"$EXPIRED"; then
  echo "ERROR: expired SPA was not dropped"
  exit 1
fi

echo "SPA timestamp anti-replay test OK"
