#!/usr/bin/env bash
set -euo pipefail

PACKET="/tmp/spa-replay-test.packet"

echo "[1] ensure lab is up"
docker compose up -d >/dev/null

echo "[2] build SPA packet"
docker exec cryptna-spa-send /app/spa-send -mode build -packet "$PACKET"

echo "[3] first send should get a response"
FIRST="$(docker exec cryptna-spa-send /app/spa-send -mode replay -packet "$PACKET")"
echo "$FIRST"

if ! echo "$FIRST" | grep -q "response size="; then
  echo "ERROR: first SPA send did not receive a response"
  exit 1
fi

echo "[4] second send should be silently dropped"
SECOND="$(docker exec cryptna-spa-send /app/spa-send -mode replay -packet "$PACKET")"
echo "$SECOND"

if ! echo "$SECOND" | grep -q "timeout/no-response"; then
  echo "ERROR: replayed SPA was not dropped"
  exit 1
fi

echo "SPA replay test OK"
