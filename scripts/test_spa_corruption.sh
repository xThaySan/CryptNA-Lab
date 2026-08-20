#!/usr/bin/env bash
set -euo pipefail

PACKET="/tmp/spa-corruption-test.packet"

echo "[1] build valid SPA packet"
docker exec cryptna-spa-send /app/spa-send -mode build -packet "$PACKET"

for PART in epub ns nm random; do
  echo "[2] corrupt part=$PART should be silently dropped"
  OUT="$(docker exec cryptna-spa-send /app/spa-send -mode corrupt -packet "$PACKET" -corrupt-part "$PART")"
  echo "$OUT"

  if ! grep -q "timeout/no-response" <<<"$OUT"; then
    echo "ERROR: corrupted packet part=$PART was not dropped"
    exit 1
  fi
done

echo "SPA corruption tests OK"
