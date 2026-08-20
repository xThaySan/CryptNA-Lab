#!/usr/bin/env bash
set -euo pipefail

WRONG_PSK="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

echo "[1] wrong PSK should make Noise opening fail silently"
OUT="$(docker exec cryptna-spa-send /app/spa-send -mode send -psk "$WRONG_PSK")"
echo "$OUT"

if ! grep -q "timeout/no-response" <<<"$OUT"; then
  echo "ERROR: wrong PSK was not silently dropped"
  exit 1
fi

echo "SPA wrong PSK test OK"
