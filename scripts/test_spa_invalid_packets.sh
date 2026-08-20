#!/usr/bin/env bash
set -euo pipefail

echo "[1] random UDP packet should be silently dropped"
OUT="$(docker exec cryptna-spa-send /app/spa-send -mode random -random-size 128)"
echo "$OUT"
grep -q "timeout/no-response" <<<"$OUT"

echo "[2] empty UDP packet should be silently dropped"
OUT="$(docker exec cryptna-spa-send /app/spa-send -mode random -random-size 0)"
echo "$OUT"
grep -q "timeout/no-response" <<<"$OUT"

echo "[3] clear JSON should be silently dropped"
OUT="$(docker exec cryptna-spa-send /app/spa-send -mode json)"
echo "$OUT"
grep -q "timeout/no-response" <<<"$OUT"

echo "SPA invalid packet tests OK"
