#!/usr/bin/env bash
set -euo pipefail

echo "[1] authorized service should receive response"
OK="$(docker exec cryptna-spa-send /app/spa-send -mode send -service svc-http)"
echo "$OK"
echo "$OK" | grep -q "response size="

BEFORE="$(docker exec cryptna-pep curl -fsS http://localhost:8080/sessions | jq 'length')"

echo "[2] unauthorized service should be silently dropped"
BAD="$(docker exec cryptna-spa-send /app/spa-send -mode send -service svc-admin)"
echo "$BAD"
echo "$BAD" | grep -q "timeout/no-response"

AFTER="$(docker exec cryptna-pep curl -fsS http://localhost:8080/sessions | jq 'length')"

if [ "$BEFORE" != "$AFTER" ]; then
  echo "ERROR: unauthorized service created a PEP session"
  echo "before=$BEFORE after=$AFTER"
  exit 1
fi

echo "SPA authorization tests OK"
