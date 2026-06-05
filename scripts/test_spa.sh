#!/usr/bin/env bash
set -euo pipefail

docker compose up -d --build >/dev/null
echo "[1] client SPA request"
docker exec cryptna-client /app/client

echo "[2] PEP session state"
docker exec cryptna-pep curl -s http://localhost:8080/sessions | jq
