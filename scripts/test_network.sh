#!/usr/bin/env bash
set -euo pipefail

echo "[1] client -> pdp"
docker exec cryptna-client ping -c 1 172.20.0.20 >/dev/null
echo "OK"

echo "[2] pdp -> pip"
docker exec cryptna-pdp ping -c 1 172.20.0.30 >/dev/null
echo "OK"

echo "[3] pdp -> pep"
docker exec cryptna-pdp ping -c 1 172.20.0.40 >/dev/null
echo "OK"

echo "[4] client -> pep data plane"
docker exec cryptna-client ping -c 1 172.21.0.40 >/dev/null
echo "OK"

echo "[5] pep -> service"
docker exec cryptna-pep curl -fsI http://172.22.0.50 >/dev/null
echo "OK"

echo "[6] client -> service direct should fail"
if docker exec cryptna-client curl -fsI --max-time 2 http://172.22.0.50 >/dev/null 2>&1; then
  echo "ERROR: client can reach service directly"
  exit 1
else
  echo "OK: direct access blocked"
fi

echo "Network lab OK"
