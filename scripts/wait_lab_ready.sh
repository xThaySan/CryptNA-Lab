#!/usr/bin/env bash
set -euo pipefail

TIMEOUT_SECONDS="${LAB_READY_TIMEOUT_SECONDS:-90}"
CONTAINERS=(cryptna-pip cryptna-pdp cryptna-verifier cryptna-pep)

deadline=$((SECONDS + TIMEOUT_SECONDS))
for container in "${CONTAINERS[@]}"; do
  echo "waiting for $container"
  until docker exec "$container" curl -fsS http://localhost:8080/health >/dev/null 2>&1; do
    if [ "$SECONDS" -ge "$deadline" ]; then
      echo "ERROR: $container did not become healthy within ${TIMEOUT_SECONDS}s" >&2
      docker ps --filter "name=$container" >&2 || true
      docker logs "$container" 2>&1 | tail -120 >&2 || true
      exit 1
    fi
    sleep 1
  done
done

echo "CRYPTNA lab ready"
