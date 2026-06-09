#!/usr/bin/env bash
set -euo pipefail

OUT="${1:-pip/clients.json}"
shift || true

if [ "$#" -eq 0 ]; then
  set -- client/identities/client1.json
fi

jq -n '[inputs | {
  client_pubkey: .client_static_pub,
  psk: .spa_psk,
  allowed_services: ["svc-http"],
  revoked: false
}]' "$@" > "$OUT"

echo "Registered clients in $OUT:"
jq -r '.[] | "  client_pubkey=" + .client_pubkey' "$OUT"
