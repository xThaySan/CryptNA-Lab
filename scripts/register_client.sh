#!/usr/bin/env bash
set -euo pipefail

CLIENT_IDENTITY="${1:-client/identity.json}"
OUT="${2:-pip/clients.json}"

CLIENT_PUB=$(jq -r .client_static_pub "$CLIENT_IDENTITY")

cat > "$OUT" <<JSON
[
  {
    "client_pubkey": "$CLIENT_PUB",
    "psk": "psk-demo",
    "allowed_services": ["svc-http"],
    "revoked": false
  }
]
JSON

echo "Registered client public key in $OUT:"
echo "$CLIENT_PUB"
