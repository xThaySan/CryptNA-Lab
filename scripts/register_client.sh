#!/usr/bin/env bash
set -euo pipefail

CLIENT_IDENTITY="${1:-client/identity.json}"
OUT="${2:-pip/clients.json}"

CLIENT_PUB=$(jq -r .client_static_pub "$CLIENT_IDENTITY")
SPA_PSK=$(jq -r .spa_psk "$CLIENT_IDENTITY")

if [[ -z "$CLIENT_PUB" || "$CLIENT_PUB" == "null" ]]; then
  echo "missing client_static_pub in $CLIENT_IDENTITY" >&2
  exit 1
fi

if [[ -z "$SPA_PSK" || "$SPA_PSK" == "null" ]]; then
  echo "missing spa_psk in $CLIENT_IDENTITY" >&2
  exit 1
fi

cat > "$OUT" <<JSON
[
  {
    "client_pubkey": "$CLIENT_PUB",
    "psk": "$SPA_PSK",
    "allowed_services": ["svc-http"],
    "revoked": false
  }
]
JSON

echo "Registered client in $OUT:"
echo "  client_pubkey=$CLIENT_PUB"
echo "  psk=<copied from client identity>"
