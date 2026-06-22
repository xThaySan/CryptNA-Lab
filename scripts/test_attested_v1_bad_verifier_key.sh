#!/usr/bin/env bash
set -euo pipefail

chmod +x scripts/*.sh

BACKUP="$(mktemp)"
cp client/config.json "$BACKUP"
restore() {
  cp "$BACKUP" client/config.json
  rm -f "$BACKUP"
}
trap restore EXIT

python3 - <<'PY'
import json
from pathlib import Path
p = Path('client/config.json')
data = json.loads(p.read_text())
# 32 zero bytes in base64: syntactically valid Ed25519 public key, but not the verifier key.
data['verifier_pubkey'] = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
data['attestation_required'] = True
p.write_text(json.dumps(data, indent=2) + '\n')
PY

echo "[1] start attested V1 lab with wrong client verifier key"
docker compose down -v --remove-orphans >/dev/null
PEP_ATTESTATION_ENABLED=1 XFRM_MODE=dry-run CRYPTNA_DEBUG=0 docker compose up -d --build >/dev/null

echo "[2] client must reject attested tunnel"
set +e
OUT="$(docker exec -e XFRM_MODE=dry-run cryptna-client /app/client 2>&1)"
RC=$?
set -e

echo "$OUT"
if [ "$RC" -eq 0 ]; then
  echo "ERROR: client accepted a tunnel with an invalid Verifier public key"
  exit 1
fi

echo "$OUT" | grep -qi 'attested PEP verification failed'

echo "Attested V1 bad verifier key test OK"
