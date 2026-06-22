#!/usr/bin/env bash
set -euo pipefail

RESULT_DIR="experiments/results"
OUT="$RESULT_DIR/08_history_token_size.csv"
mkdir -p "$RESULT_DIR"

echo "[1] start lab in attested dry-run mode"
docker compose down -v --remove-orphans >/dev/null
PEP_ATTESTATION_ENABLED=1 \
XFRM_MODE=dry-run \
CRYPTNA_DEBUG=0 \
VERIFIER_TOKEN_TTL_SECONDS=25 \
  docker compose up -d --build >/dev/null

echo "[2] create tunnel and capture response JSON"
RESP="$(docker exec -e XFRM_MODE=dry-run -e CRYPTNA_DEBUG=0 cryptna-client /app/client)"

echo "[3] compute JSON object sizes"
python3 - <<'PY' "$OUT" "$RESP"
import csv, json, sys
from pathlib import Path
out = Path(sys.argv[1])
text = sys.argv[2]
start = text.find('{')
end = text.rfind('}')
if start < 0 or end < 0:
    raise SystemExit('could not find JSON object in client output')
obj = json.loads(text[start:end+1])
tunnel = obj.get('tunnel') or {}
token = tunnel.get('capacity_token') or {}
binding = tunnel.get('sa_binding') or {}
rows = [
    ('access_response_json_bytes', len(json.dumps(obj, separators=(',', ':')).encode())),
    ('tunnel_json_bytes', len(json.dumps(tunnel, separators=(',', ':')).encode())),
    ('capacity_token_json_bytes', len(json.dumps(token, separators=(',', ':')).encode())),
    ('sa_binding_json_bytes', len(json.dumps(binding, separators=(',', ':')).encode())),
]
with out.open('w', newline='') as f:
    w = csv.writer(f)
    w.writerow(['metric', 'bytes'])
    w.writerows(rows)
for k, v in rows:
    print(f'{k},{v}')
PY

echo "csv=$OUT"
