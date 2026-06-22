#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
(cd common/attest && go test ./...)
(cd verifier && go test ./...)

echo "History-bound attestation unit tests OK"
