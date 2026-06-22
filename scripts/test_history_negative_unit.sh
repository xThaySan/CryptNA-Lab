#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

(cd common/attest && go test ./... -run 'TestVerifyHistoryEvidence')
(cd verifier && go test ./... -run 'TestVerifyEnforcementPolicy|TestScopeSubset')

echo "History-bound negative unit tests OK"
