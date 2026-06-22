#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

(cd pep && go test ./... -run 'TestPEP|TestClientInnerIPPool|TestPosthocObserver')
(cd verifier && go test -race ./... -run 'TestCapacityHandler')
(cd client && go test ./... -run 'TestRuntimeAttestationRequirement|TestRuntimeBaseline')

echo "History persistence, crash and concurrent multi-PEP tests OK"
