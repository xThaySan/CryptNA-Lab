#!/usr/bin/env bash
set -euo pipefail

PEP_ATTESTATION_ENABLED=1 \
CLIENT_ATTESTATION_REQUIRED=1 \
VERIFIER_REQUIRED_OBSERVER_PROFILE=posthoc \
  ./scripts/test_xfrm_end_to_end.sh
