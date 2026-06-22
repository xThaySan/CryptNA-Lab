# CRYPTNA V1 - Attested PEP Capacity and SA Binding

This implementation adds the V1 attestation model discussed for the new paper.

## Goal

The PDP remains the CRYPTNA orchestrator, but the client no longer accepts tunnel parameters solely because they are returned by the PDP. When attestation is enabled, the client verifies that:

1. a Verifier signed a short-lived PEP capacity token;
2. the token binds a temporary PEP signing key to an attested PEP state;
3. the PEP signed the concrete SA parameters with the key named in that token;
4. the SA lifetime does not exceed the token validity window or max SA lifetime.

## Components

- `verifier`: new Docker service acting as the V1 Verifier.
- `common/attest`: Ed25519 signing, token verification, SA binding verification.
- `protocol.CapacityToken`: Verifier-signed token for a PEP signing key.
- `protocol.SABinding`: PEP-signed binding over the concrete tunnel parameters.
- `pep`: fetches capacity tokens from the Verifier when `PEP_ATTESTATION_ENABLED=1`.
- `pdp`: relays the token and binding to the client inside the encrypted SPA response.
- `client`: verifies the token and binding before installing XFRM.

## Runtime flags

Attestation is disabled by default to preserve baseline CRYPTNA tests:

```bash
PEP_ATTESTATION_ENABLED=0
```

To enable V1:

```bash
PEP_ATTESTATION_ENABLED=1 XFRM_MODE=dry-run docker compose up -d --build
```

## Test commands

Positive path:

```bash
./scripts/test_attested_v1_end_to_end.sh
```

Negative path, client rejects a token under the wrong Verifier key:

```bash
./scripts/test_attested_v1_bad_verifier_key.sh
```

Baseline regression after implementation:

```bash
./experiments/01_correctness_matrix.sh
```

## Limits

V1 is not a hardware remote attestation system. The lab uses a simulated software measurement and a Verifier-signed capability to validate the cryptographic binding and protocol flow. TPM/TEE integration and continuity evidence are left for later work.
