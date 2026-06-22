# CRYPTNA V1 - Attested PEP Capacity and SA Binding

This implementation adds the V1 attestation model discussed for the new paper.

## Goal

The PDP remains the CRYPTNA orchestrator, but the client no longer accepts tunnel parameters solely because they are returned by the PDP. When attestation is enabled, the client verifies that:

1. a Verifier signed a short-lived PEP capacity token;
2. the token binds an explicitly enrolled PEP signing key to the appraised PEP state and history checkpoint;
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
PEP_ATTESTATION_ENABLED=1 XFRM_MODE=dry-run VERIFIER_REQUIRED_OBSERVER_PROFILE=dry-run docker compose up -d --build
```

Compose also sets `CLIENT_ATTESTATION_REQUIRED=1` from `PEP_ATTESTATION_ENABLED`, so an attested run fails closed if the PDP response omits the token or SA binding. The PEP pins the Verifier public key through `PEP_VERIFIER_PUBLIC_KEY`, verifies every returned token signature, and checks its PEP identity, scope, software profile, observer profile, lifetime, epoch, and checkpoint hash before using it.

## Test commands

Positive path:

```bash
./scripts/test_attested_v1_end_to_end.sh
```

Positive path with real XFRM installation and protected HTTP traffic:

```bash
./scripts/test_attested_xfrm_end_to_end.sh
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

The Verifier loads an explicit enrollment map from `verifier/enrolled_peps.json` and rejects a capacity request when its `pep_id` and signing key do not match that map. The lab PEP key is stable across restarts and the demonstration public key is pinned by this enrollment. Conversely, the PEP and clients pin the demonstration Verifier public key. Production deployments must provision unique non-public identities through a protected enrollment process.

V1 is not a hardware remote attestation system. The lab uses a software measurement identifier and a Verifier-signed capability to validate the cryptographic binding and protocol flow. It does not generate a TPM quote or fresh hardware Evidence. A production profile should bind `PEPID`, the PEP signing key, the checkpoint hash, and a Verifier nonce into TPM/TEE-backed Evidence.
