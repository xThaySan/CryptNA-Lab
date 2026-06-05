# Changelog — SPA Noise IKpsk1 integration

## Main changes

### 1. Common modules

Added shared Go modules under `common/`:

- `common/protocol`
  - Centralizes wire structures shared by client, PDP, PEP and PIP.
  - Defines `AccessPayload`, `ActivateRequest`, `AccessResponse`, `TunnelParams`, `ClientInfo`, and `Session`.

- `common/cryptoutil`
  - Centralizes X25519 key generation, shared-secret derivation and HKDF session-key derivation.
  - Removes duplicated X25519/HKDF logic from client and PEP.

- `common/noiseutil`
  - Implements the CRYPTNA SPA handshake in a compact custom Noise-style flow:
    - protocol basis: `Noise_IKpsk1_25519_AESGCM_SHA256`;
    - first UDP packet layout: `epub || ns || nm`;
    - `ns = Enc(timestamp_ms || client_static_pub)`;
    - `nm = Enc(AccessPayload)`;
    - PDP response encrypted with the responder-to-initiator transport key after split.
  - Adds `PacketHash(packet)` for replay-cache keys.

### 2. Client → PDP interaction

Replaced the previous UDP JSON-clear access request with an encrypted SPA packet:

- Client builds `AccessPayload` containing only:
  - `service_id`;
  - `client_spi`;
  - `client_dh_pub`;
  - `aead_suites`.
- Client identity and timestamp are no longer in the business payload.
- Client sends one UDP packet to `cryptna-pdp:4000`.
- Client decrypts the UDP response using the Noise-derived response key.
- Client still derives local client-to-PEP and PEP-to-client session keys from the PEP ephemeral DH public key.

### 3. PDP SPA processing

The PDP now:

- loads its static identity from `pdp/identity.json`;
- listens for UDP SPA packets on port `4000`;
- computes `SHA256(full_spa_packet)` as replay key;
- drops silently on:
  - malformed SPA;
  - invalid timestamp;
  - replayed packet hash;
  - unknown client;
  - revoked client;
  - unauthorized service;
  - PEP activation failure;
- decrypts `ns` to recover:
  - timestamp;
  - client static public key;
- decrypts `nm` to recover the access payload;
- queries the PIP using the recovered client public key;
- activates the PEP over HTTP as before;
- encrypts the PDP response before sending it back over UDP.

### 4. Replay protection

Replay protection now follows the optimized design:

- timestamp remains in `ns`, as in the paper design;
- no extra client nonce was added;
- the replay cache key is `SHA256(epub || ns || nm)`, i.e. the full SPA packet;
- entries are cached for a 10-second TTL;
- invalid packets receive no response.

### 5. PEP and PIP refactor

- PEP now uses `common/protocol` and `common/cryptoutil`.
- PIP now uses `common/protocol.ClientInfo`.
- PEP still stores derived sessions in memory.
- PEP activation remains HTTP for now, as agreed.
- No IPsec/XFRM Security Association is installed yet.

### 6. Docker/build changes

- Updated Go component Dockerfiles to build from the repository root when common modules are needed.
- Added root `go.work` for local multi-module development.
- Added `pdp/identity.json` for PDP static key and SPA PSK.
- Updated `client/config.json` with the PDP static public key.
- Updated `client/identity.json` with `spa_psk`.
- Updated `scripts/register_client.sh` to copy the current client public key and PSK into `pip/clients.json`.
- Added `scripts/test_spa.sh` for a quick end-to-end SPA test.

## Current protocol state

Implemented:

```text
Client -> PDP: UDP SPA using custom Noise IKpsk1-style packet
PDP -> PIP: HTTP lookup by decrypted client static public key
PDP -> PEP: HTTP activation
PEP -> PDP: tunnel params
PDP -> Client: encrypted UDP response
Client/PEP: derive matching session keys
```

Not implemented yet:

```text
Noise transport beyond the single encrypted response
IPsec/XFRM SA installation
PEP-only-IPsec access policy
PDP -> PEP over IPsec
Remote Attestation / capacity tokens
SPA packet metrics and replay-cache benchmarks
```

## Important design note

This implementation uses one configured `spa_psk` known by both the client and the PDP. This is necessary because in `IKpsk1`, the PSK is mixed before decrypting the encrypted client identity. A strictly per-client PSK would require either an external client hint, a PSK identifier, or trial decryption against candidate PSKs, which is not implemented in this minimal lab.
