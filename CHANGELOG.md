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

## Refactor IPsec/XFRM model

- Renamed SPI fields to match IPsec receiver-owned semantics:
  - `client_in_spi`: SPI chosen by the client to receive PEP -> Client traffic.
  - `pep_in_spi`: SPI chosen by the PEP to receive Client -> PEP traffic.
- Removed the previous ambiguous `client_spi` / `pep_spi` model from the active protocol structs.
- Added `common/ipsecutil` to factorize IPsec/XFRM-related helpers:
  - random SPI generation;
  - random reqid generation helper;
  - RFC4106 AES-GCM key material derivation;
  - XFRM tunnel plan generation.
- Moved XFRM command construction out of `pep/xfrm.go` into `common/ipsecutil`.
- Updated client and `tools/spa-send` to generate `client_in_spi` with the common helper.
- Updated PEP to generate `pep_in_spi` itself, instead of trusting the client for the inbound SPI.
- Added per-session metadata to `protocol.Session`:
  - `reqid`;
  - `client_outer_ip`;
  - `client_inner_ip`;
  - `pep_outer_ip`;
  - `service_ip`.
- Added per-session client inner IP allocation (`CLIENT_INNER_IP_PREFIX` / `CLIENT_INNER_IP_START`) so multiple clients sharing the same outer IP can still receive distinct XFRM policies.
- Reworked XFRM tunnel generation so policies are keyed on `client_inner_ip -> service_ip`, avoiding global flushes and avoiding policy collisions for multiple sessions.
- Added per-session `delete_commands` in the XFRM plan for future targeted cleanup instead of `ip xfrm flush`.
- Updated Docker Compose PEP environment:
  - `CLIENT_OUTER_IP`;
  - `PEP_OUTER_IP`;
  - `XFRM_REQID_BASE`;
  - `CLIENT_INNER_IP_PREFIX`;
  - `CLIENT_INNER_IP_START`.
- Updated Dockerfiles to include `common/ipsecutil` in the relevant build contexts.

## Client-side XFRM/NAT-T tunnel plan and L3 service forwarding model

- Fixed the CRYPTNA data-plane model around the validated L3 tunnel semantics:
  - the PEP assigns a per-session `client_inner_ip`;
  - the client agent uses this address as the inner source address;
  - the client still learns the real `service_ip` only after authorization;
  - traffic is protected as `client_inner_ip -> service_ip` inside the IPsec tunnel;
  - outer transport remains `client_outer_ip -> pep_outer_ip` using ESP-in-UDP NAT-T.
- Extended `common/protocol.TunnelParams` to include:
  - `service_ip`;
  - `client_inner_ip`;
  - `reqid`.
- Extended `common/protocol.Session` to consistently include `client_inner_ip` and NAT-T metadata.
- Refactored `common/ipsecutil`:
  - added `BuildPEPXFRMTunnelPlan(...)` for PEP-side tunnel states/policies;
  - added `BuildClientXFRMTunnelPlan(...)` for client-side tunnel states/policies;
  - preserved `BuildXFRMTunnelPlan(...)` as a PEP-side compatibility wrapper.
- Corrected PEP XFRM policies to match the intended inner traffic:
  - `client_inner_ip -> service_ip` with `dir fwd`;
  - `service_ip -> client_inner_ip` with `dir out`.
- Added client-side XFRM support:
  - configures `client_inner_ip/32` on `lo`;
  - installs route to `service_ip` via the PEP outer IP with source `client_inner_ip`;
  - installs NAT-T XFRM states/policies for both directions;
  - respects `XFRM_MODE=dry-run|apply`.
- Updated the client image to include `iproute2` and added `NET_ADMIN` to the client service.
- Updated the service HTTP container:
  - now built from `service/Dockerfile`;
  - includes `iproute2`;
  - adds a return route for `10.200.0.0/24` via the PEP service-side IP.
- Added `scripts/test_xfrm_end_to_end.sh`:
  - creates a tunnel;
  - checks client and PEP XFRM state/policy installation;
  - checks service-side route to tunnel clients;
  - attempts an HTTP request from client to service through the tunnel.
- Updated `scripts/test_xfrm_multi_session.sh` to also account for client-side XFRM installation and cleanup.
