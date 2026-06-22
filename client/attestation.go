package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"cryptna-lab/common/attest"
	"cryptna-lab/common/protocol"
)

func verifyTunnelAttestation(cfg ClientConfig, id ClientIdentity, payload protocol.AccessPayload, tunnel protocol.TunnelParams) error {
	if value, ok := os.LookupEnv("CLIENT_ATTESTATION_REQUIRED"); ok {
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "1", "true", "yes", "on":
			cfg.AttestationRequired = true
		case "0", "false", "no", "off":
			cfg.AttestationRequired = false
		}
	}
	hasAttestation := tunnel.CapacityToken != nil || tunnel.SABinding != nil
	if !cfg.AttestationRequired && !hasAttestation {
		return nil
	}
	if cfg.AttestationRequired && !hasAttestation {
		return fmt.Errorf("attestation required but tunnel has no capacity token / SA binding")
	}
	if !hasAttestation {
		return nil
	}
	if tunnel.CapacityToken == nil || tunnel.SABinding == nil {
		return fmt.Errorf("incomplete attestation: capacity_token and sa_binding are both required")
	}
	if cfg.VerifierPubKey == "" {
		return fmt.Errorf("missing verifier_pubkey in client config")
	}
	if cfg.ExpectedPolicyHash != "" && tunnel.CapacityToken.PolicyHash != cfg.ExpectedPolicyHash {
		return fmt.Errorf("policy_hash mismatch expected=%s token=%s", cfg.ExpectedPolicyHash, tunnel.CapacityToken.PolicyHash)
	}
	if tunnel.CapacityToken.CheckpointHash == "" || tunnel.CapacityToken.HistoryEpoch == 0 {
		return fmt.Errorf("capacity token is not bound to an enforcement history checkpoint")
	}
	if payload.ServiceID != tunnel.ServiceID {
		return fmt.Errorf("service mismatch payload=%s tunnel=%s", payload.ServiceID, tunnel.ServiceID)
	}
	if payload.ClientInSPI != tunnel.ClientInSPI {
		return fmt.Errorf("client_in_spi mismatch payload=%s tunnel=%s", payload.ClientInSPI, tunnel.ClientInSPI)
	}
	if payload.ClientDHPub == "" {
		return fmt.Errorf("missing client_dh_pub in original payload")
	}
	return attest.VerifyTunnelBinding(tunnel, id.ClientStaticPub, payload.ClientDHPub, cfg.VerifierPubKey, time.Now().UTC())
}
