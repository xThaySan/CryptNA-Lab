package main

import (
	"strings"
	"testing"

	"cryptna-lab/common/protocol"
)

func TestRuntimeAttestationRequirementFailsClosed(t *testing.T) {
	t.Setenv("CLIENT_ATTESTATION_REQUIRED", "1")
	err := verifyTunnelAttestation(ClientConfig{}, ClientIdentity{}, protocol.AccessPayload{}, protocol.TunnelParams{})
	if err == nil || !strings.Contains(err.Error(), "attestation required") {
		t.Fatalf("missing attestation was not rejected: %v", err)
	}
}

func TestRuntimeBaselineAllowsMissingAttestation(t *testing.T) {
	t.Setenv("CLIENT_ATTESTATION_REQUIRED", "0")
	err := verifyTunnelAttestation(ClientConfig{AttestationRequired: true}, ClientIdentity{}, protocol.AccessPayload{}, protocol.TunnelParams{})
	if err != nil {
		t.Fatalf("baseline override unexpectedly required attestation: %v", err)
	}
}
