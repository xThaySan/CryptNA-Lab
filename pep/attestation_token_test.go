package main

import (
	"strings"
	"testing"
	"time"

	"cryptna-lab/common/attest"
	"cryptna-lab/common/protocol"
)

func TestPEPValidatesPinnedVerifierToken(t *testing.T) {
	verifierIdentity, err := attest.GenerateEd25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	pepIdentity, err := attest.GenerateEd25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	evidence := protocol.HistoryEvidence{Checkpoint: protocol.EnforcementCheckpoint{
		Version:        1,
		PEPID:          "pep-test",
		Epoch:          1,
		LastEventIndex: 0,
		EventCount:     0,
		CreatedAt:      time.Now().UTC().Format(time.RFC3339),
	}}
	checkpointHash, err := attest.HashEnforcementCheckpoint(evidence.Checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	state := &pepAttestationState{
		pepID:            "pep-test",
		measurement:      "measurement-test",
		policyHash:       "policy-test",
		scope:            []string{"svc-http"},
		maxSALifetime:    60,
		verifierPubKey:   verifierIdentity.PublicKey,
		requiredObserver: "posthoc",
		key:              pepIdentity,
	}
	now := time.Now().UTC()
	token, err := attest.SignCapacityToken(protocol.CapacityToken{
		Version:          1,
		TokenType:        "cryptna-pep-capacity-v1",
		VerifierID:       "verifier-test",
		PEPID:            state.pepID,
		PEPSigningPubKey: pepIdentity.PublicKey,
		Measurement:      state.measurement,
		PolicyHash:       state.policyHash,
		Scope:            []string{"svc-http"},
		IssuedAt:         now.Add(-time.Second).Format(time.RFC3339),
		ExpiresAt:        now.Add(time.Minute).Format(time.RFC3339),
		MaxSALifetime:    60,
		ObserverProfile:  "posthoc",
		CheckpointHash:   checkpointHash,
		HistoryEpoch:     1,
	}, verifierIdentity.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.validateCapacityToken(token, evidence); err != nil {
		t.Fatalf("valid pinned token rejected: %v", err)
	}

	rogueIdentity, err := attest.GenerateEd25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	rogueToken := token
	rogueToken.Signature = ""
	rogueToken, err = attest.SignCapacityToken(rogueToken, rogueIdentity.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.validateCapacityToken(rogueToken, evidence); err == nil || !strings.Contains(err.Error(), "verify capacity token") {
		t.Fatalf("token under an unpinned Verifier key was not rejected: %v", err)
	}
}

func TestPEPRejectsTokenWithWrongObserverProfile(t *testing.T) {
	verifierIdentity, err := attest.GenerateEd25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	pepIdentity, err := attest.GenerateEd25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	evidence := protocol.HistoryEvidence{Checkpoint: protocol.EnforcementCheckpoint{Version: 1, PEPID: "pep-test", Epoch: 1}}
	checkpointHash, err := attest.HashEnforcementCheckpoint(evidence.Checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	token, err := attest.SignCapacityToken(protocol.CapacityToken{
		Version:          1,
		TokenType:        "cryptna-pep-capacity-v1",
		PEPID:            "pep-test",
		PEPSigningPubKey: pepIdentity.PublicKey,
		Measurement:      "measurement-test",
		PolicyHash:       "policy-test",
		Scope:            []string{"svc-http"},
		IssuedAt:         now.Add(-time.Second).Format(time.RFC3339),
		ExpiresAt:        now.Add(time.Minute).Format(time.RFC3339),
		MaxSALifetime:    60,
		ObserverProfile:  "dry-run",
		CheckpointHash:   checkpointHash,
		HistoryEpoch:     1,
	}, verifierIdentity.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	state := &pepAttestationState{
		pepID:            "pep-test",
		measurement:      "measurement-test",
		policyHash:       "policy-test",
		scope:            []string{"svc-http"},
		maxSALifetime:    60,
		verifierPubKey:   verifierIdentity.PublicKey,
		requiredObserver: "posthoc",
		key:              pepIdentity,
	}
	if _, err := state.validateCapacityToken(token, evidence); err == nil || !strings.Contains(err.Error(), "observer profile mismatch") {
		t.Fatalf("wrong observer profile was not rejected: %v", err)
	}
}
