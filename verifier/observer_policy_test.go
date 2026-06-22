package main

import (
	"strings"
	"testing"
	"time"

	"cryptna-lab/common/protocol"
)

func TestVerifyEnforcementPolicyRejectsMissingRequiredObserverProfile(t *testing.T) {
	exp := time.Now().UTC().Add(30 * time.Second)
	observed := testEvent(2, "xfrm_apply_observed", exp)
	delete(observed.Metadata, "observer_source")
	history := protocol.HistoryEvidence{
		Events: []protocol.EnforcementEvent{
			testEvent(1, "xfrm_apply_intent", exp),
			observed,
			testEvent(3, "session_activated", exp),
		},
		Checkpoint: protocol.EnforcementCheckpoint{CreatedAt: time.Now().UTC().Format(time.RFC3339)},
	}
	err := verifyEnforcementPolicy(history, testCapacityRequest(), map[string]trackedSession{}, "posthoc")
	if err == nil || !strings.Contains(err.Error(), "required posthoc observer profile missing") {
		t.Fatalf("expected observer profile rejection, got %v", err)
	}
}

func TestVerifyEnforcementPolicyRejectsUnmatchedHybridObservation(t *testing.T) {
	exp := time.Now().UTC().Add(30 * time.Second)
	observed := testEvent(2, "xfrm_apply_observed", exp)
	observed.Metadata["observer_source"] = "posthoc+ebpf"
	observed.Metadata["ebpf_matched"] = "false"
	history := protocol.HistoryEvidence{
		Events: []protocol.EnforcementEvent{
			testEvent(1, "xfrm_apply_intent", exp),
			observed,
			testEvent(3, "session_activated", exp),
		},
		Checkpoint: protocol.EnforcementCheckpoint{CreatedAt: time.Now().UTC().Format(time.RFC3339)},
	}
	err := verifyEnforcementPolicy(history, testCapacityRequest(), map[string]trackedSession{}, "hybrid")
	if err == nil || !strings.Contains(err.Error(), "required hybrid observer profile missing") {
		t.Fatalf("expected unmatched hybrid rejection, got %v", err)
	}
}

func TestVerifyEnforcementPolicyRejectsPlanSubstitution(t *testing.T) {
	exp := time.Now().UTC().Add(30 * time.Second)
	observed := testEvent(2, "xfrm_apply_observed", exp)
	observed.Metadata["xfrm_plan_hash"] = "different-plan"
	history := protocol.HistoryEvidence{
		Events: []protocol.EnforcementEvent{
			testEvent(1, "xfrm_apply_intent", exp),
			observed,
		},
		Checkpoint: protocol.EnforcementCheckpoint{CreatedAt: time.Now().UTC().Format(time.RFC3339)},
	}
	err := verifyEnforcementPolicy(history, testCapacityRequest(), map[string]trackedSession{}, "posthoc")
	if err == nil || !strings.Contains(err.Error(), "plan mismatch") {
		t.Fatalf("expected XFRM plan substitution rejection, got %v", err)
	}
}

func TestVerifyEnforcementPolicyRejectsPartialTransactionAtCheckpoint(t *testing.T) {
	exp := time.Now().UTC().Add(30 * time.Second)
	history := protocol.HistoryEvidence{
		Events:     []protocol.EnforcementEvent{testEvent(1, "xfrm_apply_intent", exp)},
		Checkpoint: protocol.EnforcementCheckpoint{CreatedAt: time.Now().UTC().Format(time.RFC3339)},
	}
	err := verifyEnforcementPolicy(history, testCapacityRequest(), map[string]trackedSession{}, "posthoc")
	if err == nil || !strings.Contains(err.Error(), "incomplete enforcement transaction") {
		t.Fatalf("expected partial transaction rejection, got %v", err)
	}
}
