package main

import (
	"strings"
	"testing"
	"time"

	"cryptna-lab/common/protocol"
)

func TestVerifyEnforcementPolicyRejectsScopeViolation(t *testing.T) {
	exp := time.Now().UTC().Add(30 * time.Second)
	h := protocol.HistoryEvidence{
		Events: []protocol.EnforcementEvent{
			testEventWithService(1, "xfrm_apply_intent", "svc-admin", exp),
		},
		Checkpoint: protocol.EnforcementCheckpoint{CreatedAt: time.Now().UTC().Format(time.RFC3339)},
	}
	err := verifyEnforcementPolicy(h, testCapacityRequest(), map[string]trackedSession{})
	if err == nil || !strings.Contains(err.Error(), "outside requested scope") {
		t.Fatalf("expected scope violation rejection, got %v", err)
	}
}

func TestVerifyEnforcementPolicyRejectsApplyObservedWithoutIntent(t *testing.T) {
	exp := time.Now().UTC().Add(30 * time.Second)
	h := protocol.HistoryEvidence{
		Events: []protocol.EnforcementEvent{
			testEvent(1, "xfrm_apply_observed", exp),
		},
		Checkpoint: protocol.EnforcementCheckpoint{CreatedAt: time.Now().UTC().Format(time.RFC3339)},
	}
	err := verifyEnforcementPolicy(h, testCapacityRequest(), map[string]trackedSession{})
	if err == nil || !strings.Contains(err.Error(), "without matching intent") {
		t.Fatalf("expected observed-without-intent rejection, got %v", err)
	}
}

func TestVerifyEnforcementPolicyRejectsActivationWithoutObservedApply(t *testing.T) {
	exp := time.Now().UTC().Add(30 * time.Second)
	h := protocol.HistoryEvidence{
		Events: []protocol.EnforcementEvent{
			testEvent(1, "xfrm_apply_intent", exp),
			testEvent(2, "session_activated", exp),
		},
		Checkpoint: protocol.EnforcementCheckpoint{CreatedAt: time.Now().UTC().Format(time.RFC3339)},
	}
	err := verifyEnforcementPolicy(h, testCapacityRequest(), map[string]trackedSession{})
	if err == nil || !strings.Contains(err.Error(), "without observed XFRM apply") {
		t.Fatalf("expected activation-without-observation rejection, got %v", err)
	}
}

func TestVerifyEnforcementPolicyRejectsApplyNotObserved(t *testing.T) {
	exp := time.Now().UTC().Add(30 * time.Second)
	observed := testEvent(2, "xfrm_apply_observed", exp)
	observed.Metadata["applied"] = "false"
	h := protocol.HistoryEvidence{
		Events: []protocol.EnforcementEvent{
			testEvent(1, "xfrm_apply_intent", exp),
			observed,
		},
		Checkpoint: protocol.EnforcementCheckpoint{CreatedAt: time.Now().UTC().Format(time.RFC3339)},
	}
	err := verifyEnforcementPolicy(h, testCapacityRequest(), map[string]trackedSession{})
	if err == nil || !strings.Contains(err.Error(), "apply not observed") {
		t.Fatalf("expected failed-apply-observation rejection, got %v", err)
	}
}

func TestVerifyEnforcementPolicyRejectsDeleteWithoutActivation(t *testing.T) {
	exp := time.Now().UTC().Add(-1 * time.Second)
	h := protocol.HistoryEvidence{
		Events: []protocol.EnforcementEvent{
			testEvent(1, "session_expired", exp),
			testEvent(2, "xfrm_delete_intent", exp),
			testEvent(3, "xfrm_delete_observed", exp),
		},
		Checkpoint: protocol.EnforcementCheckpoint{CreatedAt: time.Now().UTC().Format(time.RFC3339)},
	}
	err := verifyEnforcementPolicy(h, testCapacityRequest(), map[string]trackedSession{})
	if err == nil || !strings.Contains(err.Error(), "expiration for unknown session") {
		t.Fatalf("expected delete-without-activation rejection, got %v", err)
	}
}

func TestVerifyEnforcementPolicyRejectsDeleteObservedWithoutIntent(t *testing.T) {
	exp := time.Now().UTC().Add(-1 * time.Second)
	h := protocol.HistoryEvidence{
		Events: []protocol.EnforcementEvent{
			testEvent(1, "xfrm_apply_intent", exp),
			testEvent(2, "xfrm_apply_observed", exp),
			testEvent(3, "session_activated", exp),
			testEvent(4, "session_expired", exp),
			testEvent(5, "xfrm_delete_observed", exp),
		},
		Checkpoint: protocol.EnforcementCheckpoint{CreatedAt: time.Now().UTC().Format(time.RFC3339)},
	}
	err := verifyEnforcementPolicy(h, testCapacityRequest(), map[string]trackedSession{})
	if err == nil || !strings.Contains(err.Error(), "delete observed without matching intent") {
		t.Fatalf("expected delete-observed-without-intent rejection, got %v", err)
	}
}

func TestVerifyEnforcementPolicyRejectsDeleteNotObserved(t *testing.T) {
	exp := time.Now().UTC().Add(-1 * time.Second)
	deleted := testEvent(6, "xfrm_delete_observed", exp)
	deleted.Metadata["deleted"] = "false"
	h := protocol.HistoryEvidence{
		Events: []protocol.EnforcementEvent{
			testEvent(1, "xfrm_apply_intent", exp),
			testEvent(2, "xfrm_apply_observed", exp),
			testEvent(3, "session_activated", exp),
			testEvent(4, "session_expired", exp),
			testEvent(5, "xfrm_delete_intent", exp),
			deleted,
		},
		Checkpoint: protocol.EnforcementCheckpoint{CreatedAt: time.Now().UTC().Format(time.RFC3339)},
	}
	err := verifyEnforcementPolicy(h, testCapacityRequest(), map[string]trackedSession{})
	if err == nil || !strings.Contains(err.Error(), "delete not observed") {
		t.Fatalf("expected failed-delete-observation rejection, got %v", err)
	}
}

func TestVerifyEnforcementPolicyRejectsDuplicateActiveSession(t *testing.T) {
	exp := time.Now().UTC().Add(30 * time.Second)
	h := protocol.HistoryEvidence{
		Events: []protocol.EnforcementEvent{
			testEvent(1, "xfrm_apply_intent", exp),
			testEvent(2, "xfrm_apply_observed", exp),
			testEvent(3, "session_activated", exp),
			testEvent(4, "xfrm_apply_intent", exp),
		},
		Checkpoint: protocol.EnforcementCheckpoint{CreatedAt: time.Now().UTC().Format(time.RFC3339)},
	}
	err := verifyEnforcementPolicy(h, testCapacityRequest(), map[string]trackedSession{})
	if err == nil || !strings.Contains(err.Error(), "session already active") {
		t.Fatalf("expected duplicate-active-session rejection, got %v", err)
	}
}

func TestVerifyEnforcementPolicyRejectsUnsupportedEventType(t *testing.T) {
	h := protocol.HistoryEvidence{
		Events: []protocol.EnforcementEvent{
			{Version: 1, Index: 1, EventType: "iptables_bypass", PEPID: "cryptna-pep-1", Timestamp: time.Now().UTC().Format(time.RFC3339)},
		},
		Checkpoint: protocol.EnforcementCheckpoint{CreatedAt: time.Now().UTC().Format(time.RFC3339)},
	}
	err := verifyEnforcementPolicy(h, testCapacityRequest(), map[string]trackedSession{})
	if err == nil || !strings.Contains(err.Error(), "unsupported event type") {
		t.Fatalf("expected unsupported-event rejection, got %v", err)
	}
}

func testEventWithService(index uint64, typ, service string, exp time.Time) protocol.EnforcementEvent {
	e := testEvent(index, typ, exp)
	e.ServiceID = service
	return e
}
