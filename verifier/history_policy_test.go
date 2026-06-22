package main

import (
	"strings"
	"testing"
	"time"

	"cryptna-lab/common/protocol"
)

func TestVerifyEnforcementPolicyRejectsExpiredActiveSession(t *testing.T) {
	exp := time.Now().UTC().Add(-1 * time.Second)
	h := protocol.HistoryEvidence{
		Events: []protocol.EnforcementEvent{
			testEvent(1, "xfrm_apply_intent", exp),
			testEvent(2, "xfrm_apply_observed", exp),
			testEvent(3, "session_activated", exp),
		},
		Checkpoint: protocol.EnforcementCheckpoint{CreatedAt: time.Now().UTC().Format(time.RFC3339)},
	}
	err := verifyEnforcementPolicy(h, testCapacityRequest(), map[string]trackedSession{})
	if err == nil || !strings.Contains(err.Error(), "expired session still active") {
		t.Fatalf("expected expired active session rejection, got %v", err)
	}
}

func TestVerifyEnforcementPolicyAcceptsDeletedExpiredSession(t *testing.T) {
	exp := time.Now().UTC().Add(-1 * time.Second)
	h := protocol.HistoryEvidence{
		Events: []protocol.EnforcementEvent{
			testEvent(1, "xfrm_apply_intent", exp),
			testEvent(2, "xfrm_apply_observed", exp),
			testEvent(3, "session_activated", exp),
			testEvent(4, "session_expired", exp),
			testEvent(5, "xfrm_delete_intent", exp),
			testEvent(6, "xfrm_delete_observed", exp),
		},
		Checkpoint: protocol.EnforcementCheckpoint{CreatedAt: time.Now().UTC().Format(time.RFC3339)},
	}
	active := map[string]trackedSession{}
	if err := verifyEnforcementPolicy(h, testCapacityRequest(), active); err != nil {
		t.Fatalf("expected valid deleted session, got %v", err)
	}
	if len(active) != 0 {
		t.Fatalf("expected no active sessions after delete, got %d", len(active))
	}
}

func TestVerifyEnforcementPolicyRejectsDeleteWithoutExpiration(t *testing.T) {
	exp := time.Now().UTC().Add(30 * time.Second)
	h := protocol.HistoryEvidence{
		Events: []protocol.EnforcementEvent{
			testEvent(1, "xfrm_apply_intent", exp),
			testEvent(2, "xfrm_apply_observed", exp),
			testEvent(3, "session_activated", exp),
			testEvent(4, "xfrm_delete_intent", exp),
		},
		Checkpoint: protocol.EnforcementCheckpoint{CreatedAt: time.Now().UTC().Format(time.RFC3339)},
	}
	err := verifyEnforcementPolicy(h, testCapacityRequest(), map[string]trackedSession{})
	if err == nil || !strings.Contains(err.Error(), "delete intent without session_expired") {
		t.Fatalf("expected delete without expiration rejection, got %v", err)
	}
}

func testCapacityRequest() protocol.CapacityRequest {
	return protocol.CapacityRequest{PEPID: "cryptna-pep-1", Scope: []string{"svc-http"}, MaxSALifetime: 60}
}

func testEvent(index uint64, typ string, exp time.Time) protocol.EnforcementEvent {
	return protocol.EnforcementEvent{
		Version:       1,
		Index:         index,
		EventType:     typ,
		PEPID:         "cryptna-pep-1",
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		ServiceID:     "svc-http",
		ClientPubKey:  "client-key",
		ClientOuterIP: "172.20.0.10",
		ClientInnerIP: "10.200.0.10",
		ClientInSPI:   "0x11111111",
		PEPInSPI:      "0x22222222",
		ReqID:         1000,
		Metadata: map[string]string{
			"expires_at":      exp.UTC().Format(time.RFC3339),
			"xfrm_plan_hash":  "test-plan-hash",
			"xfrm_mode":       "apply",
			"observer_source": "posthoc",
			"applied":         "true",
			"deleted":         "true",
		},
	}
}
