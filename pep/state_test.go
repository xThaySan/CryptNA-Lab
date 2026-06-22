package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cryptna-lab/common/protocol"
)

func TestClientInnerIPPoolSupportsOneThousandSessions(t *testing.T) {
	address, err := clientInnerIPFromOffset("10.200.0.0/16", 1009)
	if err != nil {
		t.Fatal(err)
	}
	if address != "10.200.3.241" {
		t.Fatalf("unexpected address at offset 1009: %s", address)
	}
	if _, err := clientInnerIPFromOffset("10.200.0.0/24", 255); err == nil {
		t.Fatal("expected /24 broadcast offset to be rejected")
	}
}

func TestPEPStatePersistsHistoryAndSessions(t *testing.T) {
	originalHistory := enforcementHistory
	originalSessions := sessions
	originalPath := pepStatePath
	originalPending := pendingPEP
	originalPendingCapacity := pendingCapacity
	defer func() {
		enforcementHistory = originalHistory
		sessions = originalSessions
		pepStatePath = originalPath
		pendingPEP = originalPending
		pendingCapacity = originalPendingCapacity
	}()

	enforcementHistory = NewEnforcementHistory("pep-test")
	pepStatePath = filepath.Join(t.TempDir(), "pep-state.json")
	sessions = map[string]protocol.Session{
		"0x22222222": {PEPInSPI: "0x22222222", ReqID: 1000, ClientInnerIP: "10.200.0.10"},
	}
	if _, err := enforcementHistory.AppendEvent("pep_start", nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := persistPEPState(); err != nil {
		t.Fatal(err)
	}

	restoredHistory := NewEnforcementHistory("pep-test")
	sessions = map[string]protocol.Session{}
	if err := loadPEPState(pepStatePath, restoredHistory); err != nil {
		t.Fatal(err)
	}
	if restoredHistory.Snapshot().LastIndex != 1 || len(sessions) != 1 {
		t.Fatalf("PEP state was not restored: index=%d sessions=%d", restoredHistory.Snapshot().LastIndex, len(sessions))
	}
}

func TestPEPStateFailsClosedOnInterruptedTransaction(t *testing.T) {
	originalHistory := enforcementHistory
	originalSessions := sessions
	originalPath := pepStatePath
	originalPending := pendingPEP
	originalPendingCapacity := pendingCapacity
	defer func() {
		enforcementHistory = originalHistory
		sessions = originalSessions
		pepStatePath = originalPath
		pendingPEP = originalPending
		pendingCapacity = originalPendingCapacity
	}()

	enforcementHistory = NewEnforcementHistory("pep-test")
	pepStatePath = filepath.Join(t.TempDir(), "pep-state.json")
	sessions = map[string]protocol.Session{}
	pendingPEP = &pendingEnforcementOperation{
		Operation: "xfrm_apply",
		Session: protocol.Session{
			PEPInSPI:  "0x22222222",
			ExpiresAt: time.Now().UTC().Add(time.Minute).Format(time.RFC3339),
		},
	}
	if err := persistPEPState(); err != nil {
		t.Fatal(err)
	}
	err := loadPEPState(pepStatePath, NewEnforcementHistory("pep-test"))
	if err == nil || !strings.Contains(err.Error(), "incomplete persisted xfrm_apply transaction") {
		t.Fatalf("expected fail-closed interrupted transaction detection, got %v", err)
	}
}
