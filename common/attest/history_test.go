package attest

import (
	"fmt"
	"testing"
	"time"

	"cryptna-lab/common/protocol"
)

func makeHistoryForTest(t *testing.T, id Ed25519Identity, pepID string, previous *protocol.EnforcementCheckpoint, epoch uint64, startIndex uint64, prevHash string, types ...string) protocol.HistoryEvidence {
	t.Helper()
	events := make([]protocol.EnforcementEvent, 0, len(types))
	lastHash := prevHash
	lastIndex := startIndex
	for _, typ := range types {
		e := protocol.EnforcementEvent{
			Version:   1,
			Index:     lastIndex + 1,
			EventType: typ,
			PEPID:     pepID,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			PrevHash:  lastHash,
		}
		if typ == "xfrm_apply_intent" || typ == "xfrm_apply_observed" || typ == "session_activated" {
			e.ServiceID = "svc-http"
			e.ClientPubKey = "client"
			e.ClientInnerIP = "10.200.0.10"
			e.ClientInSPI = "0x11111111"
			e.PEPInSPI = "0x22222222"
		}
		h, err := HashEnforcementEvent(e)
		if err != nil {
			t.Fatal(err)
		}
		e.EventHash = h
		events = append(events, e)
		lastHash = h
		lastIndex = e.Index
	}
	prevCheckpointHash := ""
	if previous != nil {
		var err error
		prevCheckpointHash, err = HashEnforcementCheckpoint(*previous)
		if err != nil {
			t.Fatal(err)
		}
	}
	checkpoint := protocol.EnforcementCheckpoint{
		Version:                1,
		PEPID:                  pepID,
		Epoch:                  epoch,
		PreviousCheckpointHash: prevCheckpointHash,
		LastEventIndex:         lastIndex,
		LastEventHash:          lastHash,
		EventCount:             len(events),
		CreatedAt:              time.Now().UTC().Format(time.RFC3339),
	}
	signed, err := SignEnforcementCheckpoint(checkpoint, id.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	return protocol.HistoryEvidence{PreviousCheckpointHash: prevCheckpointHash, Events: events, Checkpoint: signed}
}

func TestVerifyHistoryEvidenceAcceptsValidChain(t *testing.T) {
	id, err := GenerateEd25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	ev := makeHistoryForTest(t, id, "pep-1", nil, 1, 0, "", "pep_start", "capacity_requested")
	if _, err := VerifyHistoryEvidence(ev, "pep-1", id.PublicKey, nil); err != nil {
		t.Fatalf("valid history rejected: %v", err)
	}
}

func TestVerifyHistoryEvidenceRejectsTamperedEvent(t *testing.T) {
	id, err := GenerateEd25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	ev := makeHistoryForTest(t, id, "pep-1", nil, 1, 0, "", "pep_start", "capacity_requested")
	ev.Events[0].EventType = "tampered"
	if _, err := VerifyHistoryEvidence(ev, "pep-1", id.PublicKey, nil); err == nil {
		t.Fatal("tampered event accepted")
	}
}

func TestVerifyHistoryEvidenceRejectsReorderedEvents(t *testing.T) {
	id, err := GenerateEd25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	ev := makeHistoryForTest(t, id, "pep-1", nil, 1, 0, "", "pep_start", "capacity_requested", "capacity_accepted")
	ev.Events[0], ev.Events[1] = ev.Events[1], ev.Events[0]
	if _, err := VerifyHistoryEvidence(ev, "pep-1", id.PublicKey, nil); err == nil {
		t.Fatal("reordered history accepted")
	}
}

func TestVerifyHistoryEvidenceRejectsRollback(t *testing.T) {
	id, err := GenerateEd25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	first := makeHistoryForTest(t, id, "pep-1", nil, 1, 0, "", "pep_start", "capacity_requested")
	if _, err := VerifyHistoryEvidence(first, "pep-1", id.PublicKey, nil); err != nil {
		t.Fatal(err)
	}
	second := makeHistoryForTest(t, id, "pep-1", &first.Checkpoint, 2, first.Checkpoint.LastEventIndex, first.Checkpoint.LastEventHash, "capacity_accepted")
	wrongPrevious := first.Checkpoint
	wrongPrevious.Epoch = 99
	if _, err := VerifyHistoryEvidence(second, "pep-1", id.PublicKey, &wrongPrevious); err == nil {
		t.Fatal(fmt.Sprintf("rollback accepted"))
	}
}
