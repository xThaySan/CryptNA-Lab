package attest

import (
	"fmt"
	"testing"
	"time"

	"cryptna-lab/common/protocol"
)

func BenchmarkVerifyHistoryEvidence(b *testing.B) {
	cases := []int{1, 10, 100, 1000}
	for _, n := range cases {
		b.Run(fmt.Sprintf("events_%d", n), func(b *testing.B) {
			id, err := GenerateEd25519Identity()
			if err != nil {
				b.Fatal(err)
			}
			ev := makeHistoryForBench(b, id, "pep-1", nil, 1, 0, "", n)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := VerifyHistoryEvidence(ev, "pep-1", id.PublicKey, nil); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkHashEnforcementEvent(b *testing.B) {
	id, err := GenerateEd25519Identity()
	if err != nil {
		b.Fatal(err)
	}
	ev := makeHistoryForBench(b, id, "pep-1", nil, 1, 0, "", 1).Events[0]
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := HashEnforcementEvent(ev); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHashEnforcementCheckpoint(b *testing.B) {
	id, err := GenerateEd25519Identity()
	if err != nil {
		b.Fatal(err)
	}
	checkpoint := makeHistoryForBench(b, id, "pep-1", nil, 1, 0, "", 2).Checkpoint
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := HashEnforcementCheckpoint(checkpoint); err != nil {
			b.Fatal(err)
		}
	}
}

func makeHistoryForBench(b *testing.B, id Ed25519Identity, pepID string, previous *protocol.EnforcementCheckpoint, epoch uint64, startIndex uint64, prevHash string, eventCount int) protocol.HistoryEvidence {
	b.Helper()
	events := make([]protocol.EnforcementEvent, 0, eventCount)
	lastHash := prevHash
	lastIndex := startIndex
	for i := 0; i < eventCount; i++ {
		e := protocol.EnforcementEvent{
			Version:   1,
			Index:     lastIndex + 1,
			EventType: "capacity_requested",
			PEPID:     pepID,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			PrevHash:  lastHash,
		}
		h, err := HashEnforcementEvent(e)
		if err != nil {
			b.Fatal(err)
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
			b.Fatal(err)
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
		b.Fatal(err)
	}
	return protocol.HistoryEvidence{PreviousCheckpointHash: prevCheckpointHash, Events: events, Checkpoint: signed}
}
