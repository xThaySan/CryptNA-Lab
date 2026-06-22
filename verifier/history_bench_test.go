package main

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"cryptna-lab/common/attest"
	"cryptna-lab/common/protocol"
)

type benchmarkAppraisal struct {
	history   protocol.HistoryEvidence
	request   protocol.CapacityRequest
	pepPubKey string
}

func BenchmarkConcurrentPEPAppraisal(b *testing.B) {
	for _, pepCount := range []int{1, 10, 100} {
		b.Run(fmt.Sprintf("peps_%d_events_100", pepCount), func(b *testing.B) {
			workloads := make([]benchmarkAppraisal, 0, pepCount)
			for pep := 0; pep < pepCount; pep++ {
				workloads = append(workloads, makeFullAppraisalBenchmarkHistory(b, fmt.Sprintf("benchmark-pep-%d", pep), 16, 4))
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				var wg sync.WaitGroup
				errs := make(chan error, pepCount)
				for pep := range workloads {
					workload := workloads[pep]
					wg.Add(1)
					go func() {
						defer wg.Done()
						if _, err := attest.VerifyHistoryEvidence(workload.history, workload.request.PEPID, workload.pepPubKey, nil); err != nil {
							errs <- err
							return
						}
						if err := verifyEnforcementPolicy(workload.history, workload.request, map[string]trackedSession{}, "posthoc"); err != nil {
							errs <- err
						}
					}()
				}
				wg.Wait()
				close(errs)
				for err := range errs {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkVerifyFullHistoryAppraisal(b *testing.B) {
	for _, tc := range []struct {
		name     string
		sessions int
		padding  int
	}{
		{name: "events_100", sessions: 16, padding: 4},
		{name: "events_1000", sessions: 166, padding: 4},
	} {
		b.Run(tc.name, func(b *testing.B) {
			workload := makeFullAppraisalBenchmarkHistory(b, "cryptna-pep-1", tc.sessions, tc.padding)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := attest.VerifyHistoryEvidence(workload.history, workload.request.PEPID, workload.pepPubKey, nil); err != nil {
					b.Fatal(err)
				}
				if err := verifyEnforcementPolicy(workload.history, workload.request, map[string]trackedSession{}, "posthoc"); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func makeFullAppraisalBenchmarkHistory(b *testing.B, pepID string, sessions, padding int) benchmarkAppraisal {
	b.Helper()
	identity, err := attest.GenerateEd25519Identity()
	if err != nil {
		b.Fatal(err)
	}
	history := makePolicyBenchmarkHistory(sessions, true)
	history.Events = append(makeManagementPadding(pepID, padding), history.Events...)
	for i := range history.Events {
		history.Events[i].PEPID = pepID
		history.Events[i].Index = uint64(i + 1)
		if i == 0 {
			history.Events[i].PrevHash = ""
		} else {
			history.Events[i].PrevHash = history.Events[i-1].EventHash
		}
		hash, hashErr := attest.HashEnforcementEvent(history.Events[i])
		if hashErr != nil {
			b.Fatal(hashErr)
		}
		history.Events[i].EventHash = hash
	}
	history.Checkpoint = protocol.EnforcementCheckpoint{
		Version:        1,
		PEPID:          pepID,
		Epoch:          1,
		LastEventIndex: uint64(len(history.Events)),
		LastEventHash:  history.Events[len(history.Events)-1].EventHash,
		EventCount:     len(history.Events),
		CreatedAt:      time.Now().UTC().Format(time.RFC3339),
	}
	history.Checkpoint, err = attest.SignEnforcementCheckpoint(history.Checkpoint, identity.PrivateKey)
	if err != nil {
		b.Fatal(err)
	}
	request := testCapacityRequest()
	request.PEPID = pepID
	request.PEPSigningPubKey = identity.PublicKey
	return benchmarkAppraisal{history: history, request: request, pepPubKey: identity.PublicKey}
}

func makeManagementPadding(pepID string, count int) []protocol.EnforcementEvent {
	events := make([]protocol.EnforcementEvent, 0, count)
	for i := 0; i < count; i++ {
		events = append(events, protocol.EnforcementEvent{
			Version:   1,
			EventType: "capacity_requested",
			PEPID:     pepID,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		})
	}
	return events
}

func BenchmarkVerifyEnforcementPolicy(b *testing.B) {
	for _, sessions := range []int{1, 10, 100, 500} {
		b.Run(fmt.Sprintf("deleted_sessions_%d", sessions), func(b *testing.B) {
			h := makePolicyBenchmarkHistory(sessions, true)
			req := testCapacityRequest()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				active := map[string]trackedSession{}
				if err := verifyEnforcementPolicy(h, req, active, "posthoc"); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(fmt.Sprintf("active_sessions_%d", sessions), func(b *testing.B) {
			h := makePolicyBenchmarkHistory(sessions, false)
			req := testCapacityRequest()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				active := map[string]trackedSession{}
				if err := verifyEnforcementPolicy(h, req, active, "posthoc"); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func makePolicyBenchmarkHistory(sessions int, includeDelete bool) protocol.HistoryEvidence {
	now := time.Now().UTC()
	activeExp := now.Add(30 * time.Second)
	deletedExp := now.Add(-5 * time.Second)
	events := make([]protocol.EnforcementEvent, 0, sessions*6)
	idx := uint64(0)
	for i := 0; i < sessions; i++ {
		exp := activeExp
		if includeDelete {
			exp = deletedExp
		}
		base := testEvent(0, "xfrm_apply_intent", exp)
		base.ClientPubKey = fmt.Sprintf("client-%d", i)
		base.ClientInnerIP = fmt.Sprintf("10.200.0.%d", 10+(i%200))
		base.ClientInSPI = fmt.Sprintf("0x%08x", 0x10000000+i)
		base.PEPInSPI = fmt.Sprintf("0x%08x", 0x20000000+i)
		base.ReqID = uint32(1000 + i)

		for _, typ := range []string{"xfrm_apply_intent", "xfrm_apply_observed", "session_activated"} {
			idx++
			e := base
			e.Index = idx
			e.EventType = typ
			e.Timestamp = now.Format(time.RFC3339)
			events = append(events, e)
		}
		if includeDelete {
			for _, typ := range []string{"session_expired", "xfrm_delete_intent", "xfrm_delete_observed"} {
				idx++
				e := base
				e.Index = idx
				e.EventType = typ
				e.Timestamp = now.Format(time.RFC3339)
				events = append(events, e)
			}
		}
	}
	return protocol.HistoryEvidence{
		Events: events,
		Checkpoint: protocol.EnforcementCheckpoint{
			CreatedAt: now.Format(time.RFC3339),
		},
	}
}
