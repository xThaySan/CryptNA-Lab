package main

import (
	"fmt"
	"testing"
	"time"

	"cryptna-lab/common/protocol"
)

func BenchmarkVerifyEnforcementPolicy(b *testing.B) {
	for _, sessions := range []int{1, 10, 100, 500} {
		b.Run(fmt.Sprintf("deleted_sessions_%d", sessions), func(b *testing.B) {
			h := makePolicyBenchmarkHistory(sessions, true)
			req := testCapacityRequest()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				active := map[string]trackedSession{}
				if err := verifyEnforcementPolicy(h, req, active); err != nil {
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
				if err := verifyEnforcementPolicy(h, req, active); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func makePolicyBenchmarkHistory(sessions int, includeDelete bool) protocol.HistoryEvidence {
	now := time.Now().UTC()
	activeExp := now.Add(5 * time.Minute)
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
