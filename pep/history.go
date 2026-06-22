package main

import (
	"fmt"
	"sync"
	"time"

	"cryptna-lab/common/attest"
	"cryptna-lab/common/logutil"
	"cryptna-lab/common/protocol"
)

const (
	eventPEPStart           = "pep_start"
	eventCapacityRequested  = "capacity_requested"
	eventCapacityAccepted   = "capacity_accepted"
	eventXFRMApplyIntent    = "xfrm_apply_intent"
	eventXFRMApplyObserved  = "xfrm_apply_observed"
	eventSessionActivated   = "session_activated"
	eventXFRMDeleteIntent   = "xfrm_delete_intent"
	eventXFRMDeleteObserved = "xfrm_delete_observed"
	eventSessionExpired     = "session_expired"
)

type EnforcementHistory struct {
	mu sync.Mutex

	pepID string

	events []protocol.EnforcementEvent

	lastEventHash string
	lastIndex     uint64

	lastAcceptedCheckpointHash  string
	lastAcceptedCheckpointIndex uint64
	lastAcceptedEpoch           uint64
}

var enforcementHistory *EnforcementHistory

// historyTransactionMu serializes checkpoint construction with multi-event
// enforcement transactions. Without this barrier, a capacity refresh can
// checkpoint a partial operation, e.g. xfrm_delete_intent without the
// matching xfrm_delete_observed event.
var historyTransactionMu sync.Mutex

func NewEnforcementHistory(pepID string) *EnforcementHistory {
	return &EnforcementHistory{pepID: pepID}
}

func (h *EnforcementHistory) AppendEvent(eventType string, session *protocol.Session, meta map[string]string) (protocol.EnforcementEvent, error) {
	if h == nil {
		return protocol.EnforcementEvent{}, fmt.Errorf("enforcement history not initialized")
	}
	h.mu.Lock()
	defer h.mu.Unlock()

	e := protocol.EnforcementEvent{
		Version:   1,
		Index:     h.lastIndex + 1,
		EventType: eventType,
		PEPID:     h.pepID,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Metadata:  meta,
		PrevHash:  h.lastEventHash,
	}
	if session != nil {
		e.ServiceID = session.ServiceID
		e.ClientPubKey = session.ClientPubKey
		e.ClientOuterIP = session.ClientOuterIP
		e.ClientInnerIP = session.ClientInnerIP
		e.ClientInSPI = session.ClientInSPI
		e.PEPInSPI = session.PEPInSPI
		e.ReqID = session.ReqID
		if e.Metadata == nil {
			e.Metadata = map[string]string{}
		}
		if session.ExpiresAt != "" {
			e.Metadata["expires_at"] = session.ExpiresAt
		}
		if session.AEAD != "" {
			e.Metadata["aead"] = session.AEAD
		}
	}
	if e.Metadata != nil && len(e.Metadata) == 0 {
		e.Metadata = nil
	}
	eh, err := attest.HashEnforcementEvent(e)
	if err != nil {
		return protocol.EnforcementEvent{}, err
	}
	e.EventHash = eh
	h.events = append(h.events, e)
	h.lastIndex = e.Index
	h.lastEventHash = eh
	logutil.Debugf("pep", "history append index=%d type=%s hash=%s", e.Index, e.EventType, logutil.Short(e.EventHash))
	return e, nil
}

func (h *EnforcementHistory) BuildEvidence(pepPrivB64 string) (protocol.HistoryEvidence, error) {
	if h == nil {
		return protocol.HistoryEvidence{}, fmt.Errorf("enforcement history not initialized")
	}
	h.mu.Lock()
	defer h.mu.Unlock()

	start := h.lastAcceptedCheckpointIndex
	if start > uint64(len(h.events)) {
		return protocol.HistoryEvidence{}, fmt.Errorf("history index beyond event log")
	}
	events := make([]protocol.EnforcementEvent, 0, len(h.events)-int(start))
	for _, e := range h.events[start:] {
		events = append(events, e)
	}
	checkpoint := protocol.EnforcementCheckpoint{
		Version:                1,
		PEPID:                  h.pepID,
		Epoch:                  h.lastAcceptedEpoch + 1,
		PreviousCheckpointHash: h.lastAcceptedCheckpointHash,
		LastEventIndex:         h.lastIndex,
		LastEventHash:          h.lastEventHash,
		EventCount:             len(events),
		CreatedAt:              time.Now().UTC().Format(time.RFC3339),
	}
	signed, err := attest.SignEnforcementCheckpoint(checkpoint, pepPrivB64)
	if err != nil {
		return protocol.HistoryEvidence{}, err
	}
	return protocol.HistoryEvidence{
		PreviousCheckpointHash: h.lastAcceptedCheckpointHash,
		Events:                 events,
		Checkpoint:             signed,
	}, nil
}

func (h *EnforcementHistory) MarkCheckpointAccepted(checkpoint protocol.EnforcementCheckpoint) error {
	if h == nil {
		return fmt.Errorf("enforcement history not initialized")
	}
	h.mu.Lock()
	defer h.mu.Unlock()

	checkpointHash, err := attest.HashEnforcementCheckpoint(checkpoint)
	if err != nil {
		return err
	}
	if checkpoint.LastEventIndex > h.lastIndex {
		return fmt.Errorf("accepted checkpoint is ahead of local history")
	}
	h.lastAcceptedCheckpointHash = checkpointHash
	h.lastAcceptedCheckpointIndex = checkpoint.LastEventIndex
	h.lastAcceptedEpoch = checkpoint.Epoch
	logutil.Debugf("pep", "history checkpoint accepted epoch=%d hash=%s last_event_index=%d", checkpoint.Epoch, logutil.Short(checkpointHash), checkpoint.LastEventIndex)
	return nil
}

func xfrmPlanHash(plan protocol.XFRMPlan) string {
	h, err := attest.HashCanonical(plan)
	if err != nil {
		return "hash_error"
	}
	return h
}

func historyAppend(eventType string, session *protocol.Session, meta map[string]string) {
	if enforcementHistory == nil {
		return
	}
	if _, err := enforcementHistory.AppendEvent(eventType, session, meta); err != nil {
		logutil.Debugf("pep", "history append failed type=%s err=%v", eventType, err)
	}
}
