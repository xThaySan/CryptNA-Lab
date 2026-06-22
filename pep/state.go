package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"cryptna-lab/common/protocol"
)

type pendingEnforcementOperation struct {
	Operation string           `json:"operation"`
	Session   protocol.Session `json:"session"`
}

type persistentPEPState struct {
	Version         int                          `json:"version"`
	History         enforcementHistorySnapshot   `json:"history"`
	Sessions        map[string]protocol.Session  `json:"sessions"`
	Pending         *pendingEnforcementOperation `json:"pending_operation,omitempty"`
	PendingCapacity *protocol.HistoryEvidence    `json:"pending_capacity,omitempty"`
}

var (
	pepStatePath    string
	pendingMu       sync.Mutex
	pendingPEP      *pendingEnforcementOperation
	pendingCapacity *protocol.HistoryEvidence
)

func loadPEPState(path string, history *EnforcementHistory) error {
	pepStatePath = path
	if path == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()
	var persisted persistentPEPState
	if err := json.NewDecoder(f).Decode(&persisted); err != nil {
		return err
	}
	if persisted.Version != 1 {
		return fmt.Errorf("unsupported PEP state version %d", persisted.Version)
	}
	if persisted.Pending != nil {
		return fmt.Errorf("incomplete persisted %s transaction detected; reset both pep_data and verifier_data after investigating the failed operation", persisted.Pending.Operation)
	}
	pendingMu.Lock()
	pendingCapacity = persisted.PendingCapacity
	pendingMu.Unlock()
	if err := history.Restore(persisted.History); err != nil {
		return err
	}
	if persisted.Sessions != nil {
		sessionsMu.Lock()
		sessions = persisted.Sessions
		sessionsMu.Unlock()
	}
	return nil
}

func setPendingPEPOperation(operation string, session protocol.Session) error {
	pendingMu.Lock()
	previous := pendingPEP
	pendingPEP = &pendingEnforcementOperation{Operation: operation, Session: session}
	pendingMu.Unlock()
	if err := persistPEPState(); err != nil {
		pendingMu.Lock()
		pendingPEP = previous
		pendingMu.Unlock()
		return err
	}
	return nil
}

func clearPendingPEPOperation() error {
	pendingMu.Lock()
	previous := pendingPEP
	pendingPEP = nil
	pendingMu.Unlock()
	if err := persistPEPState(); err != nil {
		pendingMu.Lock()
		pendingPEP = previous
		pendingMu.Unlock()
		return err
	}
	return nil
}

func getPendingCapacityEvidence() *protocol.HistoryEvidence {
	pendingMu.Lock()
	defer pendingMu.Unlock()
	if pendingCapacity == nil {
		return nil
	}
	copyEvidence := *pendingCapacity
	copyEvidence.Events = append([]protocol.EnforcementEvent{}, pendingCapacity.Events...)
	return &copyEvidence
}

func setPendingCapacityEvidence(evidence *protocol.HistoryEvidence) error {
	pendingMu.Lock()
	previous := pendingCapacity
	if evidence == nil {
		pendingCapacity = nil
	} else {
		copyEvidence := *evidence
		copyEvidence.Events = append([]protocol.EnforcementEvent{}, evidence.Events...)
		pendingCapacity = &copyEvidence
	}
	pendingMu.Unlock()
	if err := persistPEPState(); err != nil {
		pendingMu.Lock()
		pendingCapacity = previous
		pendingMu.Unlock()
		return err
	}
	return nil
}

func persistPEPState() error {
	if pepStatePath == "" || enforcementHistory == nil {
		return nil
	}
	snapshot := persistentPEPState{Version: 1, History: enforcementHistory.Snapshot()}
	sessionsMu.RLock()
	snapshot.Sessions = make(map[string]protocol.Session, len(sessions))
	for key, session := range sessions {
		snapshot.Sessions[key] = session
	}
	sessionsMu.RUnlock()
	pendingMu.Lock()
	if pendingPEP != nil {
		copyPending := *pendingPEP
		snapshot.Pending = &copyPending
	}
	if pendingCapacity != nil {
		copyEvidence := *pendingCapacity
		copyEvidence.Events = append([]protocol.EnforcementEvent{}, pendingCapacity.Events...)
		snapshot.PendingCapacity = &copyEvidence
	}
	pendingMu.Unlock()

	if err := os.MkdirAll(filepath.Dir(pepStatePath), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	tmp := pepStatePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, pepStatePath)
}

func validateRestoredSessions() error {
	if pepAttestation == nil || !pepAttestation.enabled {
		return nil
	}
	historyTransactionMu.Lock()
	if err := cleanupExpiredSessionsUnderHistoryLock(time.Now().UTC()); err != nil {
		historyTransactionMu.Unlock()
		return err
	}
	historyTransactionMu.Unlock()
	if getenv("XFRM_MODE", "dry-run") != "apply" {
		return nil
	}
	sessionsMu.RLock()
	restored := make([]protocol.Session, 0, len(sessions))
	for _, session := range sessions {
		restored = append(restored, session)
	}
	sessionsMu.RUnlock()
	for _, session := range restored {
		metadata := observeXFRMAppliedPosthoc(session)
		if !observationMeetsLocalProfile(metadata, "applied") {
			return fmt.Errorf("persisted session %s has no exact matching XFRM state", session.PEPInSPI)
		}
	}
	return nil
}
