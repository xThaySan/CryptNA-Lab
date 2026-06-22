package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"cryptna-lab/common/attest"
	"cryptna-lab/common/protocol"
)

func TestCapacityHandlerRejectsUnenrolledPEPKey(t *testing.T) {
	verifierID := mustTestIdentity(t)
	enrolledID := mustTestIdentity(t)
	requestID := mustTestIdentity(t)
	cfg := testVerifierConfig("")
	state := newTestVerifierState()
	handler := capacityHandler(cfg, verifierID, map[string]enrolledPEP{
		"pep-1": {SigningPublicKey: enrolledID.PublicKey},
	}, state)
	req := signedCapacityRequest(t, "pep-1", requestID)
	recorder := performCapacityRequest(t, handler, req)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected unenrolled key rejection, got status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestCapacityHandlerReplaysAcceptedResponseIdempotently(t *testing.T) {
	verifierID := mustTestIdentity(t)
	pepID := mustTestIdentity(t)
	statePath := filepath.Join(t.TempDir(), "verifier-state.json")
	cfg := testVerifierConfig(statePath)
	state := newTestVerifierState()
	handler := capacityHandler(cfg, verifierID, map[string]enrolledPEP{
		"pep-1": {SigningPublicKey: pepID.PublicKey},
	}, state)
	req := signedCapacityRequest(t, "pep-1", pepID)
	first := performCapacityRequest(t, handler, req)
	second := performCapacityRequest(t, handler, req)
	if first.Code != http.StatusOK || second.Code != http.StatusOK {
		t.Fatalf("expected two successful idempotent responses, got %d/%d: %s / %s", first.Code, second.Code, first.Body.String(), second.Body.String())
	}
	var firstToken, secondToken protocol.CapacityToken
	if err := json.Unmarshal(first.Body.Bytes(), &firstToken); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(second.Body.Bytes(), &secondToken); err != nil {
		t.Fatal(err)
	}
	if firstToken.Signature == "" || !reflect.DeepEqual(firstToken, secondToken) {
		t.Fatal("idempotent retry did not return the exact persisted token")
	}

	reloaded := newTestVerifierState()
	if err := loadVerifierState(statePath, reloaded); err != nil {
		t.Fatal(err)
	}
	replayedAfterRestart := performCapacityRequest(t, capacityHandler(cfg, verifierID, map[string]enrolledPEP{
		"pep-1": {SigningPublicKey: pepID.PublicKey},
	}, reloaded), req)
	if replayedAfterRestart.Code != http.StatusOK {
		t.Fatalf("persisted idempotent retry failed after restart: %d %s", replayedAfterRestart.Code, replayedAfterRestart.Body.String())
	}
}

func TestCapacityHandlerDoesNotReplayTokenForChangedRequest(t *testing.T) {
	verifierID := mustTestIdentity(t)
	pepID := mustTestIdentity(t)
	cfg := testVerifierConfig("")
	state := newTestVerifierState()
	handler := capacityHandler(cfg, verifierID, map[string]enrolledPEP{
		"pep-1": {SigningPublicKey: pepID.PublicKey},
	}, state)
	req := signedCapacityRequest(t, "pep-1", pepID)
	first := performCapacityRequest(t, handler, req)
	if first.Code != http.StatusOK {
		t.Fatalf("initial capacity request failed: %d %s", first.Code, first.Body.String())
	}
	req.MaxSALifetime = 30
	replay := performCapacityRequest(t, handler, req)
	if replay.Code != http.StatusForbidden {
		t.Fatalf("changed request received a replayed token: %d %s", replay.Code, replay.Body.String())
	}
}

func TestCapacityHandlerRestoresActiveLifecycleAcrossRestart(t *testing.T) {
	verifierID := mustTestIdentity(t)
	pepID := mustTestIdentity(t)
	statePath := filepath.Join(t.TempDir(), "verifier-state.json")
	cfg := testVerifierConfig(statePath)
	enrolled := map[string]enrolledPEP{"pep-1": {SigningPublicKey: pepID.PublicKey}}
	now := time.Now().UTC().Truncate(time.Second)
	expiresAt := now.Add(-time.Minute)
	activationTime := now.Add(-2 * time.Minute)
	firstCheckpointTime := now.Add(-90 * time.Second)

	firstEvents := []protocol.EnforcementEvent{
		testEvent(0, "xfrm_apply_intent", expiresAt),
		testEvent(0, "xfrm_apply_observed", expiresAt),
		testEvent(0, "session_activated", expiresAt),
	}
	for i := range firstEvents {
		firstEvents[i].Timestamp = activationTime.Format(time.RFC3339)
	}
	firstRequest := signedLifecycleCapacityRequest(t, "pep-1", pepID, firstEvents, nil, firstCheckpointTime)
	state := newTestVerifierState()
	first := performCapacityRequest(t, capacityHandler(cfg, verifierID, enrolled, state), firstRequest)
	if first.Code != http.StatusOK {
		t.Fatalf("activation checkpoint failed: %d %s", first.Code, first.Body.String())
	}

	reloaded := newTestVerifierState()
	if err := loadVerifierState(statePath, reloaded); err != nil {
		t.Fatal(err)
	}
	if len(reloaded.activeStates["pep-1"]) != 1 {
		t.Fatalf("active lifecycle state was not restored: %v", reloaded.activeStates["pep-1"])
	}
	secondEvents := []protocol.EnforcementEvent{
		testEvent(0, "session_expired", expiresAt),
		testEvent(0, "xfrm_delete_intent", expiresAt),
		testEvent(0, "xfrm_delete_observed", expiresAt),
	}
	for i := range secondEvents {
		secondEvents[i].Timestamp = now.Format(time.RFC3339)
	}
	previous := firstRequest.History.Checkpoint
	secondRequest := signedLifecycleCapacityRequest(t, "pep-1", pepID, secondEvents, &previous, now)
	second := performCapacityRequest(t, capacityHandler(cfg, verifierID, enrolled, reloaded), secondRequest)
	if second.Code != http.StatusOK {
		t.Fatalf("post-restart deletion checkpoint failed: %d %s", second.Code, second.Body.String())
	}
	if len(reloaded.activeStates["pep-1"]) != 0 {
		t.Fatalf("deleted session remained active after restart continuation: %v", reloaded.activeStates["pep-1"])
	}
}

func TestCapacityHandlerKeepsConcurrentPEPStateIndependent(t *testing.T) {
	const pepCount = 16
	verifierID := mustTestIdentity(t)
	cfg := testVerifierConfig(filepath.Join(t.TempDir(), "verifier-state.json"))
	state := newTestVerifierState()
	enrolled := make(map[string]enrolledPEP, pepCount)
	requests := make([]protocol.CapacityRequest, 0, pepCount)
	for i := 0; i < pepCount; i++ {
		pepName := fmt.Sprintf("pep-%d", i)
		identity := mustTestIdentity(t)
		enrolled[pepName] = enrolledPEP{SigningPublicKey: identity.PublicKey}
		requests = append(requests, signedCapacityRequest(t, pepName, identity))
	}
	handler := capacityHandler(cfg, verifierID, enrolled, state)
	var wg sync.WaitGroup
	errs := make(chan string, pepCount)
	for _, request := range requests {
		request := request
		wg.Add(1)
		go func() {
			defer wg.Done()
			recorder := performCapacityRequest(t, handler, request)
			if recorder.Code != http.StatusOK {
				errs <- fmt.Sprintf("pep=%s status=%d body=%s", request.PEPID, recorder.Code, recorder.Body.String())
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if len(state.checkpoints) != pepCount || len(state.lastTokens) != pepCount {
		t.Fatalf("expected independent state for %d PEPs, got checkpoints=%d tokens=%d", pepCount, len(state.checkpoints), len(state.lastTokens))
	}
}

func testVerifierConfig(statePath string) verifierConfig {
	return verifierConfig{
		VerifierID:          "verifier-test",
		ExpectedMeasurement: "measurement-test",
		ExpectedPolicyHash:  "policy-test",
		TokenTTLSeconds:     60,
		AllowedScope:        []string{"svc-http"},
		MaxSALifetime:       60,
		RequiredObserver:    "posthoc",
		StatePath:           statePath,
	}
}

func newTestVerifierState() *verifierState {
	return &verifierState{
		checkpoints:  map[string]protocol.EnforcementCheckpoint{},
		activeStates: map[string]map[string]trackedSession{},
		lastTokens:   map[string]protocol.CapacityToken{},
	}
}

func mustTestIdentity(t *testing.T) attest.Ed25519Identity {
	t.Helper()
	id, err := attest.GenerateEd25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func signedCapacityRequest(t *testing.T, pepID string, identity attest.Ed25519Identity) protocol.CapacityRequest {
	t.Helper()
	now := time.Now().UTC()
	events := []protocol.EnforcementEvent{
		{Version: 1, Index: 1, EventType: "pep_start", PEPID: pepID, Timestamp: now.Format(time.RFC3339)},
		{Version: 1, Index: 2, EventType: "capacity_requested", PEPID: pepID, Timestamp: now.Format(time.RFC3339)},
	}
	previousHash := ""
	for i := range events {
		events[i].PrevHash = previousHash
		hash, err := attest.HashEnforcementEvent(events[i])
		if err != nil {
			t.Fatal(err)
		}
		events[i].EventHash = hash
		previousHash = hash
	}
	checkpoint, err := attest.SignEnforcementCheckpoint(protocol.EnforcementCheckpoint{
		Version:        1,
		PEPID:          pepID,
		Epoch:          1,
		LastEventIndex: 2,
		LastEventHash:  previousHash,
		EventCount:     len(events),
		CreatedAt:      now.Format(time.RFC3339),
	}, identity.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	return protocol.CapacityRequest{
		PEPID:            pepID,
		PEPSigningPubKey: identity.PublicKey,
		Measurement:      "measurement-test",
		PolicyHash:       "policy-test",
		Scope:            []string{"svc-http"},
		MaxSALifetime:    60,
		History: &protocol.HistoryEvidence{
			Events:     events,
			Checkpoint: checkpoint,
		},
	}
}

func signedLifecycleCapacityRequest(t *testing.T, pepID string, identity attest.Ed25519Identity, events []protocol.EnforcementEvent, previous *protocol.EnforcementCheckpoint, checkpointTime time.Time) protocol.CapacityRequest {
	t.Helper()
	lastHash := ""
	lastIndex := uint64(0)
	epoch := uint64(1)
	previousCheckpointHash := ""
	if previous != nil {
		lastHash = previous.LastEventHash
		lastIndex = previous.LastEventIndex
		epoch = previous.Epoch + 1
		var err error
		previousCheckpointHash, err = attest.HashEnforcementCheckpoint(*previous)
		if err != nil {
			t.Fatal(err)
		}
	}
	for i := range events {
		events[i].PEPID = pepID
		events[i].Index = lastIndex + 1
		events[i].PrevHash = lastHash
		hash, err := attest.HashEnforcementEvent(events[i])
		if err != nil {
			t.Fatal(err)
		}
		events[i].EventHash = hash
		lastHash = hash
		lastIndex = events[i].Index
	}
	checkpoint, err := attest.SignEnforcementCheckpoint(protocol.EnforcementCheckpoint{
		Version:                1,
		PEPID:                  pepID,
		Epoch:                  epoch,
		PreviousCheckpointHash: previousCheckpointHash,
		LastEventIndex:         lastIndex,
		LastEventHash:          lastHash,
		EventCount:             len(events),
		CreatedAt:              checkpointTime.UTC().Format(time.RFC3339),
	}, identity.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	return protocol.CapacityRequest{
		PEPID:            pepID,
		PEPSigningPubKey: identity.PublicKey,
		Measurement:      "measurement-test",
		PolicyHash:       "policy-test",
		Scope:            []string{"svc-http"},
		MaxSALifetime:    60,
		History: &protocol.HistoryEvidence{
			PreviousCheckpointHash: previousCheckpointHash,
			Events:                 events,
			Checkpoint:             checkpoint,
		},
	}
}

func performCapacityRequest(t *testing.T, handler http.HandlerFunc, request protocol.CapacityRequest) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	httpRequest := httptest.NewRequest(http.MethodPost, "/capacity", bytes.NewReader(body))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httpRequest)
	return recorder
}
