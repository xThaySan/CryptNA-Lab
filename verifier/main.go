package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"cryptna-lab/common/attest"
	"cryptna-lab/common/protocol"
)

type verifierConfig struct {
	VerifierID          string
	IdentityPath        string
	EnrollmentPath      string
	ExpectedMeasurement string
	ExpectedPolicyHash  string
	TokenTTLSeconds     int
	AllowedScope        []string
	MaxSALifetime       int
	RequiredObserver    string
	StatePath           string
}

type enrolledPEP struct {
	SigningPublicKey string `json:"signing_public_key"`
}

type verifierState struct {
	mu           sync.Mutex
	checkpoints  map[string]protocol.EnforcementCheckpoint
	activeStates map[string]map[string]trackedSession
	lastTokens   map[string]protocol.CapacityToken
}

type trackedSession struct {
	ServiceID     string
	ClientPubKey  string
	ClientInnerIP string
	ClientInSPI   string
	PEPInSPI      string
	ReqID         uint32
	ExpiresAt     string
	XFRMPlanHash  string
}

func main() {
	cfg := verifierConfig{
		VerifierID:          getenv("VERIFIER_ID", "cryptna-verifier-v1"),
		IdentityPath:        getenv("VERIFIER_IDENTITY", "/app/identity.json"),
		EnrollmentPath:      getenv("VERIFIER_ENROLLED_PEPS", "/app/enrolled_peps.json"),
		ExpectedMeasurement: getenv("VERIFIER_EXPECTED_MEASUREMENT", ""),
		ExpectedPolicyHash:  getenv("VERIFIER_EXPECTED_POLICY_HASH", ""),
		TokenTTLSeconds:     getenvInt("VERIFIER_TOKEN_TTL_SECONDS", 120),
		AllowedScope:        splitCSV(getenv("VERIFIER_ALLOWED_SCOPE", "svc-http")),
		MaxSALifetime:       getenvInt("VERIFIER_MAX_SA_LIFETIME_SECONDS", 60),
		RequiredObserver:    strings.ToLower(getenv("VERIFIER_REQUIRED_OBSERVER_PROFILE", "posthoc")),
		StatePath:           getenv("VERIFIER_STATE_PATH", ""),
	}
	id := mustLoadJSON[attest.Ed25519Identity](cfg.IdentityPath)
	enrolled := mustLoadJSON[map[string]enrolledPEP](cfg.EnrollmentPath)
	state := &verifierState{
		checkpoints:  map[string]protocol.EnforcementCheckpoint{},
		activeStates: map[string]map[string]trackedSession{},
		lastTokens:   map[string]protocol.CapacityToken{},
	}
	if err := loadVerifierState(cfg.StatePath, state); err != nil {
		log.Fatalf("load verifier state: %v", err)
	}

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok\n"))
	})

	http.HandleFunc("/capacity", capacityHandler(cfg, id, enrolled, state))

	log.Printf("[verifier] listening on :8080 id=%s enrolled_peps=%d expected_measurement=%s expected_policy_hash=%s ttl=%ds allowed_scope=%v max_sa_lifetime=%ds required_observer=%s", cfg.VerifierID, len(enrolled), cfg.ExpectedMeasurement, cfg.ExpectedPolicyHash, cfg.TokenTTLSeconds, cfg.AllowedScope, cfg.MaxSALifetime, cfg.RequiredObserver)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func capacityHandler(cfg verifierConfig, id attest.Ed25519Identity, enrolled map[string]enrolledPEP, state *verifierState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req protocol.CapacityRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		if req.PEPID == "" || req.PEPSigningPubKey == "" || req.Measurement == "" || req.PolicyHash == "" || req.MaxSALifetime <= 0 {
			http.Error(w, "invalid capacity request", http.StatusBadRequest)
			return
		}
		pepEnrollment, ok := enrolled[req.PEPID]
		if !ok || pepEnrollment.SigningPublicKey == "" {
			http.Error(w, "PEP is not enrolled", http.StatusForbidden)
			return
		}
		if req.PEPSigningPubKey != pepEnrollment.SigningPublicKey {
			http.Error(w, "PEP signing key does not match enrollment", http.StatusForbidden)
			return
		}
		if cfg.ExpectedMeasurement != "" && req.Measurement != cfg.ExpectedMeasurement {
			http.Error(w, "unexpected PEP measurement", http.StatusForbidden)
			return
		}
		if cfg.ExpectedPolicyHash != "" && req.PolicyHash != cfg.ExpectedPolicyHash {
			http.Error(w, "unexpected policy hash", http.StatusForbidden)
			return
		}
		if len(req.Scope) == 0 {
			http.Error(w, "empty scope", http.StatusBadRequest)
			return
		}
		if !scopeSubset(req.Scope, cfg.AllowedScope) {
			http.Error(w, "scope exceeds verifier policy", http.StatusForbidden)
			return
		}
		if cfg.MaxSALifetime > 0 && req.MaxSALifetime > cfg.MaxSALifetime {
			req.MaxSALifetime = cfg.MaxSALifetime
		}
		if req.History == nil {
			http.Error(w, "missing enforcement history evidence", http.StatusBadRequest)
			return
		}

		state.mu.Lock()
		previous, ok := state.checkpoints[req.PEPID]
		if ok {
			if tok, retryOK := acceptedCheckpointRetry(*req.History, req, cfg, previous, state.lastTokens[req.PEPID], pepEnrollment.SigningPublicKey, id.PublicKey); retryOK {
				state.mu.Unlock()
				log.Printf("[verifier] replayed accepted response pep_id=%s epoch=%d checkpoint_hash=%s", req.PEPID, previous.Epoch, shortHash(tok.CheckpointHash))
				writeJSON(w, tok)
				return
			}
		}
		activeCopy := copyTrackedSessions(state.activeStates[req.PEPID])
		state.mu.Unlock()

		var previousPtr *protocol.EnforcementCheckpoint
		if ok {
			previousPtr = &previous
		}
		checkpointHash, err := attest.VerifyHistoryEvidence(*req.History, req.PEPID, req.PEPSigningPubKey, previousPtr)
		if err == nil {
			err = verifyEnforcementPolicy(*req.History, req, activeCopy, cfg.RequiredObserver)
		}
		if err != nil {
			log.Printf("[verifier] rejected history pep_id=%s err=%v", req.PEPID, err)
			http.Error(w, "invalid enforcement history: "+err.Error(), http.StatusForbidden)
			return
		}
		now := time.Now().UTC()
		tok := protocol.CapacityToken{
			Version:          1,
			TokenType:        "cryptna-pep-capacity-v1",
			VerifierID:       cfg.VerifierID,
			PEPID:            req.PEPID,
			PEPSigningPubKey: req.PEPSigningPubKey,
			Measurement:      req.Measurement,
			PolicyHash:       req.PolicyHash,
			Scope:            append([]string{}, req.Scope...),
			IssuedAt:         now.Format(time.RFC3339),
			ExpiresAt:        now.Add(time.Duration(cfg.TokenTTLSeconds) * time.Second).Format(time.RFC3339),
			MaxSALifetime:    req.MaxSALifetime,
			ObserverProfile:  cfg.RequiredObserver,
			CheckpointHash:   checkpointHash,
			HistoryEpoch:     req.History.Checkpoint.Epoch,
		}
		signed, err := attest.SignCapacityToken(tok, id.PrivateKey)
		if err != nil {
			http.Error(w, "sign capacity token failed", http.StatusInternalServerError)
			log.Println("sign capacity token:", err)
			return
		}

		state.mu.Lock()
		current, currentOK := state.checkpoints[req.PEPID]
		stateChanged := currentOK != ok || (ok && current != previous)
		if stateChanged {
			if currentOK {
				if replay, retryOK := acceptedCheckpointRetry(*req.History, req, cfg, current, state.lastTokens[req.PEPID], pepEnrollment.SigningPublicKey, id.PublicKey); retryOK {
					state.mu.Unlock()
					writeJSON(w, replay)
					return
				}
			}
			state.mu.Unlock()
			http.Error(w, "concurrent checkpoint update; retry with current state", http.StatusConflict)
			return
		}

		next := persistentVerifierState{
			Checkpoints:  copyCheckpoints(state.checkpoints),
			ActiveStates: copyAllActiveStates(state.activeStates),
			LastTokens:   copyCapacityTokens(state.lastTokens),
		}
		next.Checkpoints[req.PEPID] = req.History.Checkpoint
		next.ActiveStates[req.PEPID] = activeCopy
		next.LastTokens[req.PEPID] = signed
		if err := savePersistentVerifierState(cfg.StatePath, next); err != nil {
			state.mu.Unlock()
			log.Printf("[verifier] persist state failed pep_id=%s err=%v", req.PEPID, err)
			http.Error(w, "persist verifier state failed", http.StatusInternalServerError)
			return
		}
		state.checkpoints = next.Checkpoints
		state.activeStates = next.ActiveStates
		state.lastTokens = next.LastTokens
		log.Printf("[verifier] accepted history pep_id=%s epoch=%d checkpoint_hash=%s events=%d last_event_index=%d",
			req.PEPID,
			req.History.Checkpoint.Epoch,
			shortHash(checkpointHash),
			len(req.History.Events),
			req.History.Checkpoint.LastEventIndex,
		)
		state.mu.Unlock()
		writeJSON(w, signed)
	}
}

func acceptedCheckpointRetry(history protocol.HistoryEvidence, req protocol.CapacityRequest, cfg verifierConfig, current protocol.EnforcementCheckpoint, tok protocol.CapacityToken, pepPubKey, verifierPubKey string) (protocol.CapacityToken, bool) {
	if history.Checkpoint != current || tok.Signature == "" {
		return protocol.CapacityToken{}, false
	}
	if err := attest.VerifyEnforcementCheckpoint(history.Checkpoint, pepPubKey); err != nil {
		return protocol.CapacityToken{}, false
	}
	h, err := attest.HashEnforcementCheckpoint(history.Checkpoint)
	if err != nil || tok.CheckpointHash != h || tok.PEPID != history.Checkpoint.PEPID || tok.PEPSigningPubKey != pepPubKey {
		return protocol.CapacityToken{}, false
	}
	issuedAt, err := time.Parse(time.RFC3339, tok.IssuedAt)
	if err != nil || attest.VerifyCapacityToken(tok, verifierPubKey, issuedAt) != nil {
		return protocol.CapacityToken{}, false
	}
	if tok.VerifierID != cfg.VerifierID || tok.Measurement != req.Measurement || tok.PolicyHash != req.PolicyHash ||
		tok.MaxSALifetime != req.MaxSALifetime || tok.ObserverProfile != cfg.RequiredObserver || !sameStringsUnordered(tok.Scope, req.Scope) {
		return protocol.CapacityToken{}, false
	}
	return tok, true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("encode response: %v", err)
	}
}

type lifecycleStage struct {
	phase        string
	xfrmPlanHash string
}

func verifyEnforcementPolicy(history protocol.HistoryEvidence, req protocol.CapacityRequest, active map[string]trackedSession, requiredProfiles ...string) error {
	requiredProfile := "posthoc"
	if len(requiredProfiles) > 0 && strings.TrimSpace(requiredProfiles[0]) != "" {
		requiredProfile = strings.ToLower(strings.TrimSpace(requiredProfiles[0]))
	}
	allowedTypes := map[string]bool{
		"pep_start":            true,
		"capacity_requested":   true,
		"capacity_accepted":    true,
		"xfrm_apply_intent":    true,
		"xfrm_apply_observed":  true,
		"session_activated":    true,
		"session_expired":      true,
		"xfrm_delete_intent":   true,
		"xfrm_delete_observed": true,
	}
	stages := map[string]lifecycleStage{}

	for _, e := range history.Events {
		if !allowedTypes[e.EventType] {
			return fmt.Errorf("unsupported event type %s", e.EventType)
		}
		if e.ServiceID != "" && !contains(req.Scope, e.ServiceID) && !contains(req.Scope, "*") {
			return fmt.Errorf("event service %s outside requested scope", e.ServiceID)
		}

		key := sessionKey(e)
		switch e.EventType {
		case "xfrm_apply_intent":
			if err := requireCompleteSessionEvent(e); err != nil {
				return err
			}
			if _, exists := active[key]; exists {
				return fmt.Errorf("session already active at index %d", e.Index)
			}
			if _, exists := stages[key]; exists {
				return fmt.Errorf("duplicate or overlapping apply intent at index %d", e.Index)
			}
			planHash, err := requireXFRMPlanHash(e)
			if err != nil {
				return err
			}
			if err := validateSessionLifetime(e, req.MaxSALifetime); err != nil {
				return err
			}
			stages[key] = lifecycleStage{phase: "apply_intent", xfrmPlanHash: planHash}
		case "xfrm_apply_observed":
			if err := requireCompleteSessionEvent(e); err != nil {
				return err
			}
			stage := stages[key]
			if stage.phase != "apply_intent" {
				return fmt.Errorf("xfrm apply observed without matching intent at index %d", e.Index)
			}
			if err := verifyObservedEvent(e, "applied", requiredProfile, stage.xfrmPlanHash); err != nil {
				return err
			}
			stages[key] = lifecycleStage{phase: "apply_observed", xfrmPlanHash: stage.xfrmPlanHash}
		case "session_activated":
			if err := requireCompleteSessionEvent(e); err != nil {
				return err
			}
			stage := stages[key]
			if stage.phase != "apply_observed" {
				return fmt.Errorf("session activated without observed XFRM apply at index %d", e.Index)
			}
			exp := eventExpiry(e)
			if exp == "" {
				return fmt.Errorf("session activation missing expiry at index %d", e.Index)
			}
			active[key] = trackedSession{
				ServiceID:     e.ServiceID,
				ClientPubKey:  e.ClientPubKey,
				ClientInnerIP: e.ClientInnerIP,
				ClientInSPI:   e.ClientInSPI,
				PEPInSPI:      e.PEPInSPI,
				ReqID:         e.ReqID,
				ExpiresAt:     exp,
				XFRMPlanHash:  stage.xfrmPlanHash,
			}
			stages[key] = lifecycleStage{phase: "active", xfrmPlanHash: stage.xfrmPlanHash}
		case "session_expired":
			if err := requireCompleteSessionEvent(e); err != nil {
				return err
			}
			tracked, exists := active[key]
			if !exists {
				return fmt.Errorf("expiration for unknown session at index %d", e.Index)
			}
			if err := validateExpirationEvent(e, tracked); err != nil {
				return err
			}
			stages[key] = lifecycleStage{phase: "expired", xfrmPlanHash: tracked.XFRMPlanHash}
		case "xfrm_delete_intent":
			if err := requireCompleteSessionEvent(e); err != nil {
				return err
			}
			tracked, exists := active[key]
			if !exists {
				return fmt.Errorf("delete intent for unknown session at index %d", e.Index)
			}
			if stages[key].phase != "expired" {
				return fmt.Errorf("delete intent without session_expired at index %d", e.Index)
			}
			planHash, err := requireXFRMPlanHash(e)
			if err != nil {
				return err
			}
			if planHash != tracked.XFRMPlanHash {
				return fmt.Errorf("delete intent XFRM plan mismatch at index %d", e.Index)
			}
			stages[key] = lifecycleStage{phase: "delete_intent", xfrmPlanHash: planHash}
		case "xfrm_delete_observed":
			if err := requireCompleteSessionEvent(e); err != nil {
				return err
			}
			stage := stages[key]
			if stage.phase != "delete_intent" {
				return fmt.Errorf("xfrm delete observed without matching intent at index %d", e.Index)
			}
			if err := verifyObservedEvent(e, "deleted", requiredProfile, stage.xfrmPlanHash); err != nil {
				return err
			}
			delete(active, key)
			stages[key] = lifecycleStage{phase: "deleted", xfrmPlanHash: stage.xfrmPlanHash}
		}
	}

	for key, stage := range stages {
		switch stage.phase {
		case "apply_intent", "apply_observed", "expired", "delete_intent":
			return fmt.Errorf("incomplete enforcement transaction for %s at checkpoint: %s", key, stage.phase)
		}
	}

	checkpointTime, err := time.Parse(time.RFC3339, history.Checkpoint.CreatedAt)
	if err != nil {
		return fmt.Errorf("invalid checkpoint time: %w", err)
	}
	for key, session := range active {
		exp, err := time.Parse(time.RFC3339, session.ExpiresAt)
		if err != nil {
			return fmt.Errorf("invalid active session expiry for %s: %w", key, err)
		}
		if !checkpointTime.Before(exp) {
			return fmt.Errorf("expired session still active at checkpoint: %s expired_at=%s", key, session.ExpiresAt)
		}
	}
	return nil
}

func requireCompleteSessionEvent(e protocol.EnforcementEvent) error {
	if e.ServiceID == "" || e.ClientPubKey == "" || e.ClientInSPI == "" || e.PEPInSPI == "" || e.ClientInnerIP == "" || e.ClientOuterIP == "" || e.ReqID == 0 {
		return fmt.Errorf("incomplete session event at index %d", e.Index)
	}
	return nil
}

func sessionKey(e protocol.EnforcementEvent) string {
	return fmt.Sprintf("%s|%s|%s|%s|%s|%s|%d", e.ClientPubKey, e.ServiceID, e.ClientOuterIP, e.ClientInnerIP, e.ClientInSPI, e.PEPInSPI, e.ReqID)
}

func requireXFRMPlanHash(e protocol.EnforcementEvent) (string, error) {
	if e.Metadata == nil || strings.TrimSpace(e.Metadata["xfrm_plan_hash"]) == "" || e.Metadata["xfrm_plan_hash"] == "hash_error" {
		return "", fmt.Errorf("event missing valid XFRM plan hash at index %d", e.Index)
	}
	return e.Metadata["xfrm_plan_hash"], nil
}

func verifyObservedEvent(e protocol.EnforcementEvent, outcome, requiredProfile, expectedPlanHash string) error {
	planHash, err := requireXFRMPlanHash(e)
	if err != nil {
		return err
	}
	if planHash != expectedPlanHash {
		return fmt.Errorf("observed XFRM plan mismatch at index %d", e.Index)
	}
	if e.Metadata == nil {
		return fmt.Errorf("missing observer metadata at index %d", e.Index)
	}
	mode := strings.ToLower(strings.TrimSpace(e.Metadata["xfrm_mode"]))
	actualProfile := strings.ToLower(strings.TrimSpace(e.Metadata["observer_source"]))
	value := strings.ToLower(strings.TrimSpace(e.Metadata[outcome]))
	if requiredProfile == "dry-run" {
		if mode == "apply" || value != "assumed" {
			return fmt.Errorf("dry-run observer profile not satisfied at index %d", e.Index)
		}
		return nil
	}
	if mode != "apply" || value != "true" {
		action := "apply"
		if outcome == "deleted" {
			action = "delete"
		}
		return fmt.Errorf("xfrm %s not observed at index %d", action, e.Index)
	}
	switch requiredProfile {
	case "posthoc":
		if actualProfile != "posthoc" && actualProfile != "posthoc+ebpf" {
			return fmt.Errorf("required posthoc observer profile missing at index %d", e.Index)
		}
	case "hybrid":
		if actualProfile != "posthoc+ebpf" || e.Metadata["ebpf_matched"] != "true" {
			return fmt.Errorf("required hybrid observer profile missing at index %d", e.Index)
		}
	case "ebpf":
		if actualProfile != "ebpf" || e.Metadata["ebpf_matched"] != "true" {
			return fmt.Errorf("required eBPF observer profile missing at index %d", e.Index)
		}
	default:
		return fmt.Errorf("unsupported required observer profile %q", requiredProfile)
	}
	return nil
}

func validateSessionLifetime(e protocol.EnforcementEvent, maxLifetime int) error {
	expRaw := eventExpiry(e)
	if expRaw == "" {
		return fmt.Errorf("session event missing expiry at index %d", e.Index)
	}
	exp, err := time.Parse(time.RFC3339, expRaw)
	if err != nil {
		return fmt.Errorf("invalid session expiry at index %d: %w", e.Index, err)
	}
	ts, err := time.Parse(time.RFC3339, e.Timestamp)
	if err != nil {
		return fmt.Errorf("invalid session timestamp at index %d: %w", e.Index, err)
	}
	if maxLifetime > 0 && exp.Sub(ts) > time.Duration(maxLifetime+1)*time.Second {
		return fmt.Errorf("session lifetime exceeds requested maximum at index %d", e.Index)
	}
	return nil
}

func validateExpirationEvent(e protocol.EnforcementEvent, tracked trackedSession) error {
	if eventExpiry(e) != tracked.ExpiresAt {
		return fmt.Errorf("expiration metadata mismatch at index %d", e.Index)
	}
	exp, err := time.Parse(time.RFC3339, tracked.ExpiresAt)
	if err != nil {
		return fmt.Errorf("invalid tracked expiry at index %d: %w", e.Index, err)
	}
	ts, err := time.Parse(time.RFC3339, e.Timestamp)
	if err != nil {
		return fmt.Errorf("invalid expiration timestamp at index %d: %w", e.Index, err)
	}
	if ts.Before(exp) {
		return fmt.Errorf("session expired event precedes expiry at index %d", e.Index)
	}
	return nil
}

func eventExpiry(e protocol.EnforcementEvent) string {
	if e.Metadata == nil {
		return ""
	}
	return strings.TrimSpace(e.Metadata["expires_at"])
}

func copyTrackedSessions(in map[string]trackedSession) map[string]trackedSession {
	out := map[string]trackedSession{}
	for k, v := range in {
		out[k] = v
	}
	return out
}

type persistentVerifierState struct {
	Checkpoints  map[string]protocol.EnforcementCheckpoint `json:"checkpoints"`
	ActiveStates map[string]map[string]trackedSession      `json:"active_states"`
	LastTokens   map[string]protocol.CapacityToken         `json:"last_tokens"`
}

func loadVerifierState(path string, state *verifierState) error {
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
	var persisted persistentVerifierState
	if err := json.NewDecoder(f).Decode(&persisted); err != nil {
		return err
	}
	if persisted.Checkpoints != nil {
		state.checkpoints = persisted.Checkpoints
	}
	if persisted.ActiveStates != nil {
		state.activeStates = persisted.ActiveStates
	}
	if persisted.LastTokens != nil {
		state.lastTokens = persisted.LastTokens
	}
	log.Printf("[verifier] loaded persisted state path=%s peps=%d", path, len(state.checkpoints))
	return nil
}

func saveVerifierState(path string, state *verifierState) error {
	return savePersistentVerifierState(path, persistentVerifierState{
		Checkpoints:  state.checkpoints,
		ActiveStates: state.activeStates,
		LastTokens:   state.lastTokens,
	})
}

func savePersistentVerifierState(path string, persisted persistentVerifierState) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	b, err := json.MarshalIndent(persisted, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func copyCheckpoints(in map[string]protocol.EnforcementCheckpoint) map[string]protocol.EnforcementCheckpoint {
	out := make(map[string]protocol.EnforcementCheckpoint, len(in)+1)
	for k, v := range in {
		out[k] = v
	}
	return out
}

func copyAllActiveStates(in map[string]map[string]trackedSession) map[string]map[string]trackedSession {
	out := make(map[string]map[string]trackedSession, len(in)+1)
	for pepID, sessions := range in {
		out[pepID] = copyTrackedSessions(sessions)
	}
	return out
}

func copyCapacityTokens(in map[string]protocol.CapacityToken) map[string]protocol.CapacityToken {
	out := make(map[string]protocol.CapacityToken, len(in)+1)
	for k, v := range in {
		v.Scope = append([]string{}, v.Scope...)
		out[k] = v
	}
	return out
}

func scopeSubset(requested, allowed []string) bool {
	if contains(allowed, "*") {
		return true
	}
	for _, s := range requested {
		if s == "" {
			continue
		}
		if !contains(allowed, s) {
			return false
		}
	}
	return true
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if strings.TrimSpace(v) == want {
			return true
		}
	}
	return false
}

func sameStringsUnordered(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	counts := make(map[string]int, len(left))
	for _, value := range left {
		counts[strings.TrimSpace(value)]++
	}
	for _, value := range right {
		key := strings.TrimSpace(value)
		counts[key]--
		if counts[key] < 0 {
			return false
		}
	}
	for _, count := range counts {
		if count != 0 {
			return false
		}
	}
	return true
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func mustLoadJSON[T any](path string) T {
	var out T
	f, err := os.Open(path)
	if err != nil {
		log.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	if err := json.NewDecoder(f).Decode(&out); err != nil {
		log.Fatalf("decode %s: %v", path, err)
	}
	return out
}

func shortHash(s string) string {
	if len(s) <= 16 {
		return s
	}
	return s[:8] + "..." + s[len(s)-8:]
}

func getenv(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}

func getenvInt(k string, fallback int) int {
	v := strings.TrimSpace(getenv(k, ""))
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}
