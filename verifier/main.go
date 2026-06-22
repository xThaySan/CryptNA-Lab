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
	ExpectedMeasurement string
	ExpectedPolicyHash  string
	TokenTTLSeconds     int
	AllowedScope        []string
	MaxSALifetime       int
	StatePath           string
}

type verifierState struct {
	mu           sync.Mutex
	checkpoints  map[string]protocol.EnforcementCheckpoint
	activeStates map[string]map[string]trackedSession
}

type trackedSession struct {
	ServiceID     string
	ClientPubKey  string
	ClientInnerIP string
	ClientInSPI   string
	PEPInSPI      string
	ReqID         uint32
	ExpiresAt     string
}

func main() {
	cfg := verifierConfig{
		VerifierID:          getenv("VERIFIER_ID", "cryptna-verifier-v1"),
		IdentityPath:        getenv("VERIFIER_IDENTITY", "/app/identity.json"),
		ExpectedMeasurement: getenv("VERIFIER_EXPECTED_MEASUREMENT", ""),
		ExpectedPolicyHash:  getenv("VERIFIER_EXPECTED_POLICY_HASH", ""),
		TokenTTLSeconds:     getenvInt("VERIFIER_TOKEN_TTL_SECONDS", 120),
		AllowedScope:        splitCSV(getenv("VERIFIER_ALLOWED_SCOPE", "svc-http")),
		MaxSALifetime:       getenvInt("VERIFIER_MAX_SA_LIFETIME_SECONDS", 60),
		StatePath:           getenv("VERIFIER_STATE_PATH", ""),
	}
	id := mustLoadJSON[attest.Ed25519Identity](cfg.IdentityPath)
	state := &verifierState{
		checkpoints:  map[string]protocol.EnforcementCheckpoint{},
		activeStates: map[string]map[string]trackedSession{},
	}
	if err := loadVerifierState(cfg.StatePath, state); err != nil {
		log.Fatalf("load verifier state: %v", err)
	}

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok\n"))
	})

	http.HandleFunc("/capacity", func(w http.ResponseWriter, r *http.Request) {
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
		var previousPtr *protocol.EnforcementCheckpoint
		if ok {
			previousPtr = &previous
		}
		checkpointHash, err := attest.VerifyHistoryEvidence(*req.History, req.PEPID, req.PEPSigningPubKey, previousPtr)
		activeCopy := copyTrackedSessions(state.activeStates[req.PEPID])
		if err == nil {
			err = verifyEnforcementPolicy(*req.History, req, activeCopy)
		}
		if err != nil {
			state.mu.Unlock()
			log.Printf("[verifier] rejected history pep_id=%s err=%v", req.PEPID, err)
			http.Error(w, "invalid enforcement history: "+err.Error(), http.StatusForbidden)
			return
		}
		state.checkpoints[req.PEPID] = req.History.Checkpoint
		state.activeStates[req.PEPID] = activeCopy
		if err := saveVerifierState(cfg.StatePath, state); err != nil {
			state.mu.Unlock()
			log.Printf("[verifier] persist state failed pep_id=%s err=%v", req.PEPID, err)
			http.Error(w, "persist verifier state failed", http.StatusInternalServerError)
			return
		}
		log.Printf("[verifier] accepted history pep_id=%s epoch=%d checkpoint_hash=%s events=%d last_event_index=%d",
			req.PEPID,
			req.History.Checkpoint.Epoch,
			shortHash(checkpointHash),
			len(req.History.Events),
			req.History.Checkpoint.LastEventIndex,
		)
		state.mu.Unlock()

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
			CheckpointHash:   checkpointHash,
			HistoryEpoch:     req.History.Checkpoint.Epoch,
		}
		signed, err := attest.SignCapacityToken(tok, id.PrivateKey)
		if err != nil {
			http.Error(w, "sign capacity token failed", http.StatusInternalServerError)
			log.Println("sign capacity token:", err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(signed)
	})

	log.Printf("[verifier] listening on :8080 id=%s expected_measurement=%s expected_policy_hash=%s ttl=%ds allowed_scope=%v max_sa_lifetime=%ds", cfg.VerifierID, cfg.ExpectedMeasurement, cfg.ExpectedPolicyHash, cfg.TokenTTLSeconds, cfg.AllowedScope, cfg.MaxSALifetime)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func verifyEnforcementPolicy(history protocol.HistoryEvidence, req protocol.CapacityRequest, active map[string]trackedSession) error {
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
	stages := map[string]string{}

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
			stages[key] = "apply_intent"
		case "xfrm_apply_observed":
			if err := requireCompleteSessionEvent(e); err != nil {
				return err
			}
			if stages[key] != "apply_intent" {
				return fmt.Errorf("xfrm apply observed without matching intent at index %d", e.Index)
			}
			if e.Metadata != nil && e.Metadata["applied"] == "false" {
				return fmt.Errorf("xfrm apply not observed at index %d", e.Index)
			}
			stages[key] = "apply_observed"
		case "session_activated":
			if err := requireCompleteSessionEvent(e); err != nil {
				return err
			}
			if stages[key] != "apply_observed" {
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
			}
			stages[key] = "active"
		case "session_expired":
			if err := requireCompleteSessionEvent(e); err != nil {
				return err
			}
			if _, exists := active[key]; !exists {
				return fmt.Errorf("expiration for unknown session at index %d", e.Index)
			}
			stages[key] = "expired"
		case "xfrm_delete_intent":
			if err := requireCompleteSessionEvent(e); err != nil {
				return err
			}
			if _, exists := active[key]; !exists {
				return fmt.Errorf("delete intent for unknown session at index %d", e.Index)
			}
			if stages[key] != "expired" {
				return fmt.Errorf("delete intent without session_expired at index %d", e.Index)
			}
			stages[key] = "delete_intent"
		case "xfrm_delete_observed":
			if err := requireCompleteSessionEvent(e); err != nil {
				return err
			}
			if stages[key] != "delete_intent" {
				return fmt.Errorf("xfrm delete observed without matching intent at index %d", e.Index)
			}
			if e.Metadata != nil && e.Metadata["deleted"] == "false" {
				return fmt.Errorf("xfrm delete not observed at index %d", e.Index)
			}
			delete(active, key)
			stages[key] = "deleted"
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
	if e.ServiceID == "" || e.ClientPubKey == "" || e.ClientInSPI == "" || e.PEPInSPI == "" || e.ClientInnerIP == "" {
		return fmt.Errorf("incomplete session event at index %d", e.Index)
	}
	return nil
}

func sessionKey(e protocol.EnforcementEvent) string {
	return e.ClientPubKey + "|" + e.ServiceID + "|" + e.ClientInnerIP + "|" + e.ClientInSPI + "|" + e.PEPInSPI
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
	log.Printf("[verifier] loaded persisted state path=%s peps=%d", path, len(state.checkpoints))
	return nil
}

func saveVerifierState(path string, state *verifierState) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	persisted := persistentVerifierState{
		Checkpoints:  state.checkpoints,
		ActiveStates: state.activeStates,
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
