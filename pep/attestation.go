package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"cryptna-lab/common/attest"
	"cryptna-lab/common/protocol"
)

type pepAttestationState struct {
	enabled       bool
	pepID         string
	verifierURL   string
	measurement   string
	policyHash    string
	scope         []string
	maxSALifetime int
	key           attest.Ed25519Identity

	mu    sync.Mutex
	token *protocol.CapacityToken
}

var pepAttestation *pepAttestationState

func initAttestation() {
	enabled := getenvBool("PEP_ATTESTATION_ENABLED", false)
	if !enabled {
		pepAttestation = &pepAttestationState{enabled: false}
		return
	}

	key, err := loadOrGeneratePEPAttestationKey(getenv("PEP_ATTESTATION_KEY", "/app/pep_attestation_key.json"))
	if err != nil {
		log.Fatalf("load/generate PEP attestation key: %v", err)
	}

	serviceID := getenv("PEP_ATTESTATION_SCOPE", "svc-http")
	maxLifetime := getenvInt("PEP_CAPACITY_MAX_SA_LIFETIME_SECONDS", getenvInt("SA_LIFETIME_SECONDS", 60))

	pepAttestation = &pepAttestationState{
		enabled:       true,
		pepID:         getenv("PEP_ID", "cryptna-pep-1"),
		verifierURL:   getenv("VERIFIER_URL", "http://cryptna-verifier:8080"),
		measurement:   getenv("PEP_MEASUREMENT", "cryptna-lab-pep-measurement-v1"),
		policyHash:    getenv("PEP_POLICY_HASH", "cryptna-lab-policy-v1"),
		scope:         strings.Split(serviceID, ","),
		maxSALifetime: maxLifetime,
		key:           key,
	}

	log.Printf("[pep] attestation enabled pep_id=%s verifier=%s scope=%v measurement=%s policy_hash=%s max_sa_lifetime=%d", pepAttestation.pepID, pepAttestation.verifierURL, pepAttestation.scope, pepAttestation.measurement, pepAttestation.policyHash, pepAttestation.maxSALifetime)

	enforcementHistory = NewEnforcementHistory(pepAttestation.pepID)
	historyAppend(eventPEPStart, nil, map[string]string{
		"measurement":  pepAttestation.measurement,
		"policy_hash":  pepAttestation.policyHash,
		"history_mode": "hash-chain-xfrm-observation",
	})

	var lastErr error
	for i := 0; i < 20; i++ {
		if _, err := pepAttestation.ensureCapacityToken(); err == nil {
			lastErr = nil
			break
		} else {
			lastErr = err
			time.Sleep(500 * time.Millisecond)
		}
	}
	if lastErr != nil {
		log.Fatalf("initial PEP capacity token fetch failed: %v", lastErr)
	}
	go pepAttestation.refreshLoop()
}

func loadOrGeneratePEPAttestationKey(path string) (attest.Ed25519Identity, error) {
	if path != "" {
		if f, err := os.Open(path); err == nil {
			defer f.Close()
			var id attest.Ed25519Identity
			if err := json.NewDecoder(f).Decode(&id); err != nil {
				return attest.Ed25519Identity{}, err
			}
			if id.PublicKey != "" && id.PrivateKey != "" {
				return id, nil
			}
		}
	}
	return attest.GenerateEd25519Identity()
}

func (s *pepAttestationState) refreshLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if _, err := s.ensureCapacityToken(); err != nil {
			log.Printf("[pep] capacity token refresh failed: %v", err)
		}
	}
}

func (s *pepAttestationState) ensureCapacityToken() (protocol.CapacityToken, error) {
	if s == nil || !s.enabled {
		return protocol.CapacityToken{}, fmt.Errorf("PEP attestation disabled")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.token != nil {
		exp, err := time.Parse(time.RFC3339, s.token.ExpiresAt)
		if err == nil && time.Until(exp) > 20*time.Second {
			return *s.token, nil
		}
	}

	historyTransactionMu.Lock()
	defer historyTransactionMu.Unlock()

	// Before submitting a checkpoint, drain any expired sessions. Otherwise, a
	// capacity refresh can race with the session reaper and get accepted while an
	// expired XFRM state has not yet produced its delete events.
	cleanupExpiredSessionsUnderHistoryLock(time.Now().UTC())

	historyAppend(eventCapacityRequested, nil, map[string]string{
		"scope": strings.Join(s.scope, ","),
	})
	historyEvidence, err := enforcementHistory.BuildEvidence(s.key.PrivateKey)
	if err != nil {
		return protocol.CapacityToken{}, err
	}
	req := protocol.CapacityRequest{
		PEPID:            s.pepID,
		PEPSigningPubKey: s.key.PublicKey,
		Measurement:      s.measurement,
		PolicyHash:       s.policyHash,
		Scope:            append([]string{}, s.scope...),
		MaxSALifetime:    s.maxSALifetime,
		History:          &historyEvidence,
	}
	body, err := json.Marshal(req)
	if err != nil {
		return protocol.CapacityToken{}, err
	}
	resp, err := http.Post(s.verifierURL+"/capacity", "application/json", bytes.NewReader(body))
	if err != nil {
		return protocol.CapacityToken{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return protocol.CapacityToken{}, fmt.Errorf("verifier returned status %d", resp.StatusCode)
	}
	var tok protocol.CapacityToken
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return protocol.CapacityToken{}, err
	}
	checkpointHash, err := attest.HashEnforcementCheckpoint(historyEvidence.Checkpoint)
	if err != nil {
		return protocol.CapacityToken{}, err
	}
	if tok.CheckpointHash != "" && tok.CheckpointHash != checkpointHash {
		return protocol.CapacityToken{}, fmt.Errorf("verifier token checkpoint hash mismatch")
	}
	if err := enforcementHistory.MarkCheckpointAccepted(historyEvidence.Checkpoint); err != nil {
		return protocol.CapacityToken{}, err
	}
	historyAppend(eventCapacityAccepted, nil, map[string]string{
		"checkpoint_hash": checkpointHash,
		"history_epoch":   fmt.Sprintf("%d", historyEvidence.Checkpoint.Epoch),
	})
	s.token = &tok
	return tok, nil
}

func (s *pepAttestationState) boundLifetime(lifetime int, tok protocol.CapacityToken) (int, error) {
	if lifetime > tok.MaxSALifetime {
		lifetime = tok.MaxSALifetime
	}
	exp, err := time.Parse(time.RFC3339, tok.ExpiresAt)
	if err != nil {
		return 0, err
	}
	remaining := int(time.Until(exp).Seconds())
	if remaining < lifetime {
		lifetime = remaining
	}
	if lifetime <= 0 {
		return 0, fmt.Errorf("capacity token has no remaining SA lifetime")
	}
	return lifetime, nil
}

func (s *pepAttestationState) signSABinding(req protocol.ActivateRequest, session protocol.Session, resp protocol.PEPActivationResponse, tok protocol.CapacityToken) (protocol.SABinding, error) {
	tokHash, err := attest.CapacityTokenHash(tok)
	if err != nil {
		return protocol.SABinding{}, err
	}
	b := protocol.SABinding{
		Version:       1,
		TokenHash:     tokHash,
		PEPID:         tok.PEPID,
		ClientPubKey:  req.ClientPubKey,
		ServiceID:     resp.ServiceID,
		ServiceIP:     resp.ServiceIP,
		ClientInnerIP: resp.ClientInnerIP,
		ClientInSPI:   resp.ClientInSPI,
		PEPInSPI:      resp.PEPInSPI,
		ClientDHPub:   req.ClientDHPub,
		PEPDHPub:      resp.PEPDHPub,
		AEAD:          resp.AEAD,
		SALifetime:    resp.SALifetime,
		ExpiresAt:     resp.ExpiresAt,
	}
	_ = session
	return attest.SignSABinding(b, s.key.PrivateKey)
}

func getenvBool(k string, fallback bool) bool {
	v := strings.ToLower(strings.TrimSpace(getenv(k, "")))
	if v == "" {
		return fallback
	}
	return v == "1" || v == "true" || v == "yes" || v == "on"
}
