package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
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
}

func main() {
	cfg := verifierConfig{
		VerifierID:          getenv("VERIFIER_ID", "cryptna-verifier-v1"),
		IdentityPath:        getenv("VERIFIER_IDENTITY", "/app/identity.json"),
		ExpectedMeasurement: getenv("VERIFIER_EXPECTED_MEASUREMENT", ""),
		ExpectedPolicyHash:  getenv("VERIFIER_EXPECTED_POLICY_HASH", ""),
		TokenTTLSeconds:     getenvInt("VERIFIER_TOKEN_TTL_SECONDS", 120),
	}
	id := mustLoadJSON[attest.Ed25519Identity](cfg.IdentityPath)

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

	log.Printf("[verifier] listening on :8080 id=%s expected_measurement=%s expected_policy_hash=%s ttl=%ds", cfg.VerifierID, cfg.ExpectedMeasurement, cfg.ExpectedPolicyHash, cfg.TokenTTLSeconds)
	log.Fatal(http.ListenAndServe(":8080", nil))
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
