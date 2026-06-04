package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/base64"
	"log"
	"net/http"
	"time"

	"golang.org/x/crypto/curve25519"
)

type ActivateRequest struct {
	ClientPubKey string   `json:"client_pubkey"`
	ServiceID    string   `json:"service_id"`
	ClientSPI    string   `json:"client_spi"`
	ClientDHPub  string   `json:"client_dh_pub"`
	AEADSuites   []string `json:"aead_suites"`
}

type ActivateResponse struct {
	ServiceID   string `json:"service_id"`
	PEPAddress  string `json:"pep_address"`
	PEPPort     int    `json:"pep_port"`
	PEPSPI      string `json:"pep_spi"`
	PEPDHPub    string `json:"pep_dh_pub"`
	AEAD        string `json:"aead"`
	SALifetime  int    `json:"sa_lifetime_seconds"`
	ExpiresAt   string `json:"expires_at"`
}

func main() {
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok\n"))
	})

	http.HandleFunc("/activate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req ActivateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}

		aead := "aes-gcm-128"
		if len(req.AEADSuites) > 0 {
			aead = req.AEADSuites[0]
		}

		lifetime := 60
		_, pepDHPub := mustGenerateX25519()
		resp := ActivateResponse{
			ServiceID:  req.ServiceID,
			PEPAddress: "172.21.0.40",
			PEPPort:    4500,
			PEPSPI:     randomHex(4),
			PEPDHPub:   pepDHPub,
			AEAD:       aead,
			SALifetime: lifetime,
			ExpiresAt:  time.Now().Add(time.Duration(lifetime) * time.Second).UTC().Format(time.RFC3339),
		}

		log.Printf("activated service=%s client=%s pep_spi=%s", req.ServiceID, req.ClientPubKey, resp.PEPSPI)
		writeJSON(w, resp)
	})

	log.Println("PEP listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return "0x" + hex.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func mustGenerateX25519() (string, string) {
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		log.Fatal(err)
	}

	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		log.Fatal(err)
	}

	return base64.StdEncoding.EncodeToString(priv), base64.StdEncoding.EncodeToString(pub)
}
