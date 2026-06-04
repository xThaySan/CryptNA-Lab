package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"time"
	"io"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

type ActivateRequest struct {
	ClientPubKey string   `json:"client_pubkey"`
	ServiceID    string   `json:"service_id"`
	ClientSPI    string   `json:"client_spi"`
	ClientDHPub  string   `json:"client_dh_pub"`
	AEADSuites   []string `json:"aead_suites"`
}

type ActivateResponse struct {
	ServiceID          string `json:"service_id"`
	PEPAddress        string `json:"pep_address"`
	PEPPort           int    `json:"pep_port"`
	PEPSPI            string `json:"pep_spi"`
	PEPDHPub          string `json:"pep_dh_pub"`
	AEAD              string `json:"aead"`
	SALifetime        int    `json:"sa_lifetime_seconds"`
	ExpiresAt         string `json:"expires_at"`
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

		pepDHPriv, pepDHPub := mustGenerateX25519()
		sharedSecret := mustDeriveSharedSecret(pepDHPriv, req.ClientDHPub)
		c2pKey, p2cKey := mustDeriveSessionKeys(sharedSecret)
		log.Printf("derived session keys client=%s service=%s c2p=%s p2c=%s", req.ClientPubKey, req.ServiceID, c2pKey, p2cKey)

		lifetime := 60
		resp := ActivateResponse{
			ServiceID:          req.ServiceID,
			PEPAddress:        "172.21.0.40",
			PEPPort:           4500,
			PEPSPI:            randomHex(4),
			PEPDHPub:          pepDHPub,
			AEAD:              aead,
			SALifetime:        lifetime,
			ExpiresAt:         time.Now().Add(time.Duration(lifetime) * time.Second).UTC().Format(time.RFC3339),
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

func mustDeriveSharedSecret(privB64, pubB64 string) string {
	priv, err := base64.StdEncoding.DecodeString(privB64)
	if err != nil {
		log.Fatal(err)
	}

	pub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil {
		log.Fatal(err)
	}

	shared, err := curve25519.X25519(priv, pub)
	if err != nil {
		log.Fatal(err)
	}

	return base64.StdEncoding.EncodeToString(shared)
}

func mustDeriveSessionKeys(sharedB64 string) (string, string) {
	shared, err := base64.StdEncoding.DecodeString(sharedB64)
	if err != nil {
		log.Fatal(err)
	}

	salt := []byte("CRYPTNA-LAB-v0")
	info := []byte("client-pep-session-keys")

	reader := hkdf.New(sha256.New, shared, salt, info)

	c2p := make([]byte, 32)
	p2c := make([]byte, 32)

	if _, err := io.ReadFull(reader, c2p); err != nil {
		log.Fatal(err)
	}
	if _, err := io.ReadFull(reader, p2c); err != nil {
		log.Fatal(err)
	}

	return base64.StdEncoding.EncodeToString(c2p), base64.StdEncoding.EncodeToString(p2c)
}

func constantTimeEqual(a, b string) bool {
	return hmac.Equal([]byte(a), []byte(b))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
