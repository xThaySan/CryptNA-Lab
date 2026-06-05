package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

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
	ServiceID   string `json:"service_id"`
	PEPAddress string `json:"pep_address"`
	PEPPort    int    `json:"pep_port"`
	PEPSPI     string `json:"pep_spi"`
	PEPDHPub   string `json:"pep_dh_pub"`
	AEAD       string `json:"aead"`
	SALifetime int    `json:"sa_lifetime_seconds"`
	ExpiresAt  string `json:"expires_at"`
}

type Session struct {
	ClientPubKey string `json:"client_pubkey"`
	ServiceID    string `json:"service_id"`
	ClientSPI    string `json:"client_spi"`
	PEPSPI       string `json:"pep_spi"`
	ClientDHPub  string `json:"client_dh_pub"`
	PEPDHPub     string `json:"pep_dh_pub"`
	AEAD         string `json:"aead"`
	C2PKey       string `json:"c2p_key"`
	P2CKey       string `json:"p2c_key"`
	ExpiresAt    string `json:"expires_at"`
}

var (
	sessionsMu sync.RWMutex
	sessions   = map[string]Session{}
)

func main() {
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok\n"))
	})

	http.HandleFunc("/activate", activateHandler)
	http.HandleFunc("/sessions", sessionsHandler)

	log.Println("PEP listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func activateHandler(w http.ResponseWriter, r *http.Request) {
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

	lifetime := 60
	expiresAt := time.Now().Add(time.Duration(lifetime) * time.Second).UTC().Format(time.RFC3339)
	pepSPI := randomHex(4)

	session := Session{
		ClientPubKey: req.ClientPubKey,
		ServiceID:    req.ServiceID,
		ClientSPI:    req.ClientSPI,
		PEPSPI:       pepSPI,
		ClientDHPub:  req.ClientDHPub,
		PEPDHPub:     pepDHPub,
		AEAD:         aead,
		C2PKey:       c2pKey,
		P2CKey:       p2cKey,
		ExpiresAt:    expiresAt,
	}

	sessionsMu.Lock()
	sessions[pepSPI] = session
	sessionsMu.Unlock()

	resp := ActivateResponse{
		ServiceID:   req.ServiceID,
		PEPAddress: "172.21.0.40",
		PEPPort:    4500,
		PEPSPI:     pepSPI,
		PEPDHPub:   pepDHPub,
		AEAD:       aead,
		SALifetime: lifetime,
		ExpiresAt:  expiresAt,
	}

	log.Printf("activated service=%s client=%s pep_spi=%s", req.ServiceID, req.ClientPubKey, pepSPI)
	writeJSON(w, resp)
}

func sessionsHandler(w http.ResponseWriter, r *http.Request) {
	sessionsMu.RLock()
	defer sessionsMu.RUnlock()

	out := make([]Session, 0, len(sessions))
	for _, s := range sessions {
		out = append(out, s)
	}

	writeJSON(w, out)
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

	reader := hkdf.New(
		sha256.New,
		shared,
		[]byte("CRYPTNA-LAB-v0"),
		[]byte("client-pep-session-keys"),
	)

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

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}