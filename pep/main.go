package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"cryptna-lab/common/cryptoutil"
	"cryptna-lab/common/protocol"
	"cryptna-lab/common/logutil"
)

var (
	sessionsMu sync.RWMutex
	sessions   = map[string]protocol.Session{}
)

func main() {
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok\n"))
	})

	http.HandleFunc("/activate", activateHandler)
	http.HandleFunc("/sessions", sessionsHandler)

	logutil.Infof("pep", "listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func activateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req protocol.ActivateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	logutil.Debugf("pep", "activation request client=%s service=%s client_spi=%s client_dh_pub=%s aead=%v", logutil.Short(req.ClientPubKey), req.ServiceID, req.ClientSPI, logutil.Short(req.ClientDHPub), req.AEADSuites)

	aead := "aes-gcm-128"
	if len(req.AEADSuites) > 0 {
		aead = req.AEADSuites[0]
	}

	pepDH, err := cryptoutil.GenerateX25519KeyPair()
	if err != nil {
		http.Error(w, "dh generation failed", http.StatusInternalServerError)
		return
	}
	logutil.Debugf("pep", "generated pep dh pub=%s", logutil.Short(pepDH.PublicB64))

	sharedSecret, err := cryptoutil.DeriveSharedSecretB64(pepDH.PrivateB64, req.ClientDHPub)
	if err != nil {
		http.Error(w, "dh derivation failed", http.StatusBadRequest)
		return
	}
	c2pKey, p2cKey, err := cryptoutil.DeriveSessionKeys(sharedSecret)
	if err != nil {
		http.Error(w, "kdf failed", http.StatusInternalServerError)
		return
	}
	logutil.Debugf("pep", "derived session keys c2p=%s p2c=%s", logutil.Short(c2pKey), logutil.Short(p2cKey))

	lifetime := 60
	expiresAt := time.Now().Add(time.Duration(lifetime) * time.Second).UTC().Format(time.RFC3339)
	pepSPI := randomHex(4)

	session := protocol.Session{
		ClientPubKey: req.ClientPubKey,
		ServiceID:    req.ServiceID,
		ClientSPI:    req.ClientSPI,
		PEPSPI:       pepSPI,
		ClientDHPub:  req.ClientDHPub,
		PEPDHPub:     pepDH.PublicB64,
		AEAD:         aead,
		C2PKey:       c2pKey,
		P2CKey:       p2cKey,
		ExpiresAt:    expiresAt,
	}

	sessionsMu.Lock()
	sessions[pepSPI] = session
	logutil.Debugf("pep", "stored session pep_spi=%s expires_at=%s sessions_count=%d", pepSPI, expiresAt, len(sessions))
	sessionsMu.Unlock()

	resp := protocol.TunnelParams{
		ServiceID:  req.ServiceID,
		PEPAddress: "172.21.0.40",
		PEPPort:    4500,
		PEPSPI:     pepSPI,
		PEPDHPub:   pepDH.PublicB64,
		AEAD:       aead,
		SALifetime: lifetime,
		ExpiresAt:  expiresAt,
	}

	logutil.Infof("pep", "activated service=%s client=%s pep_spi=%s", req.ServiceID, logutil.Short(req.ClientPubKey), pepSPI)
	writeJSON(w, resp)
}

func sessionsHandler(w http.ResponseWriter, r *http.Request) {
	sessionsMu.RLock()
	defer sessionsMu.RUnlock()

	out := make([]protocol.Session, 0, len(sessions))
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

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
