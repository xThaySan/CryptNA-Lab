package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"cryptna-lab/common/cryptoutil"
	"cryptna-lab/common/ipsecutil"
	"cryptna-lab/common/logutil"
	"cryptna-lab/common/protocol"
)

var (
	sessionsMu sync.RWMutex
	sessions   = map[string]protocol.Session{}

	nextReqID         uint32
	nextClientInnerID uint32
)

func main() {
	initAllocators()

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
	logutil.Debugf("pep", "activation request client=%s service=%s client_in_spi=%s client_dh_pub=%s aead=%v", logutil.Short(req.ClientPubKey), req.ServiceID, req.ClientInSPI, logutil.Short(req.ClientDHPub), req.AEADSuites)

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

	pepInSPI, err := ipsecutil.GenerateSPI()
	if err != nil {
		http.Error(w, "spi generation failed", http.StatusInternalServerError)
		return
	}
	reqID := allocateReqID()
	clientInnerIP := allocateClientInnerIP()
	clientOuterIP := getenv("CLIENT_OUTER_IP", getenv("CLIENT_DATA_IP", "172.21.0.10"))
	pepOuterIP := getenv("PEP_OUTER_IP", getenv("PEP_DATA_IP", "172.21.0.40"))
	serviceIP := getenv("SERVICE_IP", "172.22.0.50")

	lifetime := 60
	expiresAt := time.Now().Add(time.Duration(lifetime) * time.Second).UTC().Format(time.RFC3339)

	session := protocol.Session{
		ClientPubKey:  req.ClientPubKey,
		ServiceID:     req.ServiceID,
		ReqID:         reqID,
		ClientInSPI:   req.ClientInSPI,
		PEPInSPI:      pepInSPI,
		ClientOuterIP: clientOuterIP,
		ClientInnerIP: clientInnerIP,
		PEPOuterIP:    pepOuterIP,
		ServiceIP:     serviceIP,
		ClientDHPub:   req.ClientDHPub,
		PEPDHPub:      pepDH.PublicB64,
		AEAD:          aead,
		C2PKey:        c2pKey,
		P2CKey:        p2cKey,
		ExpiresAt:     expiresAt,
	}

	session.XFRM, err = buildXFRMPlan(session)
	if err != nil {
		http.Error(w, "xfrm plan failed", http.StatusInternalServerError)
		return
	}
	if err := maybeApplyXFRM(session.XFRM); err != nil {
		log.Printf("xfrm apply failed: %v", err)
		http.Error(w, "xfrm apply failed", http.StatusInternalServerError)
		return
	}

	sessionsMu.Lock()
	sessions[pepInSPI] = session
	logutil.Debugf("pep", "stored session pep_in_spi=%s client_in_spi=%s reqid=%d client_inner_ip=%s sessions_count=%d", pepInSPI, req.ClientInSPI, reqID, clientInnerIP, len(sessions))
	sessionsMu.Unlock()

	resp := protocol.TunnelParams{
		ServiceID:     req.ServiceID,
		PEPAddress:    pepOuterIP,
		PEPPort:       4500,
		ClientInSPI:   req.ClientInSPI,
		PEPInSPI:      pepInSPI,
		ClientInnerIP: clientInnerIP,
		PEPDHPub:      pepDH.PublicB64,
		AEAD:          aead,
		SALifetime:    lifetime,
		ExpiresAt:     expiresAt,
	}

	logutil.Infof("pep", "activated service=%s client=%s pep_in_spi=%s client_in_spi=%s reqid=%d", req.ServiceID, logutil.Short(req.ClientPubKey), pepInSPI, req.ClientInSPI, reqID)
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

func initAllocators() {
	baseReqID, err := strconv.ParseUint(getenv("XFRM_REQID_BASE", "1000"), 10, 32)
	if err != nil || baseReqID == 0 {
		baseReqID = 1000
	}
	atomic.StoreUint32(&nextReqID, uint32(baseReqID-1))

	baseInnerHost, err := strconv.ParseUint(getenv("CLIENT_INNER_IP_START", "10"), 10, 32)
	if err != nil || baseInnerHost == 0 {
		baseInnerHost = 10
	}
	atomic.StoreUint32(&nextClientInnerID, uint32(baseInnerHost-1))
}

func allocateReqID() uint32 {
	return atomic.AddUint32(&nextReqID, 1)
}

func allocateClientInnerIP() string {
	prefix := getenv("CLIENT_INNER_IP_PREFIX", "10.200.0")
	host := atomic.AddUint32(&nextClientInnerID, 1)
	return fmt.Sprintf("%s.%d", prefix, host)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func getenv(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}
