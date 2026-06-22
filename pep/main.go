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
	"cryptna-lab/common/nattutil"
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
	initAttestation()
	go sessionReaper()

	if err := setupPEPFirewall(); err != nil {
		log.Fatalf("setup PEP firewall: %v", err)
	}

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok\n"))
	})

	http.HandleFunc("/activate", activateHandler)
	http.HandleFunc("/sessions", sessionsHandler)

	nattSocket, err := nattutil.ListenESPInUDP(4500)
	if err != nil {
		log.Fatalf("start NAT-T UDP/4500 socket: %v", err)
	}
	defer nattSocket.Close()
	logutil.Infof("pep", "NAT-T ESP-in-UDP socket listening on :4500")

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
	logutil.Debugf("pep", "activation request client=%s service=%s client_outer_ip=%s client_in_spi=%s client_dh_pub=%s aead=%v", logutil.Short(req.ClientPubKey), req.ServiceID, req.ClientOuterIP, req.ClientInSPI, logutil.Short(req.ClientDHPub), req.AEADSuites)
	if req.ClientOuterIP == "" {
		logutil.Debugf("pep", "reject activation: missing client_outer_ip client=%s service=%s", logutil.Short(req.ClientPubKey), req.ServiceID)
		http.Error(w, "missing client_outer_ip", http.StatusBadRequest)
		return
	}
	if req.ClientInSPI == "" {
		logutil.Debugf("pep", "reject activation: missing client_in_spi client=%s service=%s", logutil.Short(req.ClientPubKey), req.ServiceID)
		http.Error(w, "missing client_in_spi", http.StatusBadRequest)
		return
	}
	if req.ClientDHPub == "" {
		logutil.Debugf("pep", "reject activation: missing client_dh_pub client=%s service=%s", logutil.Short(req.ClientPubKey), req.ServiceID)
		http.Error(w, "missing client_dh_pub", http.StatusBadRequest)
		return
	}

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
	clientOuterIP := req.ClientOuterIP
	pepOuterIP := getenv("PEP_LOCAL_ENDPOINT_IP", "")
	if pepOuterIP == "" {
		http.Error(w, "missing PEP_LOCAL_ENDPOINT_IP", http.StatusInternalServerError)
		return
	}
	serviceIP := getenv("SERVICE_IP", "172.22.0.50")
	nattPort := getenvInt("NATT_PORT", 4500)

	lifetime := getenvInt("SA_LIFETIME_SECONDS", 60)
	var capacityToken *protocol.CapacityToken
	if pepAttestation != nil && pepAttestation.enabled {
		tok, err := pepAttestation.ensureCapacityToken()
		if err != nil {
			log.Printf("capacity token unavailable: %v", err)
			http.Error(w, "capacity token unavailable", http.StatusServiceUnavailable)
			return
		}
		lifetime, err = pepAttestation.boundLifetime(lifetime, tok)
		if err != nil {
			log.Printf("capacity token lifetime invalid: %v", err)
			http.Error(w, "capacity token lifetime invalid", http.StatusServiceUnavailable)
			return
		}
		capacityToken = &tok
	}
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
		NATTPort:      nattPort,
		ClientDHPub:   req.ClientDHPub,
		PEPDHPub:      pepDH.PublicB64,
		AEAD:          aead,
		C2PKey:        c2pKey,
		P2CKey:        p2cKey,
		ExpiresAt:     expiresAt,
	}

	resp := protocol.PEPActivationResponse{
		ServiceID:     req.ServiceID,
		ServiceIP:     serviceIP,
		ClientInSPI:   req.ClientInSPI,
		PEPInSPI:      pepInSPI,
		ClientInnerIP: clientInnerIP,
		PEPDHPub:      pepDH.PublicB64,
		AEAD:          aead,
		SALifetime:    lifetime,
		ExpiresAt:     expiresAt,
	}
	if capacityToken != nil {
		binding, err := pepAttestation.signSABinding(req, session, resp, *capacityToken)
		if err != nil {
			log.Printf("SA binding signature failed: %v", err)
			http.Error(w, "SA binding signature failed", http.StatusInternalServerError)
			return
		}
		resp.CapacityToken = capacityToken
		resp.SABinding = &binding
	}

	session.XFRM, err = buildXFRMPlan(session)
	if err != nil {
		http.Error(w, "xfrm plan failed", http.StatusInternalServerError)
		return
	}
	historyTransactionMu.Lock()
	historyAppend(eventXFRMApplyIntent, &session, map[string]string{
		"xfrm_mode":      getenv("XFRM_MODE", "dry-run"),
		"xfrm_plan_hash": xfrmPlanHash(session.XFRM),
	})
	if err := maybeApplyXFRM(session.XFRM); err != nil {
		historyTransactionMu.Unlock()
		log.Printf("xfrm apply failed: %v", err)
		http.Error(w, "xfrm apply failed", http.StatusInternalServerError)
		return
	}
	historyAppend(eventXFRMApplyObserved, &session, observeXFRMApplied(session))

	sessionsMu.Lock()
	sessions[pepInSPI] = session
	logutil.Debugf("pep", "stored session pep_in_spi=%s client_in_spi=%s reqid=%d client_inner_ip=%s sessions_count=%d", pepInSPI, req.ClientInSPI, reqID, clientInnerIP, len(sessions))
	sessionsMu.Unlock()
	historyAppend(eventSessionActivated, &session, map[string]string{
		"attested": fmt.Sprintf("%t", resp.CapacityToken != nil),
	})
	historyTransactionMu.Unlock()

	logutil.Infof("pep", "activated service=%s client=%s pep_in_spi=%s client_in_spi=%s reqid=%d attested=%v", req.ServiceID, logutil.Short(req.ClientPubKey), pepInSPI, req.ClientInSPI, reqID, resp.CapacityToken != nil)
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

func sessionReaper() {
	interval := time.Duration(getenvInt("SESSION_REAPER_INTERVAL_SECONDS", 5)) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	logutil.Infof("pep", "session reaper started interval=%s", interval)

	for range ticker.C {
		cleanupExpiredSessions(time.Now().UTC())
	}
}

func cleanupExpiredSessions(now time.Time) {
	historyTransactionMu.Lock()
	defer historyTransactionMu.Unlock()
	cleanupExpiredSessionsUnderHistoryLock(now)
}

// cleanupExpiredSessionsUnderHistoryLock removes expired sessions and records the
// full expiration/delete observation sequence. The caller must hold
// historyTransactionMu. This is also used immediately before capacity renewal so a
// checkpoint cannot be accepted while an expired XFRM state is still pending
// deletion in the local session table.
func cleanupExpiredSessionsUnderHistoryLock(now time.Time) {
	expired := make([]protocol.Session, 0)

	sessionsMu.Lock()
	for key, session := range sessions {
		expiresAt, err := time.Parse(time.RFC3339, session.ExpiresAt)
		if err != nil {
			logutil.Debugf("pep", "invalid session expiry pep_in_spi=%s expires_at=%s err=%v", session.PEPInSPI, session.ExpiresAt, err)
			continue
		}

		if now.Before(expiresAt) {
			continue
		}

		delete(sessions, key)
		expired = append(expired, session)
	}
	sessionsMu.Unlock()

	for _, session := range expired {
		logutil.Infof("pep", "session expired, deleting XFRM client=%s service=%s pep_in_spi=%s client_in_spi=%s reqid=%d",
			logutil.Short(session.ClientPubKey),
			session.ServiceID,
			session.PEPInSPI,
			session.ClientInSPI,
			session.ReqID,
		)

		historyAppend(eventSessionExpired, &session, map[string]string{
			"expires_at": session.ExpiresAt,
		})
		historyAppend(eventXFRMDeleteIntent, &session, map[string]string{
			"xfrm_mode":      getenv("XFRM_MODE", "dry-run"),
			"xfrm_plan_hash": xfrmPlanHash(session.XFRM),
		})
		if err := maybeDeleteXFRM(session.XFRM); err != nil {
			log.Printf("xfrm delete failed: %v", err)
		}
		historyAppend(eventXFRMDeleteObserved, &session, observeXFRMDeleted(session))
	}
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

func getenvInt(k string, fallback int) int {
	v := os.Getenv(k)
	if v == "" {
		return fallback
	}
	out, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return out
}
