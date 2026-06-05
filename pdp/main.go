package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"cryptna-lab/common/noiseutil"
	"cryptna-lab/common/protocol"
	"cryptna-lab/common/logutil"
)

const (
	spaListenAddr = ":4000"
	replayTTL     = 10 * time.Second
	spaSkew       = 10 * time.Second
)

type replayCache struct {
	mu    sync.Mutex
	items map[string]time.Time
}

func newReplayCache() *replayCache {
	return &replayCache{items: map[string]time.Time{}}
}

func (c *replayCache) Seen(hash string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, exp := range c.items {
		if now.After(exp) {
			delete(c.items, k)
		}
	}
	_, ok := c.items[hash]
	return ok
}

func (c *replayCache) Add(hash string, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[hash] = now.Add(replayTTL)
}

func main() {
	pipURL := getenv("PIP_URL", "http://cryptna-pip:8080")
	pepURL := getenv("PEP_URL", "http://cryptna-pep:8080")
	identityPath := getenv("PDP_IDENTITY", "/app/identity.json")
	pdpID := mustLoadJSON[noiseutil.PDPIdentity](identityPath)
	replays := newReplayCache()

	logutil.Debugf("pdp", "debug enabled replay_ttl=%s spa_skew=%s", replayTTL, spaSkew)

	go startHealthServer()

	addr, err := net.ResolveUDPAddr("udp", spaListenAddr)
	if err != nil {
		log.Fatal(err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	logutil.Infof("pdp", "UDP Noise SPA listener on %s", spaListenAddr)

	buf := make([]byte, 2048)
	for {
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Println("udp read:", err)
			continue
		}
		packet := make([]byte, n)
		copy(packet, buf[:n])
		go handleUDPPacket(conn, remote, packet, pipURL, pepURL, pdpID, replays)
	}
}

func startHealthServer() {
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok\n"))
	})
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleUDPPacket(conn *net.UDPConn, remote *net.UDPAddr, packet []byte, pipURL, pepURL string, pdpID noiseutil.PDPIdentity, replays *replayCache) {
	now := time.Now().UTC()
	packetHash := noiseutil.PacketHash(packet)
	logutil.Debugf("pdp", "udp packet from=%s size=%d hash=%s", remote.String(), len(packet), packetHash)
	
	if replays.Seen(packetHash, now) {
		logutil.Debugf("pdp", "drop replay hash=%s", packetHash)
		return
	}

	opened, err := noiseutil.OpenIKpsk1SPA(packet, pdpID, now, spaSkew)
	if err != nil {
		logutil.Debugf("pdp", "drop invalid SPA from=%s err=%v", remote.String(), err)
		return
	}
	logutil.Debugf("pdp", "SPA opened client=%s timestamp_ms=%d payload_size=%d hash=%s", logutil.Short(opened.ClientStaticPub), opened.TimestampMS, len(opened.Payload), opened.PacketHash)
	replays.Add(opened.PacketHash, now)

	var payload protocol.AccessPayload
	if err := json.Unmarshal(opened.Payload, &payload); err != nil {
		return
	}
	logutil.Debugf("pdp", "access payload service=%s client_spi=%s client_dh_pub=%s aead=%v", payload.ServiceID, payload.ClientSPI, logutil.Short(payload.ClientDHPub), payload.AEADSuites)

	logutil.Debugf("pdp", "query PIP client=%s", logutil.Short(opened.ClientStaticPub))
	client, err := fetchClient(pipURL, opened.ClientStaticPub)
	if err != nil || client.Revoked || !contains(client.AllowedServices, payload.ServiceID) {
		logutil.Debugf("pdp", "drop unauthorized client=%s service=%s err=%v revoked=%v", logutil.Short(opened.ClientStaticPub), payload.ServiceID, err, client.Revoked)
		return
	}

	logutil.Debugf("pdp", "activate PEP client=%s service=%s", logutil.Short(opened.ClientStaticPub), payload.ServiceID)
	tunnel, err := activatePEP(pepURL, protocol.ActivateRequest{
		ClientPubKey: opened.ClientStaticPub,
		ServiceID:    payload.ServiceID,
		ClientSPI:    payload.ClientSPI,
		ClientDHPub:  payload.ClientDHPub,
		AEADSuites:   payload.AEADSuites,
	})
	if err != nil {
		log.Println("activate PEP:", err)
		return
	}
	logutil.Debugf("pdp", "PEP activated pep_spi=%s pep_dh_pub=%s expires_at=%s", tunnel.PEPSPI, logutil.Short(tunnel.PEPDHPub), tunnel.ExpiresAt)

	resp := protocol.AccessResponse{
		Authorized: true,
		Reason:     "authorized",
		Tunnel:     &tunnel,
	}
	plainResp, err := json.Marshal(resp)
	if err != nil {
		log.Println("marshal response:", err)
		return
	}

	cipherResp, err := noiseutil.EncryptResponse(opened.ResponseKey, plainResp)
	if err != nil {
		log.Println("encrypt response:", err)
		return
	}

	logutil.Debugf("pdp", "sending encrypted response to=%s size=%d", remote.String(), len(cipherResp))
	if _, err := conn.WriteToUDP(cipherResp, remote); err != nil {
		log.Println("udp write:", err)
	}
}

func fetchClient(pipURL, pubkey string) (protocol.ClientInfo, error) {
	var c protocol.ClientInfo
	resp, err := http.Get(pipURL + "/clients/" + pubkey)
	if err != nil {
		return c, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return c, http.ErrNoLocation
	}
	err = json.NewDecoder(resp.Body).Decode(&c)
	return c, err
}

func activatePEP(pepURL string, req protocol.ActivateRequest) (protocol.TunnelParams, error) {
	var out protocol.TunnelParams
	body, err := json.Marshal(req)
	if err != nil {
		return out, err
	}
	resp, err := http.Post(pepURL+"/activate", "application/json", bytes.NewReader(body))
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, http.ErrNoLocation
	}
	err = json.NewDecoder(resp.Body).Decode(&out)
	return out, err
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func getenv(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
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
