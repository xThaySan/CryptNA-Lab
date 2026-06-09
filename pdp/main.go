package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"cryptna-lab/common/logutil"
	"cryptna-lab/common/noiseutil"
	"cryptna-lab/common/protocol"
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
	pipURL := getenv("PIP_URL", "")
	if pipURL == "" {
		log.Fatal("missing PIP_URL: PDP must know the PIP control endpoint")
	}
	pepControlURL := getenv("PEP_CONTROL_URL", "")
	if pepControlURL == "" {
		log.Fatal("missing PEP_CONTROL_URL: PDP must know the selected PEP control endpoint")
	}
	pepWANAddress := getenv("PEP_WAN_ADDRESS", "")
	if pepWANAddress == "" {
		log.Fatal("missing PEP_WAN_ADDRESS: PDP must provide the client-facing PEP endpoint")
	}
	pepNATTPort := getenvInt("PEP_NATT_PORT", 4500)
	identityPath := getenv("PDP_IDENTITY", "/app/identity.json")
	pdpID := mustLoadJSON[noiseutil.PDPIdentity](identityPath)
	replays := newReplayCache()

	logutil.Debugf("pdp", "debug enabled replay_ttl=%s spa_skew=%s", replayTTL, spaSkew)
	logutil.Infof("pdp", "selected PEP control_url=%s wan_endpoint=%s:%d", pepControlURL, pepWANAddress, pepNATTPort)

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
		go handleUDPPacket(conn, remote, packet, pipURL, pepControlURL, pepWANAddress, pepNATTPort, pdpID, replays)
	}
}

func startHealthServer() {
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok\n"))
	})
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleUDPPacket(conn *net.UDPConn, remote *net.UDPAddr, packet []byte, pipURL, pepControlURL, pepWANAddress string, pepNATTPort int, pdpID noiseutil.PDPIdentity, replays *replayCache) {
	now := time.Now().UTC()
	packetHash := noiseutil.PacketHash(packet)
	clientOuterIP := remote.IP.String()
	logutil.Debugf("pdp", "udp packet from=%s observed_client_outer_ip=%s size=%d hash=%s", remote.String(), clientOuterIP, len(packet), packetHash)

	if replays.Seen(packetHash, now) {
		logutil.Debugf("pdp", "drop replay hash=%s", packetHash)
		return
	}

	header, err := noiseutil.OpenIKpsk1SPAHeader(packet, pdpID, now, spaSkew)
	if err != nil {
		logutil.Debugf("pdp", "drop invalid SPA header from=%s err=%v", remote.String(), err)
		return
	}
	logutil.Debugf("pdp", "SPA header opened client=%s timestamp_ms=%d hash=%s", logutil.Short(header.ClientStaticPub), header.TimestampMS, header.PacketHash)

	logutil.Debugf("pdp", "query PIP client=%s", logutil.Short(header.ClientStaticPub))
	client, err := fetchClient(pipURL, header.ClientStaticPub)
	if err != nil || client.Revoked {
		logutil.Debugf("pdp", "drop unknown/revoked client=%s err=%v revoked=%v", logutil.Short(header.ClientStaticPub), err, client.Revoked)
		return
	}

	opened, err := noiseutil.CompleteIKpsk1SPA(header, client.PSK)
	if err != nil {
		logutil.Debugf("pdp", "drop invalid SPA payload client=%s err=%v", logutil.Short(header.ClientStaticPub), err)
		return
	}
	logutil.Debugf("pdp", "SPA opened client=%s timestamp_ms=%d payload_size=%d hash=%s", logutil.Short(opened.ClientStaticPub), opened.TimestampMS, len(opened.Payload), opened.PacketHash)
	replays.Add(opened.PacketHash, now)

	var payload protocol.AccessPayload
	if err := json.Unmarshal(opened.Payload, &payload); err != nil {
		return
	}
	logutil.Debugf("pdp", "access payload service=%s client_in_spi=%s client_dh_pub=%s aead=%v", payload.ServiceID, payload.ClientInSPI, logutil.Short(payload.ClientDHPub), payload.AEADSuites)

	if !contains(client.AllowedServices, payload.ServiceID) {
		logutil.Debugf("pdp", "drop unauthorized client=%s service=%s", logutil.Short(opened.ClientStaticPub), payload.ServiceID)
		return
	}

	logutil.Debugf("pdp", "activate PEP client=%s service=%s observed_client_outer_ip=%s", logutil.Short(opened.ClientStaticPub), payload.ServiceID, clientOuterIP)
	activation, err := activatePEP(pepControlURL, protocol.ActivateRequest{
		ClientPubKey:  opened.ClientStaticPub,
		ClientOuterIP: clientOuterIP,
		ServiceID:     payload.ServiceID,
		ClientInSPI:   payload.ClientInSPI,
		ClientDHPub:   payload.ClientDHPub,
		AEADSuites:    payload.AEADSuites,
	})
	if err != nil {
		log.Println("activate PEP:", err)
		return
	}

	tunnel := protocol.TunnelParams{
		ServiceID:     activation.ServiceID,
		ServiceIP:     activation.ServiceIP,
		PEPAddress:    pepWANAddress,
		PEPPort:       pepNATTPort,
		ClientInnerIP: activation.ClientInnerIP,
		ClientInSPI:   activation.ClientInSPI,
		PEPInSPI:      activation.PEPInSPI,
		PEPDHPub:      activation.PEPDHPub,
		AEAD:          activation.AEAD,
		SALifetime:    activation.SALifetime,
		ExpiresAt:     activation.ExpiresAt,
	}

	logutil.Debugf("pdp", "PEP activated pep_in_spi=%s pep_dh_pub=%s expires_at=%s client_endpoint=%s:%d", tunnel.PEPInSPI, logutil.Short(tunnel.PEPDHPub), tunnel.ExpiresAt, tunnel.PEPAddress, tunnel.PEPPort)

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

func activatePEP(pepURL string, req protocol.ActivateRequest) (protocol.PEPActivationResponse, error) {
	var out protocol.PEPActivationResponse
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

func getenvInt(k string, fallback int) int {
	v := getenv(k, "")
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
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
