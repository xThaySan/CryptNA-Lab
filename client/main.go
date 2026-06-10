package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"cryptna-lab/common/cryptoutil"
	"cryptna-lab/common/ipsecutil"
	"cryptna-lab/common/logutil"
	"cryptna-lab/common/noiseutil"
	"cryptna-lab/common/protocol"
)

type ClientConfig struct {
	PDPUDPAddr   string   `json:"pdp_udp_addr"`
	PDPStaticPub string   `json:"pdp_static_pub"`
	ServiceID    string   `json:"service_id"`
	AEADSuites   []string `json:"aead_suites"`
}

type ClientIdentity = noiseutil.ClientIdentity

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "gen-identity":
			genIdentity()
			return
		case "bench-handshake":
			benchHandshake(os.Args[2:])
			return
		case "bench-handshake-rate":
			benchHandshakeRate(os.Args[2:])
			return
		}
	}

	cfg := mustLoadJSON[ClientConfig]("/app/config.json")
	id := mustLoadJSON[ClientIdentity]("/app/identity.json")

	logutil.Debugf("client", "loaded config pdp_udp_addr=%s service_id=%s", cfg.PDPUDPAddr, cfg.ServiceID)
	logutil.Debugf("client", "loaded identity client_pub=%s", logutil.Short(id.ClientStaticPub))

	eph, err := cryptoutil.GenerateX25519KeyPair()
	if err != nil {
		log.Fatal(err)
	}
	logutil.Debugf("client", "generated ephemeral dh pub=%s", logutil.Short(eph.PublicB64))

	clientInSPI, err := ipsecutil.GenerateSPI()
	if err != nil {
		log.Fatal(err)
	}
	logutil.Debugf("client", "generated client_in_spi=%s", clientInSPI)

	payload := protocol.AccessPayload{
		ServiceID:   cfg.ServiceID,
		ClientInSPI: clientInSPI,
		ClientDHPub: eph.PublicB64,
		AEADSuites:  cfg.AEADSuites,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		log.Fatal(err)
	}

	spa, err := noiseutil.BuildIKpsk1SPA(id, cfg.PDPStaticPub, payloadBytes, time.Now().UTC())
	if err != nil {
		log.Fatal(err)
	}
	logutil.Debugf("client", "built SPA packet size=%d hash=%s timestamp_ms=%d", len(spa.Packet), spa.PacketHash, spa.TimestampMS)

	logutil.Debugf("client", "sending SPA to %s", cfg.PDPUDPAddr)
	udpAddr, err := net.ResolveUDPAddr("udp", cfg.PDPUDPAddr)
	if err != nil {
		log.Fatal(err)
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	if _, err := conn.Write(spa.Packet); err != nil {
		log.Fatal(err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		log.Fatal(err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		log.Fatalf("no valid response from PDP: %v", err)
	}
	logutil.Debugf("client", "received encrypted response size=%d", n)

	plainResp, err := noiseutil.DecryptResponse(spa.ResponseKey, buf[:n])
	if err != nil {
		log.Fatalf("invalid encrypted PDP response: %v", err)
	}
	logutil.Debugf("client", "decrypted PDP response size=%d", len(plainResp))

	var out protocol.AccessResponse
	if err := json.Unmarshal(plainResp, &out); err != nil {
		log.Fatal(err)
	}

	pretty, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(pretty))
	fmt.Println("spa_packet_hash:", spa.PacketHash)

	if !out.Authorized || out.Tunnel == nil {
		os.Exit(1)
	}

	shared, err := cryptoutil.DeriveSharedSecretB64(eph.PrivateB64, out.Tunnel.PEPDHPub)
	if err != nil {
		log.Fatal(err)
	}
	c2p, p2c, err := cryptoutil.DeriveSessionKeys(shared)
	if err != nil {
		log.Fatal(err)
	}
	logutil.Debugf("client", "derived session keys c2p=%s p2c=%s", logutil.Short(c2p), logutil.Short(p2c))
	logutil.Debugf("client", "tunnel params service_ip=%s client_inner_ip=%s client_in_spi=%s pep_in_spi=%s", out.Tunnel.ServiceIP, out.Tunnel.ClientInnerIP, out.Tunnel.ClientInSPI, out.Tunnel.PEPInSPI)

	clientReqID, err := ipsecutil.GenerateReqID()
	if err != nil {
		log.Fatal(err)
	}
	logutil.Debugf("client", "generated local xfrm reqid=%d", clientReqID)
	xfrmPlan, err := buildClientXFRMPlan(*out.Tunnel, c2p, p2c, clientReqID)
	if err != nil {
		log.Fatal(err)
	}
	if err := maybeApplyClientXFRM(xfrmPlan); err != nil {
		log.Fatalf("client xfrm apply failed: %v", err)
	}
	if err := scheduleClientXFRMCleanup(xfrmPlan, out.Tunnel.SALifetime); err != nil {
		log.Fatalf("client xfrm cleanup scheduling failed: %v", err)
	}
}

func genIdentity() {
	priv, pub, err := noiseutil.GenerateStaticKeypair()
	if err != nil {
		log.Fatal(err)
	}
	psk, err := noiseutil.GeneratePSK()
	if err != nil {
		log.Fatal(err)
	}

	id := ClientIdentity{
		ClientStaticPriv: priv,
		ClientStaticPub:  pub,
		SPAPSK:           psk,
	}

	out, _ := json.MarshalIndent(id, "", "  ")
	fmt.Println(string(out))
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
