package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"cryptna-lab/common/cryptoutil"
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
	mode := flag.String("mode", "send", "send | build | replay")
	packetPath := flag.String("packet", "/tmp/spa.packet", "packet path")
	configPath := flag.String("config", "/app/config.json", "client config path")
	identityPath := flag.String("identity", "/app/identity.json", "client identity path")
	timeout := flag.Duration("timeout", 2*time.Second, "UDP read timeout")
	timestampOffset := flag.Duration("timestamp-offset", 0, "timestamp offset, e.g. -30s")
	flag.Parse()

	cfg := mustLoadJSON[ClientConfig](*configPath)
	id := mustLoadJSON[ClientIdentity](*identityPath)

	switch *mode {
	case "build":
		packet := buildPacket(cfg, id, *timestampOffset)
		if err := os.WriteFile(*packetPath, packet, 0600); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("built packet path=%s size=%d b64=%s\n",
			*packetPath, len(packet), base64.StdEncoding.EncodeToString(packet))

	case "send":
		packet := buildPacket(cfg, id, *timestampOffset)
		sendPacket(cfg.PDPUDPAddr, packet, *timeout)

	case "replay":
		packet, err := os.ReadFile(*packetPath)
		if err != nil {
			log.Fatal(err)
		}
		sendPacket(cfg.PDPUDPAddr, packet, *timeout)

	default:
		log.Fatalf("unknown mode: %s", *mode)
	}
}

func buildPacket(cfg ClientConfig, id ClientIdentity, offset time.Duration) []byte {
	eph, err := cryptoutil.GenerateX25519KeyPair()
	if err != nil {
		log.Fatal(err)
	}

	payload := protocol.AccessPayload{
		ServiceID:   cfg.ServiceID,
		ClientSPI:   "0x1001",
		ClientDHPub: eph.PublicB64,
		AEADSuites:  cfg.AEADSuites,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		log.Fatal(err)
	}

	spaTime := time.Now().UTC().Add(offset)
	spa, err := noiseutil.BuildIKpsk1SPA(id, cfg.PDPStaticPub, payloadBytes, spaTime)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("packet_hash=%s timestamp_ms=%d size=%d\n",
		spa.PacketHash, spa.TimestampMS, len(spa.Packet))

	return spa.Packet
}

func sendPacket(addr string, packet []byte, timeout time.Duration) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Fatal(err)
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	if _, err := conn.Write(packet); err != nil {
		log.Fatal(err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		log.Fatal(err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Printf("timeout/no-response err=%v\n", err)
		return
	}

	fmt.Printf("response size=%d b64=%s\n", n, base64.StdEncoding.EncodeToString(buf[:n]))
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
