package main

import (
	"crypto/rand"
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
	mode := flag.String("mode", "send", "send | build | replay | random | corrupt | json")
	packetPath := flag.String("packet", "/tmp/spa.packet", "packet path")
	configPath := flag.String("config", "/app/config.json", "client config path")
	identityPath := flag.String("identity", "/app/identity.json", "client identity path")
	timeout := flag.Duration("timeout", 2*time.Second, "UDP read timeout")
	timestampOffset := flag.Duration("timestamp-offset", 0, "timestamp offset, e.g. -30s")
	serviceOverride := flag.String("service", "", "override service_id")
	pskOverride := flag.String("psk", "", "override SPA PSK base64")
	count := flag.Int("count", 1, "number of packets for random mode")
	randomSize := flag.Int("random-size", 128, "random packet size")
	waitResponse := flag.Bool("wait", true, "wait for UDP response")
	corruptPart := flag.String("corrupt-part", "random", "epub | ns | nm | random")
	corruptIndex := flag.Int("corrupt-index", -1, "byte index inside selected part, -1 means first byte")
	flag.Parse()

	cfg := mustLoadJSON[ClientConfig](*configPath)
	id := mustLoadJSON[ClientIdentity](*identityPath)

	if *serviceOverride != "" {
		cfg.ServiceID = *serviceOverride
	}
	if *pskOverride != "" {
		id.SPAPSK = *pskOverride
	}

	switch *mode {
	case "build":
		packet := buildPacket(cfg, id, *timestampOffset)
		writePacket(*packetPath, packet)

	case "send":
		packet := buildPacket(cfg, id, *timestampOffset)
		sendPacket(cfg.PDPUDPAddr, packet, *timeout, *waitResponse)

	case "replay":
		packet := readPacket(*packetPath)
		sendPacket(cfg.PDPUDPAddr, packet, *timeout, *waitResponse)

	case "random":
		for i := 0; i < *count; i++ {
			packet := randomPacket(*randomSize)
			sendPacket(cfg.PDPUDPAddr, packet, *timeout, *waitResponse)
		}

	case "corrupt":
		packet := readPacket(*packetPath)
		packet = corruptPacket(packet, *corruptPart, *corruptIndex)
		sendPacket(cfg.PDPUDPAddr, packet, *timeout, *waitResponse)

	case "json":
		packet := buildClearJSON(cfg, id)
		sendPacket(cfg.PDPUDPAddr, packet, *timeout, *waitResponse)

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

	fmt.Printf("packet_hash=%s timestamp_ms=%d size=%d offset=%s\n",
		spa.PacketHash, spa.TimestampMS, len(spa.Packet), offset)

	return spa.Packet
}

func buildClearJSON(cfg ClientConfig, id ClientIdentity) []byte {
	eph, err := cryptoutil.GenerateX25519KeyPair()
	if err != nil {
		log.Fatal(err)
	}

	req := map[string]any{
		"client_pubkey": id.ClientStaticPub,
		"service_id":   cfg.ServiceID,
		"client_spi":   "0x1001",
		"client_dh_pub": eph.PublicB64,
		"aead_suites":  cfg.AEADSuites,
	}

	out, err := json.Marshal(req)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("clear_json size=%d\n", len(out))
	return out
}

func corruptPacket(packet []byte, part string, index int) []byte {
	if len(packet) == 0 {
		log.Fatal("empty packet")
	}

	out := make([]byte, len(packet))
	copy(out, packet)

	start, end := 0, len(out)

	switch part {
	case "epub":
		start, end = 0, min(32, len(out))
	case "ns":
		start, end = 32, min(88, len(out)) // epub=32, ns=56
	case "nm":
		start, end = min(88, len(out)), len(out)
	case "random":
		start, end = 0, len(out)
	default:
		log.Fatalf("invalid corrupt-part: %s", part)
	}

	if start >= end {
		log.Fatalf("cannot corrupt part=%s on packet size=%d", part, len(out))
	}

	pos := start
	if index >= 0 {
		pos = start + index
		if pos >= end {
			log.Fatalf("corrupt-index out of range for part=%s", part)
		}
	}

	out[pos] ^= 0x01
	fmt.Printf("corrupted part=%s byte=%d size=%d\n", part, pos, len(out))
	return out
}

func randomPacket(size int) []byte {
	if size < 0 {
		log.Fatal("random-size must be >= 0")
	}

	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("random_packet size=%d\n", size)
	return buf
}

func sendPacket(addr string, packet []byte, timeout time.Duration, wait bool) {
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

	if !wait {
		fmt.Println("sent without waiting")
		return
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

func writePacket(path string, packet []byte) {
	if err := os.WriteFile(path, packet, 0600); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("built packet path=%s size=%d b64=%s\n",
		path, len(packet), base64.StdEncoding.EncodeToString(packet))
}

func readPacket(path string) []byte {
	packet, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	return packet
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
