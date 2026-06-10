package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	"cryptna-lab/common/cryptoutil"
	"cryptna-lab/common/ipsecutil"
	"cryptna-lab/common/logutil"
	"cryptna-lab/common/noiseutil"
	"cryptna-lab/common/protocol"
)

type benchmarkHandshakeResult struct {
	Response   protocol.AccessResponse
	PacketHash string
	Duration   time.Duration
}

func benchHandshake(args []string) {
	fs := flag.NewFlagSet("bench-handshake", flag.ExitOnError)
	n := fs.Int("n", 1000, "number of sequential handshakes")
	outPath := fs.String("out", "/tmp/handshake_latency.csv", "CSV output path")
	delayMS := fs.Int("delay-ms", 0, "delay between runs in milliseconds")
	if err := fs.Parse(args); err != nil {
		log.Fatal(err)
	}
	if *n <= 0 {
		log.Fatal("-n must be > 0")
	}

	cfg := mustLoadJSON[ClientConfig]("/app/config.json")
	id := mustLoadJSON[ClientIdentity]("/app/identity.json")

	f, err := os.Create(*outPath)
	if err != nil {
		log.Fatalf("create %s: %v", *outPath, err)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	if err := w.Write([]string{
		"run",
		"status",
		"duration_ms",
		"packet_hash",
		"client_inner_ip",
		"service_ip",
		"pep_in_spi",
		"client_in_spi",
		"error",
	}); err != nil {
		log.Fatal(err)
	}

	failures := 0
	for i := 1; i <= *n; i++ {
		res, err := benchmarkHandshakeOnce(cfg, id)

		status := "ok"
		errMsg := ""
		clientInnerIP := ""
		serviceIP := ""
		pepInSPI := ""
		clientInSPI := ""

		if err != nil {
			status = "error"
			errMsg = err.Error()
			failures++
		} else if !res.Response.Authorized || res.Response.Tunnel == nil {
			status = "denied"
			errMsg = res.Response.Reason
			failures++
		} else {
			clientInnerIP = res.Response.Tunnel.ClientInnerIP
			serviceIP = res.Response.Tunnel.ServiceIP
			pepInSPI = res.Response.Tunnel.PEPInSPI
			clientInSPI = res.Response.Tunnel.ClientInSPI
		}

		if err := w.Write([]string{
			strconv.Itoa(i),
			status,
			fmt.Sprintf("%.3f", float64(res.Duration.Microseconds())/1000.0),
			res.PacketHash,
			clientInnerIP,
			serviceIP,
			pepInSPI,
			clientInSPI,
			errMsg,
		}); err != nil {
			log.Fatal(err)
		}

		if *delayMS > 0 {
			time.Sleep(time.Duration(*delayMS) * time.Millisecond)
		}
	}

	if failures > 0 {
		log.Fatalf("benchmark finished with %d/%d failures; CSV written to %s", failures, *n, *outPath)
	}

	fmt.Printf("benchmark OK: runs=%d out=%s\n", *n, *outPath)
}

func benchmarkHandshakeOnce(cfg ClientConfig, id ClientIdentity) (benchmarkHandshakeResult, error) {
	start := time.Now()
	var result benchmarkHandshakeResult

	logutil.Debugf("client", "loaded config pdp_udp_addr=%s service_id=%s", cfg.PDPUDPAddr, cfg.ServiceID)
	logutil.Debugf("client", "loaded identity client_pub=%s", logutil.Short(id.ClientStaticPub))

	eph, err := cryptoutil.GenerateX25519KeyPair()
	if err != nil {
		result.Duration = time.Since(start)
		return result, err
	}

	clientInSPI, err := ipsecutil.GenerateSPI()
	if err != nil {
		result.Duration = time.Since(start)
		return result, err
	}

	payload := protocol.AccessPayload{
		ServiceID:   cfg.ServiceID,
		ClientInSPI: clientInSPI,
		ClientDHPub: eph.PublicB64,
		AEADSuites:  cfg.AEADSuites,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		result.Duration = time.Since(start)
		return result, err
	}

	spa, err := noiseutil.BuildIKpsk1SPA(id, cfg.PDPStaticPub, payloadBytes, time.Now().UTC())
	if err != nil {
		result.Duration = time.Since(start)
		return result, err
	}
	result.PacketHash = spa.PacketHash

	udpAddr, err := net.ResolveUDPAddr("udp", cfg.PDPUDPAddr)
	if err != nil {
		result.Duration = time.Since(start)
		return result, err
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		result.Duration = time.Since(start)
		return result, err
	}
	defer conn.Close()

	if _, err := conn.Write(spa.Packet); err != nil {
		result.Duration = time.Since(start)
		return result, err
	}
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		result.Duration = time.Since(start)
		return result, err
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		result.Duration = time.Since(start)
		return result, fmt.Errorf("no valid response from PDP: %w", err)
	}

	plainResp, err := noiseutil.DecryptResponse(spa.ResponseKey, buf[:n])
	if err != nil {
		result.Duration = time.Since(start)
		return result, fmt.Errorf("invalid encrypted PDP response: %w", err)
	}

	var out protocol.AccessResponse
	if err := json.Unmarshal(plainResp, &out); err != nil {
		result.Duration = time.Since(start)
		return result, err
	}
	result.Response = out

	if !out.Authorized || out.Tunnel == nil {
		result.Duration = time.Since(start)
		return result, nil
	}

	shared, err := cryptoutil.DeriveSharedSecretB64(eph.PrivateB64, out.Tunnel.PEPDHPub)
	if err != nil {
		result.Duration = time.Since(start)
		return result, err
	}
	c2p, p2c, err := cryptoutil.DeriveSessionKeys(shared)
	if err != nil {
		result.Duration = time.Since(start)
		return result, err
	}
	clientReqID, err := ipsecutil.GenerateReqID()
	if err != nil {
		result.Duration = time.Since(start)
		return result, err
	}
	xfrmPlan, err := buildClientXFRMPlan(*out.Tunnel, c2p, p2c, clientReqID)
	if err != nil {
		result.Duration = time.Since(start)
		return result, err
	}
	if err := maybeApplyClientXFRM(xfrmPlan); err != nil {
		result.Duration = time.Since(start)
		return result, fmt.Errorf("client xfrm apply failed: %w", err)
	}
	if err := scheduleClientXFRMCleanup(xfrmPlan, out.Tunnel.SALifetime); err != nil {
		result.Duration = time.Since(start)
		return result, fmt.Errorf("client xfrm cleanup scheduling failed: %w", err)
	}

	result.Duration = time.Since(start)
	return result, nil
}
