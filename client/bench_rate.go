package main

import (
	"crypto/rand"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"cryptna-lab/common/cryptoutil"
	"cryptna-lab/common/ipsecutil"
	"cryptna-lab/common/noiseutil"
	"cryptna-lab/common/protocol"
)

type rateRunResult struct {
	Run           int
	Scenario      string
	TargetRate    float64
	Status        string
	StartOffsetMS float64
	DurationMS    float64
	PacketHash    string
	ClientInnerIP string
	ServiceIP     string
	Error         string
}

func benchHandshakeRate(args []string) {
	fs := flag.NewFlagSet("bench-handshake-rate", flag.ExitOnError)

	n := fs.Int("n", 1000, "number of SPAs")
	rate := fs.Float64("rate-sps", 10, "target SPA rate per second")
	scenario := fs.String("scenario", "valid", "scenario: valid, wrong-psk, random")
	outPath := fs.String("out", "/tmp/handshake_rate.csv", "CSV output path")
	maxInflight := fs.Int("max-inflight", 256, "maximum concurrent handshakes")
	timeoutMS := fs.Int("timeout-ms", 100, "response timeout for drop scenarios")

	if err := fs.Parse(args); err != nil {
		log.Fatal(err)
	}

	if *n <= 0 {
		log.Fatal("-n must be > 0")
	}
	if *rate <= 0 {
		log.Fatal("-rate-sps must be > 0")
	}
	if *maxInflight <= 0 {
		log.Fatal("-max-inflight must be > 0")
	}

	sc := strings.ToLower(*scenario)
	switch sc {
	case "valid", "wrong-psk", "random":
	default:
		log.Fatalf("unsupported scenario %q", *scenario)
	}

	if strings.ToLower(os.Getenv("XFRM_MODE")) != "dry-run" {
		log.Fatal("bench-handshake-rate must be run with XFRM_MODE=dry-run")
	}

	cfg := mustLoadJSON[ClientConfig]("/app/config.json")
	id := mustLoadJSON[ClientIdentity]("/app/identity.json")

	interval := time.Duration(float64(time.Second) / *rate)
	benchStart := time.Now()

	results := make([]rateRunResult, *n)
	sem := make(chan struct{}, *maxInflight)
	var wg sync.WaitGroup

	for i := 1; i <= *n; i++ {
		runID := i
		scheduled := benchStart.Add(time.Duration(runID-1) * interval)

		if sleep := time.Until(scheduled); sleep > 0 {
			time.Sleep(sleep)
		}

		sem <- struct{}{}
		wg.Add(1)

		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			runStart := time.Now()

			r := rateRunResult{
				Run:           runID,
				Scenario:      sc,
				TargetRate:    *rate,
				Status:        "ok",
				StartOffsetMS: float64(runStart.Sub(benchStart).Microseconds()) / 1000.0,
			}

			switch sc {
			case "valid":
				res, err := benchmarkHandshakeOnce(cfg, id)
				r.DurationMS = float64(res.Duration.Microseconds()) / 1000.0
				r.PacketHash = res.PacketHash

				if err != nil {
					r.Status = "error"
					r.Error = err.Error()
				} else if !res.Response.Authorized || res.Response.Tunnel == nil {
					r.Status = "denied"
					r.Error = res.Response.Reason
				} else {
					r.ClientInnerIP = res.Response.Tunnel.ClientInnerIP
					r.ServiceIP = res.Response.Tunnel.ServiceIP
				}

			case "wrong-psk":
				res, err := benchmarkWrongPSKDropOnce(cfg, id, time.Duration(*timeoutMS)*time.Millisecond)
				r.DurationMS = float64(res.Duration.Microseconds()) / 1000.0
				r.PacketHash = res.PacketHash
				if err != nil {
					r.Status = "error"
					r.Error = err.Error()
				}

			case "random":
				res, err := benchmarkRandomDropOnce(cfg, time.Duration(*timeoutMS)*time.Millisecond)
				r.DurationMS = float64(res.Duration.Microseconds()) / 1000.0
				r.PacketHash = res.PacketHash
				if err != nil {
					r.Status = "error"
					r.Error = err.Error()
				}
			}

			results[runID-1] = r
		}()
	}

	wg.Wait()

	sort.Slice(results, func(i, j int) bool {
		return results[i].Run < results[j].Run
	})

	f, err := os.Create(*outPath)
	if err != nil {
		log.Fatalf("create %s: %v", *outPath, err)
	}
	defer f.Close()

	w := csv.NewWriter(f)

	if err := w.Write([]string{
		"run",
		"scenario",
		"target_rate_sps",
		"status",
		"start_offset_ms",
		"duration_ms",
		"packet_hash",
		"client_inner_ip",
		"service_ip",
		"error",
	}); err != nil {
		log.Fatal(err)
	}

	failures := 0

	for _, r := range results {
		if r.Status != "ok" {
			failures++
		}

		if err := w.Write([]string{
			strconv.Itoa(r.Run),
			r.Scenario,
			fmt.Sprintf("%.3f", r.TargetRate),
			r.Status,
			fmt.Sprintf("%.3f", r.StartOffsetMS),
			fmt.Sprintf("%.3f", r.DurationMS),
			r.PacketHash,
			r.ClientInnerIP,
			r.ServiceIP,
			r.Error,
		}); err != nil {
			log.Fatal(err)
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		log.Fatalf("flush open-loop benchmark CSV: %v", err)
	}

	if failures > 0 {
		log.Printf("open-loop rate benchmark finished with %d/%d failures; CSV written to %s", failures, *n, *outPath)
		os.Exit(1)
	}

	fmt.Printf(
		"open-loop rate benchmark OK: scenario=%s runs=%d target_rate_sps=%.3f max_inflight=%d out=%s\n",
		sc,
		*n,
		*rate,
		*maxInflight,
		*outPath,
	)
}

type dropBenchmarkResult struct {
	PacketHash string
	Duration   time.Duration
}

func benchmarkWrongPSKDropOnce(cfg ClientConfig, id ClientIdentity, timeout time.Duration) (dropBenchmarkResult, error) {
	start := time.Now()

	wrongPSK, err := noiseutil.GeneratePSK()
	if err != nil {
		return dropBenchmarkResult{Duration: time.Since(start)}, err
	}

	wrongID := id
	wrongID.SPAPSK = wrongPSK

	eph, err := cryptoutil.GenerateX25519KeyPair()
	if err != nil {
		return dropBenchmarkResult{Duration: time.Since(start)}, err
	}

	clientInSPI, err := ipsecutil.GenerateSPI()
	if err != nil {
		return dropBenchmarkResult{Duration: time.Since(start)}, err
	}

	payload := protocol.AccessPayload{
		ServiceID:   cfg.ServiceID,
		ClientInSPI: clientInSPI,
		ClientDHPub: eph.PublicB64,
		AEADSuites:  cfg.AEADSuites,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return dropBenchmarkResult{Duration: time.Since(start)}, err
	}

	spa, err := noiseutil.BuildIKpsk1SPA(wrongID, cfg.PDPStaticPub, payloadBytes, time.Now().UTC())
	if err != nil {
		return dropBenchmarkResult{Duration: time.Since(start)}, err
	}

	err = sendUDPExpectNoResponse(cfg.PDPUDPAddr, spa.Packet, timeout)

	return dropBenchmarkResult{
		PacketHash: spa.PacketHash,
		Duration:   time.Since(start),
	}, err
}

func benchmarkRandomDropOnce(cfg ClientConfig, timeout time.Duration) (dropBenchmarkResult, error) {
	start := time.Now()

	packet := make([]byte, 251)
	if _, err := rand.Read(packet); err != nil {
		return dropBenchmarkResult{Duration: time.Since(start)}, err
	}

	err := sendUDPExpectNoResponse(cfg.PDPUDPAddr, packet, timeout)

	return dropBenchmarkResult{
		PacketHash: noiseutil.PacketHash(packet),
		Duration:   time.Since(start),
	}, err
}

func sendUDPExpectNoResponse(addr string, packet []byte, timeout time.Duration) error {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	if _, err := conn.Write(packet); err != nil {
		return err
	}

	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return nil
		}
		return err
	}

	return fmt.Errorf("unexpected PDP response size=%d", n)
}
