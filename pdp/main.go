package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
)

type AccessRequest struct {
	ClientPubKey string   `json:"client_pubkey"`
	ServiceID    string   `json:"service_id"`
	ClientSPI    string   `json:"client_spi"`
	ClientDHPub  string   `json:"client_dh_pub"`
	AEADSuites   []string `json:"aead_suites"`
}

type ClientInfo struct {
	ClientPubKey     string   `json:"client_pubkey"`
	PSK             string   `json:"psk"`
	AllowedServices []string `json:"allowed_services"`
	Revoked         bool     `json:"revoked"`
}

type AccessResponse struct {
	Authorized bool             `json:"authorized"`
	Reason     string           `json:"reason"`
	Tunnel     *ActivateResponse `json:"tunnel,omitempty"`
}

type ActivateResponse struct {
	ServiceID   string `json:"service_id"`
	PEPAddress string `json:"pep_address"`
	PEPPort    int    `json:"pep_port"`
	PEPSPI     string `json:"pep_spi"`
	PEPDHPub   string `json:"pep_dh_pub"`
	AEAD       string `json:"aead"`
	SALifetime int    `json:"sa_lifetime_seconds"`
	ExpiresAt  string `json:"expires_at"`
}

func main() {
	pipURL := getenv("PIP_URL", "http://cryptna-pip:8080")
	pepURL := getenv("PEP_URL", "http://cryptna-pep:8080")

	go startHealthServer()

	addr, err := net.ResolveUDPAddr("udp", ":4000")
	if err != nil {
		log.Fatal(err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	log.Println("PDP UDP SPA listener on :4000")

	buf := make([]byte, 4096)
	for {
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Println("udp read:", err)
			continue
		}

		packet := make([]byte, n)
		copy(packet, buf[:n])

		go handleUDPPacket(conn, remote, packet, pipURL, pepURL)
	}
}

func startHealthServer() {
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok\n"))
	})

	log.Println("PDP health server on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleUDPPacket(conn *net.UDPConn, remote *net.UDPAddr, packet []byte, pipURL, pepURL string) {
	var req AccessRequest
	if err := json.Unmarshal(packet, &req); err != nil {
		log.Println("drop: invalid json")
		return // silence on invalid SPA
	}

	log.Printf("UDP SPA from=%s client=%s service=%s", remote.String(), req.ClientPubKey, req.ServiceID)

	client, err := fetchClient(pipURL, req.ClientPubKey)
	if err != nil {
		log.Println("drop: unknown client or PIP error:", err)
		return // silence on unknown client
	}

	if client.Revoked {
		log.Println("drop: revoked client")
		return
	}

	if !contains(client.AllowedServices, req.ServiceID) {
		log.Println("drop: service not allowed")
		return
	}

	tunnel, err := activatePEP(pepURL, req)
	if err != nil {
		log.Println("activate PEP:", err)
		return
	}

	resp := AccessResponse{
		Authorized: true,
		Reason:     "authorized",
		Tunnel:     &tunnel,
	}

	out, err := json.Marshal(resp)
	if err != nil {
		log.Println("marshal response:", err)
		return
	}

	if _, err := conn.WriteToUDP(out, remote); err != nil {
		log.Println("udp write:", err)
	}
}

func fetchClient(pipURL, pubkey string) (ClientInfo, error) {
	var c ClientInfo
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

func activatePEP(pepURL string, req AccessRequest) (ActivateResponse, error) {
	var out ActivateResponse

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