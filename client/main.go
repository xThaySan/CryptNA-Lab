package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
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

func main() {
	pdpURL := getenv("PDP_URL", "http://cryptna-pdp:8080")

	req := AccessRequest{
		ClientPubKey: "client-static-pubkey-demo",
		ServiceID:    "svc-http",
		ClientSPI:    "0x1001",
		ClientDHPub:  "fake-client-dh",
		AEADSuites:   []string{"aes-gcm-128"},
	}

	body, err := json.Marshal(req)
	if err != nil {
		log.Fatal(err)
	}

	resp, err := http.Post(pdpURL+"/access", "application/json", bytes.NewReader(body))
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	var out any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		log.Fatal(err)
	}

	pretty, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(pretty))
}

func getenv(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}
