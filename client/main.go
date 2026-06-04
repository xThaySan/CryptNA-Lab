package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"golang.org/x/crypto/curve25519"
)

type ClientConfig struct {
	PDPURL       string   `json:"pdp_url"`
	PDPStaticPub string   `json:"pdp_static_pub"`
	ServiceID    string   `json:"service_id"`
	AEADSuites   []string `json:"aead_suites"`
}

type ClientIdentity struct {
	ClientStaticPub  string `json:"client_static_pub"`
	ClientStaticPriv string `json:"client_static_priv"`
}

type AccessRequest struct {
	ClientPubKey string   `json:"client_pubkey"`
	ServiceID    string   `json:"service_id"`
	ClientSPI    string   `json:"client_spi"`
	ClientDHPub  string   `json:"client_dh_pub"`
	AEADSuites   []string `json:"aead_suites"`
}

type AccessResponse struct {
	Authorized bool           `json:"authorized"`
	Reason     string         `json:"reason"`
	Tunnel     TunnelResponse `json:"tunnel"`
}

type TunnelResponse struct {
	PEPDHPub          string `json:"pep_dh_pub"`
	DebugSharedSecret string `json:"debug_shared_secret"`
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "gen-identity" {
		genIdentity()
		return
	}

	cfg := mustLoadJSON[ClientConfig]("/app/config.json")
	id := mustLoadJSON[ClientIdentity]("/app/identity.json")

	ephPriv, ephPub := mustGenerateX25519()

	req := AccessRequest{
		ClientPubKey: id.ClientStaticPub,
		ServiceID:    cfg.ServiceID,
		ClientSPI:    "0x1001",
		ClientDHPub:  ephPub,
		AEADSuites:   cfg.AEADSuites,
	}

	_ = ephPriv // utilisé plus tard pour dériver la clé IPSec

	body, err := json.Marshal(req)
	if err != nil {
		log.Fatal(err)
	}

	resp, err := http.Post(cfg.PDPURL+"/access", "application/json", bytes.NewReader(body))
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	var out AccessResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		log.Fatal(err)
	}

	clientShared := mustDeriveSharedSecret(ephPriv, out.Tunnel.PEPDHPub)

	pretty, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(pretty))
	fmt.Println("client_shared_secret:", clientShared)
	fmt.Println("pep_shared_secret:   ", out.Tunnel.DebugSharedSecret)

	if clientShared == out.Tunnel.DebugSharedSecret {
		fmt.Println("DH OK: shared secrets match")
	} else {
		fmt.Println("DH ERROR: shared secrets differ")
	}
}

func genIdentity() {
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		log.Fatal(err)
	}

	// X25519 scalar clamping
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		log.Fatal(err)
	}

	id := ClientIdentity{
		ClientStaticPriv: base64.StdEncoding.EncodeToString(priv),
		ClientStaticPub:  base64.StdEncoding.EncodeToString(pub),
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

func mustGenerateX25519() (string, string) {
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		log.Fatal(err)
	}

	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		log.Fatal(err)
	}

	return base64.StdEncoding.EncodeToString(priv), base64.StdEncoding.EncodeToString(pub)
}

func mustDeriveSharedSecret(privB64, pubB64 string) string {
	priv, err := base64.StdEncoding.DecodeString(privB64)
	if err != nil {
		log.Fatal(err)
	}

	pub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil {
		log.Fatal(err)
	}

	shared, err := curve25519.X25519(priv, pub)
	if err != nil {
		log.Fatal(err)
	}

	return base64.StdEncoding.EncodeToString(shared)
}
