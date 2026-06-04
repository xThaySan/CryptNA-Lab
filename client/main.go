package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
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

	pretty, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(pretty))

	if !out.Authorized {
		os.Exit(1)
	}

	shared := mustDeriveSharedSecret(ephPriv, out.Tunnel.PEPDHPub)
	c2p, p2c := mustDeriveSessionKeys(shared)

	fmt.Println("derived client-side session keys")
	fmt.Println("c2p:", c2p)
	fmt.Println("p2c:", p2c)
}

func genIdentity() {
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

func mustDeriveSessionKeys(sharedB64 string) (string, string) {
	shared, err := base64.StdEncoding.DecodeString(sharedB64)
	if err != nil {
		log.Fatal(err)
	}

	reader := hkdf.New(
		sha256.New,
		shared,
		[]byte("CRYPTNA-LAB-v0"),
		[]byte("client-pep-session-keys"),
	)

	c2p := make([]byte, 32)
	p2c := make([]byte, 32)

	if _, err := io.ReadFull(reader, c2p); err != nil {
		log.Fatal(err)
	}
	if _, err := io.ReadFull(reader, p2c); err != nil {
		log.Fatal(err)
	}

	return base64.StdEncoding.EncodeToString(c2p), base64.StdEncoding.EncodeToString(p2c)
}