package cryptoutil

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

type KeyPair struct {
	PrivateB64 string `json:"private"`
	PublicB64  string `json:"public"`
}

func GenerateX25519KeyPair() (KeyPair, error) {
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		return KeyPair{}, err
	}
	ClampX25519Private(priv)

	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return KeyPair{}, err
	}

	return KeyPair{
		PrivateB64: base64.StdEncoding.EncodeToString(priv),
		PublicB64:  base64.StdEncoding.EncodeToString(pub),
	}, nil
}

func ClampX25519Private(priv []byte) {
	if len(priv) != 32 {
		return
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
}

func MustDecodeB64(s string, expectedLen int) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if expectedLen > 0 && len(b) != expectedLen {
		return nil, fmt.Errorf("invalid decoded length: got %d want %d", len(b), expectedLen)
	}
	return b, nil
}

func DeriveSharedSecretB64(privB64, pubB64 string) (string, error) {
	priv, err := MustDecodeB64(privB64, 32)
	if err != nil {
		return "", err
	}
	pub, err := MustDecodeB64(pubB64, 32)
	if err != nil {
		return "", err
	}

	shared, err := curve25519.X25519(priv, pub)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(shared), nil
}

func DeriveSessionKeys(sharedB64 string) (c2pB64, p2cB64 string, err error) {
	shared, err := MustDecodeB64(sharedB64, 32)
	if err != nil {
		return "", "", err
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
		return "", "", err
	}
	if _, err := io.ReadFull(reader, p2c); err != nil {
		return "", "", err
	}

	return base64.StdEncoding.EncodeToString(c2p), base64.StdEncoding.EncodeToString(p2c), nil
}
