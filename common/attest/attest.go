package attest

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"cryptna-lab/common/protocol"
)

var (
	ErrInvalidKey       = errors.New("invalid attestation key")
	ErrInvalidSignature = errors.New("invalid attestation signature")
	ErrExpiredToken     = errors.New("expired capacity token")
	ErrImmatureToken    = errors.New("capacity token not yet valid")
	ErrScopeDenied      = errors.New("capacity token scope denied")
	ErrLifetimeExceeded = errors.New("SA lifetime exceeds capacity token")
	ErrBindingMismatch  = errors.New("SA binding mismatch")
)

type Ed25519Identity struct {
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

func GenerateEd25519Identity() (Ed25519Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Ed25519Identity{}, err
	}
	return Ed25519Identity{
		PublicKey:  base64.StdEncoding.EncodeToString(pub),
		PrivateKey: base64.StdEncoding.EncodeToString(priv),
	}, nil
}

func SignCapacityToken(t protocol.CapacityToken, verifierPrivB64 string) (protocol.CapacityToken, error) {
	priv, err := decodePrivateKey(verifierPrivB64)
	if err != nil {
		return protocol.CapacityToken{}, err
	}
	t.Signature = ""
	b, err := CapacityTokenSigningBytes(t)
	if err != nil {
		return protocol.CapacityToken{}, err
	}
	t.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, b))
	return t, nil
}

func VerifyCapacityToken(t protocol.CapacityToken, verifierPubB64 string, now time.Time) error {
	if t.Version != 1 || t.TokenType != "cryptna-pep-capacity-v1" {
		return fmt.Errorf("unsupported capacity token version/type")
	}
	pub, err := decodePublicKey(verifierPubB64)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(t.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return ErrInvalidSignature
	}
	unsigned := t
	unsigned.Signature = ""
	b, err := CapacityTokenSigningBytes(unsigned)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, b, sig) {
		return ErrInvalidSignature
	}
	if t.IssuedAt != "" {
		iat, err := time.Parse(time.RFC3339, t.IssuedAt)
		if err != nil {
			return err
		}
		if now.Add(5 * time.Second).Before(iat) {
			return ErrImmatureToken
		}
	}
	exp, err := time.Parse(time.RFC3339, t.ExpiresAt)
	if err != nil {
		return err
	}
	if !now.Before(exp) {
		return ErrExpiredToken
	}
	return nil
}

func CapacityTokenSigningBytes(t protocol.CapacityToken) ([]byte, error) {
	t.Signature = ""
	if t.Scope == nil {
		t.Scope = []string{}
	} else {
		t.Scope = append([]string{}, t.Scope...)
	}
	sort.Strings(t.Scope)
	return json.Marshal(t)
}

func CapacityTokenHash(t protocol.CapacityToken) (string, error) {
	b, err := json.Marshal(t)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

func SignSABinding(b protocol.SABinding, pepPrivB64 string) (protocol.SABinding, error) {
	priv, err := decodePrivateKey(pepPrivB64)
	if err != nil {
		return protocol.SABinding{}, err
	}
	b.Signature = ""
	bs, err := SABindingSigningBytes(b)
	if err != nil {
		return protocol.SABinding{}, err
	}
	b.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, bs))
	return b, nil
}

func VerifySABinding(b protocol.SABinding, pepPubB64 string) error {
	pub, err := decodePublicKey(pepPubB64)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(b.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return ErrInvalidSignature
	}
	unsigned := b
	unsigned.Signature = ""
	bs, err := SABindingSigningBytes(unsigned)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, bs, sig) {
		return ErrInvalidSignature
	}
	return nil
}

func SABindingSigningBytes(b protocol.SABinding) ([]byte, error) {
	b.Signature = ""
	return json.Marshal(b)
}

func VerifyTunnelBinding(t protocol.TunnelParams, clientPubKey, clientDHPub, verifierPubB64 string, now time.Time) error {
	if t.CapacityToken == nil || t.SABinding == nil {
		return fmt.Errorf("missing attested PEP capacity or SA binding")
	}
	tok := *t.CapacityToken
	bind := *t.SABinding
	if err := VerifyCapacityToken(tok, verifierPubB64, now); err != nil {
		return err
	}
	if !ContainsScope(tok.Scope, t.ServiceID) {
		return ErrScopeDenied
	}
	if t.SALifetime > tok.MaxSALifetime {
		return ErrLifetimeExceeded
	}
	tokenExp, err := time.Parse(time.RFC3339, tok.ExpiresAt)
	if err != nil {
		return err
	}
	saExp, err := time.Parse(time.RFC3339, t.ExpiresAt)
	if err != nil {
		return err
	}
	if saExp.After(tokenExp) {
		return ErrLifetimeExceeded
	}
	tokHash, err := CapacityTokenHash(tok)
	if err != nil {
		return err
	}
	if bind.TokenHash != tokHash {
		return ErrBindingMismatch
	}
	if bind.Version != 1 {
		return fmt.Errorf("unsupported SA binding version")
	}
	if err := VerifySABinding(bind, tok.PEPSigningPubKey); err != nil {
		return err
	}
	expected := protocol.SABinding{
		Version:       bind.Version,
		TokenHash:     tokHash,
		PEPID:         tok.PEPID,
		ClientPubKey:  clientPubKey,
		ServiceID:     t.ServiceID,
		ServiceIP:     t.ServiceIP,
		ClientInnerIP: t.ClientInnerIP,
		ClientInSPI:   t.ClientInSPI,
		PEPInSPI:      t.PEPInSPI,
		ClientDHPub:   clientDHPub,
		PEPDHPub:      t.PEPDHPub,
		AEAD:          t.AEAD,
		SALifetime:    t.SALifetime,
		ExpiresAt:     t.ExpiresAt,
		Signature:     bind.Signature,
	}
	if bind != expected {
		return ErrBindingMismatch
	}
	return nil
}

func ContainsScope(scope []string, serviceID string) bool {
	for _, s := range scope {
		if s == serviceID || s == "*" {
			return true
		}
	}
	return false
}

func HashCanonical(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

func decodePublicKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, ErrInvalidKey
	}
	return ed25519.PublicKey(b), nil
}

func decodePrivateKey(s string) (ed25519.PrivateKey, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != ed25519.PrivateKeySize {
		return nil, ErrInvalidKey
	}
	return ed25519.PrivateKey(b), nil
}
