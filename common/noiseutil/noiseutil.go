package noiseutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/curve25519"
)

const (
	ProtocolName = "Noise_IKpsk1_25519_AESGCM_SHA256"
	// CRYPTNA keeps the IKpsk1 token order e, es, s, ss, psk.
	// The encrypted s slot carries timestamp_ms || client_static_pub instead of only s.
	NSTimestampLen = 8
	NSClientPubLen = 32
	NSPlainLen     = NSTimestampLen + NSClientPubLen
	NSTagLen       = 16
	NSCipherLen    = NSPlainLen + NSTagLen
	EPublicLen     = 32
	MaxSPAPacket   = 1200
)

var (
	ErrInvalidPacket = errors.New("invalid SPA packet")
	ErrInvalidTime   = errors.New("invalid SPA timestamp")
	ErrInvalidKey    = errors.New("invalid key")
	ErrDecryptFailed = errors.New("SPA decrypt failed")
)

type ClientIdentity struct {
	ClientStaticPub  string `json:"client_static_pub"`
	ClientStaticPriv string `json:"client_static_priv"`
	SPAPSK           string `json:"spa_psk"`
}

type PDPIdentity struct {
	PDPStaticPub  string `json:"pdp_static_pub"`
	PDPStaticPriv string `json:"pdp_static_priv"`
	SPAPSK        string `json:"spa_psk"`
}

type BuildResult struct {
	Packet      []byte
	PacketHash  string
	ResponseKey []byte
	TimestampMS int64
}

type OpenResult struct {
	ClientStaticPub string
	TimestampMS     int64
	Payload         []byte
	PacketHash      string
	ResponseKey     []byte
}

type OpenHeaderResult struct {
	ClientStaticPub string
	TimestampMS     int64
	PacketHash      string

	pdpStaticPriv      []byte
	clientStaticPubRaw []byte
	nmCipher           []byte
	ss                 *symmetricState
}

type symmetricState struct {
	ck []byte
	h  []byte
	k  []byte
	n  uint64
}

func GenerateStaticKeypair() (privB64, pubB64 string, err error) {
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		return "", "", err
	}
	clamp(priv)
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(priv), base64.StdEncoding.EncodeToString(pub), nil
}

func GeneratePSK() (string, error) {
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(psk), nil
}

func BuildIKpsk1SPA(client ClientIdentity, pdpStaticPubB64 string, payload []byte, now time.Time) (BuildResult, error) {
	clientStaticPriv, err := decodeB64(client.ClientStaticPriv, 32)
	if err != nil {
		return BuildResult{}, err
	}
	clientStaticPub, err := decodeB64(client.ClientStaticPub, 32)
	if err != nil {
		return BuildResult{}, err
	}
	pdpStaticPub, err := decodeB64(pdpStaticPubB64, 32)
	if err != nil {
		return BuildResult{}, err
	}
	psk, err := decodeB64(client.SPAPSK, 32)
	if err != nil {
		return BuildResult{}, err
	}

	ePriv := make([]byte, 32)
	if _, err := rand.Read(ePriv); err != nil {
		return BuildResult{}, err
	}
	clamp(ePriv)
	ePub, err := curve25519.X25519(ePriv, curve25519.Basepoint)
	if err != nil {
		return BuildResult{}, err
	}

	ss := newSymmetricState()
	ss.mixHash(ePub)                        // e
	if err := ss.mixKey(ePub); err != nil { // PSK-mode rule: MixKey(e.public_key) after every e
		return BuildResult{}, err
	}

	es, err := curve25519.X25519(ePriv, pdpStaticPub)
	if err != nil {
		return BuildResult{}, err
	}
	if err := ss.mixKey(es); err != nil { // es
		return BuildResult{}, err
	}

	timestampMS := now.UnixMilli()
	nsPlain := make([]byte, NSPlainLen)
	binary.BigEndian.PutUint64(nsPlain[:8], uint64(timestampMS))
	copy(nsPlain[8:], clientStaticPub)

	nsCipher, err := ss.encryptAndHash(nsPlain)
	if err != nil {
		return BuildResult{}, err
	}

	ssDH, err := curve25519.X25519(clientStaticPriv, pdpStaticPub)
	if err != nil {
		return BuildResult{}, err
	}
	if err := ss.mixKey(ssDH); err != nil { // ss
		return BuildResult{}, err
	}
	if err := ss.mixKeyAndHash(psk); err != nil { // psk1: end of first message, before nm payload
		return BuildResult{}, err
	}

	nmCipher, err := ss.encryptAndHash(payload)
	if err != nil {
		return BuildResult{}, err
	}

	packet := make([]byte, 0, len(ePub)+len(nsCipher)+len(nmCipher))
	packet = append(packet, ePub...)
	packet = append(packet, nsCipher...)
	packet = append(packet, nmCipher...)

	_, responderToInitiator, err := ss.split()
	if err != nil {
		return BuildResult{}, err
	}

	return BuildResult{
		Packet:      packet,
		PacketHash:  PacketHash(packet),
		ResponseKey: responderToInitiator,
		TimestampMS: timestampMS,
	}, nil
}

func OpenIKpsk1SPAHeader(packet []byte, pdp PDPIdentity, now time.Time, allowedSkew time.Duration) (OpenHeaderResult, error) {
	if len(packet) < EPublicLen+NSCipherLen+NSTagLen || len(packet) > MaxSPAPacket {
		return OpenHeaderResult{}, ErrInvalidPacket
	}

	pdpStaticPriv, err := decodeB64(pdp.PDPStaticPriv, 32)
	if err != nil {
		return OpenHeaderResult{}, err
	}

	ePub := packet[:EPublicLen]
	nsCipher := packet[EPublicLen : EPublicLen+NSCipherLen]
	nmCipher := packet[EPublicLen+NSCipherLen:]

	ss := newSymmetricState()
	ss.mixHash(ePub)                        // e
	if err := ss.mixKey(ePub); err != nil { // PSK-mode rule: MixKey(e.public_key) after every e
		return OpenHeaderResult{}, err
	}

	es, err := curve25519.X25519(pdpStaticPriv, ePub)
	if err != nil {
		return OpenHeaderResult{}, err
	}
	if err := ss.mixKey(es); err != nil { // es
		return OpenHeaderResult{}, err
	}

	nsPlain, err := ss.decryptAndHash(nsCipher)
	if err != nil {
		return OpenHeaderResult{}, ErrDecryptFailed
	}
	if len(nsPlain) != NSPlainLen {
		return OpenHeaderResult{}, ErrInvalidPacket
	}

	timestampMS := int64(binary.BigEndian.Uint64(nsPlain[:8]))
	packetTime := time.UnixMilli(timestampMS)
	if now.Sub(packetTime) > allowedSkew || packetTime.Sub(now) > allowedSkew {
		return OpenHeaderResult{}, ErrInvalidTime
	}

	clientStaticPub := make([]byte, 32)
	copy(clientStaticPub, nsPlain[8:])

	return OpenHeaderResult{
		ClientStaticPub:    base64.StdEncoding.EncodeToString(clientStaticPub),
		TimestampMS:        timestampMS,
		PacketHash:         PacketHash(packet),
		pdpStaticPriv:      append([]byte{}, pdpStaticPriv...),
		clientStaticPubRaw: clientStaticPub,
		nmCipher:           append([]byte{}, nmCipher...),
		ss:                 ss,
	}, nil
}

func CompleteIKpsk1SPA(header OpenHeaderResult, pskB64 string) (OpenResult, error) {
	psk, err := decodeB64(pskB64, 32)
	if err != nil {
		return OpenResult{}, err
	}
	if header.ss == nil || len(header.pdpStaticPriv) != 32 || len(header.clientStaticPubRaw) != 32 {
		return OpenResult{}, ErrInvalidPacket
	}

	ssDH, err := curve25519.X25519(header.pdpStaticPriv, header.clientStaticPubRaw)
	if err != nil {
		return OpenResult{}, err
	}
	if err := header.ss.mixKey(ssDH); err != nil { // ss
		return OpenResult{}, err
	}
	if err := header.ss.mixKeyAndHash(psk); err != nil { // psk1: end of first message, before nm payload
		return OpenResult{}, err
	}

	payload, err := header.ss.decryptAndHash(header.nmCipher)
	if err != nil {
		return OpenResult{}, ErrDecryptFailed
	}

	_, responderToInitiator, err := header.ss.split()
	if err != nil {
		return OpenResult{}, err
	}

	return OpenResult{
		ClientStaticPub: header.ClientStaticPub,
		TimestampMS:     header.TimestampMS,
		Payload:         payload,
		PacketHash:      header.PacketHash,
		ResponseKey:     responderToInitiator,
	}, nil
}

func OpenIKpsk1SPA(packet []byte, pdp PDPIdentity, now time.Time, allowedSkew time.Duration) (OpenResult, error) {
	header, err := OpenIKpsk1SPAHeader(packet, pdp, now, allowedSkew)
	if err != nil {
		return OpenResult{}, err
	}
	return CompleteIKpsk1SPA(header, pdp.SPAPSK)
}

func EncryptResponse(key []byte, plaintext []byte) ([]byte, error) {
	return encryptWithKey(key, 0, nil, plaintext)
}

func DecryptResponse(key []byte, ciphertext []byte) ([]byte, error) {
	return decryptWithKey(key, 0, nil, ciphertext)
}

func PacketHash(packet []byte) string {
	h := sha256.Sum256(packet)
	return hex.EncodeToString(h[:])
}

func newSymmetricState() *symmetricState {
	h := sha256.Sum256([]byte(ProtocolName))
	ck := make([]byte, 32)
	copy(ck, h[:])
	hb := make([]byte, 32)
	copy(hb, h[:])
	return &symmetricState{ck: ck, h: hb}
}

func (s *symmetricState) mixHash(data []byte) {
	h := sha256.New()
	h.Write(s.h)
	h.Write(data)
	s.h = h.Sum(nil)
}

func (s *symmetricState) mixKey(input []byte) error {
	out1, out2 := hkdf2(s.ck, input)
	s.ck = out1
	s.k = out2
	s.n = 0
	return nil
}

func (s *symmetricState) mixKeyAndHash(input []byte) error {
	out1, out2, out3 := hkdf3(s.ck, input)
	s.ck = out1
	s.mixHash(out2)
	s.k = out3
	s.n = 0
	return nil
}

func (s *symmetricState) encryptAndHash(plaintext []byte) ([]byte, error) {
	ciphertext, err := encryptWithKey(s.k, s.n, s.h, plaintext)
	if err != nil {
		return nil, err
	}
	if s.k != nil {
		s.n++
	}
	s.mixHash(ciphertext)
	return ciphertext, nil
}

func (s *symmetricState) decryptAndHash(ciphertext []byte) ([]byte, error) {
	plaintext, err := decryptWithKey(s.k, s.n, s.h, ciphertext)
	if err != nil {
		return nil, err
	}
	if s.k != nil {
		s.n++
	}
	s.mixHash(ciphertext)
	return plaintext, nil
}

func (s *symmetricState) split() ([]byte, []byte, error) {
	k1, k2 := hkdf2(s.ck, nil)
	return k1, k2, nil
}

func hkdf2(ck, input []byte) ([]byte, []byte) {
	tempKey := hmacSHA256(ck, input)
	out1 := hmacSHA256(tempKey, []byte{0x01})
	out2 := hmacSHA256(tempKey, append(append([]byte{}, out1...), 0x02))
	return out1, out2
}

func hkdf3(ck, input []byte) ([]byte, []byte, []byte) {
	tempKey := hmacSHA256(ck, input)
	out1 := hmacSHA256(tempKey, []byte{0x01})
	out2 := hmacSHA256(tempKey, append(append([]byte{}, out1...), 0x02))
	out3 := hmacSHA256(tempKey, append(append([]byte{}, out2...), 0x03))
	return out1, out2, out3
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func encryptWithKey(key []byte, nonce uint64, ad, plaintext []byte) ([]byte, error) {
	if key == nil {
		return append([]byte{}, plaintext...), nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, noiseNonce(nonce), plaintext, ad), nil
}

func decryptWithKey(key []byte, nonce uint64, ad, ciphertext []byte) ([]byte, error) {
	if key == nil {
		return append([]byte{}, ciphertext...), nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, noiseNonce(nonce), ciphertext, ad)
}

func noiseNonce(n uint64) []byte {
	nonce := make([]byte, 12)
	binary.LittleEndian.PutUint64(nonce[4:], n)
	return nonce
}

func decodeB64(s string, expected int) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != expected {
		return nil, fmt.Errorf("%w: got %d want %d", ErrInvalidKey, len(b), expected)
	}
	return b, nil
}

func clamp(priv []byte) {
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
}
