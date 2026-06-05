package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"

	"cryptna-lab/common/protocol"
)

func buildXFRMDryRun(s protocol.Session) protocol.XFRMDryRun {
	clientIP := getenv("CLIENT_DATA_IP", "172.21.0.10")
	pepIP := getenv("PEP_DATA_IP", "172.21.0.40")
	reqID := getenv("XFRM_REQID", "100")

	c2pKey := deriveXFRMAEADKey(s.C2PKey, "xfrm-c2p")
	p2cKey := deriveXFRMAEADKey(s.P2CKey, "xfrm-p2c")

	commands := []string{
		fmt.Sprintf(
			"ip xfrm state add src %s dst %s proto esp spi %s reqid %s mode transport aead 'rfc4106(gcm(aes))' 0x%s 128",
			clientIP, pepIP, s.ClientSPI, reqID, c2pKey,
		),
		fmt.Sprintf(
			"ip xfrm policy add src %s dst %s dir in tmpl src %s dst %s proto esp reqid %s mode transport",
			clientIP, pepIP, clientIP, pepIP, reqID,
		),
		fmt.Sprintf(
			"ip xfrm state add src %s dst %s proto esp spi %s reqid %s mode transport aead 'rfc4106(gcm(aes))' 0x%s 128",
			pepIP, clientIP, s.PEPSPI, reqID, p2cKey,
		),
		fmt.Sprintf(
			"ip xfrm policy add src %s dst %s dir out tmpl src %s dst %s proto esp reqid %s mode transport",
			pepIP, clientIP, pepIP, clientIP, reqID,
		),
	}

	return protocol.XFRMDryRun{
		Mode:     "dry-run",
		Commands: commands,
	}
}

// RFC4106 AES-GCM for AES-128 expects 20 bytes:
// 16 bytes AES key + 4 bytes salt.
func deriveXFRMAEADKey(sessionKeyB64 string, label string) string {
	raw, err := base64.StdEncoding.DecodeString(sessionKeyB64)
	if err != nil {
		panic(err)
	}

	h := sha256.Sum256(append([]byte(label), raw...))
	return hex.EncodeToString(h[:20])
}

func getenv(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}
