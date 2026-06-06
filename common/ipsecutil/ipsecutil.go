package ipsecutil

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"cryptna-lab/common/protocol"
)

type TunnelPlanInput struct {
	ClientOuterIP string
	ClientInnerIP string
	PEPOuterIP    string
	ServiceIP     string
	ClientInSPI   string
	PEPInSPI      string
	ReqID         uint32
	C2PKeyB64     string
	P2CKeyB64     string
}

func GenerateSPI() (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	if b == [4]byte{} {
		b[3] = 1
	}
	return fmt.Sprintf("0x%08x", binary.BigEndian.Uint32(b[:])), nil
}

func GenerateReqID() (uint32, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	reqID := binary.BigEndian.Uint32(b[:])
	if reqID == 0 {
		reqID = 1
	}
	return reqID, nil
}

func DeriveXFRMAEADKey(sessionKeyB64 string, label string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(sessionKeyB64)
	if err != nil {
		return "", err
	}

	h := sha256.Sum256(append([]byte(label), raw...))
	return hex.EncodeToString(h[:20]), nil
}

func BuildXFRMTunnelPlan(in TunnelPlanInput) (protocol.XFRMPlan, error) {
	c2pKey, err := DeriveXFRMAEADKey(in.C2PKeyB64, "xfrm-c2p")
	if err != nil {
		return protocol.XFRMPlan{}, err
	}
	p2cKey, err := DeriveXFRMAEADKey(in.P2CKeyB64, "xfrm-p2c")
	if err != nil {
		return protocol.XFRMPlan{}, err
	}

	reqID := fmt.Sprintf("%d", in.ReqID)

	commands := []string{
		fmt.Sprintf(
			"ip xfrm state add src %s dst %s proto esp spi %s reqid %s mode tunnel aead 'rfc4106(gcm(aes))' 0x%s 128",
			in.ClientOuterIP, in.PEPOuterIP, in.PEPInSPI, reqID, c2pKey,
		),
		fmt.Sprintf(
			"ip xfrm policy add src %s dst %s dir fwd tmpl src %s dst %s proto esp reqid %s mode tunnel",
			in.ClientInnerIP, in.ServiceIP, in.ClientOuterIP, in.PEPOuterIP, reqID,
		),
		fmt.Sprintf(
			"ip xfrm state add src %s dst %s proto esp spi %s reqid %s mode tunnel aead 'rfc4106(gcm(aes))' 0x%s 128",
			in.PEPOuterIP, in.ClientOuterIP, in.ClientInSPI, reqID, p2cKey,
		),
		fmt.Sprintf(
			"ip xfrm policy add src %s dst %s dir out tmpl src %s dst %s proto esp reqid %s mode tunnel",
			in.ServiceIP, in.ClientInnerIP, in.PEPOuterIP, in.ClientOuterIP, reqID,
		),
	}

	deleteCommands := []string{
		fmt.Sprintf("ip xfrm policy delete src %s dst %s dir fwd", in.ClientInnerIP, in.ServiceIP),
		fmt.Sprintf("ip xfrm policy delete src %s dst %s dir out", in.ServiceIP, in.ClientInnerIP),
		fmt.Sprintf("ip xfrm state delete src %s dst %s proto esp spi %s", in.ClientOuterIP, in.PEPOuterIP, in.PEPInSPI),
		fmt.Sprintf("ip xfrm state delete src %s dst %s proto esp spi %s", in.PEPOuterIP, in.ClientOuterIP, in.ClientInSPI),
	}

	return protocol.XFRMPlan{
		Mode:           "dry-run-tunnel",
		Commands:       commands,
		DeleteCommands: deleteCommands,
	}, nil
}
