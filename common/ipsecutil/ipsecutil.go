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
	NATTPort      int

	ClientInSPI string
	PEPInSPI    string
	ReqID       uint32

	C2PKeyB64 string
	P2CKeyB64 string
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

	v := binary.BigEndian.Uint32(b[:])

	// Linux accepte reqid 0, mais on l'évite pour garder un état local explicite.
	if v == 0 {
		v = 1
	}

	return v, nil
}

func DeriveXFRMAEADKey(sessionKeyB64 string, label string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(sessionKeyB64)
	if err != nil {
		return "", err
	}

	h := sha256.Sum256(append([]byte(label), raw...))
	return hex.EncodeToString(h[:20]), nil
}

// BuildPEPXFRMTunnelPlan builds the PEP-side XFRM plan for a CRYPTNA L3 tunnel.
// Inner traffic is client_inner_ip <-> service_ip.
// Outer transport is client_outer_ip <-> pep_outer_ip with ESP-in-UDP NAT-T.
func BuildPEPXFRMTunnelPlan(in TunnelPlanInput) (protocol.XFRMPlan, error) {
	c2pKey, err := DeriveXFRMAEADKey(in.C2PKeyB64, "xfrm-c2p")
	if err != nil {
		return protocol.XFRMPlan{}, err
	}

	p2cKey, err := DeriveXFRMAEADKey(in.P2CKeyB64, "xfrm-p2c")
	if err != nil {
		return protocol.XFRMPlan{}, err
	}

	reqID := fmt.Sprintf("%d", in.ReqID)
	nattPort := fmt.Sprintf("%d", in.NATTPort)

	commands := []string{
		// Client -> PEP: PEP receives ESP/NAT-T with SPI chosen by the PEP.
		fmt.Sprintf(
			"ip xfrm state add src %s dst %s proto esp spi %s reqid %s mode tunnel encap espinudp %s %s 0.0.0.0 aead 'rfc4106(gcm(aes))' 0x%s 128",
			in.ClientOuterIP, in.PEPOuterIP, in.PEPInSPI, reqID, nattPort, nattPort, c2pKey,
		),
		fmt.Sprintf(
			"ip xfrm policy add src %s dst %s dir fwd tmpl src %s dst %s proto esp reqid %s mode tunnel",
			in.ClientInnerIP, in.ServiceIP, in.ClientOuterIP, in.PEPOuterIP, reqID,
		),

		// PEP -> Client: client receives ESP/NAT-T with SPI chosen by the client.
		fmt.Sprintf(
			"ip xfrm state add src %s dst %s proto esp spi %s reqid %s mode tunnel encap espinudp %s %s 0.0.0.0 aead 'rfc4106(gcm(aes))' 0x%s 128",
			in.PEPOuterIP, in.ClientOuterIP, in.ClientInSPI, reqID, nattPort, nattPort, p2cKey,
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
		Mode:           "pep-natt-tunnel",
		Commands:       commands,
		DeleteCommands: deleteCommands,
	}, nil
}

// BuildClientXFRMTunnelPlan builds the client-side XFRM plan for the same session.
// The agent configures client_inner_ip locally; the end user only targets service_ip.
func BuildClientXFRMTunnelPlan(in TunnelPlanInput) (protocol.XFRMPlan, error) {
	c2pKey, err := DeriveXFRMAEADKey(in.C2PKeyB64, "xfrm-c2p")
	if err != nil {
		return protocol.XFRMPlan{}, err
	}

	p2cKey, err := DeriveXFRMAEADKey(in.P2CKeyB64, "xfrm-p2c")
	if err != nil {
		return protocol.XFRMPlan{}, err
	}

	reqID := fmt.Sprintf("%d", in.ReqID)
	nattPort := fmt.Sprintf("%d", in.NATTPort)

	commands := []string{
		fmt.Sprintf("ip addr replace %s/32 dev lo", in.ClientInnerIP),
		fmt.Sprintf("ip route replace %s/32 via %s src %s", in.ServiceIP, in.PEPOuterIP, in.ClientInnerIP),

		// PEP -> Client: client receives ESP/NAT-T with SPI chosen by the client.
		fmt.Sprintf(
			"ip xfrm state add src %s dst %s proto esp spi %s reqid %s mode tunnel encap espinudp %s %s 0.0.0.0 aead 'rfc4106(gcm(aes))' 0x%s 128",
			in.PEPOuterIP, in.ClientOuterIP, in.ClientInSPI, reqID, nattPort, nattPort, p2cKey,
		),
		fmt.Sprintf(
			"ip xfrm policy add src %s dst %s dir in tmpl src %s dst %s proto esp reqid %s mode tunnel",
			in.ServiceIP, in.ClientInnerIP, in.PEPOuterIP, in.ClientOuterIP, reqID,
		),

		// Client -> PEP: PEP receives ESP/NAT-T with SPI chosen by the PEP.
		fmt.Sprintf(
			"ip xfrm state add src %s dst %s proto esp spi %s reqid %s mode tunnel encap espinudp %s %s 0.0.0.0 aead 'rfc4106(gcm(aes))' 0x%s 128",
			in.ClientOuterIP, in.PEPOuterIP, in.PEPInSPI, reqID, nattPort, nattPort, c2pKey,
		),
		fmt.Sprintf(
			"ip xfrm policy add src %s dst %s dir out tmpl src %s dst %s proto esp reqid %s mode tunnel",
			in.ClientInnerIP, in.ServiceIP, in.ClientOuterIP, in.PEPOuterIP, reqID,
		),
	}

	deleteCommands := []string{
		fmt.Sprintf("ip xfrm policy delete src %s dst %s dir out", in.ClientInnerIP, in.ServiceIP),
		fmt.Sprintf("ip xfrm policy delete src %s dst %s dir in", in.ServiceIP, in.ClientInnerIP),
		fmt.Sprintf("ip xfrm state delete src %s dst %s proto esp spi %s", in.ClientOuterIP, in.PEPOuterIP, in.PEPInSPI),
		fmt.Sprintf("ip xfrm state delete src %s dst %s proto esp spi %s", in.PEPOuterIP, in.ClientOuterIP, in.ClientInSPI),
		fmt.Sprintf("ip route delete %s/32 via %s src %s", in.ServiceIP, in.PEPOuterIP, in.ClientInnerIP),
		fmt.Sprintf("ip addr delete %s/32 dev lo", in.ClientInnerIP),
	}

	return protocol.XFRMPlan{
		Mode:           "client-natt-tunnel",
		Commands:       commands,
		DeleteCommands: deleteCommands,
	}, nil
}

// BuildXFRMTunnelPlan is kept as a compatibility wrapper for PEP-side code.
func BuildXFRMTunnelPlan(in TunnelPlanInput) (protocol.XFRMPlan, error) {
	return BuildPEPXFRMTunnelPlan(in)
}
