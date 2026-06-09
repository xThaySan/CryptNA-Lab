package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	"cryptna-lab/common/ipsecutil"
	"cryptna-lab/common/logutil"
	"cryptna-lab/common/protocol"
)

func buildClientXFRMPlan(t protocol.TunnelParams, c2pKey, p2cKey string, reqID uint32) (protocol.XFRMPlan, error) {
	if t.ServiceIP == "" {
		return protocol.XFRMPlan{}, fmt.Errorf("missing service_ip in tunnel params")
	}
	if t.ClientInnerIP == "" {
		return protocol.XFRMPlan{}, fmt.Errorf("missing client_inner_ip in tunnel params")
	}
	if t.PEPAddress == "" {
		return protocol.XFRMPlan{}, fmt.Errorf("missing pep_address in tunnel params")
	}
	if t.PEPPort == 0 {
		t.PEPPort = 4500
	}
	clientOuterIP, err := localIPForRemote(t.PEPAddress, t.PEPPort)
	if err != nil {
		return protocol.XFRMPlan{}, err
	}
	logutil.Debugf("client", "inferred local outer ip for PEP %s:%d as %s", t.PEPAddress, t.PEPPort, clientOuterIP)

	return ipsecutil.BuildClientXFRMTunnelPlan(ipsecutil.TunnelPlanInput{
		ClientOuterIP: clientOuterIP,
		ClientInnerIP: t.ClientInnerIP,
		PEPOuterIP:    t.PEPAddress,
		ServiceIP:     t.ServiceIP,
		NATTPort:      t.PEPPort,
		ClientInSPI:   t.ClientInSPI,
		PEPInSPI:      t.PEPInSPI,
		ReqID:         reqID,
		C2PKeyB64:     c2pKey,
		P2CKeyB64:     p2cKey,
	})
}

func maybeApplyClientXFRM(x protocol.XFRMPlan) error {
	mode := getenv("XFRM_MODE", "dry-run")
	if mode != "apply" {
		logutil.Debugf("client", "XFRM dry-run mode, not applying commands")
		for _, cmd := range x.Commands {
			logutil.Debugf("client", "XFRM dry-run: %s", cmd)
		}
		return nil
	}

	// Make repeated activations for the same allocated inner IP idempotent on the client.
	// Deletion errors are ignored because the first activation has nothing to remove.
	for _, cmd := range x.DeleteCommands {
		logutil.Debugf("client", "pre-clean XFRM: %s", cmd)
		_, _ = exec.Command("sh", "-c", cmd).CombinedOutput()
	}

	for _, cmd := range x.Commands {
		logutil.Infof("client", "applying XFRM: %s", cmd)

		out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
		if err != nil {
			return fmt.Errorf("xfrm command failed: %s: %v: %s", cmd, err, string(out))
		}
	}

	return nil
}

func scheduleClientXFRMCleanup(x protocol.XFRMPlan, delaySeconds int) error {
	mode := getenv("XFRM_MODE", "dry-run")
	if mode != "apply" {
		logutil.Debugf("client", "XFRM dry-run mode, not scheduling cleanup")
		return nil
	}

	if delaySeconds <= 0 {
		logutil.Debugf("client", "invalid cleanup delay=%d, not scheduling cleanup", delaySeconds)
		return nil
	}

	commands := make([]string, 0, len(x.DeleteCommands)+1)
	commands = append(commands, fmt.Sprintf("sleep %d", delaySeconds))

	for _, cmd := range x.DeleteCommands {
		commands = append(commands, cmd+" >/dev/null 2>&1 || true")
	}

	script := strings.Join(commands, "; ")

	logutil.Infof("client", "scheduling local XFRM cleanup in %ds", delaySeconds)

	c := exec.Command("sh", "-c", script)
	return c.Start()
}

func getenv(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}

func localIPForRemote(host string, port int) (string, error) {
	raddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return "", err
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	laddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || laddr.IP == nil {
		return "", fmt.Errorf("could not infer local outer IP for %s:%d", host, port)
	}
	return laddr.IP.String(), nil
}
