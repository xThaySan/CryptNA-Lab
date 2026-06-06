package main

import (
	"fmt"
	"os"
	"os/exec"

	"cryptna-lab/common/ipsecutil"
	"cryptna-lab/common/logutil"
	"cryptna-lab/common/protocol"
)

func buildClientXFRMPlan(t protocol.TunnelParams, c2pKey, p2cKey string, reqID uint32) (protocol.XFRMPlan, error) {
	clientOuterIP := getenv("CLIENT_OUTER_IP", getenv("CLIENT_DATA_IP", "172.21.0.10"))
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

func getenv(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}
