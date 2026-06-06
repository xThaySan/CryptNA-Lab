package main

import (
	"fmt"
	"os/exec"

	"cryptna-lab/common/ipsecutil"
	"cryptna-lab/common/logutil"
	"cryptna-lab/common/protocol"
)

func buildXFRMPlan(s protocol.Session) (protocol.XFRMPlan, error) {
	return ipsecutil.BuildXFRMTunnelPlan(ipsecutil.TunnelPlanInput{
		ClientOuterIP: s.ClientOuterIP,
		ClientInnerIP: s.ClientInnerIP,
		PEPOuterIP:    s.PEPOuterIP,
		ServiceIP:     s.ServiceIP,
		NATTPort:      s.NATTPort,
		ClientInSPI:   s.ClientInSPI,
		PEPInSPI:      s.PEPInSPI,
		ReqID:         s.ReqID,
		C2PKeyB64:     s.C2PKey,
		P2CKeyB64:     s.P2CKey,
	})
}

func maybeApplyXFRM(x protocol.XFRMPlan) error {
	mode := getenv("XFRM_MODE", "dry-run")
	if mode != "apply" {
		logutil.Debugf("pep", "XFRM dry-run mode, not applying commands")
		return nil
	}

	for _, cmd := range x.Commands {
		logutil.Infof("pep", "applying XFRM: %s", cmd)

		out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
		if err != nil {
			return fmt.Errorf("xfrm command failed: %s: %v: %s", cmd, err, string(out))
		}
	}

	return nil
}
