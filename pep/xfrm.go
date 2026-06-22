package main

import (
	"fmt"
	"os/exec"
	"strings"

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

func maybeDeleteXFRM(x protocol.XFRMPlan) error {
	mode := getenv("XFRM_MODE", "dry-run")
	if mode != "apply" {
		logutil.Debugf("pep", "XFRM dry-run mode, not deleting commands")
		return nil
	}

	for _, cmd := range x.DeleteCommands {
		logutil.Infof("pep", "deleting XFRM: %s", cmd)

		out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
		if err != nil {
			// Best effort cleanup: the state/policy may already be gone.
			logutil.Debugf("pep", "XFRM delete command failed but ignored: cmd=%s err=%v out=%s", cmd, err, string(out))
			continue
		}
	}

	return nil
}

func observeXFRMAppliedPosthoc(s protocol.Session) map[string]string {
	mode := getenv("XFRM_MODE", "dry-run")
	out := map[string]string{
		"xfrm_mode":      mode,
		"xfrm_plan_hash": xfrmPlanHash(s.XFRM),
	}
	if mode != "apply" {
		out["observation"] = "dry-run-no-kernel-observation"
		out["applied"] = "assumed"
		return out
	}
	state, stateErr := exec.Command("sh", "-c", "ip xfrm state").CombinedOutput()
	policy, policyErr := exec.Command("sh", "-c", "ip xfrm policy").CombinedOutput()
	stateText := string(state)
	policyText := string(policy)
	if stateErr != nil {
		out["state_error"] = stateErr.Error()
	}
	if policyErr != nil {
		out["policy_error"] = policyErr.Error()
	}
	out["pep_in_spi_present"] = fmt.Sprintf("%t", strings.Contains(stateText, s.PEPInSPI))
	out["client_in_spi_present"] = fmt.Sprintf("%t", strings.Contains(stateText, s.ClientInSPI))
	out["fwd_policy_present"] = fmt.Sprintf("%t", strings.Contains(policyText, s.ClientInnerIP) && strings.Contains(policyText, s.ServiceIP))
	out["applied"] = fmt.Sprintf("%t", stateErr == nil && policyErr == nil && strings.Contains(stateText, s.PEPInSPI) && strings.Contains(stateText, s.ClientInSPI) && strings.Contains(policyText, s.ClientInnerIP) && strings.Contains(policyText, s.ServiceIP))
	return out
}

func observeXFRMDeletedPosthoc(s protocol.Session) map[string]string {
	mode := getenv("XFRM_MODE", "dry-run")
	out := map[string]string{
		"xfrm_mode":      mode,
		"xfrm_plan_hash": xfrmPlanHash(s.XFRM),
	}
	if mode != "apply" {
		out["observation"] = "dry-run-no-kernel-observation"
		out["deleted"] = "assumed"
		return out
	}
	state, stateErr := exec.Command("sh", "-c", "ip xfrm state").CombinedOutput()
	policy, policyErr := exec.Command("sh", "-c", "ip xfrm policy").CombinedOutput()
	stateText := string(state)
	policyText := string(policy)
	if stateErr != nil {
		out["state_error"] = stateErr.Error()
	}
	if policyErr != nil {
		out["policy_error"] = policyErr.Error()
	}
	pepPresent := strings.Contains(stateText, s.PEPInSPI)
	clientPresent := strings.Contains(stateText, s.ClientInSPI)
	policyPresent := strings.Contains(policyText, s.ClientInnerIP) && strings.Contains(policyText, s.ServiceIP)
	out["pep_in_spi_present"] = fmt.Sprintf("%t", pepPresent)
	out["client_in_spi_present"] = fmt.Sprintf("%t", clientPresent)
	out["policy_present"] = fmt.Sprintf("%t", policyPresent)
	out["deleted"] = fmt.Sprintf("%t", stateErr == nil && policyErr == nil && !pepPresent && !clientPresent && !policyPresent)
	return out
}
