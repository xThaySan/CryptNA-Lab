package main

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"cryptna-lab/common/ipsecutil"
	"cryptna-lab/common/logutil"
	"cryptna-lab/common/protocol"
)

var runIPXFRM = func(args ...string) ([]byte, error) {
	return exec.Command("ip", args...).CombinedOutput()
}

type xfrmLookupResult struct {
	present bool
	exact   bool
	detail  string
}

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
	checks := exactSessionXFRMLookups(s)
	applied := true
	for name, check := range checks {
		out[name+"_present"] = strconv.FormatBool(check.present)
		out[name+"_exact"] = strconv.FormatBool(check.exact)
		if check.detail != "" {
			out[name+"_error"] = check.detail
		}
		if !check.present || !check.exact {
			applied = false
		}
	}
	out["applied"] = strconv.FormatBool(applied)
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
	checks := exactSessionXFRMLookups(s)
	deleted := true
	for name, check := range checks {
		out[name+"_present"] = strconv.FormatBool(check.present)
		out[name+"_absence_confirmed"] = strconv.FormatBool(check.exact && !check.present)
		if check.detail != "" {
			out[name+"_error"] = check.detail
		}
		if check.present || !check.exact {
			deleted = false
		}
	}
	out["deleted"] = strconv.FormatBool(deleted)
	return out
}

func exactSessionXFRMLookups(s protocol.Session) map[string]xfrmLookupResult {
	reqid := strconv.FormatUint(uint64(s.ReqID), 10)
	return map[string]xfrmLookupResult{
		"c2p_state":  lookupXFRMState(s.ClientOuterIP, s.PEPOuterIP, s.PEPInSPI, reqid),
		"p2c_state":  lookupXFRMState(s.PEPOuterIP, s.ClientOuterIP, s.ClientInSPI, reqid),
		"c2p_policy": lookupXFRMPolicy("fwd", s.ClientInnerIP, s.ServiceIP, s.ClientOuterIP, s.PEPOuterIP, reqid),
		"p2c_policy": lookupXFRMPolicy("out", s.ServiceIP, s.ClientInnerIP, s.PEPOuterIP, s.ClientOuterIP, reqid),
	}
}

func lookupXFRMState(src, dst, spi, reqid string) xfrmLookupResult {
	out, err := runIPXFRM("xfrm", "state", "get", "src", src, "dst", dst, "proto", "esp", "spi", spi)
	if err != nil {
		if isXFRMNotFound(out) {
			return xfrmLookupResult{present: false, exact: true}
		}
		return xfrmLookupResult{detail: strings.TrimSpace(string(out)) + ": " + err.Error()}
	}
	fields := strings.Fields(strings.ToLower(string(out)))
	exact := containsFieldPair(fields, "src", src) &&
		containsFieldPair(fields, "dst", dst) &&
		containsFieldPair(fields, "proto", "esp") &&
		containsFieldPair(fields, "spi", strings.ToLower(spi)) &&
		containsFieldPair(fields, "reqid", reqid) &&
		containsFieldPair(fields, "mode", "tunnel")
	return xfrmLookupResult{present: true, exact: exact, detail: mismatchDetail(exact, out)}
}

func lookupXFRMPolicy(direction, selectorSrc, selectorDst, tunnelSrc, tunnelDst, reqid string) xfrmLookupResult {
	out, err := runIPXFRM("xfrm", "policy", "get", "src", selectorSrc, "dst", selectorDst, "dir", direction)
	if err != nil {
		if isXFRMNotFound(out) {
			return xfrmLookupResult{present: false, exact: true}
		}
		return xfrmLookupResult{detail: strings.TrimSpace(string(out)) + ": " + err.Error()}
	}
	fields := strings.Fields(strings.ToLower(string(out)))
	exact := containsAddressPair(fields, "src", selectorSrc) &&
		containsAddressPair(fields, "dst", selectorDst) &&
		containsFieldPair(fields, "dir", direction) &&
		containsSequence(fields, "tmpl", "src", strings.ToLower(tunnelSrc), "dst", strings.ToLower(tunnelDst)) &&
		containsFieldPair(fields, "proto", "esp") &&
		containsFieldPair(fields, "reqid", reqid) &&
		containsFieldPair(fields, "mode", "tunnel")
	return xfrmLookupResult{present: true, exact: exact, detail: mismatchDetail(exact, out)}
}

func containsFieldPair(fields []string, key, value string) bool {
	return containsSequence(fields, strings.ToLower(key), strings.ToLower(value))
}

func containsAddressPair(fields []string, key, address string) bool {
	return containsSequence(fields, strings.ToLower(key), strings.ToLower(address)) ||
		containsSequence(fields, strings.ToLower(key), strings.ToLower(address)+"/32")
}

func containsSequence(fields []string, sequence ...string) bool {
	if len(sequence) == 0 || len(sequence) > len(fields) {
		return false
	}
	for i := 0; i <= len(fields)-len(sequence); i++ {
		matched := true
		for j := range sequence {
			if fields[i+j] != strings.ToLower(sequence[j]) {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

func isXFRMNotFound(out []byte) bool {
	text := strings.ToLower(string(out))
	return strings.Contains(text, "no such file") || strings.Contains(text, "no such process") || strings.Contains(text, "not found")
}

func mismatchDetail(exact bool, out []byte) string {
	if exact {
		return ""
	}
	return "XFRM object exists but does not match all expected fields: " + strings.TrimSpace(string(out))
}
