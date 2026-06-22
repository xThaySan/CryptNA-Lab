package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"cryptna-lab/common/protocol"
)

func TestPosthocObserverRequiresExactXFRMFields(t *testing.T) {
	t.Setenv("XFRM_MODE", "apply")
	original := runIPXFRM
	defer func() { runIPXFRM = original }()
	session := exactObserverTestSession()
	runIPXFRM = matchingXFRMOutput(session, session.ReqID)
	metadata := observeXFRMAppliedPosthoc(session)
	if metadata["applied"] != "true" {
		t.Fatalf("expected exact state to be accepted, metadata=%v", metadata)
	}

	runIPXFRM = matchingXFRMOutput(session, session.ReqID+1)
	metadata = observeXFRMAppliedPosthoc(session)
	if metadata["applied"] != "false" {
		t.Fatalf("expected reqid mismatch to be rejected, metadata=%v", metadata)
	}
}

func TestPosthocObserverConfirmsExactXFRMAbsence(t *testing.T) {
	t.Setenv("XFRM_MODE", "apply")
	original := runIPXFRM
	defer func() { runIPXFRM = original }()
	runIPXFRM = func(args ...string) ([]byte, error) {
		return []byte("RTNETLINK answers: No such file or directory"), errors.New("exit status 2")
	}
	metadata := observeXFRMDeletedPosthoc(exactObserverTestSession())
	if metadata["deleted"] != "true" {
		t.Fatalf("expected confirmed absence, metadata=%v", metadata)
	}
}

func TestPosthocObserverDoesNotTreatLookupFailureAsDeletion(t *testing.T) {
	t.Setenv("XFRM_MODE", "apply")
	original := runIPXFRM
	defer func() { runIPXFRM = original }()
	runIPXFRM = func(args ...string) ([]byte, error) {
		return []byte("permission denied"), errors.New("exit status 1")
	}
	metadata := observeXFRMDeletedPosthoc(exactObserverTestSession())
	if metadata["deleted"] != "false" {
		t.Fatalf("lookup failure must not prove deletion, metadata=%v", metadata)
	}
}

func TestDryRunBaselineAllowsExplicitlyAssumedObservation(t *testing.T) {
	t.Setenv("PEP_REQUIRED_OBSERVER_PROFILE", "posthoc")
	original := pepAttestation
	defer func() { pepAttestation = original }()
	pepAttestation = &pepAttestationState{enabled: false}
	metadata := map[string]string{"xfrm_mode": "dry-run", "applied": "assumed", "observer_source": "dry-run"}
	if !observationMeetsLocalProfile(metadata, "applied") {
		t.Fatal("non-attested baseline dry-run observation was rejected")
	}
}

func TestDryRunAttestationRequiresDryRunProfile(t *testing.T) {
	t.Setenv("PEP_REQUIRED_OBSERVER_PROFILE", "posthoc")
	original := pepAttestation
	defer func() { pepAttestation = original }()
	pepAttestation = &pepAttestationState{enabled: true}
	metadata := map[string]string{"xfrm_mode": "dry-run", "applied": "assumed", "observer_source": "dry-run"}
	if observationMeetsLocalProfile(metadata, "applied") {
		t.Fatal("attested dry-run was accepted under a posthoc apply profile")
	}
}

func TestObserverConfigurationRejectsHybridFallback(t *testing.T) {
	t.Setenv("XFRM_MODE", "apply")
	t.Setenv("PEP_REQUIRED_OBSERVER_PROFILE", "hybrid")
	originalAttestation := pepAttestation
	originalObserver := globalXFRMObserver
	defer func() {
		pepAttestation = originalAttestation
		globalXFRMObserver = originalObserver
	}()
	pepAttestation = &pepAttestationState{enabled: true}
	globalXFRMObserver = &xfrmObserver{mode: xfrmObserverPosthoc}
	if err := validateXFRMObserverConfiguration(); err == nil {
		t.Fatal("required hybrid profile accepted a posthoc fallback")
	}
}

func TestObserverConfigurationAcceptsReadyHybrid(t *testing.T) {
	t.Setenv("XFRM_MODE", "apply")
	t.Setenv("PEP_REQUIRED_OBSERVER_PROFILE", "hybrid")
	originalAttestation := pepAttestation
	originalObserver := globalXFRMObserver
	defer func() {
		pepAttestation = originalAttestation
		globalXFRMObserver = originalObserver
	}()
	pepAttestation = &pepAttestationState{enabled: true}
	globalXFRMObserver = &xfrmObserver{mode: xfrmObserverHybrid, ready: true}
	if err := validateXFRMObserverConfiguration(); err != nil {
		t.Fatalf("ready hybrid observer was rejected: %v", err)
	}
}

func exactObserverTestSession() protocol.Session {
	return protocol.Session{
		ClientOuterIP: "172.20.0.10",
		ClientInnerIP: "10.200.0.10",
		PEPOuterIP:    "172.20.0.40",
		ServiceIP:     "172.22.0.50",
		ClientInSPI:   "0x11111111",
		PEPInSPI:      "0x22222222",
		ReqID:         1000,
	}
}

func matchingXFRMOutput(session protocol.Session, returnedReqID uint32) func(args ...string) ([]byte, error) {
	return func(args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		if strings.Contains(joined, "state get") {
			src := valueAfter(args, "src")
			dst := valueAfter(args, "dst")
			spi := valueAfter(args, "spi")
			return []byte(fmt.Sprintf("src %s dst %s proto esp spi %s reqid %d mode tunnel", src, dst, spi, returnedReqID)), nil
		}
		if strings.Contains(joined, "policy get") {
			direction := valueAfter(args, "dir")
			src := valueAfter(args, "src")
			dst := valueAfter(args, "dst")
			tunnelSrc, tunnelDst := session.ClientOuterIP, session.PEPOuterIP
			if direction == "out" {
				tunnelSrc, tunnelDst = session.PEPOuterIP, session.ClientOuterIP
			}
			return []byte(fmt.Sprintf("src %s/32 dst %s/32 dir %s tmpl src %s dst %s proto esp reqid %d mode tunnel", src, dst, direction, tunnelSrc, tunnelDst, returnedReqID)), nil
		}
		return nil, fmt.Errorf("unexpected ip arguments: %v", args)
	}
}

func valueAfter(values []string, key string) string {
	for i := 0; i+1 < len(values); i++ {
		if values[i] == key {
			return values[i+1]
		}
	}
	return ""
}
