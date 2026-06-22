package main

import "testing"

func TestParseXFRMKernelEventClassifiesApply(t *testing.T) {
	e := parseXFRMKernelEvent("cryptna_xfrm_event ts_ns=1 pid=42 comm=ip probe=kprobe:xfrm_state_add action=unknown")
	if e.Probe != "kprobe:xfrm_state_add" {
		t.Fatalf("unexpected probe: %s", e.Probe)
	}
	if e.Action != "apply" {
		t.Fatalf("expected apply, got %s", e.Action)
	}
}

func TestParseXFRMKernelEventClassifiesDelete(t *testing.T) {
	e := parseXFRMKernelEvent("cryptna_xfrm_event ts_ns=1 pid=42 comm=ip probe=kprobe:xfrm_policy_delete action=unknown")
	if e.Action != "delete" {
		t.Fatalf("expected delete, got %s", e.Action)
	}
}

func TestAnnotateStrictEBPFOverridesApplyOutcome(t *testing.T) {
	obs := &xfrmObserver{mode: xfrmObserverEBPF}
	mark := obs.mark()
	meta := obs.annotate(map[string]string{"applied": "true", "xfrm_mode": "apply"}, mark, "apply")
	if meta["applied"] != "false" {
		t.Fatalf("expected strict eBPF mode to reject missing eBPF event, got applied=%s", meta["applied"])
	}
}

func TestAnnotateHybridKeepsPosthocOutcome(t *testing.T) {
	obs := &xfrmObserver{mode: xfrmObserverHybrid}
	mark := obs.mark()
	meta := obs.annotate(map[string]string{"applied": "true", "xfrm_mode": "apply"}, mark, "apply")
	if meta["applied"] != "true" {
		t.Fatalf("expected hybrid mode to keep posthoc result, got applied=%s", meta["applied"])
	}
	if meta["observer_source"] != "posthoc+ebpf" {
		t.Fatalf("unexpected observer source: %s", meta["observer_source"])
	}
}

func TestAnnotateStrictEBPFRequiresMinimumActionEvents(t *testing.T) {
	obs := &xfrmObserver{mode: xfrmObserverEBPF, minApplyEvents: 2}
	mark := obs.mark()
	obs.events = append(obs.events, xfrmKernelEvent{Action: "apply", Probe: "kprobe:xfrm_state_add"})
	meta := obs.annotate(map[string]string{"applied": "true", "xfrm_mode": "apply"}, mark, "apply")
	if meta["applied"] != "false" {
		t.Fatalf("expected strict eBPF mode to reject below-threshold events, got applied=%s", meta["applied"])
	}
	if meta["ebpf_event_count"] != "1" {
		t.Fatalf("expected one matching event, got %s", meta["ebpf_event_count"])
	}
	if meta["ebpf_min_event_count"] != "2" {
		t.Fatalf("expected min event count 2, got %s", meta["ebpf_min_event_count"])
	}
}

func TestAnnotateCountsOnlyExpectedActionEvents(t *testing.T) {
	obs := &xfrmObserver{mode: xfrmObserverHybrid, minApplyEvents: 2}
	mark := obs.mark()
	obs.events = append(obs.events,
		xfrmKernelEvent{Action: "delete", Probe: "kprobe:xfrm_state_delete"},
		xfrmKernelEvent{Action: "apply", Probe: "kprobe:xfrm_state_add"},
		xfrmKernelEvent{Action: "apply", Probe: "kprobe:xfrm_policy_insert"},
	)
	meta := obs.annotate(map[string]string{"applied": "true", "xfrm_mode": "apply"}, mark, "apply")
	if meta["ebpf_event_count"] != "2" {
		t.Fatalf("expected two matching apply events, got %s", meta["ebpf_event_count"])
	}
	if meta["ebpf_total_event_count"] != "3" {
		t.Fatalf("expected three total events, got %s", meta["ebpf_total_event_count"])
	}
	if meta["ebpf_matched"] != "true" {
		t.Fatalf("expected matched=true, got %s", meta["ebpf_matched"])
	}
}
