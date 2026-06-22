package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"time"

	"cryptna-lab/common/logutil"
	"cryptna-lab/common/protocol"
)

const (
	xfrmObserverPosthoc = "posthoc"
	xfrmObserverEBPF    = "ebpf"
	xfrmObserverHybrid  = "hybrid"
)

type xfrmObservationPoint struct {
	Index int
	Time  time.Time
}

type xfrmKernelEvent struct {
	ObservedAt time.Time
	Raw        string
	Probe      string
	Action     string
}

type xfrmObserver struct {
	mode      string
	strict    bool
	logEvents bool

	minApplyEvents  int
	minDeleteEvents int

	mu      sync.Mutex
	events  []xfrmKernelEvent
	started bool
	ready   bool
	exited  bool
	exitErr string

	cancel context.CancelFunc
	cmd    *exec.Cmd
}

var globalXFRMObserver *xfrmObserver

func initXFRMObserver() {
	mode := strings.ToLower(getenv("XFRM_OBSERVER", xfrmObserverPosthoc))
	if mode == "" {
		mode = xfrmObserverPosthoc
	}
	if mode != xfrmObserverPosthoc && mode != xfrmObserverEBPF && mode != xfrmObserverHybrid {
		logutil.Infof("pep", "unknown XFRM_OBSERVER=%s, falling back to posthoc", mode)
		mode = xfrmObserverPosthoc
	}

	obs := &xfrmObserver{
		mode:            mode,
		strict:          getenv("XFRM_EBPF_STRICT", "0") == "1",
		logEvents:       getenv("XFRM_EBPF_LOG_EVENTS", "0") == "1",
		minApplyEvents:  getenvInt("XFRM_EBPF_MIN_APPLY_EVENTS", 2),
		minDeleteEvents: getenvInt("XFRM_EBPF_MIN_DELETE_EVENTS", 2),
	}
	globalXFRMObserver = obs

	// Emit this line before launching any external monitor. The smoke test uses
	// it to distinguish a wiring problem from a slow or unavailable eBPF backend.
	logutil.Infof("pep", "XFRM observer startup requested mode=%s strict=%t min_apply_events=%d min_delete_events=%d", obs.mode, obs.strict, obs.minApplyEvents, obs.minDeleteEvents)

	if mode == xfrmObserverPosthoc {
		logutil.Infof("pep", "XFRM observer initialized mode=posthoc strict=%t", obs.strict)
		return
	}

	if err := obs.start(); err != nil {
		if obs.strict {
			logutil.Infof("pep", "XFRM eBPF observer required but unavailable: %v", err)
			panic(err)
		}
		logutil.Infof("pep", "XFRM eBPF observer unavailable, falling back to posthoc: %v", err)
		obs.mode = xfrmObserverPosthoc
		logutil.Infof("pep", "XFRM observer initialized mode=posthoc strict=%t", obs.strict)
		return
	}
	logutil.Infof("pep", "XFRM observer initialized mode=%s strict=%t", obs.mode, obs.strict)
}

func shutdownXFRMObserver() {
	if globalXFRMObserver == nil {
		return
	}
	globalXFRMObserver.stop()
}

func validateXFRMObserverConfiguration() error {
	if pepAttestation == nil || !pepAttestation.enabled {
		return nil
	}
	required := strings.ToLower(strings.TrimSpace(getenv("PEP_REQUIRED_OBSERVER_PROFILE", "posthoc")))
	applyMode := getenv("XFRM_MODE", "dry-run") == "apply"
	if required == "dry-run" {
		if applyMode {
			return fmt.Errorf("dry-run observer profile cannot authorize XFRM apply mode")
		}
		return nil
	}
	if !applyMode {
		return fmt.Errorf("observer profile %q requires XFRM apply mode", required)
	}
	if globalXFRMObserver == nil {
		return fmt.Errorf("XFRM observer is not initialized")
	}
	switch required {
	case "posthoc":
		if globalXFRMObserver.mode != xfrmObserverPosthoc && globalXFRMObserver.mode != xfrmObserverHybrid {
			return fmt.Errorf("posthoc profile is not provided by observer mode %q", globalXFRMObserver.mode)
		}
	case "hybrid":
		if globalXFRMObserver.mode != xfrmObserverHybrid || !globalXFRMObserver.ready {
			return fmt.Errorf("hybrid observer is required but not ready")
		}
	case "ebpf":
		if globalXFRMObserver.mode != xfrmObserverEBPF || !globalXFRMObserver.ready {
			return fmt.Errorf("eBPF observer is required but not ready")
		}
	default:
		return fmt.Errorf("unsupported required observer profile %q", required)
	}
	return nil
}

func markXFRMObservationPoint() xfrmObservationPoint {
	if globalXFRMObserver == nil {
		return xfrmObservationPoint{Time: time.Now()}
	}
	return globalXFRMObserver.mark()
}

func (o *xfrmObserver) mark() xfrmObservationPoint {
	o.mu.Lock()
	defer o.mu.Unlock()
	return xfrmObservationPoint{Index: len(o.events), Time: time.Now()}
}

func (o *xfrmObserver) start() error {
	command := getenv("XFRM_EBPF_COMMAND", "/app/ebpf/xfrm_monitor.sh")
	logutil.Infof("pep", "starting XFRM eBPF observer command=%q", command)
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		return err
	}
	if err := cmd.Start(); err != nil {
		cancel()
		return err
	}

	o.cancel = cancel
	o.cmd = cmd
	o.started = true
	go o.readEvents(stdout)
	go o.readDiagnostics(stderr)
	go func() {
		err := cmd.Wait()
		o.mu.Lock()
		o.exited = true
		if err != nil {
			o.exitErr = err.Error()
		}
		o.mu.Unlock()
		if err != nil && o.strict {
			logutil.Infof("pep", "XFRM eBPF observer exited: %v", err)
		} else if err != nil {
			logutil.Debugf("pep", "XFRM eBPF observer exited: %v", err)
		}
	}()

	// Wait until bpftrace has actually loaded the probes and emitted the BEGIN
	// marker. Without this readiness barrier, the first XFRM apply operation may
	// race ahead of the monitor and be missed in hybrid/strict modes.
	return o.waitReady(5 * time.Second)
}

func (o *xfrmObserver) waitReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		o.mu.Lock()
		ready := o.ready
		exited := o.exited
		exitErr := o.exitErr
		o.mu.Unlock()
		if ready {
			return nil
		}
		if exited {
			if exitErr == "" {
				exitErr = "process exited"
			}
			return fmt.Errorf("eBPF monitor exited before readiness: %s", exitErr)
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("eBPF monitor did not become ready within %s", timeout)
}

func (o *xfrmObserver) stop() {
	if o.cancel != nil {
		o.cancel()
	}
}

func (o *xfrmObserver) readDiagnostics(r io.Reader) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.Contains(line, "cryptna_ebpf_selected") {
			logutil.Infof("pep", "XFRM eBPF selected probes %s", strings.TrimPrefix(line, "cryptna_ebpf_selected "))
			continue
		}
		// Keep diagnostics at info level: bpftrace failures are otherwise hard
		// to diagnose from CI/smoke-test logs when debug logging is disabled.
		logutil.Infof("pep", "xfrm-ebpf stderr: %s", line)
	}
}

func (o *xfrmObserver) readEvents(r io.Reader) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.Contains(line, "cryptna_ebpf_ready") {
			o.mu.Lock()
			o.ready = true
			o.mu.Unlock()
			logutil.Infof("pep", "XFRM eBPF monitor ready")
			continue
		}
		if !strings.Contains(line, "cryptna_xfrm_event") {
			logutil.Debugf("pep", "xfrm-ebpf: %s", line)
			continue
		}
		e := parseXFRMKernelEvent(line)
		o.mu.Lock()
		o.events = append(o.events, e)
		// Keep a bounded in-memory window. Events are also committed to the
		// enforcement history when matched to an intent/observation transaction.
		if len(o.events) > 4096 {
			o.events = append([]xfrmKernelEvent{}, o.events[len(o.events)-2048:]...)
		}
		o.mu.Unlock()
		if o.logEvents {
			logutil.Infof("pep", "xfrm-ebpf event action=%s probe=%s raw=%s", e.Action, e.Probe, e.Raw)
		} else {
			logutil.Debugf("pep", "xfrm-ebpf event action=%s probe=%s raw=%s", e.Action, e.Probe, e.Raw)
		}
	}
}

func parseXFRMKernelEvent(line string) xfrmKernelEvent {
	e := xfrmKernelEvent{ObservedAt: time.Now(), Raw: line, Action: "unknown"}
	for _, field := range strings.Fields(line) {
		if strings.HasPrefix(field, "probe=") {
			e.Probe = strings.TrimPrefix(field, "probe=")
		}
		if strings.HasPrefix(field, "action=") {
			e.Action = strings.TrimPrefix(field, "action=")
		}
	}
	if e.Action == "unknown" {
		probe := strings.ToLower(e.Probe)
		switch {
		case strings.Contains(probe, "delete"), strings.Contains(probe, "del"):
			e.Action = "delete"
		case strings.Contains(probe, "insert"), strings.Contains(probe, "add"), strings.Contains(probe, "update"):
			e.Action = "apply"
		}
	}
	return e
}

func (o *xfrmObserver) eventsSince(mark xfrmObservationPoint) []xfrmKernelEvent {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	start := mark.Index
	if start < 0 || start > len(o.events) {
		start = len(o.events)
	}
	out := append([]xfrmKernelEvent{}, o.events[start:]...)
	return out
}

func (o *xfrmObserver) eventsSinceWithWait(mark xfrmObservationPoint, expectedAction string, timeout time.Duration) []xfrmKernelEvent {
	deadline := time.Now().Add(timeout)
	var events []xfrmKernelEvent
	for {
		events = o.eventsSince(mark)
		for _, e := range events {
			if e.Action == expectedAction {
				return events
			}
		}
		if time.Now().After(deadline) {
			return events
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func (o *xfrmObserver) annotate(meta map[string]string, mark xfrmObservationPoint, expectedAction string) map[string]string {
	if meta == nil {
		meta = map[string]string{}
	}
	meta["observer_mode"] = o.mode
	if meta["xfrm_mode"] != "apply" {
		meta["observer_source"] = "dry-run"
		meta["ebpf_matched"] = "not-applicable"
		return meta
	}
	if o.mode == xfrmObserverPosthoc {
		meta["observer_source"] = "posthoc"
		return meta
	}

	events := o.eventsSinceWithWait(mark, expectedAction, 500*time.Millisecond)
	minEvents := o.minEventsForAction(expectedAction)
	actionEvents := make([]xfrmKernelEvent, 0, len(events))
	probes := make([]string, 0, len(events))
	for _, e := range events {
		if e.Action != expectedAction {
			continue
		}
		actionEvents = append(actionEvents, e)
		if e.Probe != "" {
			probes = append(probes, e.Probe)
		}
	}
	matched := len(actionEvents) >= minEvents

	meta["observer_source"] = "ebpf"
	if o.mode == xfrmObserverHybrid {
		meta["observer_source"] = "posthoc+ebpf"
	}
	// Count only action-matching events in ebpf_event_count. The total count is
	// kept separately because kprobes are global to the kernel and may observe
	// unrelated XFRM activity outside the current PEP transaction.
	meta["ebpf_event_count"] = fmt.Sprintf("%d", len(actionEvents))
	meta["ebpf_total_event_count"] = fmt.Sprintf("%d", len(events))
	meta["ebpf_min_event_count"] = fmt.Sprintf("%d", minEvents)
	meta["ebpf_matched"] = fmt.Sprintf("%t", matched)
	if len(probes) > 0 {
		if len(probes) > 6 {
			probes = probes[:6]
		}
		meta["ebpf_probes"] = strings.Join(probes, ",")
	}

	// In strict eBPF mode, the observed event must come from the kernel-side
	// monitor. In hybrid mode, post-hoc XFRM state checks still determine the
	// applied/deleted outcome, while eBPF provides additional observation data.
	if o.mode == xfrmObserverEBPF {
		switch expectedAction {
		case "apply":
			meta["applied"] = fmt.Sprintf("%t", matched)
		case "delete":
			meta["deleted"] = fmt.Sprintf("%t", matched)
		}
	}
	return meta
}

func (o *xfrmObserver) minEventsForAction(action string) int {
	switch action {
	case "apply":
		if o.minApplyEvents > 0 {
			return o.minApplyEvents
		}
	case "delete":
		if o.minDeleteEvents > 0 {
			return o.minDeleteEvents
		}
	}
	return 1
}

func observeXFRMAppliedWithObserver(s protocol.Session, mark xfrmObservationPoint) map[string]string {
	totalStart := time.Now()
	posthocStart := time.Now()
	meta := observeXFRMAppliedPosthoc(s)
	meta["posthoc_duration_us"] = fmt.Sprintf("%d", time.Since(posthocStart).Microseconds())
	if globalXFRMObserver == nil {
		meta["observer_total_duration_us"] = fmt.Sprintf("%d", time.Since(totalStart).Microseconds())
		return meta
	}
	correlationStart := time.Now()
	meta = globalXFRMObserver.annotate(meta, mark, "apply")
	meta["ebpf_correlation_duration_us"] = fmt.Sprintf("%d", time.Since(correlationStart).Microseconds())
	meta["observer_total_duration_us"] = fmt.Sprintf("%d", time.Since(totalStart).Microseconds())
	logutil.Infof("pep", "xfrm_apply_observed observer_source=%s ebpf_matched=%s ebpf_event_count=%s ebpf_min_event_count=%s posthoc_duration_us=%s ebpf_correlation_duration_us=%s observer_total_duration_us=%s ebpf_probes=%s", meta["observer_source"], meta["ebpf_matched"], meta["ebpf_event_count"], meta["ebpf_min_event_count"], meta["posthoc_duration_us"], meta["ebpf_correlation_duration_us"], meta["observer_total_duration_us"], meta["ebpf_probes"])
	return meta
}

func observeXFRMDeletedWithObserver(s protocol.Session, mark xfrmObservationPoint) map[string]string {
	totalStart := time.Now()
	posthocStart := time.Now()
	meta := observeXFRMDeletedPosthoc(s)
	meta["posthoc_duration_us"] = fmt.Sprintf("%d", time.Since(posthocStart).Microseconds())
	if globalXFRMObserver == nil {
		meta["observer_total_duration_us"] = fmt.Sprintf("%d", time.Since(totalStart).Microseconds())
		return meta
	}
	correlationStart := time.Now()
	meta = globalXFRMObserver.annotate(meta, mark, "delete")
	meta["ebpf_correlation_duration_us"] = fmt.Sprintf("%d", time.Since(correlationStart).Microseconds())
	meta["observer_total_duration_us"] = fmt.Sprintf("%d", time.Since(totalStart).Microseconds())
	logutil.Infof("pep", "xfrm_delete_observed observer_source=%s ebpf_matched=%s ebpf_event_count=%s ebpf_min_event_count=%s posthoc_duration_us=%s ebpf_correlation_duration_us=%s observer_total_duration_us=%s ebpf_probes=%s", meta["observer_source"], meta["ebpf_matched"], meta["ebpf_event_count"], meta["ebpf_min_event_count"], meta["posthoc_duration_us"], meta["ebpf_correlation_duration_us"], meta["observer_total_duration_us"], meta["ebpf_probes"])
	return meta
}
