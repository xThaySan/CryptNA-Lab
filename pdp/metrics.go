package main

import (
	"encoding/csv"
	"net/http"
	"strconv"
	"sync"
	"time"
)

type spaMetric struct {
	Seq         uint64
	StartUnixNS int64
	Scenario    string
	Outcome     string
	DurationUS  int64
	PacketSize  int
	Error       string
}

type spaMetrics struct {
	mu     sync.Mutex
	next   uint64
	max    int
	events []spaMetric
}

var globalSPAMetrics = &spaMetrics{max: 200000}

func recordSPAMetric(scenario, outcome string, start time.Time, packetSize int, err error) {
	errorText := ""
	if err != nil {
		errorText = err.Error()
	}

	globalSPAMetrics.mu.Lock()
	defer globalSPAMetrics.mu.Unlock()

	globalSPAMetrics.next++

	ev := spaMetric{
		Seq:         globalSPAMetrics.next,
		StartUnixNS: start.UnixNano(),
		Scenario:    scenario,
		Outcome:     outcome,
		DurationUS:  time.Since(start).Microseconds(),
		PacketSize:  packetSize,
		Error:       errorText,
	}

	if len(globalSPAMetrics.events) >= globalSPAMetrics.max {
		copy(globalSPAMetrics.events, globalSPAMetrics.events[1:])
		globalSPAMetrics.events[len(globalSPAMetrics.events)-1] = ev
		return
	}

	globalSPAMetrics.events = append(globalSPAMetrics.events, ev)
}

func registerSPAMetricHandlers() {
	http.HandleFunc("/metrics/spa/reset", func(w http.ResponseWriter, r *http.Request) {
		globalSPAMetrics.mu.Lock()
		globalSPAMetrics.next = 0
		globalSPAMetrics.events = nil
		globalSPAMetrics.mu.Unlock()

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok\n"))
	})

	http.HandleFunc("/metrics/spa/raw", func(w http.ResponseWriter, r *http.Request) {
		globalSPAMetrics.mu.Lock()
		events := append([]spaMetric(nil), globalSPAMetrics.events...)
		globalSPAMetrics.mu.Unlock()

		w.Header().Set("Content-Type", "text/csv")

		cw := csv.NewWriter(w)
		defer cw.Flush()

		cw.Write([]string{
			"seq",
			"start_unix_ns",
			"scenario",
			"outcome",
			"duration_us",
			"packet_size",
			"error",
		})

		for _, ev := range events {
			cw.Write([]string{
				strconv.FormatUint(ev.Seq, 10),
				strconv.FormatInt(ev.StartUnixNS, 10),
				ev.Scenario,
				ev.Outcome,
				strconv.FormatInt(ev.DurationUS, 10),
				strconv.Itoa(ev.PacketSize),
				ev.Error,
			})
		}
	})
}
