package main

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// Event is one line of kortex-events.jsonl. Per the step-15 scope, limit,
// framing and timeout decisions are always logged.
type Event struct {
	TS        string  `json:"ts"`
	SampleID  string  `json:"sample_id"`
	Decision  string  `json:"decision"`
	Status    int     `json:"status"`
	ElapsedMS float64 `json:"elapsed_ms"`
	Reason    string  `json:"reason"`
}

type eventLogger struct {
	mu   sync.Mutex
	path string
}

func newEventLogger(path string) *eventLogger { return &eventLogger{path: path} }

func (l *eventLogger) log(sampleID, decision string, status int, start time.Time, reason string) {
	if l == nil {
		return
	}
	ev := Event{
		TS:        time.Now().UTC().Format(time.RFC3339Nano),
		SampleID:  sampleID,
		Decision:  decision,
		Status:    status,
		ElapsedMS: float64(time.Since(start).Microseconds()) / 1000.0,
		Reason:    reason,
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "kortex-engine: events open failed: %v\n", err)
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "{\"ts\":%q,\"sample_id\":%q,\"decision\":%q,\"status\":%d,\"elapsed_ms\":%.3f,\"reason\":%q}\n",
		ev.TS, ev.SampleID, ev.Decision, ev.Status, ev.ElapsedMS, ev.Reason)
}
