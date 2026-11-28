package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// readEvents returns every line of the events file as a decoded event; a
// missing file is no events.
func readEvents(t *testing.T, eventsFile string) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(eventsFile)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatalf("read events: %v", err)
	}
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var ev map[string]any
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("bad event line %q: %v", line, err)
		}
		out = append(out, ev)
	}
	return out
}

// E35: every refusal of the framing gate writes one event to
// kortex-events.jsonl (decision "framing", status 400, the gate's reason and
// the request's sample id). Found in step 22 (C6): the gate answered 400
// and wrote nothing, while events.go and docs/block-discriminator.md say
// framing decisions are always logged. The refusal is synchronous: the event
// is written before the 400 is sent, so it can be read as soon as the
// response is.
func TestE35FramingRefusalLogsEvent(t *testing.T) {
	cases := []struct {
		id, raw, reason string
	}{
		{"e35-conflict", "POST / HTTP/1.1\r\nHost: localhost\r\nX-Kortex-Sample-Id: e35-conflict\r\n" +
			"Content-Length: 5\r\nContent-Length: 6\r\n\r\nhello", "conflicting-content-length"},
		{"e35-duplicate", "POST / HTTP/1.1\r\nHost: localhost\r\nX-Kortex-Sample-Id: e35-duplicate\r\n" +
			"Content-Length: 5\r\nContent-Length: 5\r\n\r\nhello", "duplicate-content-length"},
		{"e35-te-cl", "POST / HTTP/1.1\r\nHost: localhost\r\nX-Kortex-Sample-Id: e35-te-cl\r\n" +
			"Transfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n", "transfer-encoding-with-content-length"},
		{"e35-nul", "GET /?q=a\x00b HTTP/1.1\r\nHost: localhost\r\nX-Kortex-Sample-Id: e35-nul\r\n\r\n", "nul-in-target"},
		// a refusal must be logged even when the request names no sample id
		{"", "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nx", "conflicting-content-length"},
	}
	for _, c := range cases {
		name := c.id
		if name == "" {
			name = "no-sample-id"
		}
		t.Run(name, func(t *testing.T) {
			srv, events := newEnv(t, nil)
			resp := rawRequest(t, srv, c.raw)
			if resp.status != 400 || !strings.Contains(resp.body, "kortex-decision=framing") {
				t.Fatalf("E35 precondition: want the gate's 400 framing answer, got %d %q", resp.status, resp.body)
			}
			if backendHit {
				t.Fatalf("E35: request must not reach the backend")
			}
			var framing []map[string]any
			for _, ev := range readEvents(t, events) {
				if ev["decision"] == "framing" {
					framing = append(framing, ev)
				}
			}
			if len(framing) != 1 {
				t.Fatalf("E35: want exactly 1 framing event for the refused request, got %d (events: %v)",
					len(framing), readEvents(t, events))
			}
			ev := framing[0]
			if ev["status"] != float64(400) {
				t.Fatalf("E35: event status: want 400, got %v", ev["status"])
			}
			if ev["reason"] != c.reason {
				t.Fatalf("E35: event reason: want %q, got %v", c.reason, ev["reason"])
			}
			if ev["sample_id"] != c.id {
				t.Fatalf("E35: event sample_id: want %q, got %v", c.id, ev["sample_id"])
			}
		})
	}
}

// E36: the canary for E35. A request the gate lets through writes no framing
// event, so E35's event is tied to the refusal and not to every connection.
func TestE36PassedRequestWritesNoFramingEvent(t *testing.T) {
	srv, events := newEnv(t, nil)
	resp := rawRequest(t, srv, "POST / HTTP/1.1\r\nHost: localhost\r\nX-Kortex-Sample-Id: e36-ok\r\n"+
		"Content-Type: text/plain\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
	if resp.status != 200 {
		t.Fatalf("E36 precondition: want 200 from the stub, got %d %q", resp.status, resp.body)
	}
	for _, ev := range readEvents(t, events) {
		if ev["decision"] == "framing" {
			t.Fatalf("E36: a passed request wrote a framing event: %v", ev)
		}
	}
}
