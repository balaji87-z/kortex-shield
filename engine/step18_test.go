// Step-18 acceptance tests (rule 40: written and committed BEFORE the
// implementation). Test ids are listed in docs/acceptance.md
// (status: failing -> passing).
//
// E22 (T3): a client that is still streaming a body above the inspected
// limit must receive the full 413 response (status 413 and the
// kortex-decision=limit marker), not a connection reset.
package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// TestE22Limit413DeliveredWhileBodyStreaming reproduces the step-17 T4
// ConnectionResetError ids (wcp-1140885081e1, wcp-f83f7556fc66,
// wcp-908ef72be103): the engine takes the limit path while the runner is
// still streaming the body, and the client must still be able to read the
// decision. The remaining body is kept above net/http's ~256KB keep-alive
// drain threshold so the server cannot silently consume it.
func TestE22Limit413DeliveredWhileBodyStreaming(t *testing.T) {
	srv, events := newEnv(t, map[string]string{"KORTEX_MAX_INSPECTED_BYTES": "1024"})
	total := 300 * 1024
	u := strings.TrimPrefix(srv.URL, "http://")
	conn, err := net.Dial("tcp", u)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	head := fmt.Sprintf("POST / HTTP/1.1\r\nHost: localhost\r\n"+
		"X-Kortex-Sample-Id: e22-limit-stream\r\nContent-Type: text/plain\r\n"+
		"Content-Length: %d\r\n\r\n", total)
	if _, err := conn.Write([]byte(head)); err != nil {
		t.Fatalf("write head: %v", err)
	}
	// send just over the inspected limit so the engine takes the limit path
	// while the rest of the body is still unsent
	first := 2048
	if _, err := conn.Write([]byte(strings.Repeat("A", first))); err != nil {
		t.Fatalf("write first chunk: %v", err)
	}
	time.Sleep(300 * time.Millisecond) // the engine answers 413 here
	// keep streaming the rest of the body; a reset on this write is the bug
	// under test (the client must be able to finish sending and read the
	// decision)
	rest := strings.Repeat("B", total-first)
	if _, err := conn.Write([]byte(rest)); err != nil {
		t.Fatalf("E22: connection reset while the client was still streaming "+
			"the body (write: %v); the 413 decision never reached the client", err)
	}
	// the response must arrive complete, and the close must be clean (EOF),
	// not a reset that discards the response
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var out []byte
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		out = append(out, buf[:n]...)
		if err != nil {
			if strings.Contains(err.Error(), "reset") {
				t.Fatalf("E22: read failed with connection reset after %d bytes; "+
					"the 413 response was not delivered intact", len(out))
			}
			break // EOF or deadline with the response already read
		}
	}
	s := string(out)
	status := 0
	if i := strings.Index(s, "\r\n"); i > 0 {
		fmt.Sscanf(s[:i], "HTTP/1.1 %d", &status)
	}
	if status != 413 {
		t.Fatalf("E22: want 413, got %d (raw start: %q)", status, s[:min(120, len(s))])
	}
	if !strings.Contains(s, "kortex-decision=limit") {
		t.Fatalf("E22: response missing kortex-decision=limit marker: %q", s)
	}
	evData := strings.Join(readEventsFile(t, events), "\n")
	if !strings.Contains(evData, `"limit"`) {
		t.Fatalf("E22: limit decision not logged to the events file")
	}
}

func readEventsFile(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read events: %v", err)
	}
	return strings.Split(string(data), "\n")
}
