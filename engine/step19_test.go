package main

import (
	"net/http"
	"os"
	"strings"
	"testing"
)

// E27: every evaluated request must leave a decision event in
// kortex-events.jsonl — "block" with the matched rule ids, or "pass" — so a
// silent engine error can never look like a pass and flip rounds leave a
// per-request trail (step-19 T1).
func TestE27BlockAndPassEventsLogged(t *testing.T) {
	srv, events := newEnv(t, nil)
	// blocked: query-based 942100 at PL1
	resp := get(t, srv, "/?id=1'%20OR%20'1'='1", nil, "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
	ev := eventsContains(t, events, "block")
	if ev["decision"] != "block" {
		t.Fatalf("expected block event, got %v", ev)
	}
	reason, _ := ev["reason"].(string)
	if !strings.Contains(reason, "rules=") || strings.HasSuffix(reason, "rules=") {
		t.Fatalf("block event must carry matched rule ids, got %q", reason)
	}
	// passed: benign request forwarded to the stub
	resp2 := get(t, srv, "/benign", nil, "")
	resp2.Body.Close()
	ev2 := eventsContains(t, events, "pass")
	if ev2["decision"] != "pass" {
		t.Fatalf("expected pass event, got %v", ev2)
	}
}

// E28: KORTEX_CORAZA_DEBUG_LEVEL wires a coraza debug logger writing to
// KORTEX_CORAZA_DEBUG_FILE (DIAGNOSTIC tooling for the step-19 T1 flip
// investigation; default off = nop). A request under trace level must
// produce coraza debug lines in the file.
func TestE28CorazaDebugLoggerWiring(t *testing.T) {
	dir := t.TempDir()
	dbg := dir + "/coraza-debug.log"
	srv, _ := newEnv(t, map[string]string{
		"KORTEX_CORAZA_DEBUG_LEVEL": "trace",
		"KORTEX_CORAZA_DEBUG_FILE":  dbg,
	})
	resp := get(t, srv, "/?id=1", nil, "")
	resp.Body.Close()
	data, err := os.ReadFile(dbg)
	if err != nil {
		t.Fatalf("read debug file: %v", err)
	}
	if !strings.Contains(string(data), "Evaluating phase") {
		t.Fatalf("expected coraza debug lines in %s, got %d bytes", dbg, len(data))
	}
}
