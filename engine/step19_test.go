package main

import (
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
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

// E29 (step-19 T3, FAILING BY DESIGN): while all in-flight body-processing
// slots are held by slow bodies, a benign body-bearing POST must still be
// answered (forwarded), not rejected with 503 overload. Today the engine
// starves it (0/131 benign POSTs served during the step-19 T3 attack run,
// docs/logs/step19-t3-availability.txt). No fix is proposed in step-19;
// the instructor chooses. Test-first per the step-19 instruction.
func TestE29BenignPOSTServedWhileSlotsHeld(t *testing.T) {
	budget := os.Getenv("KORTEST_T3_SLOW_MS")
	_ = budget
	srv, _ := newEnv(t, map[string]string{
		"KORTEX_MAX_INFLIGHT_BODY":     "8",
		"KORTEX_ENGINE_TIME_BUDGET_MS": "100",
	})
	// 16 KB text/plain body: processing (~0.6 s) exceeds the 100 ms budget,
	// so each attacker holds a slot and the call runs abandoned.
	slow := strings.Repeat("a*b|c$d", 2300) // ~16 KB, no newline-split tricks
	slow = slow[:16100]
	type result struct {
		status int
	}
	attackerDone := make(chan result, 8)
	for i := 0; i < 8; i++ {
		go func() {
			resp := get(t, srv, "/attack", map[string]string{"Content-Type": "text/plain"}, slow)
			resp.Body.Close()
			attackerDone <- result{resp.StatusCode}
		}()
	}
	// give the attackers time to acquire all 8 slots and start processing
	time.Sleep(150 * time.Millisecond)
	resp := get(t, srv, "/benign", map[string]string{"Content-Type": "application/json"}, `{"k0":"v"}`)
	resp.Body.Close()
	if resp.StatusCode == http.StatusServiceUnavailable {
		t.Fatalf("benign body-bearing POST starved: got 503 overload while slots held by slow bodies")
	}
	for i := 0; i < 8; i++ {
		<-attackerDone
	}
}
