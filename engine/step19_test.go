package main

import (
	"io"
	"net/http"
	"os"
	"runtime"
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
// E29 (step-20 T2 rewrite, deterministic per rule 48): eight attackers
// hold body-processing slots via the test hook (KORTEX_TEST_HOLD_BODY_MS
// + X-Kortex-Test-Hold, large 100,000-B bodies, budget 30 s so the hold
// is not abandoned). Each attacker RETRIES on 503 until it holds a slot
// (a loser of the startup race must not silently shrink the attack to 7
// slots). A probe (large body, NO hook header) is then polled until it
// returns 503 — deterministic proof that every slot of the attacker's
// lane is held. Then a benign SMALL POST must still be served: non-503
// AND the backend must have received it. FAILS against the pre-lane
// engine (single global cap: the benign request 503s); PASSES once
// lanes isolate the large lane from the small one.
func TestE29BenignPOSTServedWhileSlotsHeld(t *testing.T) {
	srv, events := newEnv(t, map[string]string{
		"KORTEX_MAX_INFLIGHT_BODY":       "8",
		"KORTEX_MAX_INFLIGHT_BODY_LARGE": "2",
		"KORTEX_BODY_LANE_THRESHOLD":     "65536",
		"KORTEX_TEST_HOLD_BODY_MS":       "15000",
		"KORTEX_ENGINE_TIME_BUDGET_MS":   "30000",
	})
	big := strings.Repeat("x", 100000) // > lane threshold, <= inspected limit
	attackerDone := make(chan int, 8)
	for i := 0; i < 8; i++ {
		go func() {
			st := 0
			for try := 0; try < 200; try++ {
				resp := get(t, srv, "/attack", map[string]string{
					"Content-Type":       "text/plain",
					"X-Kortex-Test-Hold": "1",
				}, big)
				io.Copy(io.Discard, resp.Body)
				st = resp.StatusCode
				resp.Body.Close()
				if st != http.StatusServiceUnavailable {
					break // slot held for 15 s from here
				}
				time.Sleep(50 * time.Millisecond)
			}
			attackerDone <- st
		}()
	}
	// gate: probe until the attacker's lane is provably full (503). Probes
	// carry no hook header, so a probe that acquires a slot releases it at
	// once; bounded loop, deterministic outcome while the 8 holds last.
	gate := false
	for i := 0; i < 40; i++ {
		resp := get(t, srv, "/probe", map[string]string{"Content-Type": "text/plain"}, big)
		io.Copy(io.Discard, resp.Body)
		st := resp.StatusCode
		resp.Body.Close()
		if st == http.StatusServiceUnavailable {
			gate = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !gate {
		t.Fatalf("probe never observed a full lane: attackers did not hold slots")
	}
	// benign small POST must be served while the attacker lane is full
	// (sent BEFORE joining the attackers: the holds must still be active)
	resp := get(t, srv, "/benign", map[string]string{"Content-Type": "application/json"}, `{"k0":"v"}`)
	io.Copy(io.Discard, resp.Body)
	benignStatus := resp.StatusCode
	resp.Body.Close()
	attStatuses := make([]int, 8)
	for i := 0; i < 8; i++ {
		attStatuses[i] = <-attackerDone
	}
	if benignStatus == http.StatusServiceUnavailable {
		t.Fatalf("benign small POST starved (503) while the attacker lane was full: lanes not effective")
	}
	if !backendHit {
		t.Fatalf("benign small POST never reached the backend")
	}
	if ev, err := os.ReadFile(events); err == nil {
		t.Logf("events-timeline:\n%s", string(ev))
	}
}

// E30 (step-20 T1, FAILING BY DESIGN against coraza v3.7.0 — rule 40): a
// duplicate-name request (two same-named `filter` params with different
// values, the step-19 T1 flip reproducer wcp-62cd1bd36bf7) must give the
// SAME outcome on every one of N>=2000 replays with runtime.GC() between
// rounds. The transformation-cache defect makes a fraction of rounds pass
// (median 114/500 in tools/flip_repro.py). Zero flips required. Deterministic
// failure gate per rule 48: no timing luck involved — the defect is
// probabilistic per transaction and 2000 rounds make a passing build
// indistinguishable from a fixed one (median flip rate 23% >> 0).
func TestE30DuplicateArgZeroFlips(t *testing.T) {
	const N = 2000
	srv, _ := newEnv(t, map[string]string{
		"KORTEX_BLOCKING_PARANOIA":  "2",
		"KORTEX_DETECTION_PARANOIA": "2",
	})
	// wcp-62cd1bd36bf7 verbatim query (benign e-commerce search; no credentials)
	target := "/21705619e273429e5767eea44ccb1ad5/ss-unbxd-auk-extra-saudi-en-prod11541714990488/search" +
		"?q=*&filter=sellingOutFastCities_uFilter%3A%22SA-riyadh%22+OR+inStockCities_uFilter%3A%22SA-riyadh%22" +
		"&filter=productCode_uFilter%3A%22100348880%22+OR+productCode_uFilter%3A%22100350680%22+OR+productCode_uFilter%3A%22100067959%22" +
		"+OR+productCode_uFilter%3A%22100208269%22+OR+productCode_uFilter%3A%22100612854%22"
	flips := 0
	blocked := 0
	timeouts := 0
	for i := 0; i < N; i++ {
		runtime.GC()
		resp := get(t, srv, target, nil, "")
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusForbidden:
			blocked++
		case http.StatusServiceUnavailable:
			// 503 = engine time budget expired. Under CPU contention (other
			// tests' leftover goroutines, desktop load) a replay can time out
			// WITHOUT any cache flip. Counting it as a flip made this test
			// load-dependent (rule 48 violation, found in the step-20 full
			// suite run: 8/2000 "flips" that were 503s under a stray-engine
			// CPU burn). A genuine flip is a 200 pass-through.
			timeouts++
		default:
			flips++
		}
	}
	if flips > 0 {
		t.Fatalf("duplicate-arg flip defect: %d/%d rounds passed (must be 0); blocked=%d timeouts=%d", flips, N, blocked, timeouts)
	}
	if timeouts > N/10 {
		t.Fatalf("E30 environment too noisy to prove the flip fix: %d/%d timeouts (want <= %d)", timeouts, N, N/10)
	}
	t.Logf("E30: blocked=%d flips=%d timeouts=%d of %d", blocked, flips, timeouts, N)
}
