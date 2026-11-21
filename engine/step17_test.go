// Step-17 acceptance tests (rule 40: written and committed BEFORE the
// implementation). Test ids E18..E21 are listed in docs/acceptance.md
// (status: failing -> passing).
//
// E18 method allow-list: PUT/DELETE/PATCH are rejected with the block
// decision and CRS 911100 under the default policy (GET HEAD POST OPTIONS,
// mirroring the connector's crs-setup rule 900200), and pass when the
// policy includes them (KORTEX_ALLOWED_METHODS).
// E19 overload cap: when the concurrent in-flight body-processing cap is
// reached, a further body-bearing request is answered 503
// kortex-decision=overload within 50 ms and the decision is logged to
// kortex-events.jsonl.
// E20 overload recovery: after the in-flight (abandoned) calls finish, new
// body-bearing requests are inspected again (no longer overload).
// E21 benign on a cap-reached engine: a body-less benign request still
// returns promptly (it needs no body-processing slot).
package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func e18Do(t *testing.T, srv *httptest.Server, method, id string) (*http.Response, string) {
	t.Helper()
	var body io.Reader
	if method != "GET" {
		body = bytes.NewReader([]byte("{}"))
	}
	req, err := http.NewRequest(method, srv.URL+"/rest/user/login", body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = "localhost:8090"
	req.Header.Set("X-Kortex-Sample-Id", id)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, string(b)
}

// E18: methods outside the default policy are blocked with 911100; methods
// inside a widened policy pass to the backend.
func TestE18MethodAllowList(t *testing.T) {
	srv, _ := newEnv(t, nil)
	for _, m := range []string{"PUT", "DELETE", "PATCH"} {
		resp, body := e18Do(t, srv, m, "e18-"+strings.ToLower(m))
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("E18: %s: want 403 block, got %d body=%q", m, resp.StatusCode, body)
		}
		if !strings.Contains(body, "kortex-decision=block") {
			t.Fatalf("E18: %s: missing block marker: %q", m, body)
		}
		if !strings.Contains(body, "911100") {
			t.Fatalf("E18: %s: block rules missing 911100: %q", m, body)
		}
	}
	// widened policy: the same methods pass
	backendHit = false
	srv2, _ := newEnv(t, map[string]string{
		"KORTEX_ALLOWED_METHODS": "GET HEAD POST OPTIONS PUT DELETE PATCH",
	})
	for _, m := range []string{"PUT", "DELETE", "PATCH"} {
		resp, body := e18Do(t, srv2, m, "e18-ok-"+strings.ToLower(m))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("E18 widened: %s: want 200 from the stub, got %d body=%q", m, resp.StatusCode, body)
		}
	}
	if !backendHit {
		t.Fatalf("E18 widened: requests did not reach the backend")
	}
}

// e17Fixture returns the recorded wcp body (rule 25: never committed).
func e17Fixture(t *testing.T) []byte {
	t.Helper()
	bodyPath := os.Getenv("KORTEX_TEST_WCP_BODY")
	if bodyPath == "" {
		t.Skip("KORTEX_TEST_WCP_BODY not set (recorded 481,798-byte wcp body)")
	}
	body, err := os.ReadFile(bodyPath)
	if err != nil {
		t.Fatalf("read wcp body: %v", err)
	}
	if len(body) != 481798 {
		t.Fatalf("unexpected fixture size %d (want 481798)", len(body))
	}
	return body
}

// e19StartOccupy sends one wcp-body request whose abandoned body processing
// keeps running for tens of seconds after its fast 503, filling the single
// in-flight slot (cap=1).
func e19StartOccupy(t *testing.T, srv *httptest.Server, id string) {
	t.Helper()
	body := e17Fixture(t)
	go func() {
		req, err := http.NewRequest("POST", srv.URL+"/", bytes.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("X-Kortex-Sample-Id", id)
		req.Header.Set("Content-Type", "text/plain")
		resp, err := srv.Client().Do(req)
		if err != nil {
			return
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()
	// wait until the occupier is answered (503 timeout, processing abandoned
	// and still running) - its event row is the signal
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(e19Events(t), id) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("occupier %s was not answered within 10s", id)
}

func e19Events(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(os.Getenv("KORTEX_EVENTS_FILE"))
	if err != nil {
		return ""
	}
	return string(b)
}

// E19: cap reached -> the next body-bearing request gets 503
// kortex-decision=overload within 50 ms, and the decision is logged.
func TestE19OverloadCapImmediate(t *testing.T) {
	srv, _ := newEnv(t, map[string]string{
		"KORTEX_MAX_INSPECTED_BYTES":   "13107200",
		"KORTEX_ENGINE_TIME_BUDGET_MS": "200",
		"KORTEX_MAX_INFLIGHT_BODY":     "1",
		// lanes (step-20 T2): pin everything into the SMALL lane so the
		// single-cap overload semantics under test are unchanged
		"KORTEX_BODY_LANE_THRESHOLD": "13107200",
	})
	e19StartOccupy(t, srv, "e19-occupier")
	start := time.Now()
	req, err := http.NewRequest("POST", srv.URL+"/rest/user/login", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = "localhost:8090"
	req.Header.Set("X-Kortex-Sample-Id", "e19-second")
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	elapsed := time.Since(start)
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 503 || !strings.Contains(string(b), "kortex-decision=overload") {
		t.Fatalf("E19: want 503 kortex-decision=overload, got %d body=%q", resp.StatusCode, string(b))
	}
	if elapsed > 50*time.Millisecond {
		t.Fatalf("E19: overload answer took %s, want <= 50ms", elapsed)
	}
	if !strings.Contains(e19Events(t), "overload") {
		t.Fatalf("E19: overload decision not logged to the events file")
	}
}

// E20: after the abandoned call finishes, new body-bearing requests are
// inspected again (the slot is released; the request passes or is blocked
// by rules, not overload).
func TestE20OverloadRecovery(t *testing.T) {
	srv, _ := newEnv(t, map[string]string{
		"KORTEX_MAX_INSPECTED_BYTES":   "13107200",
		"KORTEX_ENGINE_TIME_BUDGET_MS": "200",
		"KORTEX_MAX_INFLIGHT_BODY":     "1",
		// lanes (step-20 T2): pin everything into the SMALL lane so the
		// single-cap overload semantics under test are unchanged
		"KORTEX_BODY_LANE_THRESHOLD": "13107200",
	})
	e19StartOccupy(t, srv, "e20-occupier")
	// poll until the occupier's abandoned call has finished (event row),
	// then a new body-bearing request must be inspected (not overload)
	deadline := time.Now().Add(120 * time.Second)
	for {
		if strings.Contains(e19Events(t), "abandoned-body-processing-finished") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("E20: abandoned call did not finish within 120s")
		}
		time.Sleep(500 * time.Millisecond)
	}
	req, err := http.NewRequest("POST", srv.URL+"/rest/user/login", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = "localhost:8090"
	req.Header.Set("X-Kortex-Sample-Id", "e20-after")
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(b), "kortex-decision=overload") {
		t.Fatalf("E20: request after the abandoned call finished still got overload: %q", string(b))
	}
}

// E21: a body-less benign request on a cap-reached engine still returns
// promptly (body-less requests need no body-processing slot).
func TestE21BenignPromptOnCapReachedEngine(t *testing.T) {
	srv, _ := newEnv(t, map[string]string{
		"KORTEX_MAX_INSPECTED_BYTES":   "13107200",
		"KORTEX_ENGINE_TIME_BUDGET_MS": "200",
		"KORTEX_MAX_INFLIGHT_BODY":     "1",
		// lanes (step-20 T2): pin everything into the SMALL lane so the
		// single-cap overload semantics under test are unchanged
		"KORTEX_BODY_LANE_THRESHOLD": "13107200",
	})
	e19StartOccupy(t, srv, "e21-occupier")
	start := time.Now()
	resp := get(t, srv, "/?q=hello", nil, "")
	elapsed := time.Since(start)
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("E21: want 200 for a body-less benign request, got %d body=%q", resp.StatusCode, string(b))
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("E21: benign request took %s on a cap-reached engine, want <= 500ms", elapsed)
	}
}
