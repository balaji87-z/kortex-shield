// Step-15 T5 acceptance tests (rule 37: written and committed BEFORE the
// implementation). Test ids E1..E9 are listed in docs/acceptance.md.
//
// E1 conflicting or duplicate Content-Length rejected
// E2 Transfer-Encoding with Content-Length rejected
// E3 raw NUL in path or query rejected
// E4 body over the inspected limit rejected without reaching the engine
// E5 body at the limit inspected
// E6 time budget expiry returns 503 and is logged
// E7 a known SQLi in the query blocked at PL1
// E8 a benign request passed to the stub
// E9 the admin endpoint is unreachable from a non-loopback address
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// stub backend: records that the request REACHED the backend and answers 200.
var backendHit bool

func newEnv(t *testing.T, overrides map[string]string) (*httptest.Server, string) {
	t.Helper()
	backendHit = false
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendHit = true
		io.Copy(io.Discard, r.Body)
		fmt.Fprint(w, "stub-ok")
	}))
	t.Cleanup(stub.Close)

	dir := t.TempDir()
	events := filepath.Join(dir, "kortex-events.jsonl")
	audit := filepath.Join(dir, "audit.log")
	env := map[string]string{
		"KORTEX_BACKEND_URL":          stub.URL,
		"KORTEX_RULES_DIR":            rulesDirForTests(),
		"KORTEX_RULE_ENGINE":          "On",
		"KORTEX_BLOCKING_PARANOIA":    "1",
		"KORTEX_DETECTION_PARANOIA":   "1",
		"KORTEX_MAX_BODY_BYTES":       "13107200",
		"KORTEX_MAX_INSPECTED_BYTES":  "131072",
		"KORTEX_ENGINE_TIME_BUDGET_MS": "2000",
		"KORTEX_LISTEN_ADDR":          "127.0.0.1:0",
		"KORTEX_EVENTS_FILE":          events,
		"KORTEX_AUDIT_LOG":            audit,
	}
	for k, v := range overrides {
		env[k] = v
	}
	for k, v := range env {
		t.Setenv(k, v)
	}
	// engine server behind the framing gate (the gate runs on the raw
	// connection before Go's HTTP parser, as in main())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &httptest.Server{
		Listener: &gatedListener{Listener: ln, gateTimeout: 30 * time.Second},
		Config:   &http.Server{Handler: buildHandler(loadConfig())},
	}
	srv.Start()
	t.Cleanup(srv.Close)
	return srv, events
}

func rulesDirForTests() string {
	// engine/crs is the copied CRS set; tests run from the engine/ package dir
	if _, err := os.Stat("crs/owasp-crs/rules"); err == nil {
		return "crs"
	}
	return "../crs"
}

func get(t *testing.T, srv *httptest.Server, target string, hdr map[string]string, body string) *http.Response {
	t.Helper()
	var req *http.Request
	var err error
	if body == "" {
		req, err = http.NewRequest("GET", srv.URL+target, nil)
	} else {
		req, err = http.NewRequest("POST", srv.URL+target, strings.NewReader(body))
	}
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	// http.Transport strips/normalises some headers; for framing tests we need
	// raw control, so use a one-shot connection write instead when needed.
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func eventsContains(t *testing.T, eventsFile, decision string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(eventsFile)
	if err != nil {
		t.Fatalf("read events: %v", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var ev map[string]any
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("bad event line %q: %v", line, err)
		}
		if ev["decision"] == decision {
			return ev
		}
	}
	t.Fatalf("no %q event in %s", decision, string(data))
	return nil
}

// --- E1: conflicting or duplicate Content-Length rejected --------------------
func TestE1DuplicateContentLengthRejected(t *testing.T) {
	srv, _ := newEnv(t, nil)
	// raw socket write: two Content-Length headers with different values
	raw := "POST / HTTP/1.1\r\nHost: localhost\r\nX-Kortex-Sample-Id: e1-dup\r\n" +
		"Content-Length: 5\r\nContent-Length: 6\r\n\r\nhello"
	resp := rawRequest(t, srv, raw)
	if resp.status != 400 {
		t.Fatalf("E1: want 400, got %d body=%q", resp.status, resp.body)
	}
	if !strings.Contains(resp.body, "kortex-decision=framing") {
		t.Fatalf("E1: body missing framing marker: %q", resp.body)
	}
	if backendHit {
		t.Fatalf("E1: request must not reach the backend")
	}
}

// --- E2: Transfer-Encoding with Content-Length rejected ----------------------
func TestE2TEWithCLRejected(t *testing.T) {
	srv, _ := newEnv(t, nil)
	raw := "POST / HTTP/1.1\r\nHost: localhost\r\nX-Kortex-Sample-Id: e2-tecl\r\n" +
		"Transfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n"
	resp := rawRequest(t, srv, raw)
	if resp.status != 400 {
		t.Fatalf("E2: want 400, got %d body=%q", resp.status, resp.body)
	}
	if !strings.Contains(resp.body, "kortex-decision=framing") {
		t.Fatalf("E2: body missing framing marker: %q", resp.body)
	}
	if backendHit {
		t.Fatalf("E2: request must not reach the backend")
	}
}

// --- E3: raw NUL in path or query rejected -----------------------------------
func TestE3RawNulInQueryRejected(t *testing.T) {
	srv, _ := newEnv(t, nil)
	raw := "GET /?q=a\x00b HTTP/1.1\r\nHost: localhost\r\nX-Kortex-Sample-Id: e3-nul\r\n\r\n"
	resp := rawRequest(t, srv, raw)
	if resp.status != 400 {
		t.Fatalf("E3: want 400, got %d body=%q", resp.status, resp.body)
	}
	if !strings.Contains(resp.body, "kortex-decision=framing") {
		t.Fatalf("E3: body missing framing marker: %q", resp.body)
	}
	if backendHit {
		t.Fatalf("E3: request must not reach the backend")
	}
}

// --- E4: body over the inspected limit rejected without reaching the engine --
func TestE4BodyOverInspectedLimitRejected(t *testing.T) {
	srv, events := newEnv(t, map[string]string{"KORTEX_MAX_INSPECTED_BYTES": "100"})
	body := strings.Repeat("A", 101)
	resp := get(t, srv, "/", map[string]string{"X-Kortex-Sample-Id": "e4-over", "Content-Type": "text/plain"}, body)
	if resp.StatusCode != 413 {
		t.Fatalf("E4: want 413, got %d", resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), "kortex-decision=limit") {
		t.Fatalf("E4: body missing limit marker: %q", string(b))
	}
	if backendHit {
		t.Fatalf("E4: request must not reach the backend")
	}
	eventsContains(t, events, "limit")
}

// --- E5: body at the limit inspected -----------------------------------------
func TestE5BodyAtLimitInspected(t *testing.T) {
	srv, _ := newEnv(t, map[string]string{"KORTEX_MAX_INSPECTED_BYTES": "100"})
	body := strings.Repeat("A", 100)
	resp := get(t, srv, "/", map[string]string{"X-Kortex-Sample-Id": "e5-at", "Content-Type": "text/plain"}, body)
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("E5: want 200 (body reaches engine then stub), got %d body=%q", resp.StatusCode, string(b))
	}
	if !backendHit {
		t.Fatalf("E5: request must reach the backend")
	}
}

// --- E6: time budget expiry returns 503 and is logged ------------------------
func TestE6TimeBudgetExpiryReturns503AndLogged(t *testing.T) {
	srv, events := newEnv(t, map[string]string{"KORTEX_ENGINE_TIME_BUDGET_MS": "0"})
	body := strings.Repeat("A", 4096)
	resp := get(t, srv, "/", map[string]string{"X-Kortex-Sample-Id": "e6-timeout", "Content-Type": "text/plain"}, body)
	if resp.StatusCode != 503 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("E6: want 503, got %d body=%q", resp.StatusCode, string(b))
	}
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), "kortex-decision=timeout") {
		t.Fatalf("E6: body missing timeout marker: %q", string(b))
	}
	if backendHit {
		t.Fatalf("E6: request must not reach the backend")
	}
	ev := eventsContains(t, events, "timeout")
	if ev["sample_id"] != "e6-timeout" {
		t.Fatalf("E6: event sample_id = %v", ev["sample_id"])
	}
}

// --- E7: a known SQLi in the query blocked at PL1 ----------------------------
func TestE7SQLiInQueryBlockedAtPL1(t *testing.T) {
	srv, _ := newEnv(t, nil)
	resp := get(t, srv, "/?q=%27%20OR%201%3D1--", map[string]string{"X-Kortex-Sample-Id": "e7-sqli"}, "")
	if resp.StatusCode != 403 {
		t.Fatalf("E7: want 403, got %d", resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), "kortex-decision=block") {
		t.Fatalf("E7: body missing block marker: %q", string(b))
	}
	if backendHit {
		t.Fatalf("E7: request must not reach the backend")
	}
}

// --- E8: a benign request passed to the stub ---------------------------------
func TestE8BenignRequestPassedToStub(t *testing.T) {
	srv, _ := newEnv(t, nil)
	resp := get(t, srv, "/?q=hello", map[string]string{"X-Kortex-Sample-Id": "e8-benign"}, "")
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("E8: want 200 from stub, got %d body=%q", resp.StatusCode, string(b))
	}
	b, _ := io.ReadAll(resp.Body)
	if string(b) != "stub-ok" {
		t.Fatalf("E8: want stub body, got %q", string(b))
	}
	if !backendHit {
		t.Fatalf("E8: request must reach the backend")
	}
}

// --- E9: the admin endpoint is unreachable from a non-loopback address -------
func TestE9AdminEndpointLoopbackOnly(t *testing.T) {
	_, _ = newEnv(t, nil)
	// direct handler invocation with a non-loopback RemoteAddr
	handler := buildHandler(loadConfig())
	req := httptest.NewRequest("GET", "http://engine/__kortex/config", nil)
	req.RemoteAddr = "10.1.2.3:4444"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code == 200 {
		t.Fatalf("E9: config leaked to non-loopback address: %s", rec.Body.String())
	}
	// and from loopback it works
	req2 := httptest.NewRequest("GET", "http://engine/__kortex/config", nil)
	req2.RemoteAddr = "127.0.0.1:5555"
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != 200 {
		t.Fatalf("E9: config not available on loopback: %d", rec2.Code)
	}
	var cfg map[string]any
	if err := json.Unmarshal(rec2.Body.Bytes(), &cfg); err != nil {
		t.Fatalf("E9: config is not JSON: %v", err)
	}
	for _, key := range []string{"backend_url", "rule_engine", "blocking_paranoia",
		"detection_paranoia", "max_body_bytes", "max_inspected_bytes",
		"engine_time_budget_ms", "rules_dir"} {
		if _, ok := cfg[key]; !ok {
			t.Fatalf("E9: config missing key %q: %v", key, cfg)
		}
	}
}

