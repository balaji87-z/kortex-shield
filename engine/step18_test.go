// Step-18 acceptance tests (rule 40: written and committed BEFORE the
// implementation). Test ids are listed in docs/acceptance.md
// (status: failing -> passing).
//
// E22 (T3): a client that is still streaming a body above the inspected
// limit must receive the full 413 response (status 413 and the
// kortex-decision=limit marker), not a connection reset.
//
// E23 (T4): a text/plain body whose SQLi payload spans the '&'-split
// boundary is blocked like on the query/urlencoded/json/multipart carriers
// (942100 on the raw body).
// E24 (T4): octet-stream and unknown-content-type bodies with a
// command-injection payload that the '&'-split destroys are blocked
// (932125/932380 at PL1; 932240 at PL2 for the ';' payload).
// E25 (T4): the '&'-split behaviour on urlencoded bodies is unchanged
// (a split-safe payload is still blocked via the parsed ARGS targets).
package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
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

// postRaw mirrors the runner's request construction for a body-bearing POST
// with an explicit content type.
func postRaw(t *testing.T, srv *httptest.Server, id, ct, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest("POST", srv.URL+"/", strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = "localhost:8090"
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("X-Kortex-Sample-Id", id)
	req.Header.Set("User-Agent",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36")
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, string(b)
}

// Payloads are from the frozen attacks-ct-v0 manifest (public payload lists,
// provenance in the dataset README; committable per rule 25 - the WCP
// recorded-content rule does not apply to these).
const (
	e23SQLiBody = `admin" or "1"="1"#`                     // sqli-6e47f23b, quick-SQLi.txt:62
	e24RceBody  = `& dir C:\Documents and Settings\*`       // command-injection-dc2932d5, command_exec.txt:75
	e24RceBody2 = `; type %SYSTEMROOT%\repair\SAM`          // command-injection-ecb32a80, command_exec.txt:386
)

// E23: the SQLi payload split by the URLENCODED processor into name
// `admin" or "1` + value `"1"#` must still be blocked via the raw body.
func TestE23TextPlainSplitSpanningSQLiBlocked(t *testing.T) {
	srv, _ := newEnv(t, nil)
	status, body := postRaw(t, srv, "e23-text-plain-sqli", "text/plain", e23SQLiBody)
	if status != 403 || !strings.Contains(body, "kortex-decision=block") {
		t.Fatalf("E23: want 403 kortex-decision=block, got %d body=%q", status, body)
	}
	if !strings.Contains(body, "942100") {
		t.Fatalf("E23: block not via 942100 on the raw body: %q", body)
	}
	if backendHit {
		t.Fatalf("E23: blocked request must not reach the backend")
	}
}

// E24: the '&' that starts the RCE payload is eaten by the URLENCODED split;
// the raw-body target must restore detection on octet-stream and unknown
// content types (PL1), and the ';' payload must be caught at PL2 (932240).
func TestE24RawCarriersSplitDestroyedRCEBlocked(t *testing.T) {
	srv, _ := newEnv(t, nil)
	for _, ct := range []string{"application/octet-stream", "application/x-kortex-probe-unknown"} {
		status, body := postRaw(t, srv, "e24-"+ct, ct, e24RceBody)
		if status != 403 || !strings.Contains(body, "kortex-decision=block") {
			t.Fatalf("E24 (%s): want 403 kortex-decision=block, got %d body=%q", ct, status, body)
		}
		if !strings.Contains(body, "932125") && !strings.Contains(body, "932380") {
			t.Fatalf("E24 (%s): block not via 932125/932380 on the raw body: %q", ct, body)
		}
	}
}

func TestE24RawCarriersSplitDestroyedRCEBlockedPL2(t *testing.T) {
	srv, _ := newEnv(t, map[string]string{
		"KORTEX_BLOCKING_PARANOIA":  "2",
		"KORTEX_DETECTION_PARANOIA": "2",
	})
	status, body := postRaw(t, srv, "e24-text-plain-pl2", "text/plain", e24RceBody2)
	if status != 403 || !strings.Contains(body, "kortex-decision=block") {
		t.Fatalf("E24 PL2: want 403 kortex-decision=block, got %d body=%q", status, body)
	}
	if !strings.Contains(body, "932240") {
		t.Fatalf("E24 PL2: block not via 932240 on the raw body: %q", body)
	}
}

// E25: regression guard - a split-safe urlencoded payload must still be
// blocked through the parsed ARGS targets (the split stays in place).
func TestE25UrlencodedSplitBehaviourUnchanged(t *testing.T) {
	srv, _ := newEnv(t, nil)
	status, body := postRaw(t, srv, "e25-urlencoded-sqli",
		"application/x-www-form-urlencoded", "q=admin%22%20or%20%221%22%3D%221%22%23")
	if status != 403 || !strings.Contains(body, "kortex-decision=block") {
		t.Fatalf("E25: want 403 kortex-decision=block, got %d body=%q", status, body)
	}
	if !strings.Contains(body, "942100") {
		t.Fatalf("E25: block not via 942100: %q", body)
	}
}

// E26 (T4 scope): literal CRLF in a raw multi-line body is normal content,
// not response splitting — CRS 921150's premise (CRLF inside a DECODED
// argument value) does not hold for REQUEST_BODY, so the REQUEST_BODY target
// must not be added to the REQUEST-921 family. Pre-fix of the scope this
// blocks a benign multi-line text/plain body via 921150.
func TestE26RawBodyCRLFNotResponseSplitting(t *testing.T) {
	srv, _ := newEnv(t, nil)
	body := "line one\r\nline two\r\nharmless payload text\r\n"
	status, resp := postRaw(t, srv, "e26-multiline-text-plain", "text/plain", body)
	if status != 200 {
		t.Fatalf("E26: want 200 (benign multi-line body passes), got %d body=%q", status, resp)
	}
	if strings.Contains(resp, "921150") {
		t.Fatalf("E26: blocked via 921150 on the raw body: %q", resp)
	}
}
