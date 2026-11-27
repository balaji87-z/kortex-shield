package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// E32: a rule that matches in phase 1 is part of the request's audit entry,
// as it is in the connector's audit log. The request is a query SQLi (942100,
// phase 2) sent with the numeric Host of the test server (920350, phase 1).
// Both ids are on the block page; the audit entry must name both. Found in
// step 22: the engine audit log never carried a 920350 or 920450 message.
func TestE32Phase1MatchInAuditLog(t *testing.T) {
	srv, _ := newEnv(t, nil)
	resp := get(t, srv, "/?id=1'%20OR%20'1'='1", nil, "")
	page, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("E32: want 403, got %d", resp.StatusCode)
	}
	for _, id := range []string{"920350", "942100"} {
		if !strings.Contains(string(page), id) {
			t.Fatalf("E32 precondition: rule %s is not among the matched rules on the block page: %q", id, page)
		}
	}
	var audit string
	deadline := time.Now().Add(3 * time.Second)
	for {
		b, _ := os.ReadFile(os.Getenv("KORTEX_AUDIT_LOG"))
		audit = string(b)
		if strings.Contains(audit, `[id \"942100\"]`) || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(audit, `[id \"942100\"]`) {
		t.Fatalf("E32 control: no audit entry with the phase-2 rule 942100 (audit log %d bytes)", len(audit))
	}
	if !strings.Contains(audit, `[id \"920350\"]`) {
		t.Fatalf("E32: the audit entry names 942100 (phase 2) but not 920350 (phase 1)")
	}
}

func postEncoded(t *testing.T, srv *httptest.Server, id, encoding, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest("POST", srv.URL+"/", strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = "localhost:8090"
	req.Header.Set("X-Kortex-Sample-Id", id)
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("User-Agent",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36")
	if encoding != "" {
		req.Header.Set("Content-Encoding", encoding)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// E33: a body sent with a Content-Encoding other than identity is refused by
// the engine itself with 415 kortex-decision=content-encoding, before any
// inspection, in blocking mode and in DetectionOnly mode alike. Neither the
// engine nor CRS decodes such a body (step-22 T5: the same compressed bytes
// without the header pass at PL1), so today only CRS 920450 stands between a
// compressed attack and the backend, and not at all in DetectionOnly mode.
func TestE33ContentEncodedBodyRefused(t *testing.T) {
	for _, mode := range []string{"On", "DetectionOnly"} {
		for _, enc := range []string{"gzip", "deflate", "br", "GZip", "identity, gzip"} {
			srv, events := newEnv(t, map[string]string{"KORTEX_RULE_ENGINE": mode})
			status, body := postEncoded(t, srv, "e33", enc, "the quick brown fox")
			if status != http.StatusUnsupportedMediaType || !strings.Contains(body, "kortex-decision=content-encoding") {
				t.Fatalf("E33 [%s, %q]: want 415 kortex-decision=content-encoding, got %d %q", mode, enc, status, body)
			}
			if backendHit {
				t.Fatalf("E33 [%s, %q]: refused request reached the backend", mode, enc)
			}
			if ev := eventsContains(t, events, "content-encoding"); ev["status"] != float64(415) {
				t.Fatalf("E33 [%s, %q]: event status %v, want 415", mode, enc, ev["status"])
			}
		}
	}
}

// E34: the E33 refusal applies to encoded bodies only. In DetectionOnly mode
// (so that no rule decides) a body without the header or with identity is
// forwarded, and so is a body-less request that carries the header.
func TestE34ContentEncodingRefusalIsNarrow(t *testing.T) {
	for _, enc := range []string{"", "identity", "Identity"} {
		srv, _ := newEnv(t, map[string]string{"KORTEX_RULE_ENGINE": "DetectionOnly"})
		if status, body := postEncoded(t, srv, "e34", enc, "the quick brown fox"); status != http.StatusOK {
			t.Fatalf("E34 [%q]: want 200 from the backend, got %d %q", enc, status, body)
		}
		if !backendHit {
			t.Fatalf("E34 [%q]: request did not reach the backend", enc)
		}
	}
	srv, _ := newEnv(t, map[string]string{"KORTEX_RULE_ENGINE": "DetectionOnly"})
	resp := get(t, srv, "/", map[string]string{"Content-Encoding": "gzip"}, "")
	if resp.StatusCode != http.StatusOK || !backendHit {
		t.Fatalf("E34 [body-less]: want 200 from the backend, got %d (backend hit %v)", resp.StatusCode, backendHit)
	}
}
