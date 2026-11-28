package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// ---- step-27 T5: found by the parsing differential ---------------------------

// s27RecordingBackend is a backend that keeps the request target of every
// request exactly as it arrived on the wire.
type s27RecordingBackend struct {
	srv *httptest.Server
	mu  sync.Mutex
	got map[string]string // sample id -> request target as received
}

func newS27RecordingBackend(t *testing.T) *s27RecordingBackend {
	t.Helper()
	b := &s27RecordingBackend{got: map[string]string{}}
	b.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		b.got[r.Header.Get("X-Kortex-Sample-Id")] = r.RequestURI
		b.mu.Unlock()
		io.Copy(io.Discard, r.Body)
		fmt.Fprint(w, "stub-ok")
	}))
	t.Cleanup(b.srv.Close)
	return b
}

func (b *s27RecordingBackend) target(id string) (string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	s, ok := b.got[id]
	return s, ok
}

// E64: the backend is sent the request target the rules were given. Since
// step 25 the rules see the target as the client sent it, while the request
// was still forwarded with Go's re-encoded form of the path
// (r.URL.RequestURI()): a raw byte that Go escapes on output reached the rules
// in one form and the backend in another. Found by the step-27 differential:
// `ovl-path-raw` (raw C0 AF in the path) was judged as raw bytes and
// forwarded as %C0%AF, the spelling CRS 930100 is written for. (A raw '#'
// is escaped by Go as well, but CRS 920610 blocks it, so it is never
// forwarded and is not a case here.)
func TestE64BackendGetsTheRequestTargetTheRulesWereGiven(t *testing.T) {
	backend := newS27RecordingBackend(t)
	for _, mode := range []struct {
		name string
		env  map[string]string
	}{
		{"inprocess", map[string]string{}},
		{"worker", map[string]string{"KORTEX_WORKER_MODE": "on"}},
	} {
		t.Run(mode.name, func(t *testing.T) {
			env := map[string]string{"KORTEX_BACKEND_URL": backend.srv.URL}
			for k, v := range mode.env {
				env[k] = v
			}
			srv, _ := newEnv(t, env)
			addr := strings.TrimPrefix(srv.URL, "http://")
			cases := []struct{ id, target string }{
				{"e64-control", "/plain/path?q=1"},
				{"e64-control-pct", "/caf%C3%A9/menu?x=%C0%AF"},
				{"e64-overlong-raw", "/static/..\xc0\xaf..\xc0\xafetc/passwd"},
				{"e64-utf8-raw", "/caf\xc3\xa9/menu"},
				{"e64-latin1-raw", "/caf\xe9/menu?x=\xe9"},
				{"e64-quote", `/a"b`},
				{"e64-braces", "/a{b}c"},
				{"e64-caret", "/a^b"},
				{"e64-backtick", "/a`b"},
				{"e64-empty-query", "/a\xc3\xa9?"},
				{"e64-absolute", "http://localhost/caf\xc3\xa9/menu?x=1"},
			}
			differ := 0
			for _, c := range cases {
				id := c.id + "-" + mode.name
				raw := "GET " + c.target + " HTTP/1.1\r\nHost: localhost\r\nX-Kortex-Sample-Id: " + id + "\r\nConnection: close\r\n\r\n"
				status, body := rawExchange(t, addr, raw)
				if status != 200 || !strings.Contains(body, "stub-ok") {
					t.Errorf("E64 %s: the case must be forwarded to mean anything, got %d %q", c.id, status, strings.TrimSpace(body))
					continue
				}
				got, ok := backend.target(id)
				if !ok {
					t.Errorf("E64 %s: answered 200 but the backend saw no request", c.id)
					continue
				}
				want := c.target
				if strings.HasPrefix(want, "http://localhost") {
					want = strings.TrimPrefix(want, "http://localhost") // origin-form on the way out
				}
				if got != want {
					differ++
					t.Errorf("E64 %s: sent %q, the backend received %q", c.id, want, got)
				}
			}
			t.Logf("%s: targets %d, forwarded in another spelling: %d", mode.name, len(cases), differ)
		})
	}
}

// E65: a request target the engine cannot forward byte for byte is refused,
// not rewritten. Go's HTTP client writes a target that starts with "//" as an
// absolute URL when it is given as it stands, so a path that starts with "//"
// and also holds a byte Go would escape cannot be forwarded unchanged. The
// same path without such a byte is forwarded as it is.
func TestE65UnforwardableTargetIsRefused(t *testing.T) {
	backend := newS27RecordingBackend(t)
	srv, events := newEnv(t, map[string]string{"KORTEX_BACKEND_URL": backend.srv.URL})
	addr := strings.TrimPrefix(srv.URL, "http://")

	raw := "GET //a/b?q=1 HTTP/1.1\r\nHost: localhost\r\nX-Kortex-Sample-Id: e65-control\r\nConnection: close\r\n\r\n"
	status, body := rawExchange(t, addr, raw)
	got, _ := backend.target("e65-control")
	if status != 200 || got != "//a/b?q=1" {
		t.Fatalf("E65 control: want 200 and //a/b?q=1 at the backend, got %d %q, backend %q", status, strings.TrimSpace(body), got)
	}

	raw = "GET //a/caf\xc3\xa9 HTTP/1.1\r\nHost: localhost\r\nX-Kortex-Sample-Id: e65-refused\r\nConnection: close\r\n\r\n"
	status, body = rawExchange(t, addr, raw)
	if _, reached := backend.target("e65-refused"); reached {
		t.Fatalf("E65: the request reached the backend (as %q)", backend.got["e65-refused"])
	}
	s27WantFraming(t, events, "e65-refused", "target-not-forwardable", status, body)
}

// E66: KORTEX_XML_ATTR_INSPECT=on makes the rules inspect XML attribute
// values. CRS v4.25.2 (LTS) carries the target XML://@* on its attack rules
// and removes it again per transaction unless tx.crs_xml_attr_inspect is set
// (rules 901180, 901181; advisory GHSA-6jp8-c2w2-x7wr), so with the setup of
// the pinned images a payload in an attribute is not inspected. Found by the
// step-27 differential (`xml-attr`). The switch is the only difference
// between the two halves of each pair; the default stays off.
func TestE66XMLAttributeInspectionSwitch(t *testing.T) {
	post := func(id, body string) string {
		return fmt.Sprintf("POST /body HTTP/1.1\r\nHost: localhost\r\nX-Kortex-Sample-Id: %s\r\nContent-Type: application/xml\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", id, len(body), body)
	}
	attr := `<r q="&lt;script&gt;alert(1)&lt;/script&gt;"/>`
	text := `<r><q>&lt;script&gt;alert(1)&lt;/script&gt;</q></r>`
	harmless := `<r q="hello" lang="en"><q>world</q></r>`
	for _, c := range []struct {
		name       string
		env        map[string]string
		wantAttr   int
		wantConfig string
	}{
		{"off (default)", map[string]string{}, 200, `"xml_attr_inspect":false`},
		{"on", map[string]string{"KORTEX_XML_ATTR_INSPECT": "on"}, 403, `"xml_attr_inspect":true`},
		{"on, worker mode", map[string]string{"KORTEX_XML_ATTR_INSPECT": "on", "KORTEX_WORKER_MODE": "on"}, 403, `"xml_attr_inspect":true`},
	} {
		t.Run(c.name, func(t *testing.T) {
			srv, _ := newEnv(t, c.env)
			addr := strings.TrimPrefix(srv.URL, "http://")
			// canary (rule 47): the same payload as element text is blocked either way
			if status, body := rawExchange(t, addr, post("e66-text", text)); status != 403 || !strings.Contains(body, "941100") {
				t.Fatalf("E66 canary: the payload as element text must be blocked by 941100, got %d %q", status, strings.TrimSpace(body))
			}
			backendHit = false
			status, body := rawExchange(t, addr, post("e66-attr", attr))
			if status != c.wantAttr {
				t.Errorf("E66: payload in an attribute: want %d, got %d %q", c.wantAttr, status, strings.TrimSpace(body))
			}
			if c.wantAttr == 403 && (!strings.Contains(body, "kortex-decision=block") || !strings.Contains(body, "941100") || backendHit) {
				t.Errorf("E66: want kortex-decision=block with rule 941100 and no backend hit, got %q, backend hit %v", strings.TrimSpace(body), backendHit)
			}
			if status, body := rawExchange(t, addr, post("e66-harmless", harmless)); status != 200 {
				t.Errorf("E66: harmless attributes must pass, got %d %q", status, strings.TrimSpace(body))
			}
			resp, err := http.Get(srv.URL + "/__kortex/config")
			if err != nil {
				t.Fatalf("config: %v", err)
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			if !strings.Contains(string(b), c.wantConfig) {
				t.Errorf("E66: /__kortex/config must show %s, got %s", c.wantConfig, b)
			}
		})
	}
}
