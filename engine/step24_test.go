package main

import (
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ---- step-24 T1: refusals of Go's HTTP parser are announced -----------------

var statusLineRe = regexp.MustCompile(`^HTTP/1\.[01] (\d{3})`)

// rawExchange sends raw bytes to addr and returns the status code of the
// final response (0 when there is none) and everything after its head.
// Interim 1xx responses (100 Continue) are skipped. It reads until the peer
// closes or 10 s pass.
func rawExchange(t *testing.T, addr, raw string) (int, string) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprint(conn, raw)
	data, _ := io.ReadAll(conn)
	s := string(data)
	for {
		status := 0
		if m := statusLineRe.FindStringSubmatch(s); m != nil {
			fmt.Sscanf(m[1], "%d", &status)
		}
		body := ""
		if i := strings.Index(s, "\r\n\r\n"); i >= 0 {
			body = s[i+4:]
		}
		if status >= 100 && status < 200 && statusLineRe.MatchString(body) {
			s = body
			continue
		}
		return status, body
	}
}

// bareGoServer is Go's net/http server with nothing in front of it: the
// reference for "would Go's HTTP parser hand this request to a handler".
type bareGoServer struct {
	srv        *httptest.Server
	handlerRan bool
}

func newBareGoServer(t *testing.T) *bareGoServer {
	t.Helper()
	b := &bareGoServer{}
	b.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.handlerRan = true
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Connection", "close")
		fmt.Fprint(w, "bare-ok")
	}))
	t.Cleanup(b.srv.Close)
	return b
}

// answer sends raw to the bare server and reports the status and whether the
// handler ran.
func (b *bareGoServer) answer(t *testing.T, raw string) (int, bool) {
	t.Helper()
	b.handlerRan = false
	status, _ := rawExchange(t, strings.TrimPrefix(b.srv.URL, "http://"), raw)
	return status, b.handlerRan
}

// s24Head builds a raw request: request line, the sample id header, the given
// header lines exactly as written, a blank line and the payload.
func s24Head(id, reqLine string, lines []string, payload string) string {
	s := reqLine + "\r\nX-Kortex-Sample-Id: " + id + "\r\n"
	for _, l := range lines {
		s += l + "\r\n"
	}
	return s + "\r\n" + payload
}

func framingEventsFor(t *testing.T, eventsFile, sampleID string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, ev := range readEvents(t, eventsFile) {
		if ev["decision"] == "framing" && ev["sample_id"] == sampleID {
			out = append(out, ev)
		}
	}
	return out
}

const (
	s24Host    = "Host: localhost"
	s24Chunked = "5\r\nhello\r\n0\r\n\r\n"
)

type s24Case struct {
	id, raw, reason string
}

// s24Refused are requests that Go's net/http server answers itself, without
// running a handler. The first 17 are the cases step 23 (T5) found answered by
// the engine with no kortex marker and no event; the rest are further shapes
// of the same layer.
func s24Refused() []s24Case {
	post := func(id string, lines []string, payload string) string {
		return s24Head(id, "POST /form HTTP/1.1", append([]string{s24Host, "Content-Type: text/plain"}, lines...), payload)
	}
	get := func(id, reqLine string, lines ...string) string {
		return s24Head(id, reqLine, lines, "")
	}
	many := make([]string, 0, 502)
	many = append(many, s24Host)
	for i := 0; i < 501; i++ {
		many = append(many, fmt.Sprintf("X-N-%d: 1", i))
	}
	return []s24Case{
		// the 17 of step 23
		{"e42-cl-list-same", post("e42-cl-list-same", []string{"Content-Length: 5, 5"}, "hello"), "parser:content-length"},
		{"e42-cl-list-conflict", post("e42-cl-list-conflict", []string{"Content-Length: 5, 11"}, "hello world"), "parser:content-length"},
		{"e42-cl-plus", post("e42-cl-plus", []string{"Content-Length: +5"}, "hello"), "parser:content-length"},
		{"e42-cl-hex", post("e42-cl-hex", []string{"Content-Length: 0x5"}, "hello"), "parser:content-length"},
		{"e42-cl-negative", post("e42-cl-negative", []string{"Content-Length: -1"}, "hello"), "parser:content-length"},
		{"e42-cl-empty", post("e42-cl-empty", []string{"Content-Length:"}, "hello"), "parser:content-length"},
		{"e42-cl-non-numeric", post("e42-cl-non-numeric", []string{"Content-Length: abc"}, "hello"), "parser:content-length"},
		{"e42-cl-underscore", post("e42-cl-underscore", []string{"Content-Length: 1_1"}, "hello world"), "parser:content-length"},
		{"e42-cl-space-before-colon", post("e42-cl-space-before-colon", []string{"Content-Length : 5"}, "hello"), "parser:header-name"},
		{"e42-te-dup", post("e42-te-dup", []string{"Transfer-Encoding: chunked", "Transfer-Encoding: chunked"}, s24Chunked), "parser:transfer-encoding"},
		{"e42-te-dup-identity", post("e42-te-dup-identity", []string{"Transfer-Encoding: chunked", "Transfer-Encoding: identity"}, s24Chunked), "parser:transfer-encoding"},
		{"e42-te-list-identity", post("e42-te-list-identity", []string{"Transfer-Encoding: identity, chunked"}, s24Chunked), "parser:transfer-encoding"},
		{"e42-te-gzip-chunked", post("e42-te-gzip-chunked", []string{"Transfer-Encoding: gzip, chunked"}, s24Chunked), "parser:transfer-encoding"},
		{"e42-te-xchunked", post("e42-te-xchunked", []string{"Transfer-Encoding: xchunked"}, s24Chunked), "parser:transfer-encoding"},
		{"e42-pct-path-short", get("e42-pct-path-short", "GET /a%2 HTTP/1.1", s24Host), "parser:request-target"},
		{"e42-pct-path-nonhex", get("e42-pct-path-nonhex", "GET /a%zzb HTTP/1.1", s24Host), "parser:request-target"},
		{"e42-pct-path-bare", get("e42-pct-path-bare", "GET /a% HTTP/1.1", s24Host), "parser:request-target"},
		// further shapes of the same layer
		{"e42-host-missing", get("e42-host-missing", "GET /x HTTP/1.1", "Accept: */*"), "parser:host-missing"},
		{"e42-host-duplicate", get("e42-host-duplicate", "GET /x HTTP/1.1", s24Host, "Host: other"), "parser:host-duplicate"},
		{"e42-host-malformed", get("e42-host-malformed", "GET /x HTTP/1.1", "Host: local host"), "parser:host-malformed"},
		{"e42-version-2", get("e42-version-2", "GET /x HTTP/2.0", s24Host), "parser:http-version"},
		{"e42-version-0-9", get("e42-version-0-9", "GET /x HTTP/0.9", s24Host), "parser:http-version"},
		{"e42-version-malformed", get("e42-version-malformed", "GET /x HTTP/1.x", s24Host), "parser:http-version"},
		{"e42-request-line-short", get("e42-request-line-short", "GET /x", s24Host), "parser:request-line"},
		{"e42-method-invalid", get("e42-method-invalid", "G(T /x HTTP/1.1", s24Host), "parser:method"},
		{"e42-target-relative", get("e42-target-relative", "GET nopath HTTP/1.1", s24Host), "parser:request-target"},
		{"e42-header-no-colon", get("e42-header-no-colon", "GET /x HTTP/1.1", s24Host, "NoColonHere"), "parser:header-line"},
		{"e42-header-name-space", get("e42-header-name-space", "GET /x HTTP/1.1", s24Host, "X Bad Name: 1"), "parser:header-name"},
		{"e42-header-name-ctl", get("e42-header-name-ctl", "GET /x HTTP/1.1", s24Host, "X-B\x01d: 1"), "parser:header-line"},
		{"e42-header-value-ctl", get("e42-header-value-ctl", "GET /x HTTP/1.1", s24Host, "X-A: a\x01b"), "parser:header-line"},
		{"e42-header-count-501", get("e42-header-count-501", "GET /x HTTP/1.1", many...), "parser:header-count"},
		{"e42-expect-unknown", post("e42-expect-unknown", []string{"Expect: 200-ok", "Content-Length: 5"}, "hello"), "parser:expect"},
		// a refused head that also carries an attack: refused, never forwarded
		{"e42-cl-hex-xss", s24Head("e42-cl-hex-xss", "POST /form?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1",
			[]string{s24Host, "Content-Type: text/plain", "Content-Length: 0x5"}, "hello"), "parser:content-length"},
	}
}

// s24Accepted are well-formed neighbours of the refused shapes: Go's server
// runs the handler for each of them.
func s24Accepted() []s24Case {
	post := func(id string, lines []string, payload string) string {
		return s24Head(id, "POST /form HTTP/1.1", append([]string{s24Host, "Content-Type: text/plain"}, lines...), payload)
	}
	get := func(id, reqLine string, lines ...string) string {
		return s24Head(id, reqLine, lines, "")
	}
	many := make([]string, 0, 500)
	many = append(many, s24Host)
	for i := 0; i < 400; i++ {
		many = append(many, fmt.Sprintf("X-N-%d: 1", i))
	}
	return []s24Case{
		{"e43-cl", post("e43-cl", []string{"Content-Length: 5"}, "hello"), ""},
		{"e43-cl-leading-zeros", post("e43-cl-leading-zeros", []string{"Content-Length: 005"}, "hello"), ""},
		{"e43-te-chunked", post("e43-te-chunked", []string{"Transfer-Encoding: chunked"}, s24Chunked), ""},
		{"e43-te-case", post("e43-te-case", []string{"Transfer-Encoding: Chunked"}, s24Chunked), ""},
		{"e43-pct-valid", get("e43-pct-valid", "GET /a%20b?q=a%20b HTTP/1.1", s24Host), ""},
		{"e43-pct-query-bare", get("e43-pct-query-bare", "GET /s?q=100% HTTP/1.1", s24Host), ""},
		{"e43-expect-continue", post("e43-expect-continue", []string{"Expect: 100-continue", "Content-Length: 5"}, "hello"), ""},
		{"e43-http10-no-host", get("e43-http10-no-host", "GET /x HTTP/1.0", "Accept: */*"), ""},
		{"e43-host-port", get("e43-host-port", "GET /x HTTP/1.1", "Host: localhost:8080"), ""},
		{"e43-host-empty", get("e43-host-empty", "GET /x HTTP/1.1", "Host:"), ""},
		{"e43-absolute-uri", get("e43-absolute-uri", "GET http://localhost/x HTTP/1.1", s24Host), ""},
		{"e43-obs-fold", get("e43-obs-fold", "GET /x HTTP/1.1", s24Host, "X-A: a", " b"), ""},
		{"e43-header-count-401", get("e43-header-count-401", "GET /x HTTP/1.1", many...), ""},
	}
}

// E42: a request that Go's HTTP parser refuses must be refused by the
// engine's own gate instead: 400 with the body "400 kortex-decision=framing",
// exactly one framing event (status 400, a parser:<class> reason made of
// fixed words only, the request's sample id), and nothing sent to the
// backend. Found in step 23 (T5): 17 of 61 hand-written requests were
// answered 400 or 501 by net/http inside the engine with no marker and no
// event, which the evaluation reads as "passed".
//
// Each case first proves its own premise on a bare net/http server: the
// server answers and the handler does not run.
func TestE42ParserRefusalsAreAnnounced(t *testing.T) {
	bare := newBareGoServer(t)
	srv, events := newEnv(t, nil)
	addr := strings.TrimPrefix(srv.URL, "http://")
	reasonRe := regexp.MustCompile(`^parser:[a-z0-9-]+$`)
	for _, c := range s24Refused() {
		t.Run(c.id, func(t *testing.T) {
			bareStatus, ran := bare.answer(t, c.raw)
			if ran || bareStatus == 0 {
				t.Fatalf("E42 premise: bare net/http must answer without running the handler, got status %d, handler ran %v", bareStatus, ran)
			}
			t.Logf("bare net/http answers %d, handler not run", bareStatus)

			backendHit = false
			status, body := rawExchange(t, addr, c.raw)
			if backendHit {
				t.Fatalf("E42: request reached the backend")
			}
			if status != 400 || strings.TrimSpace(body) != "400 kortex-decision=framing" {
				t.Fatalf("E42: want 400 with body \"400 kortex-decision=framing\", got %d %q", status, body)
			}
			evs := framingEventsFor(t, events, c.id)
			if len(evs) != 1 {
				t.Fatalf("E42: want exactly 1 framing event for %s, got %d", c.id, len(evs))
			}
			ev := evs[0]
			if ev["status"] != float64(400) {
				t.Fatalf("E42: event status: want 400, got %v", ev["status"])
			}
			reason, _ := ev["reason"].(string)
			if !reasonRe.MatchString(reason) {
				t.Fatalf("E42: event reason must be parser:<fixed words>, got %q", reason)
			}
			if reason != c.reason {
				t.Fatalf("E42: event reason: want %q, got %q", c.reason, reason)
			}
		})
	}
}

// E43: the guard for E42. A well-formed neighbour of each refused shape is
// handed to a handler by bare net/http, and the engine does not refuse it at
// the gate: no framing answer, no framing event, and the request is either
// forwarded (the backend is hit) or decided by the rules (403 block).
func TestE43ParserGateLetsWellFormedRequestsThrough(t *testing.T) {
	bare := newBareGoServer(t)
	srv, events := newEnv(t, nil)
	addr := strings.TrimPrefix(srv.URL, "http://")
	for _, c := range s24Accepted() {
		t.Run(c.id, func(t *testing.T) {
			bareStatus, ran := bare.answer(t, c.raw)
			if !ran {
				t.Fatalf("E43 premise: bare net/http must run the handler, got status %d without it", bareStatus)
			}
			backendHit = false
			status, body := rawExchange(t, addr, c.raw)
			if strings.Contains(body, "kortex-decision=framing") {
				t.Fatalf("E43: the gate refused a well-formed request: %d %q", status, body)
			}
			if n := len(framingEventsFor(t, events, c.id)); n != 0 {
				t.Fatalf("E43: want 0 framing events, got %d", n)
			}
			forwarded := backendHit && status == 200 && strings.Contains(body, "stub-ok")
			blocked := !backendHit && status == 403 && strings.Contains(body, "kortex-decision=block")
			if !forwarded && !blocked {
				t.Fatalf("E43: want the request forwarded (200 from the stub) or blocked by a rule (403), got %d %q, backend hit %v",
					status, body, backendHit)
			}
			t.Logf("engine: status %d, forwarded %v, blocked by rule %v", status, forwarded, blocked)
		})
	}
}

// E44: the canary for E43 (rule 47). A request the gate lets through is still
// inspected: the same well-formed shapes with a known XSS payload in the
// query are blocked 403 by the rules and never reach the backend.
func TestE44RequestsPastTheParserGateAreInspected(t *testing.T) {
	srv, events := newEnv(t, nil)
	addr := strings.TrimPrefix(srv.URL, "http://")
	const xss = "q=%3Cscript%3Ealert(1)%3C/script%3E"
	cases := []s24Case{
		{"e44-get", s24Head("e44-get", "GET /s?"+xss+" HTTP/1.1", []string{s24Host}, ""), ""},
		{"e44-cl", s24Head("e44-cl", "POST /form?"+xss+" HTTP/1.1",
			[]string{s24Host, "Content-Type: text/plain", "Content-Length: 5"}, "hello"), ""},
		{"e44-te-chunked", s24Head("e44-te-chunked", "POST /form?"+xss+" HTTP/1.1",
			[]string{s24Host, "Content-Type: text/plain", "Transfer-Encoding: chunked"}, s24Chunked), ""},
		{"e44-expect-continue", s24Head("e44-expect-continue", "POST /form?"+xss+" HTTP/1.1",
			[]string{s24Host, "Content-Type: text/plain", "Expect: 100-continue", "Content-Length: 5"}, "hello"), ""},
	}
	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			backendHit = false
			status, body := rawExchange(t, addr, c.raw)
			if status != 403 || !strings.Contains(body, "kortex-decision=block") || backendHit {
				t.Fatalf("E44: want 403 kortex-decision=block and no backend hit, got %d %q, backend hit %v", status, body, backendHit)
			}
			if n := len(framingEventsFor(t, events, c.id)); n != 0 {
				t.Fatalf("E44: want 0 framing events, got %d", n)
			}
		})
	}
}

// E45: the parser gate and net/http agree on seeded random damage. Five
// well-formed request heads are damaged 1 to 3 times each (a byte replaced,
// deleted or inserted from a list of awkward bytes, a line repeated, a header
// line inserted), 20,000 heads in all, with a fixed seed. Each head that
// still ends in a blank line is sent to a bare net/http server. Whenever that
// server answers 400 or above without running its handler, parserGate must
// refuse the same bytes, and whenever the handler runs (or net/http answers
// below 400), parserGate must pass them: the gate refuses exactly what Go
// refuses, no less and no more.
func TestE45ParserGateAgreesWithNetHTTPOnDamagedHeads(t *testing.T) {
	var ran atomic.Bool
	bare := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ran.Store(true)
		w.Header().Set("Connection", "close")
		fmt.Fprint(w, "bare-ok")
	}))
	defer bare.Close()
	addr := strings.TrimPrefix(bare.URL, "http://")
	bases := []string{
		"GET /a/b?q=1&r=%20x HTTP/1.1\r\nHost: localhost\r\nUser-Agent: ua/1.0\r\nAccept: */*\r\nX-A: one, two\r\n\r\n",
		"POST /form HTTP/1.1\r\nHost: localhost:8080\r\nContent-Type: text/plain\r\nContent-Length: 0\r\nExpect: 100-continue\r\n\r\n",
		"POST /form HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n",
		"OPTIONS /x HTTP/1.0\r\nAccept: */*\r\nCookie: a=b; c=d\r\n\r\n",
		"HEAD http://localhost/x%41 HTTP/1.1\r\nHost: localhost\r\nUpgrade: h2c\r\nTE: trailers\r\n\r\n",
	}
	awkward := []byte(" \t:,%\x00\x01\x7f\x80\xff\r\n/*0x-+_(\";=@[]#?1HP.")
	extraLines := []string{
		"Host: other", "Host:", "Content-Length: 0", "Content-Length: 0, 0", "Content-Length: +0",
		"Transfer-Encoding: chunked", "Transfer-Encoding: gzip", "Transfer-Encoding: identity",
		"Expect: 100-continue", "Expect: later", "Expect:", "X-B : 1", "NoColon", " folded", "Connection: keep-alive",
	}
	rng := rand.New(rand.NewSource(24))
	compared, notSent, noAnswer, goRefused, gateRefused, mismatches := 0, 0, 0, 0, 0, 0
	goStatus := map[int]int{}
	gateReason := map[string]int{}
	for i := 0; i < 20000; i++ {
		b := []byte(bases[rng.Intn(len(bases))])
		for k := rng.Intn(3); k >= 0; k-- {
			pos := rng.Intn(len(b))
			switch rng.Intn(5) {
			case 0:
				b[pos] = awkward[rng.Intn(len(awkward))]
			case 1:
				b = append(b[:pos:pos], b[pos+1:]...)
			case 2:
				b = append(b[:pos:pos], append([]byte{awkward[rng.Intn(len(awkward))]}, b[pos:]...)...)
			case 3, 4:
				lines := bytes.Split(b, []byte("\r\n"))
				j := rng.Intn(len(lines))
				add := lines[j]
				if rng.Intn(2) == 0 {
					add = []byte(extraLines[rng.Intn(len(extraLines))])
				}
				out := append([][]byte{}, lines[:j+1]...)
				out = append(out, add)
				out = append(out, lines[j+1:]...)
				b = bytes.Join(out, []byte("\r\n"))
			}
		}
		if !bytes.Contains(b, []byte("\r\n\r\n")) {
			notSent++ // the engine's gate never sees a head without a blank line
			continue
		}
		ran.Store(false)
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		conn.Write(b)
		var resp []byte
		buf := make([]byte, 4096)
		for !bytes.Contains(resp, []byte("\r\n\r\n")) {
			n, err := conn.Read(buf)
			resp = append(resp, buf[:n]...)
			if err != nil {
				break
			}
		}
		conn.Close()
		status := 0
		if m := statusLineRe.FindSubmatch(resp); m != nil {
			fmt.Sscanf(string(m[1]), "%d", &status)
		}
		handlerRan := ran.Load()
		if status == 0 && !handlerRan {
			noAnswer++
			continue
		}
		compared++
		goRefuses := !handlerRan && status >= 400
		gate := parserGate(b)
		if goRefuses {
			goRefused++
			goStatus[status]++
		}
		if !gate.pass {
			gateRefused++
			gateReason[gate.reason]++
		}
		if goRefuses == gate.pass {
			mismatches++
			if mismatches <= 10 {
				t.Errorf("E45 mismatch: net/http status %d, handler ran %v; parserGate pass %v %s; head %q",
					status, handlerRan, gate.pass, gate.reason, b)
			}
		}
	}
	reasons := make([]string, 0, len(gateReason))
	for r, n := range gateReason {
		reasons = append(reasons, fmt.Sprintf("%s %d", r, n))
	}
	sort.Strings(reasons)
	t.Logf("heads compared %d (not sent, no blank line: %d; no answer from net/http: %d); net/http refused %d %v; parserGate refused %d; mismatches %d",
		compared, notSent, noAnswer, goRefused, goStatus, gateRefused, mismatches)
	t.Logf("parserGate reasons: %s", strings.Join(reasons, ", "))
	if mismatches != 0 {
		t.Fatalf("E45: %d of %d heads decided differently by parserGate and net/http", mismatches, compared)
	}
	if compared < 15000 || goRefused < 1000 || compared-goRefused < 1000 {
		t.Fatalf("E45: the sample is too thin to mean anything: compared %d, refused %d", compared, goRefused)
	}
}
