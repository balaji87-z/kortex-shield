package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// ---- step-27 T1: the gate answers what it used to leave unannounced ----------

// s27Exchange sends raw (in the given pieces, with a pause between them) and
// returns the status and body of the answer read within d, and how long the
// answer took. Status 0 means nothing readable came back in time.
func s27Exchange(t *testing.T, addr string, d time.Duration, pause time.Duration, pieces ...string) (int, string, time.Duration) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	start := time.Now()
	conn.SetDeadline(start.Add(d))
	go func() {
		for i, p := range pieces {
			if i > 0 {
				time.Sleep(pause)
			}
			if _, err := io.WriteString(conn, p); err != nil {
				return
			}
		}
	}()
	data, _ := io.ReadAll(conn)
	took := time.Since(start)
	s := string(data)
	status := 0
	if m := statusLineRe.FindStringSubmatch(s); m != nil {
		fmt.Sscanf(m[1], "%d", &status)
	}
	body := ""
	if i := strings.Index(s, "\r\n\r\n"); i >= 0 {
		body = s[i+4:]
	}
	return status, body, took
}

func s27WantFraming(t *testing.T, events, id, reason string, status int, body string) {
	t.Helper()
	if status != 400 || strings.TrimSpace(body) != "400 kortex-decision=framing" {
		t.Fatalf("want 400 with body \"400 kortex-decision=framing\", got %d %q", status, body)
	}
	evs := framingEventsFor(t, events, id)
	if len(evs) != 1 {
		t.Fatalf("want exactly 1 framing event for %s, got %d", id, len(evs))
	}
	if evs[0]["reason"] != reason || evs[0]["status"] != float64(400) {
		t.Fatalf("event: want reason %q status 400, got %v", reason, evs[0])
	}
}

// E57: `OPTIONS *` is refused by the gate. Bare net/http answers it 200
// itself without running a handler (the premise), so on the engine no rule
// saw it and no event recorded it. An OPTIONS request that names a path is
// not touched (guard).
func TestE57OptionsAsteriskIsRefusedByTheGate(t *testing.T) {
	bare := newBareGoServer(t)
	srv, events := newEnv(t, nil)
	addr := strings.TrimPrefix(srv.URL, "http://")
	for _, c := range []struct{ id, line string }{
		{"e57-options-asterisk", "OPTIONS * HTTP/1.1"},
		{"e57-options-asterisk-10", "OPTIONS * HTTP/1.0"},
	} {
		t.Run(c.id, func(t *testing.T) {
			raw := s24Head(c.id, c.line, []string{"Host: localhost"}, "")
			if st, ran := bare.answer(t, raw); ran || st != 200 {
				t.Fatalf("E57 premise: bare net/http must answer 200 without running the handler, got %d, handler ran %v", st, ran)
			}
			backendHit = false
			status, body := rawExchange(t, addr, raw)
			if backendHit {
				t.Fatalf("E57: request reached the backend")
			}
			s27WantFraming(t, events, c.id, "parser:options-asterisk", status, body)
		})
	}
	t.Run("guard: OPTIONS with a path is forwarded", func(t *testing.T) {
		backendHit = false
		status, body := rawExchange(t, addr, s24Head("e57-options-path", "OPTIONS /x HTTP/1.1", []string{"Host: localhost"}, ""))
		if status != 200 || !strings.Contains(body, "stub-ok") || !backendHit {
			t.Fatalf("E57 guard: want 200 from the stub, got %d %q, backend hit %v", status, body, backendHit)
		}
		if n := len(framingEventsFor(t, events, "e57-options-path")); n != 0 {
			t.Fatalf("E57 guard: want 0 framing events, got %d", n)
		}
	})
}

// E58: a head the gate cannot read is answered and logged. Before, the
// connection was closed with no answer and no event, for a head over 65,536
// bytes and for a head that does not end within the time limit. The limit is
// a setting (KORTEX_HEAD_TIMEOUT_MS) so that the test does not wait 30 s and
// cannot pass by luck: with the limit at 300 ms an unfinished head must be
// answered between 300 ms and 3 s.
func TestE58UnreadableHeadIsAnsweredAndLogged(t *testing.T) {
	srv, events := newEnv(t, map[string]string{"KORTEX_HEAD_TIMEOUT_MS": "300"})
	addr := strings.TrimPrefix(srv.URL, "http://")
	t.Run("the limit is on the config page", func(t *testing.T) {
		resp, err := (&http.Client{Timeout: 5 * time.Second}).Get(srv.URL + "/__kortex/config")
		if err != nil {
			t.Fatalf("config: %v", err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(b), `"head_timeout_ms":300`) {
			t.Fatalf("E58: /__kortex/config must show head_timeout_ms 300, got %s", b)
		}
	})
	t.Run("head over 65,536 bytes", func(t *testing.T) {
		backendHit = false
		raw := "GET /x HTTP/1.1\r\nHost: localhost\r\nX-Kortex-Sample-Id: e58-oversize\r\nX-Pad: " + strings.Repeat("a", 70000) + "\r\n\r\n"
		status, body, _ := s27Exchange(t, addr, 3*time.Second, 0, raw)
		if backendHit {
			t.Fatalf("E58: request reached the backend")
		}
		s27WantFraming(t, events, "e58-oversize", "head-too-large", status, body)
	})
	t.Run("head that never ends", func(t *testing.T) {
		backendHit = false
		status, body, took := s27Exchange(t, addr, 3*time.Second, 0, "GET /x HTTP/1.1\r\nHost: localhost\r\nX-Kortex-Sample-Id: e58-timeout\r\n")
		if backendHit {
			t.Fatalf("E58: request reached the backend")
		}
		s27WantFraming(t, events, "e58-timeout", "head-timeout", status, body)
		if took < 300*time.Millisecond {
			t.Fatalf("E58: answered after %v, before the 300 ms limit", took)
		}
	})
	t.Run("guard: a head that arrives in two pieces within the limit is served", func(t *testing.T) {
		backendHit = false
		status, body, _ := s27Exchange(t, addr, 3*time.Second, 100*time.Millisecond,
			"GET /x HTTP/1.1\r\nHost: localhost\r\nX-Kortex-Sample-Id: e58-slow-ok\r\n", "X-A: 1\r\n\r\n")
		if status != 200 || !strings.Contains(body, "stub-ok") || !backendHit {
			t.Fatalf("E58 guard: want 200 from the stub, got %d %q, backend hit %v", status, body, backendHit)
		}
		if n := len(framingEventsFor(t, events, "e58-slow-ok")); n != 0 {
			t.Fatalf("E58 guard: want 0 framing events, got %d", n)
		}
	})
}

// E59: the gate finds the end of the head where Go's parser finds it: the
// first blank line, ended by LF or CRLF. Before, it waited for CRLF CRLF, so
// a head whose blank line ends with a bare LF got no answer until the time
// limit. Each case proves its premise first: bare net/http runs its handler
// for the same bytes. The answer must come within 3 s (the limit is 30 s).
func TestE59EndOfHeadIsReadAsGoReadsIt(t *testing.T) {
	bare := newBareGoServer(t)
	srv, events := newEnv(t, nil)
	addr := strings.TrimPrefix(srv.URL, "http://")
	const xss = "q=%3Cscript%3Ealert(1)%3C/script%3E"
	cases := []struct {
		id, raw string
		want    int // 200 forwarded, 403 blocked by a rule, 400 framing
	}{
		{"e59-all-lf", "GET /x HTTP/1.1\nHost: localhost\nX-Kortex-Sample-Id: e59-all-lf\n\n", 200},
		{"e59-crlf-lines-lf-blank", "GET /x HTTP/1.1\r\nHost: localhost\r\nX-Kortex-Sample-Id: e59-crlf-lines-lf-blank\r\n\n", 200},
		{"e59-lf-lines-crlf-blank", "GET /x HTTP/1.1\nHost: localhost\nX-Kortex-Sample-Id: e59-lf-lines-crlf-blank\n\r\n", 200},
		{"e59-all-lf-body", "POST /form HTTP/1.1\nHost: localhost\nX-Kortex-Sample-Id: e59-all-lf-body\nContent-Type: text/plain\nContent-Length: 5\n\nhello", 200},
		{"e59-all-lf-canary", "GET /s?" + xss + " HTTP/1.1\nHost: localhost\nX-Kortex-Sample-Id: e59-all-lf-canary\n\n", 403},
		{"e59-all-lf-te-cl", "POST /form HTTP/1.1\nHost: localhost\nX-Kortex-Sample-Id: e59-all-lf-te-cl\nContent-Type: text/plain\n" +
			"Transfer-Encoding: chunked\nContent-Length: 5\n\n" + s24Chunked, 400},
	}
	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			if c.want != 400 {
				if st, ran := bare.answer(t, c.raw); !ran {
					t.Fatalf("E59 premise: bare net/http must run the handler, got %d without it", st)
				}
			}
			backendHit = false
			status, body, took := s27Exchange(t, addr, 3*time.Second, 0, c.raw)
			switch c.want {
			case 200:
				if status != 200 || !strings.Contains(body, "stub-ok") || !backendHit {
					t.Fatalf("E59: want the request forwarded (200 from the stub), got %d %q after %v, backend hit %v", status, body, took, backendHit)
				}
				if n := len(framingEventsFor(t, events, c.id)); n != 0 {
					t.Fatalf("E59: want 0 framing events, got %d", n)
				}
			case 403:
				if status != 403 || !strings.Contains(body, "kortex-decision=block") || backendHit {
					t.Fatalf("E59: want 403 kortex-decision=block, got %d %q after %v, backend hit %v", status, body, took, backendHit)
				}
			case 400:
				if backendHit {
					t.Fatalf("E59: request reached the backend")
				}
				s27WantFraming(t, events, c.id, "transfer-encoding-with-content-length", status, body)
			}
		})
	}
}

// E60: every way of ending the lines of a well-formed head, LF or CRLF line
// by line, is decided as bare net/http decides it and answered at once. Four
// heads, every combination of line endings (exhaustive, no random choice).
func TestE60EveryLineEndingMixIsAnsweredLikeNetHTTP(t *testing.T) {
	bare := newBareGoServer(t)
	srv, _ := newEnv(t, nil)
	addr := strings.TrimPrefix(srv.URL, "http://")
	bases := []struct {
		lines []string
		body  string
	}{
		{[]string{"GET /a?q=1 HTTP/1.1", "Host: localhost", "Accept: */*", ""}, ""},
		{[]string{"POST /form HTTP/1.1", "Host: localhost", "Content-Type: text/plain", "Content-Length: 5", ""}, "hello"},
		{[]string{"HEAD /x HTTP/1.0", "Accept: */*", ""}, ""},
		{[]string{"GET /b HTTP/1.1", "Host: localhost", "X-A: 1", "X-B: 2", ""}, ""},
	}
	heads, differ, late := 0, 0, 0
	for _, b := range bases {
		for mask := 0; mask < 1<<len(b.lines); mask++ {
			raw := ""
			for i, l := range b.lines {
				if mask&(1<<i) != 0 {
					raw += l + "\n"
				} else {
					raw += l + "\r\n"
				}
			}
			raw += b.body
			heads++
			bareStatus, ran := bare.answer(t, raw)
			status, body, took := s27Exchange(t, addr, 3*time.Second, 0, raw)
			engineRefuses := status == 400 && strings.Contains(body, "kortex-decision=framing")
			engineServes := status == 200 || status == 403
			if status == 0 {
				late++
				if late <= 5 {
					t.Errorf("E60: no answer within 3 s (waited %v) for %q; bare net/http: %d, handler ran %v", took, raw, bareStatus, ran)
				}
				continue
			}
			if ran != engineServes || ran == engineRefuses {
				differ++
				if differ <= 5 {
					t.Errorf("E60: bare net/http handler ran %v (status %d), engine answered %d %q for %q", ran, bareStatus, status, strings.TrimSpace(body), raw)
				}
			}
		}
	}
	t.Logf("heads %d; not answered within 3 s: %d; decided differently from bare net/http: %d", heads, late, differ)
	if late != 0 || differ != 0 {
		t.Fatalf("E60: %d of %d heads not answered in time, %d decided differently", late, heads, differ)
	}
}

// E61: a connection that does not finish its head does not delay any other
// connection. Before, the gate read each head inside the accept loop, so one
// open connection with an unfinished head stopped every other request for up
// to the head time limit (30 s). The head limit is left at its default here:
// the second request must be answered within 3 s while the first connection
// is still open. The connections waiting in the gate are counted on
// /__kortex/stats (`pending_heads`) and the count returns to zero (rule 50).
func TestE61UnfinishedHeadDoesNotDelayOtherConnections(t *testing.T) {
	srv, _ := newEnv(t, nil)
	addr := strings.TrimPrefix(srv.URL, "http://")
	idle, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer idle.Close()
	io.WriteString(idle, "GET /idle HTTP/1.1\r\nHost: localhost\r\n")
	time.Sleep(200 * time.Millisecond)
	backendHit = false
	status, body, took := s27Exchange(t, addr, 3*time.Second, 0, "GET /x HTTP/1.1\r\nHost: localhost\r\nX-Kortex-Sample-Id: e61-second\r\n\r\n")
	if status != 200 || !strings.Contains(body, "stub-ok") || !backendHit {
		t.Fatalf("E61: a request sent while another connection holds an unfinished head: want 200 from the stub within 3 s, got %d %q after %v", status, body, took)
	}
	pending := func() float64 {
		v, _ := stats(t, srv.URL)["pending_heads"].(float64)
		return v
	}
	if p, ok := stats(t, srv.URL)["pending_heads"]; !ok || p.(float64) != 1 {
		t.Fatalf("E61: /__kortex/stats must show pending_heads 1 while the unfinished head is open, got %v", p)
	}
	idle.Close()
	waitFor(t, func() bool { return pending() == 0 }, 3*time.Second, "pending_heads back to 0")
}

// E62: the connections waiting in the gate are capped. With the cap at 2 and
// two unfinished heads open, the next connection is answered at once with
// 503 kortex-decision=overload and an `overload` event (reason
// pending-heads); when the two are gone a request is served again.
func TestE62PendingHeadsAreCapped(t *testing.T) {
	srv, events := newEnv(t, map[string]string{"KORTEX_MAX_PENDING_HEADS": "2"})
	addr := strings.TrimPrefix(srv.URL, "http://")
	var idle []net.Conn
	for i := 0; i < 2; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		io.WriteString(c, "GET /idle HTTP/1.1\r\nHost: localhost\r\n")
		idle = append(idle, c)
	}
	time.Sleep(200 * time.Millisecond)
	backendHit = false
	status, body, took := s27Exchange(t, addr, 3*time.Second, 0, "GET /x HTTP/1.1\r\nHost: localhost\r\nX-Kortex-Sample-Id: e62-third\r\n\r\n")
	if status != 503 || strings.TrimSpace(body) != "503 kortex-decision=overload" || backendHit {
		t.Fatalf("E62: want 503 kortex-decision=overload for the connection over the cap, got %d %q after %v, backend hit %v", status, body, took, backendHit)
	}
	found := 0
	for _, ev := range readEvents(t, events) {
		if ev["decision"] == "overload" && ev["reason"] == "pending-heads" && ev["status"] == float64(503) {
			found++
		}
	}
	if found != 1 {
		t.Fatalf("E62: want 1 overload event with reason pending-heads, got %d", found)
	}
	for _, c := range idle {
		c.Close()
	}
	waitFor(t, func() bool {
		v, _ := stats(t, srv.URL)["pending_heads"].(float64)
		return v == 0
	}, 3*time.Second, "pending_heads back to 0")
	backendHit = false
	status, body, _ = s27Exchange(t, addr, 3*time.Second, 0, "GET /x HTTP/1.1\r\nHost: localhost\r\nX-Kortex-Sample-Id: e62-after\r\n\r\n")
	if status != 200 || !strings.Contains(body, "stub-ok") || !backendHit {
		t.Fatalf("E62: after the unfinished heads are gone a request must be served, got %d %q", status, body)
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Get(srv.URL + "/__kortex/config")
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), `"max_pending_heads":2`) {
		t.Fatalf("E62: /__kortex/config must show max_pending_heads 2, got %s", b)
	}
}
