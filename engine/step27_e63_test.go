package main

import (
	"bytes"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// E63: E45 again for heads whose lines end with a bare LF. E45 sends only
// heads that contain CRLF CRLF, because that was the only end of head the
// gate recognised before step 27. Here the same five heads get the same
// kinds of damage, then every CRLF is turned into a bare LF with
// probability 1/2, and a head is sent whenever headEnd finds its end, as the
// gate now does. parserGate must refuse exactly the heads bare net/http
// refuses. Fixed seed, 20,000 heads.
func TestE63ParserGateAgreesWithNetHTTPOnDamagedHeadsWithBareLF(t *testing.T) {
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
	rng := rand.New(rand.NewSource(27))
	compared, notSent, noAnswer, goRefused, gateRefused, mismatches := 0, 0, 0, 0, 0, 0
	lfOnlyEnd, withBareLF := 0, 0
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
		parts := bytes.Split(b, []byte("\r\n"))
		b = parts[0]
		for _, p := range parts[1:] {
			if rng.Intn(2) == 0 {
				b = append(b, '\n')
			} else {
				b = append(b, '\r', '\n')
			}
			b = append(b, p...)
		}
		end := headEnd(b)
		if end < 0 {
			notSent++ // the gate waits for more bytes: no decision to compare
			continue
		}
		if !bytes.Contains(b[:end], []byte("\r\n\r\n")) {
			lfOnlyEnd++
		}
		if bytes.Contains(bytes.ReplaceAll(b[:end], []byte("\r\n"), nil), []byte("\n")) {
			withBareLF++
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
				t.Errorf("E63 mismatch: net/http status %d, handler ran %v; parserGate pass %v %s; head %q",
					status, handlerRan, gate.pass, gate.reason, b)
			}
		}
	}
	reasons := make([]string, 0, len(gateReason))
	for r, n := range gateReason {
		reasons = append(reasons, fmt.Sprintf("%s %d", r, n))
	}
	sort.Strings(reasons)
	t.Logf("heads compared %d (not sent, no end of head: %d; no answer from net/http: %d); with a bare LF in the head %d, of them ended by a blank line without CRLF CRLF %d; net/http refused %d %v; parserGate refused %d; mismatches %d",
		compared, notSent, noAnswer, withBareLF, lfOnlyEnd, goRefused, goStatus, gateRefused, mismatches)
	t.Logf("parserGate reasons: %s", strings.Join(reasons, ", "))
	if mismatches != 0 {
		t.Fatalf("E63: %d of %d heads decided differently by parserGate and net/http", mismatches, compared)
	}
	if compared < 15000 || goRefused < 1000 || compared-goRefused < 1000 || lfOnlyEnd < 1000 {
		t.Fatalf("E63: the sample is too thin to mean anything: compared %d, refused %d, LF-ended %d", compared, goRefused, lfOnlyEnd)
	}
}
