// gatedListener wraps a net.Listener: for each accepted connection it reads
// the request head, runs the framing gate and the parser gate, and either
// rejects with a raw 400 (kortex-decision=framing) or hands the connection to
// the HTTP server with the head bytes already buffered. Each connection is
// gated in its own goroutine (step 27).
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const maxHeadBytes = 65536

var (
	errHeadTooLarge = errors.New("head too large")
	errHeadTimeout  = errors.New("head timeout")
)

// gatePending counts the accepted connections whose head the gate is still
// waiting for (served on /__kortex/stats as pending_heads, rule 50).
var gatePending atomic.Int64

const overloadGateResponse = "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n503 kortex-decision=overload\n"

type gatedListener struct {
	net.Listener
	gateTimeout time.Duration
	maxPending  int64
	events      *eventLogger

	start     sync.Once
	closeOnce sync.Once
	ready     chan net.Conn // connections that passed the gate
	errc      chan error    // accept errors, handed to the HTTP server
	done      chan struct{} // closed by Close
}

// newGatedListener is the one place main() and the tests build the gate, so
// a refusal is logged to the same events file as every other decision.
func newGatedListener(ln net.Listener, cfg *Config) *gatedListener {
	return &gatedListener{
		Listener:    ln,
		gateTimeout: time.Duration(cfg.HeadTimeoutMS) * time.Millisecond,
		maxPending:  cfg.MaxPendingHeads,
		events:      newEventLogger(cfg.EventsFile),
		ready:       make(chan net.Conn),
		errc:        make(chan error),
		done:        make(chan struct{}),
	}
}

// Accept returns the next connection that passed the gate. Each accepted
// connection is gated in its own goroutine, so a connection that is slow to
// send its head never delays another one.
func (l *gatedListener) Accept() (net.Conn, error) {
	l.start.Do(func() { go l.acceptLoop() })
	select {
	case c := <-l.ready:
		return c, nil
	case err := <-l.errc:
		return nil, err
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *gatedListener) Close() error {
	l.closeOnce.Do(func() { close(l.done) })
	return l.Listener.Close()
}

func (l *gatedListener) acceptLoop() {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			select {
			case l.errc <- err:
			case <-l.done:
				return
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		if gatePending.Add(1) > l.maxPending {
			gatePending.Add(-1)
			l.events.log("", "overload", 503, time.Now(), "pending-heads")
			go refuseConn(conn, overloadGateResponse)
			continue
		}
		go l.gate(conn)
	}
}

// gate reads one connection's head and either refuses it (raw 400
// kortex-decision=framing, one framing event) or hands the connection to the
// HTTP server with the bytes read so far buffered.
func (l *gatedListener) gate(conn net.Conn) {
	start := time.Now()
	head, err := readHead(conn, l.gateTimeout)
	gatePending.Add(-1)
	res := gateResult{pass: true}
	switch {
	case errors.Is(err, errHeadTooLarge):
		res = gateResult{reason: "head-too-large"}
	case errors.Is(err, errHeadTimeout):
		res = gateResult{reason: "head-timeout"}
	case err != nil:
		// the client went away before sending a head: nothing to answer
		conn.Close()
		return
	}
	if res.pass {
		res = framingGate(head)
	}
	if res.pass {
		res = framingGateGoView(head)
	}
	if res.pass {
		res = parserGate(head)
	}
	if res.pass {
		res = optionsAsteriskGate(head)
	}
	if res.pass {
		res = forwardableTargetGate(head)
	}
	if !res.pass {
		// logged before the answer goes out, so the event exists by the
		// time the client has read the 400
		l.events.log(headSampleID(head), "framing", 400, start, res.reason)
		refuseConn(conn, gateResponse)
		return
	}
	select {
	case l.ready <- &gatedConn{Conn: conn, prefix: head, hostLines: headHostLines(head)}:
	case <-l.done:
		conn.Close()
	}
}

// refuseConn writes a raw answer and closes. The client may still be
// sending (a head over the size limit): closing with unread bytes makes the
// kernel reset the connection and the answer can be lost, so the write side
// is closed first and what is still arriving is discarded for a short,
// bounded time.
func refuseConn(conn net.Conn, answer string) {
	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	fmt.Fprint(conn, answer)
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.CloseWrite()
	}
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	io.CopyN(io.Discard, conn, 1<<20)
	conn.Close()
}

// headEnd returns the length of the request head including its blank line,
// read the way Go's parser reads it: lines end at LF with an optional CR
// before it, and the first empty line ends the head. -1 when the head is not
// complete yet.
func headEnd(b []byte) int {
	for i := 0; i < len(b); i++ {
		if b[i] != '\n' {
			continue
		}
		if i+1 < len(b) && b[i+1] == '\n' {
			return i + 2
		}
		if i+2 < len(b) && b[i+1] == '\r' && b[i+2] == '\n' {
			return i + 3
		}
	}
	return -1
}

// optionsAsteriskGate refuses `OPTIONS *`: net/http answers it itself, so no
// rule would see it and no event would record it, and the engine has no
// request to forward it as. Called after parserGate, so the request line is
// known to parse.
// forwardableTargetGate refuses a request target the engine could only
// forward in another spelling than the one the rules judge (E65). Called
// after parserGate, so the request line is known to parse.
func forwardableTargetGate(head []byte) gateResult {
	line := string(head)
	if i := strings.Index(line, "\n"); i >= 0 {
		line = line[:i]
	}
	f := strings.Fields(line)
	if len(f) >= 2 && !targetForwardable(f[1]) {
		return gateResult{reason: "target-not-forwardable"}
	}
	return gateResult{pass: true}
}

func optionsAsteriskGate(head []byte) gateResult {
	line := string(head)
	if i := strings.Index(line, "\n"); i >= 0 {
		line = line[:i]
	}
	f := strings.Fields(line)
	if len(f) >= 2 && f[0] == "OPTIONS" && f[1] == "*" {
		return gateResult{reason: "parser:options-asterisk"}
	}
	return gateResult{pass: true}
}

// headSampleID returns the value of the first X-Kortex-Sample-Id header in a
// raw request head, or "" when there is none. The gate refuses before any
// HTTP parser runs, so the id has to be read from the raw bytes. Lines end
// at LF with an optional CR before it, as Go's parser reads them, and the
// search stops at the first empty line.
func headSampleID(head []byte) string {
	for i, line := range strings.Split(string(head), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if i == 0 {
			continue // request line
		}
		if line == "" {
			break
		}
		col := strings.Index(line, ":")
		if col < 0 {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(line[:col]), "X-Kortex-Sample-Id") {
			return strings.TrimSpace(line[col+1:])
		}
	}
	return ""
}

// readHead reads from conn until the end of the header block and returns
// EVERYTHING read so far, the head plus any body bytes that arrived in the
// same TCP segments, so no byte is lost between the gate and the HTTP
// server. On errHeadTooLarge and errHeadTimeout it also returns what was
// read, for the event's sample id.
func readHead(conn net.Conn, timeout time.Duration) ([]byte, error) {
	var buf bytes.Buffer
	tmp := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(timeout))
	for {
		if end := headEnd(buf.Bytes()); end >= 0 {
			if end > maxHeadBytes {
				return buf.Bytes(), errHeadTooLarge
			}
			return buf.Bytes(), nil
		}
		if buf.Len() > maxHeadBytes {
			return buf.Bytes(), errHeadTooLarge
		}
		n, err := conn.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
		}
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return buf.Bytes(), errHeadTimeout
			}
			if n > 0 && headEnd(buf.Bytes()) >= 0 {
				continue
			}
			return nil, err
		}
	}
}

// gatedConn replays the buffered head bytes before the live stream.
// hostLines holds the values of the Host header lines of the head the gate
// let through (none, or one: the gate refuses more), because net/http keeps
// neither the fact that a Host line was there nor its value when the
// request target is in absolute form.
type gatedConn struct {
	net.Conn
	prefix    []byte
	hostLines []string
}

// headHostLines returns the values of the Host header lines of a raw head,
// read the way Go's parser reads the header block; nil when there is none.
func headHostLines(head []byte) []string {
	hdr, err := goHeaderView(head)
	if err != nil {
		return nil
	}
	return hdr["Host"]
}

type connCtxKey int

const hostLinesKey connCtxKey = 0

// connContext hands the gate's view of the Host header to the handler.
func connContext(ctx context.Context, c net.Conn) context.Context {
	if gc, ok := c.(*gatedConn); ok {
		return context.WithValue(ctx, hostLinesKey, gc.hostLines)
	}
	return ctx
}

func (c *gatedConn) Read(b []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(b, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}
