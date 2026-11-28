// gatedListener wraps a net.Listener: for each accepted connection it reads
// the request head, runs the framing gate, and either rejects with a raw 400
// (kortex-decision=framing) or hands the connection to the HTTP server with
// the head bytes already buffered.
package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const maxHeadBytes = 65536

type gatedListener struct {
	net.Listener
	gateTimeout time.Duration
	events      *eventLogger
}

// newGatedListener is the one place main() and the tests build the gate, so
// a refusal is logged to the same events file as every other decision.
func newGatedListener(ln net.Listener, cfg *Config) *gatedListener {
	return &gatedListener{Listener: ln, gateTimeout: 30 * time.Second, events: newEventLogger(cfg.EventsFile)}
}

func (l *gatedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		start := time.Now()
		head, err := readHead(conn, l.gateTimeout)
		if err != nil {
			conn.Close()
			continue
		}
		res := framingGate(head)
		if !res.pass {
			// logged before the answer goes out, so the event exists by the
			// time the client has read the 400
			l.events.log(headSampleID(head), "framing", 400, start, res.reason)
			fmt.Fprint(conn, gateResponse)
			conn.Close()
			continue
		}
		return &gatedConn{Conn: conn, prefix: head}, nil
	}
}

// headSampleID returns the value of the first X-Kortex-Sample-Id header in a
// raw request head, or "" when there is none. The gate refuses before any
// HTTP parser runs, so the id has to be read from the raw bytes.
func headSampleID(head []byte) string {
	if end := bytes.Index(head, []byte("\r\n\r\n")); end >= 0 {
		head = head[:end]
	}
	for i, line := range strings.Split(string(head), "\r\n") {
		if i == 0 {
			continue // request line
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

// readHead reads from conn until the end of the header block (\r\n\r\n) and
// returns EVERYTHING read so far — the head plus any body bytes that arrived
// in the same TCP segments — so no byte is lost between the gate and the
// HTTP server.
func readHead(conn net.Conn, timeout time.Duration) ([]byte, error) {
	var buf bytes.Buffer
	tmp := make([]byte, 4096)
	deadline := time.Now().Add(timeout)
	conn.SetReadDeadline(deadline)
	for {
		if buf.Len() > maxHeadBytes {
			return nil, io.ErrShortBuffer
		}
		if bytes.Index(buf.Bytes(), []byte("\r\n\r\n")) >= 0 {
			return buf.Bytes(), nil
		}
		n, err := conn.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
		}
		if err != nil {
			return nil, err
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("head timeout")
		}
	}
}

// gatedConn replays the buffered head bytes before the live stream.
type gatedConn struct {
	net.Conn
	prefix []byte
}

func (c *gatedConn) Read(b []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(b, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}
