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
	"time"
)

const maxHeadBytes = 65536

type gatedListener struct {
	net.Listener
	gateTimeout time.Duration
}

func (l *gatedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		head, err := readHead(conn, l.gateTimeout)
		if err != nil {
			conn.Close()
			continue
		}
		res := framingGate(head)
		if !res.pass {
			fmt.Fprint(conn, gateResponse)
			conn.Close()
			continue
		}
		return &gatedConn{Conn: conn, prefix: head}, nil
	}
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
