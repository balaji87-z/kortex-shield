// rawRequest writes a raw HTTP/1.1 request over a TCP connection to srv and
// returns status line code + body. Used by framing tests that need header
// control Go's http.Client does not allow.
package main

import (
	"bufio"
	"fmt"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
)

type rawResp struct {
	status int
	body   string
}

func rawRequest(t *testing.T, srv *httptest.Server, raw string) rawResp {
	t.Helper()
	u := strings.TrimPrefix(srv.URL, "http://")
	conn, err := net.Dial("tcp", u)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	fmt.Fprint(conn, raw)
	data, err := readAll(conn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	s := string(data)
	status := 0
	if i := strings.Index(s, "\r\n"); i > 0 {
		fmt.Sscanf(s[:i], "HTTP/1.1 %d", &status)
	}
	body := ""
	if i := strings.Index(s, "\r\n\r\n"); i >= 0 {
		body = s[i+4:]
	}
	return rawResp{status: status, body: body}
}

func readAll(conn net.Conn) ([]byte, error) {
	var out []byte
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		out = append(out, buf[:n]...)
		if err != nil {
			if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "EOF") || strings.Contains(err.Error(), "closed") {
				return out, nil
			}
			return out, nil
		}
		if len(out) > 1<<20 {
			return out, nil
		}
	}
}

var _ = bufio.NewReader // keep import if unused later
