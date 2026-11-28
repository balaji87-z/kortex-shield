// The parser gate: the part of the gate that refuses, with the engine's own
// marker and an event, every request head that Go's net/http server would
// answer itself without running the handler (docs/engine-design.md, step 24).
package main

import (
	"bufio"
	"bytes"
	"errors"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"

	"golang.org/x/net/http/httpguts"
)

// maxHeaderLines is net/http's DefaultMaxHeaderValueCount (go1.27); the
// constant itself is not usable under this module's go 1.25 directive.
const maxHeaderLines = 500

// parserGate runs the request head through Go's own request parser and then
// repeats the checks net/http's server makes between parsing and calling a
// handler (conn.readRequest and the Expect check in conn.serve, go1.27.4).
// The reason is parser:<class> with a class from a fixed list; Go's error
// text quotes request bytes and is never used.
func parserGate(head []byte) gateResult {
	refuse := func(class string) gateResult { return gateResult{reason: "parser:" + class} }

	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(head)))
	if err != nil {
		return refuse(parserErrorClass(err))
	}
	// http.ReadRequest drops Host from the header map and folds repeated
	// values away, so the header block is read once more, the way net/http
	// reads it, to see every line the server will see.
	hdr, err := goHeaderView(head)
	if err != nil {
		return refuse("header-line")
	}

	if !(req.ProtoMajor == 1 ||
		(req.ProtoMajor == 2 && req.ProtoMinor == 0 && req.Method == "PRI" && req.RequestURI == "*")) {
		return refuse("http-version")
	}
	lines := 0
	for _, vv := range hdr {
		lines += len(vv)
	}
	if lines > maxHeaderLines {
		return refuse("header-count")
	}
	hosts := hdr["Host"]
	isH2Upgrade := req.Method == "PRI" && len(hdr) == 0 && req.URL.Path == "*" && req.Proto == "HTTP/2.0"
	if req.ProtoAtLeast(1, 1) && len(hosts) == 0 && !isH2Upgrade && req.Method != "CONNECT" {
		return refuse("host-missing")
	}
	if len(hosts) > 1 {
		return refuse("host-duplicate")
	}
	if len(hosts) == 1 && !httpguts.ValidHostHeader(hosts[0]) {
		return refuse("host-malformed")
	}
	for k, vv := range hdr {
		if !httpguts.ValidHeaderFieldName(k) {
			return refuse("header-name")
		}
		for _, v := range vv {
			if !httpguts.ValidHeaderFieldValue(v) {
				return refuse("header-value")
			}
		}
	}
	// net/http looks at the first Expect line only
	if expect := hdr["Expect"]; len(expect) > 0 && expect[0] != "" && !hasToken(expect[0], "100-continue") {
		return refuse("expect")
	}
	return gateResult{pass: true}
}

// goHeaderView parses the header block of a raw request head with the MIME
// header reader net/http uses, keeping every line (Host included).
func goHeaderView(head []byte) (textproto.MIMEHeader, error) {
	tp := textproto.NewReader(bufio.NewReader(bytes.NewReader(head)))
	if _, err := tp.ReadLine(); err != nil { // request line
		return nil, err
	}
	return tp.ReadMIMEHeader()
}

// parserErrorClass maps an error of http.ReadRequest to a fixed word.
func parserErrorClass(err error) string {
	var uerr *url.Error
	if errors.As(err, &uerr) {
		return "request-target"
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "Content-Length"):
		return "content-length"
	case strings.Contains(msg, "transfer encoding"):
		return "transfer-encoding"
	case strings.Contains(msg, "too many Host headers"):
		return "host-duplicate"
	case strings.Contains(msg, "malformed HTTP version"):
		return "http-version"
	case strings.Contains(msg, "malformed HTTP request"):
		return "request-line"
	case strings.Contains(msg, "invalid method"):
		return "method"
	case strings.Contains(msg, "malformed MIME header"):
		return "header-line"
	}
	return "other"
}

// hasToken reports whether token (lower-case ASCII) appears in v between
// token boundaries, ASCII case-insensitively: the test net/http applies to
// the Expect header (its unexported hasToken).
func hasToken(v, token string) bool {
	if len(token) > len(v) || token == "" {
		return false
	}
	boundary := func(b byte) bool { return b == ' ' || b == ',' || b == '\t' }
	for sp := 0; sp <= len(v)-len(token); sp++ {
		if sp > 0 && !boundary(v[sp-1]) {
			continue
		}
		if end := sp + len(token); end != len(v) && !boundary(v[end]) {
			continue
		}
		match := true
		for i := 0; i < len(token); i++ {
			b := v[sp+i]
			if 'A' <= b && b <= 'Z' {
				b += 'a' - 'A'
			}
			if b != token[i] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
