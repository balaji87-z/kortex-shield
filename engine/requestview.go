// What the rules are told about a request head (step 25, E52 to E54). Go's
// net/http rewrites three things before a handler sees a request: the
// request target is parsed (and an absolute-form target loses its scheme and
// host), the Host header is moved out of the header map (so "no Host line"
// and "empty Host line" look alike), and Transfer-Encoding is removed. The
// rules are written against the request as sent, so the in-process path and
// the worker both feed a transaction from this one view.
package main

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/corazawaf/coraza/v3/types"
)

type requestView struct {
	Method      string              `json:"method"`
	Target      string              `json:"uri"`   // the request target as sent
	Proto       string              `json:"proto"` // "HTTP/1.1", as coraza's own middleware passes it
	Host        string              `json:"host"`  // value of the Host line; meaningful when HostPresent
	HostPresent bool                `json:"host_present"`
	Headers     map[string][]string `json:"headers"` // without Host; with Transfer-Encoding
}

// viewOf builds the view from a parsed request. The Host line comes from the
// gate when the connection passed through it; otherwise (a handler called
// directly, as some tests do) a non-empty r.Host stands for a Host line.
func viewOf(r *http.Request) requestView {
	v := requestView{Method: r.Method, Target: r.RequestURI, Proto: r.Proto, Headers: map[string][]string{}}
	if v.Target == "" {
		v.Target = r.URL.RequestURI()
	}
	if lines, ok := r.Context().Value(hostLinesKey).([]string); ok {
		if len(lines) > 0 {
			v.Host, v.HostPresent = lines[0], true
		}
	} else if r.Host != "" {
		v.Host, v.HostPresent = r.Host, true
	}
	for k, vv := range r.Header {
		if k == "Host" {
			continue
		}
		v.Headers[k] = vv
	}
	if len(r.TransferEncoding) > 0 {
		v.Headers["Transfer-Encoding"] = append([]string(nil), r.TransferEncoding...)
	}
	return v
}

// feed gives the request line and the headers to a transaction.
func (v requestView) feed(tx types.Transaction) {
	tx.ProcessURI(v.Target, v.Method, v.Proto)
	if v.HostPresent {
		tx.AddRequestHeader("Host", v.Host)
	}
	for k, vv := range v.Headers {
		for _, val := range vv {
			tx.AddRequestHeader(k, val)
		}
	}
}

// sentPathQuery cuts the path and the query out of a request target as it
// was sent, without decoding anything: the whole target for origin form, what
// follows the authority for absolute form. ok is false for a target that has
// neither form (`*`, authority form).
func sentPathQuery(target string) (path, query string, hasQuery, ok bool) {
	rest := target
	if !strings.HasPrefix(rest, "/") {
		i := strings.Index(rest, "://")
		if i < 0 {
			return "", "", false, false
		}
		rest = rest[i+3:]
		if j := strings.IndexAny(rest, "/?"); j >= 0 {
			rest = rest[j:]
		} else {
			rest = ""
		}
		if !strings.HasPrefix(rest, "/") {
			rest = "/" + rest
		}
	}
	path, query, hasQuery = strings.Cut(rest, "?")
	return path, query, hasQuery, true
}

// sentTargetDiffers reports whether Go would write another path and query
// for this target than the client sent (it escapes on output the path bytes
// it would not write itself: 0x80 to 0xFF, `"`, `<`, `>`, `^`, a backtick,
// `{`, `|`, `}`, `\`, `#`).
func sentTargetDiffers(target string) bool {
	path, query, hasQuery, ok := sentPathQuery(target)
	if !ok {
		return false
	}
	sent := path
	if hasQuery {
		sent += "?" + query
	}
	u, err := url.ParseRequestURI(sent)
	if err != nil {
		return false // net/http refuses such a target; the gate has refused it already
	}
	return u.RequestURI() != sent
}

// targetForwardable is false for the one kind of target the engine cannot
// forward byte for byte (E65): Go's client writes an opaque path that starts
// with "//" as an absolute URL, so such a path cannot go out as sent when it
// also holds a byte Go would escape.
func targetForwardable(target string) bool {
	path, _, _, ok := sentPathQuery(target)
	return !ok || !strings.HasPrefix(path, "//") || !sentTargetDiffers(target)
}
