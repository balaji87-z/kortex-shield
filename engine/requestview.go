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
