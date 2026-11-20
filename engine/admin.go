package main

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"strings"
)

// isLoopback reports whether the remote address is a loopback address.
func isLoopback(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// adminConfig serves /__kortex/config on loopback only.
func adminConfig(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isLoopback(r.RemoteAddr) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"backend_url":%q,"rule_engine":%q,"blocking_paranoia":%d,`+
			`"detection_paranoia":%d,"max_body_bytes":%d,"max_inspected_bytes":%d,`+
			`"engine_time_budget_ms":%d,"rules_dir":%q,"listen_addr":%q,`+
			`"events_file":%q,"audit_log":%q}`+"\n",
			cfg.BackendURL, cfg.RuleEngine, cfg.BlockingParanoia, cfg.DetectionParanoia,
			cfg.MaxBodyBytes, cfg.MaxInspectedBytes, cfg.EngineTimeBudgetMS, cfg.RulesDir,
			cfg.ListenAddr, cfg.EventsFile, cfg.AuditLog)
	}
}

// gateResult is the outcome of the raw framing gate.
type gateResult struct {
	pass   bool
	reason string
}

// framingGate parses the raw request head (request line + headers) and applies
// the framing checks BEFORE any HTTP parser sees the connection. It rejects:
//   - duplicate or conflicting Content-Length headers
//   - Transfer-Encoding together with Content-Length
//   - a raw NUL byte in the request line (path or query)
//
// It runs on the FIRST request of every connection; the engine answers with
// Connection: close so every request is the first on its connection and is
// always gated.
func framingGate(head []byte) gateResult {
	// the head ends at the first blank line; anything after it is body
	end := bytes.Index(head, []byte("\r\n\r\n"))
	if end < 0 {
		end = len(head)
	}
	head = head[:end]
	// request line
	lineEnd := strings.Index(string(head), "\r\n")
	if lineEnd < 0 {
		return gateResult{reason: "no-request-line"}
	}
	reqLine := string(head[:lineEnd])
	if strings.ContainsRune(reqLine, '\x00') {
		return gateResult{reason: "nul-in-target"}
	}
	// headers
	var (
		clCount int
		clVals  []string
		hasTE   bool
	)
	for _, line := range strings.Split(reqLine+"\r\n"+string(head[lineEnd+2:]), "\r\n")[1:] {
		if line == "" {
			continue
		}
		col := strings.Index(line, ":")
		if col < 0 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(line[:col]))
		val := strings.TrimSpace(line[col+1:])
		switch name {
		case "content-length":
			clCount++
			clVals = append(clVals, val)
		case "transfer-encoding":
			hasTE = true
		}
	}
	if clCount > 1 {
		// duplicates are rejected even when the values agree; conflicting
		// values are the dangerous subset
		conflict := false
		for _, v := range clVals[1:] {
			if v != clVals[0] {
				conflict = true
			}
		}
		if conflict {
			return gateResult{reason: "conflicting-content-length"}
		}
		return gateResult{reason: "duplicate-content-length"}
	}
	if hasTE && clCount >= 1 {
		return gateResult{reason: "transfer-encoding-with-content-length"}
	}
	return gateResult{pass: true}
}

// gateResponse is the raw 400 written when the gate rejects a connection.
const gateResponse = "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n400 kortex-decision=framing\n"
