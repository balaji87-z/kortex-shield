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

// adminConfig serves /__kortex/config on loopback only. The per-client
// caps are read from the fairness state itself, i.e. the values in force
// after clamping, not the configured ones; they only act in worker mode.
func adminConfig(cfg *Config, fair *fairness) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isLoopback(r.RemoteAddr) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		clientSmall, clientLarge := fair.caps()
		fmt.Fprintf(w, `{"backend_url":%q,"rule_engine":%q,"blocking_paranoia":%d,`+
			`"detection_paranoia":%d,"max_body_bytes":%d,"max_inspected_bytes":%d,`+
			`"engine_time_budget_ms":%d,"rules_dir":%q,"listen_addr":%q,`+
			`"events_file":%q,"audit_log":%q,"allowed_methods":%q,`+
			`"max_inflight_body":%d,"max_inflight_body_large":%d,"body_lane_threshold":%d,`+
			`"worker_mode":%t,"client_max_inflight":%d,`+
			`"client_max_inflight_small":%d,"client_max_inflight_large":%d,`+
			`"request_body_target_updates":%d,"error_log":%q,"crs_test_setup":%t,`+
			`"head_timeout_ms":%d,"max_pending_heads":%d,"xml_attr_inspect":%t}`+"\n",
			cfg.BackendURL, cfg.RuleEngine, cfg.BlockingParanoia, cfg.DetectionParanoia,
			cfg.MaxBodyBytes, cfg.MaxInspectedBytes, cfg.EngineTimeBudgetMS, cfg.RulesDir,
			cfg.ListenAddr, cfg.EventsFile, cfg.AuditLog, cfg.AllowedMethods, cfg.MaxInflightBody,
			cfg.MaxInflightBodyLarge, cfg.BodyLaneThreshold,
			cfg.WorkerMode, cfg.ClientMaxInflight, clientSmall, clientLarge,
			len(cfg.RequestBodyTargetIDs), cfg.ErrorLog, cfg.CRSTestSetup,
			cfg.HeadTimeoutMS, cfg.MaxPendingHeads, cfg.XMLAttrInspect)
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
// It runs on the FIRST request of every connection; keep-alive is off on the
// engine's server (newEngineServer), so every request is the first on its
// connection and is always gated. framingGateGoView repeats the header
// checks on the lines as Go's parser reads them.
func framingGate(head []byte) gateResult {
	// the head ends at the first blank line, as Go's parser finds it (LF or
	// CRLF); anything after it is body
	if end := headEnd(head); end >= 0 {
		head = head[:end]
	}
	head = bytes.TrimRight(head, "\r\n")
	// request line: up to the first line break, LF or CRLF
	firstLF := bytes.IndexByte(head, '\n')
	if firstLF < 0 {
		return gateResult{reason: "no-request-line"}
	}
	if strings.ContainsRune(strings.TrimSuffix(string(head[:firstLF]), "\r"), '\x00') {
		return gateResult{reason: "nul-in-target"}
	}
	// this view splits on CRLF only; a head without any CRLF line has its
	// header lines checked by framingGateGoView alone
	lineEnd := strings.Index(string(head), "\r\n")
	if lineEnd < 0 {
		return gateResult{pass: true}
	}
	reqLine := string(head[:lineEnd])
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

// adminStats serves /__kortex/stats (loopback only, rule 50): every
// in-flight resource is observable here and must return to zero when the
// traffic that produced it ends.
func (p *Proxy) adminStats(w http.ResponseWriter, r *http.Request) {
	if !isLoopback(r.RemoteAddr) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	kills := p.kills.Load()
	penalised := p.fair.penalisedCount()
	clientSmall, clientLarge := p.fair.inflightTotals()
	wtotal, wbusy, widle, wkills, wrecycled := 0, 0, 0, 0, 0
	if p.wpool != nil {
		wtotal, wbusy, widle, wkills, wrecycled = p.wpool.stats()
		kills = int64(wkills)
	}
	fmt.Fprintf(w, `{"inflight_small":%d,"inflight_large":%d,`+
		`"abandoned_running":%d,"kills":%d,"overloads":%d,`+
		`"refused_before_inspection":%d,"penalised_clients":%d,`+
		`"client_inflight_small":%d,"client_inflight_large":%d,`+
		`"workers":{"pool":%d,"busy":%d,"spares":%d,"recycled":%d},"pending_heads":%d}`+"\n",
		p.inflightSmall.Load(), p.inflightLarge.Load(),
		p.abandonedRunning.Load(), kills, p.overloads.Load(),
		p.refusedEarly.Load(), penalised, clientSmall, clientLarge, wtotal, wbusy, widle, wrecycled,
		gatePending.Load())
}
