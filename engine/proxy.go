package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

// Proxy wires the Coraza WAF, the framing gate, the size limits and the time
// budget around a plain reverse proxy to the stub backend.
type Proxy struct {
	cfg    *Config
	waf    coraza.WAF
	events *eventLogger
	client *http.Client
}

func buildWAF(cfg *Config) (coraza.WAF, error) {
	return coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(cfg.directives()))
}

func buildHandler(cfg *Config) http.Handler {
	waf, err := buildWAF(cfg)
	if err != nil {
		panic(fmt.Sprintf("kortex-engine: WAF build failed: %v", err))
	}
	p := &Proxy{
		cfg:    cfg,
		waf:    waf,
		events: newEventLogger(cfg.EventsFile),
		client: &http.Client{Timeout: 60 * time.Second},
	}
	return p
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	sampleID := r.Header.Get("X-Kortex-Sample-Id")

	if r.URL.Path == "/__kortex/config" {
		adminConfig(p.cfg)(w, r)
		return
	}

	// engine phases
	tx := p.waf.NewTransaction()
	var abandoned atomic.Bool
	defer func() {
		// on the timeout path the abandoned goroutine owns the transaction
		// and closes it when its call returns (E17: closing it here while
		// ProcessRequestBody is still running makes the in-flight call
		// return within milliseconds with a stale interruption)
		if !abandoned.Load() {
			tx.Close()
		}
	}()

	tx.ProcessURI(r.URL.RequestURI(), r.Method, "1.1")
	tx.AddRequestHeader("Host", r.Host)
	for k, vv := range r.Header {
		for _, v := range vv {
			tx.AddRequestHeader(k, v)
		}
	}
	if r.ContentLength > 0 {
		tx.AddRequestHeader("Content-Length", strconv.FormatInt(r.ContentLength, 10))
	}
	if r.RemoteAddr != "" {
		if host, portStr, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			port, _ := strconv.Atoi(portStr)
			tx.ProcessConnection(host, port, "127.0.0.1", 80)
		}
	}

	it := tx.ProcessRequestHeaders()
	if p.blocked(it) {
		p.block(w, sampleID, start, tx, it)
		return
	}
	if p.overBudget(start) {
		p.timeout(w, sampleID, start, "time budget expired after headers")
		return
	}

	// body: read up to maxInspected+1; above the limit -> 413, not passed to
	// the engine
	var body []byte
	if r.Body != nil && r.ContentLength != 0 {
		if r.ContentLength > p.cfg.MaxBodyBytes {
			p.limit(w, sampleID, start, "body-over-total-limit")
			return
		}
		buf, err := io.ReadAll(io.LimitReader(r.Body, p.cfg.MaxInspectedBytes+1))
		if err != nil {
			p.timeout(w, sampleID, start, "body-read-error: "+err.Error())
			return
		}
		if int64(len(buf)) > p.cfg.MaxInspectedBytes {
			p.limit(w, sampleID, start, "body-over-inspected-limit")
			return
		}
		if int64(len(buf)) > p.cfg.MaxBodyBytes {
			p.limit(w, sampleID, start, "body-over-total-limit")
			return
		}
		body = buf
		// stream into the engine in chunks with budget checks
		const chunk = 8192
		for off := 0; off < len(body); off += chunk {
			end := off + chunk
			if end > len(body) {
				end = len(body)
			}
			if _, _, err := tx.WriteRequestBody(body[off:end]); err != nil {
				p.timeout(w, sampleID, start, "write-body-error: "+err.Error())
				return
			}
			if p.overBudget(start) {
				p.timeout(w, sampleID, start, "time budget expired writing body")
				return
			}
		}
	}
	// phase 2 runs even without a body: query-string ARGS are evaluated by
	// phase-2 rules (e.g. 942100). ProcessRequestBody is a single-shot call
	// with no internal deadline (step-15 T4 PROVED the budget cannot fire
	// inside it), so it runs in a goroutine bounded by the REMAINING budget;
	// on expiry the request is answered 503 and the call is abandoned (it
	// runs to completion - coraza has no per-call cancellation - and its
	// finish is logged as DoS-risk evidence).
	type bodyProcResult struct {
		it  *types.Interruption
		err error
	}
	remaining := time.Duration(p.cfg.EngineTimeBudgetMS)*time.Millisecond - time.Since(start)
	var err error
	if remaining <= 0 {
		p.timeout(w, sampleID, start, "time budget expired before body processing")
		return
	}
	done := make(chan bodyProcResult, 1)
	go func() {
		it2, err2 := tx.ProcessRequestBody()
		done <- bodyProcResult{it2, err2}
		if abandoned.Load() {
			// the request was already answered 503; record how long the
			// abandoned call kept running and what it returned (raw evidence
			// for the DoS-risk measurement; wall time ~= CPU time for this
			// CPU-bound call), then release the transaction
			reason := fmt.Sprintf("elapsed_ms=%d", time.Since(start).Milliseconds())
			if err2 != nil {
				reason += " error=" + err2.Error()
			} else if it2 != nil {
				reason += fmt.Sprintf(" interrupted=true rule_id=%d status=%d", it2.RuleID, it2.Status)
			} else {
				reason += " completed_no_interruption=true"
			}
			p.events.log(sampleID, "abandoned-body-processing-finished", 0, start, reason)
			tx.Close()
		}
	}()
	select {
	case r := <-done:
		it, err = r.it, r.err
	case <-time.After(remaining):
		abandoned.Store(true)
		p.timeout(w, sampleID, start, "time budget expired in body processing")
		// the abandoned goroutine owns tx now; the handler must not touch it
		return
	}
	if err != nil {
		p.timeout(w, sampleID, start, "body-processor-error: "+err.Error())
		return
	}
	if p.blocked(it) {
		p.block(w, sampleID, start, tx, it)
		return
	}
	if p.overBudget(start) {
		p.timeout(w, sampleID, start, "time budget expired in body processing")
		return
	}

	// encoding checks: LOG-ONLY (would_reject), never blocking
	p.logEncodingIssues(sampleID, r, body)

	p.forward(w, r, body)
	tx.ProcessLogging()
}

func (p *Proxy) overBudget(start time.Time) bool {
	return time.Since(start) > time.Duration(p.cfg.EngineTimeBudgetMS)*time.Millisecond
}

// blocked reports whether the transaction interrupted in blocking mode.
func (p *Proxy) blocked(it *types.Interruption) bool {
	if it == nil {
		return false
	}
	if p.cfg.RuleEngine == "DetectionOnly" {
		return false // log-only: never block, request is passed
	}
	return true
}

func (p *Proxy) block(w http.ResponseWriter, sampleID string, start time.Time, tx types.Transaction, it *types.Interruption) {
	w.Header().Set("Connection", "close")
	// Connector-image deny rules (200002/200003/200007) interrupt with an
	// explicit status (400); honour it like the connector does. Detection
	// rules without a status keep the engine's 403.
	status := http.StatusForbidden
	if it != nil && it.Status != 0 {
		status = it.Status
	}
	w.WriteHeader(status)
	fmt.Fprintf(w, "%d kortex-decision=block rules=%s\n", status, strings.Join(matchedIDs(tx), ","))
	tx.ProcessLogging()
}

var ruleIDRe = regexp.MustCompile(`^9\d{5}$`)

func matchedIDs(tx types.Transaction) []string {
	var ids []string
	for _, mr := range tx.MatchedRules() {
		r := mr.Rule()
		if r == nil {
			continue
		}
		id := fmt.Sprint(r.ID())
		if ruleIDRe.MatchString(id) {
			ids = append(ids, id)
		}
	}
	return ids
}

func (p *Proxy) limit(w http.ResponseWriter, sampleID string, start time.Time, reason string) {
	p.events.log(sampleID, "limit", 413, start, reason)
	w.Header().Set("Connection", "close")
	w.WriteHeader(http.StatusRequestEntityTooLarge)
	fmt.Fprint(w, "413 kortex-decision=limit\n")
}

func (p *Proxy) timeout(w http.ResponseWriter, sampleID string, start time.Time, reason string) {
	p.events.log(sampleID, "timeout", 503, start, reason)
	w.Header().Set("Connection", "close")
	w.WriteHeader(http.StatusServiceUnavailable)
	fmt.Fprint(w, "503 kortex-decision=timeout\n")
}

func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, body []byte) {
	out, err := http.NewRequest(r.Method, p.cfg.BackendURL+r.URL.RequestURI(), bytes.NewReader(body))
	if err != nil {
		http.Error(w, "bad upstream request", http.StatusBadGateway)
		return
	}
	out.Host = r.Host
	for k, vv := range r.Header {
		if strings.EqualFold(k, "Connection") || strings.EqualFold(k, "Transfer-Encoding") ||
			strings.EqualFold(k, "Content-Length") {
			continue
		}
		for _, v := range vv {
			out.Header.Add(k, v)
		}
	}
	if len(body) > 0 {
		out.ContentLength = int64(len(body))
	}
	resp, err := p.client.Do(out)
	if err != nil {
		http.Error(w, "backend unreachable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Connection", "close")
	for k, vv := range resp.Header {
		if strings.EqualFold(k, "Connection") || strings.EqualFold(k, "Transfer-Encoding") {
			continue
		}
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// logEncodingIssues records would_reject events for invalid percent sequences
// and overlong UTF-8 in the query and (urlencoded) body. LOG-ONLY by design:
// these never block, they only record what a stricter parser would reject.
func (p *Proxy) logEncodingIssues(sampleID string, r *http.Request, body []byte) {
	start := time.Now()
	var reasons []string
	if hasInvalidPercent(r.URL.RawQuery) {
		reasons = append(reasons, "invalid-percent-sequence-in-query")
	}
	if hasOverlongUTF8([]byte(r.URL.RawQuery)) {
		reasons = append(reasons, "overlong-utf8-in-query")
	}
	if len(body) > 0 && strings.Contains(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		if hasInvalidPercent(string(body)) {
			reasons = append(reasons, "invalid-percent-sequence-in-body")
		}
		if hasOverlongUTF8(body) {
			reasons = append(reasons, "overlong-utf8-in-body")
		}
	}
	for _, reason := range reasons {
		p.events.log(sampleID, "would_reject", 0, start, reason)
	}
}

// hasInvalidPercent reports whether s contains '%' not followed by two hex digits.
func hasInvalidPercent(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			continue
		}
		if i+2 >= len(s) || !isHex(s[i+1]) || !isHex(s[i+2]) {
			return true
		}
		i += 2
	}
	return false
}

func isHex(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'f' || b >= 'A' && b <= 'F'
}

// hasOverlongUTF8 reports whether b contains an overlong UTF-8 encoding
// (C0/C1 lead bytes, or 5-/6-byte sequences F8..FD).
func hasOverlongUTF8(b []byte) bool {
	for _, c := range b {
		if c == 0xC0 || c == 0xC1 || (c >= 0xF8 && c <= 0xFD) {
			return true
		}
	}
	return false
}

var _ = bufio.NewReader
