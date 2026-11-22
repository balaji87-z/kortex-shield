package main

// Worker mode (step-21 T3): body inspection runs in killable worker
// subprocesses so the engine's CPU is bounded by the time budget even on
// pathological bodies (coraza has no per-call cancellation; killing the
// worker is the only way to stop a running inspection).

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/corazawaf/coraza/v3"
)

// workerJob is one inspection job, framed as a single JSON line on the
// worker's stdin.
type workerJob struct {
	SampleID string              `json:"sample_id"`
	Method   string              `json:"method"`
	URI      string              `json:"uri"`
	Headers  map[string][]string `json:"headers"`
	Host     string              `json:"host"`
	BodyB64  string              `json:"body_b64,omitempty"`
	HoldMS   int64               `json:"hold_ms,omitempty"`
}

// workerResult is the worker's answer, one JSON line on stdout.
type workerResult struct {
	Interrupted bool     `json:"interrupted"`
	Status      int      `json:"status"`
	RuleIDs     []string `json:"rule_ids,omitempty"`
	Error       string   `json:"error,omitempty"`
	ElapsedMS   int64    `json:"elapsed_ms"`
}

// workerMain runs the child loop: load the WAF once, then answer jobs
// until stdin closes. Test hook: KORTEX_TEST_HOLD_BODY_MS plus the job's
// HoldMS (from the X-Kortex-Test-Hold request header) sleeps while
// holding the job, so budget kills are deterministic (rule 48).
func workerMain() {
	cfg := loadConfig()
	// coraza's audit middleware requires the log file to exist at config
	// time; the parent creates it lazily on first write
	if f, aerr := os.OpenFile(cfg.AuditLog, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); aerr != nil {
		fmt.Fprintf(os.Stderr, "worker: audit touch failed: %v\n", aerr)
	} else {
		f.Close()
	}
	waf, err := buildWAF(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "worker: rule load failed: %v\n", err)
		os.Exit(1)
	}
	// the parent passes the job pipe as ExtraFiles: fd 3 = jobs in,
	// fd 4 = results out (os.StartProcess ExtraFiles start at 3)
	in := bufio.NewReaderSize(os.NewFile(3, "worker-jobs"), 1<<20)
	out := bufio.NewWriter(os.NewFile(4, "worker-results"))
	defer out.Flush()
	enc := json.NewEncoder(out)
	// readiness handshake: the parent must not hand a job to a child that
	// is still loading rules
	if werr := enc.Encode(map[string]bool{"ready": true}); werr != nil {
		return
	}
	out.Flush()
	for {
		line, err := in.ReadString('\n')
		if line == "" && err != nil {
			return // parent closed the pipe: clean exit
		}
		var job workerJob
		if jerr := json.Unmarshal([]byte(line), &job); jerr != nil {
			fmt.Fprintf(os.Stderr, "worker: bad job: %v\n", jerr)
			return
		}
		res := runJob(waf, &job)
		if werr := enc.Encode(res); werr != nil {
			return
		}
		out.Flush()
		if err != nil {
			return
		}
	}
}

// runJob executes one full request inspection in the worker and returns
// the result. It mirrors the in-process phases: URI, headers, connection,
// phase 1, body write, phase 2.
func runJob(waf coraza.WAF, job *workerJob) workerResult {
	start := time.Now()
	tx := waf.NewTransaction()
	defer tx.Close()
	res := workerResult{}
	defer func() {
		res.ElapsedMS = time.Since(start).Milliseconds()
	}()
	tx.ProcessURI(job.URI, job.Method, "1.1")
	if job.Host != "" {
		tx.AddRequestHeader("Host", job.Host)
	}
	for k, vv := range job.Headers {
		for _, v := range vv {
			tx.AddRequestHeader(k, v)
		}
	}
	tx.ProcessConnection("127.0.0.1", 0, "127.0.0.1", 80)
	if job.HoldMS > 0 {
		time.Sleep(time.Duration(job.HoldMS) * time.Millisecond)
	}
	it := tx.ProcessRequestHeaders()
	if it != nil && it.Status != 0 {
		res.Interrupted = true
		res.Status = it.Status
		res.RuleIDs = matchedIDs(tx)
		return res
	}
	if job.BodyB64 != "" {
		body, err := base64.StdEncoding.DecodeString(job.BodyB64)
		if err != nil {
			res.Error = "body-decode: " + err.Error()
			return res
		}
		const chunk = 8192
		for off := 0; off < len(body); off += chunk {
			end := off + chunk
			if end > len(body) {
				end = len(body)
			}
			if _, _, werr := tx.WriteRequestBody(body[off:end]); werr != nil {
				res.Error = "write-body: " + werr.Error()
				return res
			}
		}
	}
	it2, err := tx.ProcessRequestBody()
	if err != nil {
		res.Error = "process-body: " + err.Error()
		return res
	}
	if it2 != nil {
		res.Interrupted = true
		res.Status = it2.Status
		res.RuleIDs = matchedIDs(tx)
	}
	tx.ProcessLogging()
	return res
}

// workerInspect runs the body inspection through the worker pool. It owns
// the lane slot for the duration and releases it on EVERY return path —
// including the kill path — which is what bounds the engine's CPU.
func (p *pool) inspect(pw *Proxy, sampleID string, r *http.Request, start time.Time, body []byte) (blocked bool, status int, ruleIDs []string, err error) {
	remaining := time.Duration(pw.cfg.EngineTimeBudgetMS)*time.Millisecond - time.Since(start)
	if remaining <= 0 {
		return false, 0, nil, errOverBudget
	}
	wk := p.checkout(remaining)
	if wk == nil {
		return false, 0, nil, errNoWorker
	}
	// the worker returns to the idle set ONLY if it survived the job; the
	// kill and recycle paths dispose of it themselves (returning a killed
	// worker to idle would hand dead workers to later requests)
	handled := false
	defer func() {
		if !handled {
			p.release(wk)
		}
	}()
	job := workerJob{
		SampleID: sampleID,
		Method:   r.Method,
		URI:      r.URL.RequestURI(),
		Headers:  map[string][]string{},
		Host:     r.Host,
	}
	for k, vv := range r.Header {
		if k == "Host" {
			continue
		}
		job.Headers[k] = vv
	}
	if pw.cfg.TestHoldBodyMS > 0 && r.Header.Get("X-Kortex-Test-Hold") == "1" {
		job.HoldMS = pw.cfg.TestHoldBodyMS
	}
	if len(body) > 0 {
		job.BodyB64 = base64.StdEncoding.EncodeToString(body)
	}
	jb, jerr := json.Marshal(job)
	if jerr != nil {
		return false, 0, nil, jerr
	}
	jb = append(jb, '\n')
	deadline := time.After(remaining)
	done := make(chan workerResult, 1)
	go func() {
		wk.stdin.Write(jb)
		line, rerr := wk.reader.ReadString('\n')
		if rerr != nil && line == "" {
			return // worker died; the deadline path handles it
		}
		var res workerResult
		if uerr := json.Unmarshal([]byte(line), &res); uerr != nil {
			return
		}
		done <- res
	}()
	select {
	case res := <-done:
		wk.jobs++
		if pw.cfg.WorkerRecycleAfter > 0 && wk.jobs >= pw.cfg.WorkerRecycleAfter {
			handled = true
			p.retire(wk)
		}
		if res.Error != "" {
			return false, 0, nil, fmt.Errorf("%s", res.Error)
		}
		return res.Interrupted, res.Status, res.RuleIDs, nil
	case <-deadline:
		// budget expired: SIGKILL the worker, count the kill, replace it.
		// The killed worker is NOT returned to idle (handled=true).
		handled = true
		p.kill(wk)
		return false, 0, nil, errKilled
	}
}

// workerServe is the worker-mode body path: fairness gates, one worker
// job bounded by the remaining budget, then block/forward. The lane slot
// is released on every return path (bounded CPU property).
func (p *Proxy) workerServe(w http.ResponseWriter, r *http.Request, sampleID string, start time.Time, body []byte, inflight *atomic.Int64) {
	defer inflight.Add(-1)
	key := clientKey(r, p.trustedNets)
	if p.fair.penalised(key) {
		p.overload(w, r, sampleID, start, "client penalty after kill")
		return
	}
	if !p.fair.acquire(key) {
		p.overload(w, r, sampleID, start, "per-client in-flight cap")
		return
	}
	defer p.fair.releaseC(key)
	blocked, status, ruleIDs, err := p.wpool.inspect(p, sampleID, r, start, body)
	switch {
	case err == errKilled:
		p.fair.penalise(key)
		p.events.log(sampleID, "worker-killed", 503, start, "budget expired; worker SIGKILLed")
		p.timeout(w, r, sampleID, start, "time budget expired in body processing (worker killed)")
	case err == errOverBudget:
		p.timeout(w, r, sampleID, start, "time budget expired before body processing")
	case err == errNoWorker:
		p.overload(w, r, sampleID, start, "no worker available")
	case err != nil:
		p.timeout(w, r, sampleID, start, "body-processor-error: "+err.Error())
	case blocked && p.cfg.RuleEngine != "DetectionOnly":
		p.blockWorker(w, sampleID, start, status, ruleIDs)
	default:
		p.logEncodingIssues(sampleID, r, body)
		p.forward(w, r, body, sampleID, start)
	}
}

// blockWorker answers a block decided by a worker result.
func (p *Proxy) blockWorker(w http.ResponseWriter, sampleID string, start time.Time, status int, ruleIDs []string) {
	w.Header().Set("Connection", "close")
	if status == 0 {
		status = http.StatusForbidden
	}
	w.WriteHeader(status)
	ids := strings.Join(ruleIDs, ",")
	p.events.log(sampleID, "block", status, start, "rules="+ids)
	fmt.Fprintf(w, "%d kortex-decision=block rules=%s\n", status, ids)
}

var (
	errOverBudget = fmt.Errorf("over budget")
	errNoWorker   = fmt.Errorf("no worker available")
	errKilled     = fmt.Errorf("worker killed at budget")
)

// workerHandle is one live worker subprocess.
type workerHandle struct {
	cmd    *os.Process
	stdin  io.WriteCloser
	reader *bufio.Reader
	jobs   int
}

// spawnWorker starts a worker child. Rule load happens inside the child
// before it answers jobs; a pre-spawned spare hides this cost from the
// hot path.
func spawnWorker() (*workerHandle, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	rp, wp, err := os.Pipe() // parent->child jobs
	if err != nil {
		return nil, err
	}
	crp, cwp, err := os.Pipe() // child->parent results
	if err != nil {
		rp.Close()
		wp.Close()
		return nil, err
	}
	// child fds: 3 = read end of the jobs pipe, 4 = write end of results
	attr := &os.ProcAttr{Files: []*os.File{os.Stdin, os.Stdout, os.Stderr, rp, cwp}}
	proc, err := os.StartProcess(exe, []string{exe, "--kortex-worker-child"}, attr)
	if err != nil {
		for _, f := range []*os.File{rp, wp, crp, cwp} {
			f.Close()
		}
		return nil, err
	}
	rp.Close()  // child owns the read end of jobs
	cwp.Close() // child owns the write end of results
	h := &workerHandle{
		cmd:    proc,
		stdin:  wp,                              // parent writes jobs
		reader: bufio.NewReaderSize(crp, 1<<20), // parent reads results
	}
	// wait for the readiness handshake so a loading child never receives
	// a job (rule-load cost is paid here, hidden by pre-spawned spares)
	line, err := h.reader.ReadString('\n')
	if err != nil || line == "" {
		h.stop()
		return nil, fmt.Errorf("worker ready handshake: %w", err)
	}
	var ready map[string]bool
	if jerr := json.Unmarshal([]byte(line), &ready); jerr != nil || !ready["ready"] {
		h.stop()
		return nil, fmt.Errorf("worker ready handshake: bad line %q", line)
	}
	return h, nil
}

func (h *workerHandle) stop() {
	h.stdin.Close()
	h.cmd.Kill()
	h.cmd.Wait()
}

// strconv-free small helpers used by the pool stats.
func itoa(i int) string { return strconv.Itoa(i) }

var _ = strings.TrimSpace
