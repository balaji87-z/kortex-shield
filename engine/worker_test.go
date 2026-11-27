package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestMain intercepts the worker-child re-execution: the engine spawns
// os.Args[0] --kortex-worker-child as the inspection worker; under `go
// test` the same binary re-runs with this flag and must NOT run the test
// framework.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "--kortex-worker-child" {
		workerMain()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func workerEnv(extra map[string]string) map[string]string {
	e := map[string]string{
		"KORTEX_WORKER_MODE": "on",
	}
	for k, v := range extra {
		e[k] = v
	}
	return e
}

func stats(t *testing.T, srvURL string) map[string]any {
	t.Helper()
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Get(srvURL + "/__kortex/stats")
	if err != nil {
		t.Fatalf("stats get: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	var s map[string]any
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatalf("stats not JSON: %v (%q)", err, string(b))
	}
	return s
}

func waitFor(t *testing.T, cond func() bool, d time.Duration, what string) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

func bodyPost(t *testing.T, srv, sampleID string, n int, hdr map[string]string) int {
	t.Helper()
	req, err := http.NewRequest("POST", srv+"/", bytes.NewReader(bytes.Repeat([]byte("a"), n)))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("X-Kortex-Sample-Id", sampleID)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return -1
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

// T3a: worker mode decides identically to in-process mode on a small
// fixture (benign pass + XSS block). The full 5-dataset parity replay is
// a separate shell task; this gates the mode.
func TestT3aWorkerModeDecisionParitySmall(t *testing.T) {
	srv, _ := newEnv(t, workerEnv(map[string]string{
		"KORTEX_TEST_HOLD_BODY_MS": "0",
	}))
	// benign small body passes
	if code := bodyPost(t, srv.URL, "t3a-benign", 1024, nil); code != 200 {
		t.Fatalf("T3a: benign body want 200, got %d", code)
	}
	// XSS payload in a text/plain body blocks (941 family, same as E-cases)
	req, _ := http.NewRequest("POST", srv.URL+"/", bytes.NewReader([]byte(`x="><script>alert(1)</script>`)))
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("X-Kortex-Sample-Id", "t3a-attack")
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("T3a: XSS body want 403 in worker mode, got %d", resp.StatusCode)
	}
}

// T3b: at the budget the worker is SIGKILLed, the kill is counted and the
// slot is released immediately (bounded CPU property).
func TestT3bWorkerKilledAtBudgetSlotReleased(t *testing.T) {
	srv, _ := newEnv(t, workerEnv(map[string]string{
		"KORTEX_ENGINE_TIME_BUDGET_MS": "300",
		"KORTEX_TEST_HOLD_BODY_MS":     "5000",
	}))
	codeCh := make(chan int, 1)
	go func() { codeCh <- bodyPost(t, srv.URL, "t3b-kill", 2048, map[string]string{"X-Kortex-Test-Hold": "1"}) }()
	waitFor(t, func() bool { return stats(t, srv.URL)["kills"].(float64) >= 1 }, 5*time.Second, "kill counter")
	if code := <-codeCh; code != 503 {
		t.Fatalf("T3b: want 503 timeout, got %d", code)
	}
	waitFor(t, func() bool {
		s := stats(t, srv.URL)
		return s["inflight_small"].(float64) == 0 && s["workers"].(map[string]any)["busy"].(float64) == 0
	}, 2*time.Second, "slot release after kill")
}

// T3c: a pre-spawned spare means the next request after a kill does not
// pay the rule-load cost (pool is whole again without a load gap).
func TestT3cSpareAvailableAfterKill(t *testing.T) {
	srv, _ := newEnv(t, workerEnv(map[string]string{
		"KORTEX_ENGINE_TIME_BUDGET_MS": "300",
		"KORTEX_TEST_HOLD_BODY_MS":     "5000",
		"KORTEX_CLIENT_PENALTY_MS":     "0", // this test measures the spare, not fairness
	}))
	go bodyPost(t, srv.URL, "t3c-kill", 2048, map[string]string{"X-Kortex-Test-Hold": "1"})
	waitFor(t, func() bool { return stats(t, srv.URL)["kills"].(float64) >= 1 }, 5*time.Second, "kill")
	// the spare was pre-spawned at startup: the pool must be whole again
	// promptly (spare moved into the pool slot, replacement spare spawning)
	waitFor(t, func() bool {
		w := stats(t, srv.URL)["workers"].(map[string]any)
		return w["pool"].(float64) >= 1 && w["busy"].(float64) == 0
	}, 2*time.Second, "pool whole after kill")
	// and the next request is served without a rule-load-sized gap
	start := time.Now()
	code := bodyPost(t, srv.URL, "t3c-next", 1024, nil)
	el := time.Since(start)
	if code != 200 {
		t.Fatalf("T3c: next request want 200, got %d", code)
	}
	if el > 3*time.Second {
		t.Fatalf("T3c: next request took %v (rule-load gap not covered by spare?)", el)
	}
}

// T3d: recycle-after-N replaces a worker after N jobs.
func TestT3dWorkerRecycleAfterN(t *testing.T) {
	srv, _ := newEnv(t, workerEnv(map[string]string{
		"KORTEX_WORKER_RECYCLE_AFTER": "2",
	}))
	for i := 0; i < 3; i++ {
		if code := bodyPost(t, srv.URL, "t3d-"+strconv.Itoa(i), 1024, nil); code != 200 {
			t.Fatalf("T3d: request %d want 200, got %d", i, code)
		}
	}
	waitFor(t, func() bool {
		return stats(t, srv.URL)["workers"].(map[string]any)["recycled"].(float64) >= 1
	}, 5*time.Second, "recycle counter")
}

// T3e: per-client in-flight cap — excess body requests from the SAME
// client are answered 503 overload with the per-client reason.
func TestT3ePerClientInflightCap(t *testing.T) {
	srv, _ := newEnv(t, workerEnv(map[string]string{
		"KORTEX_TEST_HOLD_BODY_MS":   "3000",
		"KORTEX_CLIENT_MAX_INFLIGHT": "1",
	}))
	codeCh := make(chan int, 2)
	go func() { codeCh <- bodyPost(t, srv.URL, "t3e-1", 2048, map[string]string{"X-Kortex-Test-Hold": "1"}) }()
	waitFor(t, func() bool {
		s := stats(t, srv.URL)
		return s["inflight_small"].(float64) >= 1
	}, 5*time.Second, "first request in flight")
	go func() { codeCh <- bodyPost(t, srv.URL, "t3e-2", 2048, nil) }()
	waitFor(t, func() bool {
		s := stats(t, srv.URL)
		return s["overloads"].(float64) >= 1
	}, 5*time.Second, "per-client overload")
	if code := <-codeCh; code != 503 {
		t.Fatalf("T3e: second request want 503, got %d", code)
	}
	<-codeCh
}

// T3f: after a budget kill the client enters penalty state; further body
// requests are refused until the penalty expires.
func TestT3fClientPenaltyAfterKill(t *testing.T) {
	srv, _ := newEnv(t, workerEnv(map[string]string{
		"KORTEX_ENGINE_TIME_BUDGET_MS": "300",
		"KORTEX_TEST_HOLD_BODY_MS":     "5000",
		"KORTEX_CLIENT_PENALTY_MS":     "800",
	}))
	go bodyPost(t, srv.URL, "t3f-kill", 2048, map[string]string{"X-Kortex-Test-Hold": "1"})
	waitFor(t, func() bool { return stats(t, srv.URL)["kills"].(float64) >= 1 }, 5*time.Second, "kill")
	waitFor(t, func() bool {
		return stats(t, srv.URL)["penalised_clients"].(float64) >= 1
	}, 2*time.Second, "penalty applied")
	if code := bodyPost(t, srv.URL, "t3f-penalised", 1024, nil); code != 503 {
		t.Fatalf("T3f: penalised client want 503, got %d", code)
	}
	// after the penalty expires the client is served again
	waitFor(t, func() bool {
		return stats(t, srv.URL)["penalised_clients"].(float64) == 0
	}, 3*time.Second, "penalty expiry")
	if code := bodyPost(t, srv.URL, "t3f-after", 1024, nil); code != 200 {
		t.Fatalf("T3f: after penalty want 200, got %d", code)
	}
}

// pidExists probes one PID directly with signal 0 (no process listing).
// Only ESRCH means "no such process"; a zombie that has not been reaped
// still exists and is reported as existing.
func pidExists(pid int) bool {
	return syscall.Kill(pid, 0) != syscall.ESRCH
}

// selfCPU is the user+system CPU time consumed so far by this process
// (all threads). Under `go test` the engine runs in-process, so this is
// the engine parent's own CPU; worker children are not included.
func selfCPU() (time.Duration, error) {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0, err
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano()), nil
}

// T3g: bounded CPU after a kill. The test owns everything it measures:
// the engine spawns exactly one worker (pool 1, no spare) through
// newPool/spawnWorker, the test records that worker's PID, a held request
// drives it into the budget kill, and then
//  1. that PID no longer exists (probed directly by PID), and
//  2. the parent's own CPU time does not keep growing after the kill.
//
// The hold hook sleeps, so the worker is idle when it is killed: (1) shows
// the process is gone, not that a spinning inspection was interrupted.
//
// (2) reads the CPU time of the whole process, so the checks run in a fresh
// copy of the test binary that runs nothing else. In the shared test process
// any work another test left running would be counted as parent CPU (T3n).
func TestT3gBoundedCPUAfterKill(t *testing.T) {
	if os.Getenv(t3gOwnProcessEnv) == "" {
		out, err := runT3gInOwnProcess()
		t.Logf("T3g in its own process:\n%s", out)
		if err != nil || !strings.Contains(out, "--- PASS: TestT3gBoundedCPUAfterKill") {
			t.Fatalf("T3g failed in its own process: %v", err)
		}
		return
	}
	srv, _ := newEnv(t, workerEnv(map[string]string{
		"KORTEX_ENGINE_TIME_BUDGET_MS": "300",
		"KORTEX_TEST_HOLD_BODY_MS":     "5000",
		"KORTEX_WORKER_POOL":           "1",
		"KORTEX_WORKER_SPARES":         "0",
	}))
	wp := poolHolder
	if wp == nil {
		t.Fatalf("T3g: worker mode did not create a pool")
	}
	t.Cleanup(wp.close)
	idlePIDs := func() []int {
		wp.mu.Lock()
		defer wp.mu.Unlock()
		var pids []int
		for _, wk := range wp.idle {
			pids = append(pids, wk.cmd.Pid)
		}
		return pids
	}
	pids := idlePIDs()
	if len(pids) != 1 {
		t.Fatalf("T3g: want exactly 1 worker spawned by this test, got pids %v", pids)
	}
	pid := pids[0]
	// the probe must report the live worker as existing, otherwise "gone"
	// below would prove nothing
	if !pidExists(pid) {
		t.Fatalf("T3g: worker pid %d not found before the kill", pid)
	}
	killsBefore := stats(t, srv.URL)["kills"].(float64)

	// the only worker takes the held job and is killed at the 300 ms budget
	if code := bodyPost(t, srv.URL, "t3g-kill", 2048, map[string]string{"X-Kortex-Test-Hold": "1"}); code != 503 {
		t.Fatalf("T3g: held request want 503 at the budget, got %d", code)
	}
	if k := stats(t, srv.URL)["kills"].(float64); k != killsBefore+1 {
		t.Fatalf("T3g: want exactly 1 budget kill, kills went %v -> %v", killsBefore, k)
	}
	waitFor(t, func() bool { return !pidExists(pid) }, 5*time.Second, "killed worker pid gone")

	// parent CPU over a quiet window right after the kill: no requests and
	// no stats polling in the window. The replacement worker loads its
	// rules during it, but in its own process.
	const window = 1200 * time.Millisecond
	const maxGrowth = 150 * time.Millisecond // 12.5% of one core; an abandoned in-process call burns ~100%
	if os.Getenv(t3gCanaryEnv) != "" {
		// canary (T3o): parent work during the window, which (2) must catch
		stop := make(chan struct{})
		defer close(stop)
		go func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
			}
		}()
	}
	c0, err := selfCPU()
	if err != nil {
		t.Logf("T3g: parent CPU time not readable (%v); PID-gone check only", err)
	} else {
		time.Sleep(window)
		c1, err := selfCPU()
		if err != nil {
			t.Fatalf("T3g: parent CPU time readable before the window but not after: %v", err)
		}
		t.Logf("T3g: killed worker pid %d; parent CPU %v -> %v (+%v) over %v after the kill", pid, c0, c1, c1-c0, window)
		if c1-c0 > maxGrowth {
			t.Fatalf("T3g: parent CPU grew by %v in %v after the kill (limit %v)", c1-c0, window, maxGrowth)
		}
	}
	if pidExists(pid) {
		t.Fatalf("T3g: killed worker pid %d exists again after the CPU window", pid)
	}

	// the pool is whole again with a NEW worker and nothing is left in flight
	waitFor(t, func() bool {
		s := stats(t, srv.URL)
		w := s["workers"].(map[string]any)
		return w["pool"].(float64) == 1 && w["busy"].(float64) == 0 && s["inflight_small"].(float64) == 0
	}, 15*time.Second, "replacement worker ready, nothing in flight")
	if now := idlePIDs(); len(now) != 1 || now[0] == pid {
		t.Fatalf("T3g: want one replacement worker with a new pid, got %v (killed pid %d)", now, pid)
	}
}

const (
	t3gOwnProcessEnv = "KORTEX_T3G_OWN_PROCESS"
	t3gCanaryEnv     = "KORTEX_T3G_CANARY_BUSY_PARENT"
)

// runT3gInOwnProcess re-runs this test binary with only T3g selected.
func runT3gInOwnProcess(extraEnv ...string) (string, error) {
	cmd := exec.Command(os.Args[0], "-test.run", "^TestT3gBoundedCPUAfterKill$", "-test.v", "-test.count=1")
	cmd.Env = append(append(os.Environ(), t3gOwnProcessEnv+"=1"), extraEnv...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// T3o: canary for T3g (rule 47). The same run with one goroutine of the
// parent spinning during the CPU window must fail on the CPU limit;
// otherwise a pass of T3g would say nothing about parent CPU.
func TestT3oT3gCanaryCatchesBusyParent(t *testing.T) {
	out, err := runT3gInOwnProcess(t3gCanaryEnv + "=1")
	if err == nil || !strings.Contains(out, "T3g: parent CPU grew by") {
		t.Fatalf("T3o: T3g did not fail on the CPU limit with a busy parent (err %v):\n%s", err, out)
	}
	if strings.Contains(out, "CPU time not readable") {
		t.Fatalf("T3o: parent CPU time was not readable, the CPU check did not run:\n%s", out)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "T3g: parent CPU grew by") {
			t.Logf("T3o: with a busy parent T3g failed as it must: %s", strings.TrimSpace(line))
		}
	}
}

// T3n: T3g's CPU check must measure the engine parent after the kill, not
// work that another test left running in the test process. With the wcp
// fixture set, E16-E21 each leave an abandoned in-process call burning a
// core, and T3g then fails although the kill left nothing behind
// (docs/logs/step22-t3g-fixture-DIAGNOSTIC.log). Here one goroutine spins
// for the whole test, which is that situation without the fixture and
// without timing luck (rule 48), and T3g must still pass.
func TestT3nT3gIgnoresOtherTestsCPU(t *testing.T) {
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
		}
	}()
	defer func() { close(stop); <-done }()
	if !t.Run("T3g", TestT3gBoundedCPUAfterKill) {
		t.Fatalf("T3n: T3g failed while an unrelated goroutine of the test process was busy")
	}
}

// T3h (step-22 design risk (a)): the per-client in-flight cap must default
// to floor(lane_cap/2) (at least 1) PER LANE, so one client cannot hold a
// whole lane. Large lane cap is 2 -> per-client large cap 1: the second
// concurrent large-body request from the SAME client gets 503 with the
// per-client reason even though the lane cap (2) would have allowed it.
// Failing-by-design while the cap is a single global value (default 2).
func TestT3hPerClientCapDefaultsToHalfLaneCap(t *testing.T) {
	srv, _ := newEnv(t, workerEnv(map[string]string{
		"KORTEX_TEST_HOLD_BODY_MS": "3000",
		// no KORTEX_CLIENT_MAX_INFLIGHT: the derived default must apply
	}))
	codeCh := make(chan int, 2)
	large := bytes.Repeat([]byte("a"), 131072)
	go func() {
		codeCh <- postBodyBytes(t, srv.URL, "t3h-1", large, map[string]string{"X-Kortex-Test-Hold": "1"})
	}()
	waitFor(t, func() bool {
		s := stats(t, srv.URL)
		return s["inflight_large"].(float64) >= 1
	}, 5*time.Second, "first large request in flight")
	go func() {
		codeCh <- postBodyBytes(t, srv.URL, "t3h-2", large, nil)
	}()
	waitFor(t, func() bool {
		s := stats(t, srv.URL)
		return s["overloads"].(float64) >= 1
	}, 5*time.Second, "per-client overload on the large lane")
	if code := <-codeCh; code != 503 {
		t.Fatalf("T3h: second large request from the same client want 503, got %d", code)
	}
	<-codeCh
}

// postRaw posts an explicit body and returns the status code.
func postBodyBytes(t *testing.T, srv, sampleID string, body []byte, hdr map[string]string) int {
	t.Helper()
	req, err := http.NewRequest("POST", srv+"/", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("X-Kortex-Sample-Id", sampleID)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return -1
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}
