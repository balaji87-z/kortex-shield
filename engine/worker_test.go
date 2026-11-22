package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strconv"
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

// T3g: bounded CPU after a kill — the engine process CPU stops growing
// once the worker is killed (the in-process design kept burning CPU on
// the abandoned call; E20's property, now enforced structurally).
func TestT3gBoundedCPUAfterKill(t *testing.T) {
	srv, _ := newEnv(t, workerEnv(map[string]string{
		"KORTEX_ENGINE_TIME_BUDGET_MS": "300",
		"KORTEX_TEST_HOLD_BODY_MS":     "5000",
		"KORTEX_WORKER_POOL":           "2", // + 1 spare = 3 children
	}))
	isPID := func(s string) bool {
		for _, c := range s {
			if c < '0' || c > '9' {
				return false
			}
		}
		return s != ""
	}
	// snapshot the worker children (the engine runs in-process; workers are
	// child processes of this test binary)
	children := func() map[int]bool {
		out := map[int]bool{}
		entries, _ := os.ReadDir("/proc")
		for _, e := range entries {
			if !isPID(e.Name()) || e.Name() == strconv.Itoa(os.Getpid()) {
				continue
			}
			b, err := os.ReadFile("/proc/" + e.Name() + "/stat")
			if err != nil {
				continue
			}
			f := bytes.Fields(bytes.SplitN(b, []byte(") "), 2)[1])
			if len(f) > 1 && string(f[1]) == strconv.Itoa(os.Getpid()) {
				pid, _ := strconv.Atoi(e.Name())
				out[pid] = true
			}
		}
		return out
	}
	treeCPU := func() int {
		total := 0
		for _, pid := range append([]int{os.Getpid()}, func() []int {
			var ks []int
			for p := range children() {
				ks = append(ks, p)
			}
			return ks
		}()...) {
			b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
			if err != nil {
				continue
			}
			f := bytes.Fields(bytes.SplitN(b, []byte(") "), 2)[1])
			u, _ := strconv.Atoi(string(f[11]))
			s, _ := strconv.Atoi(string(f[12]))
			total += u + s
		}
		return total
	}
	before := children() // snapshot BEFORE the kill (the replacement gets a new pid)
	go bodyPost(t, srv.URL, "t3g-kill", 2048, map[string]string{"X-Kortex-Test-Hold": "1"})
	waitFor(t, func() bool { return stats(t, srv.URL)["kills"].(float64) >= 1 }, 5*time.Second, "kill")
	// the killed worker PID must no longer exist, and the pool must be
	// whole again (a replacement child with a NEW pid). The replacement's
	// rule load is bounded by design (~1.5-2 s CPU); the bounded-CPU
	// property is measured AFTER it completes, in steady state.
	waitFor(t, func() bool {
		after := children()
		killed := []int{}
		for pid := range before {
			if !after[pid] {
				killed = append(killed, pid)
			}
		}
		if len(killed) == 0 {
			return false
		}
		for _, pid := range killed {
			if _, err := os.Stat("/proc/" + strconv.Itoa(pid)); err == nil {
				t.Errorf("T3g: killed worker pid %d still exists", pid)
				return false
			}
		}
		return true
	}, 15*time.Second, "killed worker pid gone")
	// wait for the replacement to finish its (bounded) rule load before
	// measuring steady-state CPU: the pool counts a worker only once its
	// rule load completed (spawnWorker returns), so pool==before count and
	// busy==0 means the pool is back to steady state
	waitFor(t, func() bool {
		w := stats(t, srv.URL)["workers"].(map[string]any)
		return w["busy"].(float64) == 0 && w["pool"].(float64) == 3
	}, 15*time.Second, "replacement worker ready")
	c0 := treeCPU()
	time.Sleep(1200 * time.Millisecond)
	c1 := treeCPU()
	if c1-c0 > 15 { // 15 ticks = 150 ms of CPU in 1.2 s wall, whole tree
		t.Fatalf("T3g: process-tree CPU grew by %d ticks after the kill and replacement (unbounded CPU)", c1-c0)
	}
	waitFor(t, func() bool {
		w := stats(t, srv.URL)["workers"].(map[string]any)
		return w["busy"].(float64) == 0
	}, 2*time.Second, "no busy workers after kill")
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
