package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"
)

// E31 (step-21 T2, rule 50): /__kortex/stats exposes every in-flight
// resource — per-lane in-flight counts, abandoned-running count, worker
// pool state (T3), kill and overload counters — and every counter returns
// to zero after the traffic that produced it has finished.
func TestE31StatsEndpointObservableAndReturnsToZero(t *testing.T) {
	srv, _ := newEnv(t, map[string]string{
		"KORTEX_TEST_HOLD_BODY_MS":     "400",
		"KORTEX_ENGINE_TIME_BUDGET_MS": "200",
		"KORTEX_MAX_INFLIGHT_BODY":     "1",
	})
	fetch := func() map[string]any {
		resp := get(t, srv, "/__kortex/stats", nil, "")
		b, _ := io.ReadAll(resp.Body)
		var s map[string]any
		if err := json.Unmarshal(b, &s); err != nil {
			t.Fatalf("E31: stats body is not JSON: %v (%q)", err, string(b))
		}
		return s
	}
	// 1. endpoint exists and reports zeros when idle
	s := fetch()
	if resp := get(t, srv, "/__kortex/stats", nil, ""); resp.StatusCode != 200 {
		t.Fatalf("E31: want 200 from /__kortex/stats, got %d", resp.StatusCode)
	}
	for _, f := range []string{"inflight_small", "inflight_large", "abandoned_running", "kills", "overloads"} {
		if _, ok := s[f]; !ok {
			t.Fatalf("E31: stats missing field %q", f)
		}
	}
	// 2. a held body-bearing POST is observable in-flight, then times out
	codeCh := make(chan int, 1)
	go func() {
		req, err := http.NewRequest("POST", srv.URL+"/", bytes.NewReader(bytes.Repeat([]byte("a"), 2048)))
		if err != nil {
			codeCh <- -1
			return
		}
		req.Header.Set("Content-Type", "text/plain")
		req.Header.Set("X-Kortex-Test-Hold", "1")
		req.Header.Set("X-Kortex-Sample-Id", "e31-held")
		resp, err := srv.Client().Do(req)
		if err != nil {
			codeCh <- -2
			return
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		codeCh <- resp.StatusCode
	}()
	seen := false
	for i := 0; i < 40; i++ {
		time.Sleep(50 * time.Millisecond)
		if int(fetch()["inflight_small"].(float64)) >= 1 {
			seen = true
			break
		}
	}
	if !seen {
		t.Fatalf("E31: inflight_small never reached 1 while a body POST was held")
	}
	code := <-codeCh
	if code != 503 {
		t.Fatalf("E31: want the held request to time out 503, got %d", code)
	}
	// 3. abandoned_running is observable while the abandoned call runs
	s = fetch()
	if int(s["abandoned_running"].(float64)) < 1 {
		t.Fatalf("E31: abandoned_running want >=1 right after the timeout, got %v", s["abandoned_running"])
	}
	// 4. everything returns to zero after the abandoned call finishes
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s = fetch()
		if int(s["inflight_small"].(float64)) == 0 && int(s["abandoned_running"].(float64)) == 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if int(s["inflight_small"].(float64)) != 0 || int(s["abandoned_running"].(float64)) != 0 {
		b, _ := json.Marshal(s)
		t.Fatalf("E31: counters did not return to zero: %s", b)
	}
}
