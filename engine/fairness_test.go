package main

// Per-client in-flight cap tests T3i-T3m. A client may hold at most
// floor(lane_cap/2) (at least 1) jobs in each lane, whether the cap is
// derived or set with KORTEX_CLIENT_MAX_INFLIGHT, and each lane is counted
// on its own. All requests come from 127.0.0.1, i.e. one client.

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	smallBody = 2048   // <= 65536: small lane
	largeBody = 131072 // > 65536: large lane
)

// holdEnv keeps held jobs alive for 3 s and well inside the time budget,
// so no test here causes a budget kill or a client penalty.
func holdEnv(extra map[string]string) map[string]string {
	e := workerEnv(map[string]string{
		"KORTEX_TEST_HOLD_BODY_MS":     "3000",
		"KORTEX_ENGINE_TIME_BUDGET_MS": "15000",
	})
	for k, v := range extra {
		e[k] = v
	}
	return e
}

// postCode posts an n-byte text/plain body and returns the status code, or
// -1 on a transport error. It never touches testing.T, so it is safe to
// call from a goroutine.
func postCode(srv, sampleID string, n int, hold bool) int {
	req, err := http.NewRequest("POST", srv+"/", bytes.NewReader(bytes.Repeat([]byte("a"), n)))
	if err != nil {
		return -1
	}
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("X-Kortex-Sample-Id", sampleID)
	if hold {
		req.Header.Set("X-Kortex-Test-Hold", "1")
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return -1
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

func postAsync(srv, sampleID string, n int, hold bool) <-chan int {
	ch := make(chan int, 1)
	go func() { ch <- postCode(srv, sampleID, n, hold) }()
	return ch
}

// statNum reads a numeric field of a decoded JSON object and fails the
// test (instead of panicking) when the field is absent.
func statNum(t *testing.T, m map[string]any, field string) float64 {
	t.Helper()
	v, ok := m[field].(float64)
	if !ok {
		t.Fatalf("field %q missing or not a number in %v", field, m)
	}
	return v
}

func workersBusy(t *testing.T, srvURL string) float64 {
	t.Helper()
	return stats(t, srvURL)["workers"].(map[string]any)["busy"].(float64)
}

// overloadReason returns the reason of the overload event logged for
// sampleID, or "" when there is none.
func overloadReason(t *testing.T, eventsFile, sampleID string) string {
	t.Helper()
	data, err := os.ReadFile(eventsFile)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var ev Event
		if json.Unmarshal([]byte(line), &ev) != nil {
			continue
		}
		if ev.SampleID == sampleID && ev.Decision == "overload" {
			return ev.Reason
		}
	}
	return ""
}

const perClientReason = "per-client in-flight cap"

// wantRefused asserts a request was answered 503 by the per-client cap
// (not by the lane cap, a penalty or a missing worker).
func wantRefused(t *testing.T, id, eventsFile, sampleID string, code int) {
	t.Helper()
	if code != 503 {
		t.Fatalf("%s: request %s want 503 from the per-client cap, got %d", id, sampleID, code)
	}
	if r := overloadReason(t, eventsFile, sampleID); r != perClientReason {
		t.Fatalf("%s: request %s want overload reason %q, got %q", id, sampleID, perClientReason, r)
	}
}

// smallLaneCapIsFour holds four small jobs from one client, shows all four
// are admitted, and that a fifth is refused by the per-client cap while
// the small lane (cap 8) still has room.
func smallLaneCapIsFour(t *testing.T, id string, env map[string]string) {
	t.Helper()
	env["KORTEX_WORKER_POOL"] = "4"
	env["KORTEX_WORKER_SPARES"] = "0"
	srv, events := newEnv(t, holdEnv(env))
	var held []<-chan int
	for i := 1; i <= 4; i++ {
		held = append(held, postAsync(srv.URL, id+"-held-"+strconv.Itoa(i), smallBody, true))
	}
	// a job holds a worker only after it passed the per-client cap
	waitFor(t, func() bool { return workersBusy(t, srv.URL) == 4 }, 2500*time.Millisecond, "four small jobs admitted and running")
	code := postCode(srv.URL, id+"-fifth", smallBody, false)
	wantRefused(t, id, events, id+"-fifth", code)
	for i, ch := range held {
		if c := <-ch; c != 200 {
			t.Fatalf("%s: held small job %d want 200, got %d", id, i+1, c)
		}
	}
}

// T3i: an explicit KORTEX_CLIENT_MAX_INFLIGHT above half of the large lane
// is clamped to floor(2/2) = 1, so the override cannot let one client fill
// the lane: the second concurrent large job from the same client gets 503.
func TestT3iExplicitCapClampedToHalfLargeLane(t *testing.T) {
	srv, events := newEnv(t, holdEnv(map[string]string{
		"KORTEX_CLIENT_MAX_INFLIGHT": "4",
	}))
	first := postAsync(srv.URL, "t3i-1", largeBody, true)
	waitFor(t, func() bool { return workersBusy(t, srv.URL) == 1 }, 2500*time.Millisecond, "first large job admitted and running")
	code := postCode(srv.URL, "t3i-2", largeBody, true)
	wantRefused(t, "T3i", events, "t3i-2", code)
	if c := <-first; c != 200 {
		t.Fatalf("T3i: first large job want 200, got %d", c)
	}
}

// T3j: an explicit KORTEX_CLIENT_MAX_INFLIGHT above half of the small lane
// is clamped to floor(8/2) = 4.
func TestT3jExplicitCapClampedToHalfSmallLane(t *testing.T) {
	smallLaneCapIsFour(t, "t3j", map[string]string{"KORTEX_CLIENT_MAX_INFLIGHT": "6"})
}

// T3k: with no override the small-lane per-client cap is exactly 4
// (floor(8/2)): four concurrent small jobs are admitted, the fifth is not.
func TestT3kDefaultSmallLaneCapIsFour(t *testing.T) {
	smallLaneCapIsFour(t, "t3k", map[string]string{})
}

// T3l: in-flight jobs are counted per lane. A client with one small job in
// flight may still start a large one; the large lane's own cap (1) still
// refuses a second large job; and the per-client counts are observable at
// /__kortex/stats and return to zero (rule 50).
func TestT3lPerClientCountIsPerLane(t *testing.T) {
	srv, events := newEnv(t, holdEnv(nil))
	small := postAsync(srv.URL, "t3l-small", smallBody, true)
	waitFor(t, func() bool { return workersBusy(t, srv.URL) == 1 }, 2500*time.Millisecond, "small job admitted and running")
	large := postAsync(srv.URL, "t3l-large-1", largeBody, true)
	// decided as soon as the large request reaches the per-client cap:
	// either it takes a second worker or it is refused
	waitFor(t, func() bool {
		return workersBusy(t, srv.URL) == 2 || overloadReason(t, events, "t3l-large-1") != ""
	}, 2500*time.Millisecond, "large job admitted or refused")
	if r := overloadReason(t, events, "t3l-large-1"); r != "" {
		t.Fatalf("T3l: large job refused (%q) while the client only had a small job in flight", r)
	}
	s := stats(t, srv.URL)
	if sm, lg := statNum(t, s, "client_inflight_small"), statNum(t, s, "client_inflight_large"); sm != 1 || lg != 1 {
		t.Fatalf("T3l: want per-client in-flight small=1 large=1 while both are held, got small=%v large=%v", sm, lg)
	}
	code := postCode(srv.URL, "t3l-large-2", largeBody, false)
	wantRefused(t, "T3l", events, "t3l-large-2", code)
	if c := <-small; c != 200 {
		t.Fatalf("T3l: small job want 200, got %d", c)
	}
	if c := <-large; c != 200 {
		t.Fatalf("T3l: first large job want 200, got %d", c)
	}
	waitFor(t, func() bool {
		s := stats(t, srv.URL)
		return statNum(t, s, "client_inflight_small") == 0 && statNum(t, s, "client_inflight_large") == 0 &&
			statNum(t, s, "inflight_small") == 0 && statNum(t, s, "inflight_large") == 0 &&
			workersBusy(t, srv.URL) == 0
	}, 2*time.Second, "per-client and lane in-flight counts back to zero")
}

// T3m: /__kortex/config shows the per-client caps actually in force per
// lane, next to the configured value and the worker-mode switch (the caps
// only act in worker mode), so a run can prove which values applied.
func TestT3mConfigShowsEffectivePerClientCaps(t *testing.T) {
	cases := []struct {
		name                  string
		clientMax, small, lrg string // env values; "" = unset
		wantSmall, wantLarge  float64
		wantConfigured        float64
	}{
		{"default lanes, no override", "", "", "", 4, 1, 0},
		{"override below half is kept", "1", "", "", 1, 1, 1},
		{"override 4 clamped on the large lane", "4", "", "", 4, 1, 4},
		{"override 6 clamped on both lanes", "6", "", "", 4, 1, 6},
		{"lanes 20/6, no override", "", "20", "6", 10, 3, 0},
		{"lanes 20/6, override 2 kept", "2", "20", "6", 2, 2, 2},
		{"lanes 3/3, override 9 clamped to floor(3/2)", "9", "3", "3", 1, 1, 9},
		{"lanes 1/1: at least 1", "", "1", "1", 1, 1, 0},
	}
	fetch := func(t *testing.T, srvURL string) map[string]any {
		t.Helper()
		resp, err := (&http.Client{Timeout: 10 * time.Second}).Get(srvURL + "/__kortex/config")
		if err != nil {
			t.Fatalf("T3m: config get: %v", err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		var c map[string]any
		if err := json.Unmarshal(b, &c); err != nil {
			t.Fatalf("T3m: config not JSON: %v (%q)", err, string(b))
		}
		return c
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := map[string]string{}
			if tc.clientMax != "" {
				env["KORTEX_CLIENT_MAX_INFLIGHT"] = tc.clientMax
			}
			if tc.small != "" {
				env["KORTEX_MAX_INFLIGHT_BODY"] = tc.small
			}
			if tc.lrg != "" {
				env["KORTEX_MAX_INFLIGHT_BODY_LARGE"] = tc.lrg
			}
			srv, _ := newEnv(t, env) // in-process mode: no workers needed to read the config
			c := fetch(t, srv.URL)
			if got := statNum(t, c, "client_max_inflight"); got != tc.wantConfigured {
				t.Fatalf("T3m: client_max_inflight (configured) want %v, got %v", tc.wantConfigured, got)
			}
			if got := statNum(t, c, "client_max_inflight_small"); got != tc.wantSmall {
				t.Fatalf("T3m: client_max_inflight_small (effective) want %v, got %v", tc.wantSmall, got)
			}
			if got := statNum(t, c, "client_max_inflight_large"); got != tc.wantLarge {
				t.Fatalf("T3m: client_max_inflight_large (effective) want %v, got %v", tc.wantLarge, got)
			}
			if wm, ok := c["worker_mode"].(bool); !ok || wm {
				t.Fatalf("T3m: want worker_mode=false in in-process mode, got %v", c["worker_mode"])
			}
		})
	}
	t.Run("worker mode is reported", func(t *testing.T) {
		srv, _ := newEnv(t, workerEnv(map[string]string{"KORTEX_WORKER_POOL": "1", "KORTEX_WORKER_SPARES": "0"}))
		if wm, ok := fetch(t, srv.URL)["worker_mode"].(bool); !ok || !wm {
			t.Fatalf("T3m: want worker_mode=true in worker mode")
		}
	})
}
