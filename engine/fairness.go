package main

// Per-client fairness (step-21 T3): client identity, per-client in-flight
// cap and penalty state after a budget kill. Client = peer address; with
// a configured trusted-proxy list the client is the FIRST untrusted
// X-Forwarded-For hop. Default: no trusted proxies, XFF ignored.

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// clientKey derives the fairness identity of a request.
func clientKey(r *http.Request, trusted []*net.IPNet) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil || len(trusted) == 0 || !ipInNets(ip, trusted) {
		return host
	}
	// peer is a trusted proxy: the client is the first untrusted XFF hop
	xff := r.Header.Get("X-Forwarded-For")
	for _, hop := range strings.Split(xff, ",") {
		hop = strings.TrimSpace(hop)
		h := net.ParseIP(hop)
		if h == nil {
			continue
		}
		if !ipInNets(h, trusted) {
			return hop
		}
	}
	return host
}

func ipInNets(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func parseTrustedProxies(spec string) []*net.IPNet {
	var out []*net.IPNet
	for _, s := range strings.Split(spec, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(s); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// fairness tracks per-client in-flight jobs and penalty deadlines.
// Step-22 design risk (a): the per-client cap is PER LANE and defaults to
// floor(lane_cap/2) (at least 1), so one client cannot hold a whole lane.
// An explicit KORTEX_CLIENT_MAX_INFLIGHT overrides both lanes.
type fairness struct {
	mu        sync.Mutex
	inflight  map[string]int
	penalty   map[string]time.Time
	maxSmall  int
	maxLarge  int
	penaltyMS int
	maxEntrys int
}

func newFairness(maxInflight, penaltyMS, maxEntries, smallCap, largeCap int) *fairness {
	maxSmall, maxLarge := maxInflight, maxInflight
	if maxInflight <= 0 {
		maxSmall = smallCap / 2
		if maxSmall < 1 {
			maxSmall = 1
		}
		maxLarge = largeCap / 2
		if maxLarge < 1 {
			maxLarge = 1
		}
	}
	return &fairness{
		inflight:  map[string]int{},
		penalty:   map[string]time.Time{},
		maxSmall:  maxSmall,
		maxLarge:  maxLarge,
		penaltyMS: penaltyMS,
		maxEntrys: maxEntries,
	}
}

// acquire reports whether the client may start another body job now.
// lane is "small" or "large" (the request's size-class lane).
func (f *fairness) acquire(key, lane string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sweepLocked()
	max := f.maxSmall
	if lane == "large" {
		max = f.maxLarge
	}
	if max > 0 && f.inflight[key] >= max {
		return false
	}
	f.inflight[key]++
	return true
}

func (f *fairness) releaseC(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.inflight[key] > 1 {
		f.inflight[key]--
	} else {
		delete(f.inflight, key)
	}
}

// penalise marks a client after a budget kill.
func (f *fairness) penalise(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.maxEntrys > 0 && len(f.penalty) >= f.maxEntrys {
		f.sweepLocked()
		// still full: evict the earliest deadline
		var oldestKey string
		var oldest time.Time
		for k, until := range f.penalty {
			if oldestKey == "" || until.Before(oldest) {
				oldestKey, oldest = k, until
			}
		}
		if oldestKey != "" {
			delete(f.penalty, oldestKey)
		}
	}
	f.penalty[key] = time.Now().Add(time.Duration(f.penaltyMS) * time.Millisecond)
}

// penalised reports whether the client is currently in penalty state.
func (f *fairness) penalised(key string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sweepLocked()
	_, ok := f.penalty[key]
	return ok
}

func (f *fairness) penalisedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sweepLocked()
	return len(f.penalty)
}

func (f *fairness) sweepLocked() {
	now := time.Now()
	for k, until := range f.penalty {
		if until.Before(now) {
			delete(f.penalty, k)
		}
	}
}
