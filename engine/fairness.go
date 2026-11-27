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
// Step-22 design risk (a): the per-client cap is PER LANE and is at most
// floor(lane_cap/2) (at least 1), so one client cannot hold a whole lane.
// KORTEX_CLIENT_MAX_INFLIGHT can lower the cap but never raise it above
// half a lane. In-flight jobs are counted per lane, so a job in one lane
// does not use up the client's allowance in the other.
type fairness struct {
	mu        sync.Mutex
	inflight  map[string]laneCount
	penalty   map[string]time.Time
	maxSmall  int
	maxLarge  int
	penaltyMS int
	maxEntrys int
}

// laneCount is one client's in-flight jobs in each lane.
type laneCount struct{ small, large int }

// clientLaneCap is the per-client cap in force for a lane: half the lane
// cap (floor, at least 1), or the configured value when that is lower.
// configured <= 0 means "not set". A lane cap of 1 still yields 1: "at
// least 1" wins over "at most half" there.
func clientLaneCap(configured, laneCap int) int {
	half := laneCap / 2
	if half < 1 {
		half = 1
	}
	if configured > 0 && configured < half {
		return configured
	}
	return half
}

func newFairness(maxInflight, penaltyMS, maxEntries, smallCap, largeCap int) *fairness {
	return &fairness{
		inflight:  map[string]laneCount{},
		penalty:   map[string]time.Time{},
		maxSmall:  clientLaneCap(maxInflight, smallCap),
		maxLarge:  clientLaneCap(maxInflight, largeCap),
		penaltyMS: penaltyMS,
		maxEntrys: maxEntries,
	}
}

// caps returns the per-client caps in force (small lane, large lane).
func (f *fairness) caps() (small, large int) {
	return f.maxSmall, f.maxLarge
}

// acquire reports whether the client may start another body job in the
// given lane now. lane is "small" or "large" (the request's size class).
func (f *fairness) acquire(key, lane string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sweepLocked()
	c := f.inflight[key]
	if lane == "large" {
		if c.large >= f.maxLarge {
			return false
		}
		c.large++
	} else {
		if c.small >= f.maxSmall {
			return false
		}
		c.small++
	}
	f.inflight[key] = c
	return true
}

// release gives back one job acquired for the same client and lane.
func (f *fairness) release(key, lane string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.inflight[key]
	if !ok {
		return
	}
	if lane == "large" {
		if c.large > 0 {
			c.large--
		}
	} else if c.small > 0 {
		c.small--
	}
	if c == (laneCount{}) {
		delete(f.inflight, key)
	} else {
		f.inflight[key] = c
	}
}

// inflightTotals sums the per-client in-flight jobs over all clients, per
// lane (served on /__kortex/stats).
func (f *fairness) inflightTotals() (small, large int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.inflight {
		small += c.small
		large += c.large
	}
	return small, large
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
