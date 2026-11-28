package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

// readEvents returns every line of the events file as a decoded event; a
// missing file is no events.
func readEvents(t *testing.T, eventsFile string) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(eventsFile)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatalf("read events: %v", err)
	}
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var ev map[string]any
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("bad event line %q: %v", line, err)
		}
		out = append(out, ev)
	}
	return out
}

// E35: every refusal of the framing gate writes one event to
// kortex-events.jsonl (decision "framing", status 400, the gate's reason and
// the request's sample id). Found in step 22 (C6): the gate answered 400
// and wrote nothing, while events.go and docs/block-discriminator.md say
// framing decisions are always logged. The refusal is synchronous: the event
// is written before the 400 is sent, so it can be read as soon as the
// response is.
func TestE35FramingRefusalLogsEvent(t *testing.T) {
	cases := []struct {
		id, raw, reason string
	}{
		{"e35-conflict", "POST / HTTP/1.1\r\nHost: localhost\r\nX-Kortex-Sample-Id: e35-conflict\r\n" +
			"Content-Length: 5\r\nContent-Length: 6\r\n\r\nhello", "conflicting-content-length"},
		{"e35-duplicate", "POST / HTTP/1.1\r\nHost: localhost\r\nX-Kortex-Sample-Id: e35-duplicate\r\n" +
			"Content-Length: 5\r\nContent-Length: 5\r\n\r\nhello", "duplicate-content-length"},
		{"e35-te-cl", "POST / HTTP/1.1\r\nHost: localhost\r\nX-Kortex-Sample-Id: e35-te-cl\r\n" +
			"Transfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n", "transfer-encoding-with-content-length"},
		{"e35-nul", "GET /?q=a\x00b HTTP/1.1\r\nHost: localhost\r\nX-Kortex-Sample-Id: e35-nul\r\n\r\n", "nul-in-target"},
		// a refusal must be logged even when the request names no sample id
		{"", "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nx", "conflicting-content-length"},
	}
	for _, c := range cases {
		name := c.id
		if name == "" {
			name = "no-sample-id"
		}
		t.Run(name, func(t *testing.T) {
			srv, events := newEnv(t, nil)
			resp := rawRequest(t, srv, c.raw)
			if resp.status != 400 || !strings.Contains(resp.body, "kortex-decision=framing") {
				t.Fatalf("E35 precondition: want the gate's 400 framing answer, got %d %q", resp.status, resp.body)
			}
			if backendHit {
				t.Fatalf("E35: request must not reach the backend")
			}
			var framing []map[string]any
			for _, ev := range readEvents(t, events) {
				if ev["decision"] == "framing" {
					framing = append(framing, ev)
				}
			}
			if len(framing) != 1 {
				t.Fatalf("E35: want exactly 1 framing event for the refused request, got %d (events: %v)",
					len(framing), readEvents(t, events))
			}
			ev := framing[0]
			if ev["status"] != float64(400) {
				t.Fatalf("E35: event status: want 400, got %v", ev["status"])
			}
			if ev["reason"] != c.reason {
				t.Fatalf("E35: event reason: want %q, got %v", c.reason, ev["reason"])
			}
			if ev["sample_id"] != c.id {
				t.Fatalf("E35: event sample_id: want %q, got %v", c.id, ev["sample_id"])
			}
		})
	}
}

// E36: the canary for E35. A request the gate lets through writes no framing
// event, so E35's event is tied to the refusal and not to every connection.
func TestE36PassedRequestWritesNoFramingEvent(t *testing.T) {
	srv, events := newEnv(t, nil)
	resp := rawRequest(t, srv, "POST / HTTP/1.1\r\nHost: localhost\r\nX-Kortex-Sample-Id: e36-ok\r\n"+
		"Content-Type: text/plain\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
	if resp.status != 200 {
		t.Fatalf("E36 precondition: want 200 from the stub, got %d %q", resp.status, resp.body)
	}
	for _, ev := range readEvents(t, events) {
		if ev["decision"] == "framing" {
			t.Fatalf("E36: a passed request wrote a framing event: %v", ev)
		}
	}
}

// ---- step-23 T2: deterministic rule matching --------------------------------

const browserUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36"

var auditRuleIDRe = regexp.MustCompile(`\[id "(\d+)"\]`)

// auditRuleSets reads the engine audit log and returns, per sample id, the
// sorted set of rule ids named in that transaction's messages.
func auditRuleSets(t *testing.T, auditFile string) map[string]string {
	t.Helper()
	out := map[string]string{}
	data, err := os.ReadFile(auditFile)
	if os.IsNotExist(err) {
		return out
	}
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, `{"transaction"`) {
			continue
		}
		var doc struct {
			Transaction struct {
				Request struct {
					Headers map[string][]string `json:"headers"`
				} `json:"request"`
			} `json:"transaction"`
			Messages []struct {
				ErrorMessage string `json:"error_message"`
			} `json:"messages"`
		}
		if err := json.Unmarshal([]byte(line), &doc); err != nil {
			t.Fatalf("audit line does not parse: %v", err)
		}
		ids := doc.Transaction.Request.Headers["x-kortex-sample-id"]
		if len(ids) == 0 {
			continue
		}
		seen := map[string]bool{}
		for _, m := range doc.Messages {
			for _, g := range auditRuleIDRe.FindAllStringSubmatch(m.ErrorMessage, -1) {
				seen[g[1]] = true
			}
		}
		set := make([]string, 0, len(seen))
		for id := range seen {
			set = append(set, id)
		}
		sort.Strings(set)
		out[ids[0]] = strings.Join(set, ",")
	}
	return out
}

// replayOutcomes sends the same POST n times (a fresh sample id each time,
// Host localhost as in the replay runs) and returns how often each
// (status, audit rule-id set) pair occurred, plus the number of 503 answers.
// A 503 is the engine's time budget under host load, not a matching result
// (the lesson of E30), so it is counted apart and never compared.
func replayOutcomes(t *testing.T, srv *httptest.Server, prefix, contentType, body string, n int) (map[string]int, int) {
	t.Helper()
	statuses := make(map[string]int, n)
	timeouts := 0
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("%s-%04d", prefix, i)
		req, err := http.NewRequest("POST", srv.URL+"/", strings.NewReader(body))
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Host = "localhost:8090"
		req.Header.Set("X-Kortex-Sample-Id", id)
		req.Header.Set("Content-Type", contentType)
		req.Header.Set("User-Agent", browserUA)
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusServiceUnavailable {
			timeouts++
			continue
		}
		statuses[id] = resp.StatusCode
	}
	// the audit entry of a request is written when its transaction closes;
	// wait until the log has stopped growing
	auditFile := os.Getenv("KORTEX_AUDIT_LOG")
	var sets map[string]string
	last, stable := -1, 0
	for deadline := time.Now().Add(10 * time.Second); stable < 3 && time.Now().Before(deadline); {
		sets = auditRuleSets(t, auditFile)
		if len(sets) == last {
			stable++
		} else {
			last, stable = len(sets), 0
		}
		time.Sleep(100 * time.Millisecond)
	}
	outcomes := map[string]int{}
	for id, status := range statuses {
		outcomes[fmt.Sprintf("status %d rules [%s]", status, sets[id])]++
	}
	return outcomes, timeouts
}

func describeOutcomes(outcomes map[string]int) string {
	keys := make([]string, 0, len(outcomes))
	for k := range outcomes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "\n    x%d: %s", outcomes[k], k)
	}
	return b.String()
}

func pl2Env(t *testing.T) *httptest.Server {
	t.Helper()
	srv, _ := newEnv(t, map[string]string{"KORTEX_BLOCKING_PARANOIA": "2", "KORTEX_DETECTION_PARANOIA": "2"})
	return srv
}

// requireOneOutcome fails unless all n replays that were not a 503 gave the
// same status and the same audit rule-id set.
func requireOneOutcome(t *testing.T, id, name string, outcomes map[string]int, timeouts, n int) {
	t.Helper()
	if timeouts > n/10 {
		t.Fatalf("%s [%s]: environment too noisy: %d of %d replays were 503 (want <= %d)", id, name, timeouts, n, n/10)
	}
	if len(outcomes) != 1 {
		t.Fatalf("%s [%s]: %d replays of one unchanged request gave %d distinct (status, rule-id set) outcomes, want 1 (503s set aside: %d):%s",
			id, name, n, len(outcomes), timeouts, describeOutcomes(outcomes))
	}
	t.Logf("%s [%s]: %d replays, 503s set aside: %d, one outcome:%s", id, name, n, timeouts, describeOutcomes(outcomes))
}

const (
	synXSS    = "%3Cscript%3Ealert(1)%3C%2Fscript%3E"
	synOthers = "&a=1&b=2&c=3&d=4&e=5&f=6&g=7&h=8"
)

// E37: an unchanged request gets the same status and the same matched rules
// every time. The two requests are the synthetic ones of step-22 F1
// (tools/run_step22_variance_diag.py), 2,000 replays each at PL2:
//
//	syn-chain  JSON {"filter":"color=blue","note":"1=1"}: CRS 942130 captures
//	           both sides of x=y from every matching value and its chained
//	           rule compares the captures of whichever value came last. On
//	           stock coraza v3.8.1 the map-backed collections iterate in
//	           random order, so the request was blocked in 131 of 200 replays
//	           and passed in 69.
//	syn-dup    urlencoded, the key "tag" twice ("hello" and an XSS canary)
//	           plus eight other keys: the transformation cache is keyed by
//	           position in the iteration, so the matched rule set varied (2
//	           sets, 8 inbound scores in 200 replays).
//
// Not timing luck (rule 48): on the stock library each replay of syn-chain
// passes with probability about 1/3, so 2,000 identical outcomes do not
// happen by chance.
func TestE37UnchangedRequestMatchesTheSameEveryTime(t *testing.T) {
	const n = 2000
	cases := []struct{ name, contentType, body string }{
		{"syn-chain", "application/json", `{"filter":"color=blue","note":"1=1"}`},
		{"syn-dup", "application/x-www-form-urlencoded", "tag=hello&tag=" + synXSS + synOthers},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := pl2Env(t)
			outcomes, timeouts := replayOutcomes(t, srv, "e37-"+c.name, c.contentType, c.body, n)
			requireOneOutcome(t, "E37", c.name, outcomes, timeouts, n)
		})
	}
}

// E38: the order in which a JSON body lists its members does not change the
// decision. syn-chain and syn-chain-rev hold the same two members; on stock
// coraza v3.8.1 they were blocked 131 and 69 times of 200.
func TestE38MemberOrderDoesNotChangeTheDecision(t *testing.T) {
	const n = 300
	srv := pl2Env(t)
	a, ta := replayOutcomes(t, srv, "e38-fwd", "application/json", `{"filter":"color=blue","note":"1=1"}`, n)
	b, tb := replayOutcomes(t, srv, "e38-rev", "application/json", `{"note":"1=1","filter":"color=blue"}`, n)
	requireOneOutcome(t, "E38", "filter-then-note", a, ta, n)
	requireOneOutcome(t, "E38", "note-then-filter", b, tb, n)
	for k := range a {
		if _, ok := b[k]; !ok {
			t.Fatalf("E38: the two member orders are decided differently:\n  filter-then-note:%s\n  note-then-filter:%s",
				describeOutcomes(a), describeOutcomes(b))
		}
	}
}

// E39: determinism is all that sorted iteration gives. When the tautology's
// key sorts BEFORE the decoy's key, the chained rule of 942130 always sees
// the decoy's captures. This test requires one outcome in every replay and
// logs which one it is; it does not require a block, because whether CRS
// 942130 should catch a tautology followed by a harmless x=y member is a
// rule question, not an engine one (step-22 F2b: ModSecurity passes it too).
func TestE39TautologySortedFirstIsDecidedTheSameEveryTime(t *testing.T) {
	const n = 300
	srv := pl2Env(t)
	outcomes, timeouts := replayOutcomes(t, srv, "e39", "application/json", `{"anote":"1=1","zfilter":"color=blue"}`, n)
	requireOneOutcome(t, "E39", "tautology-key-sorts-first", outcomes, timeouts, n)
}
