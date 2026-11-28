package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

// ---- step-25 T1: what the CRS regression suite's runner needs ---------------

const s25XSS = "<script>alert(1)</script>"

var errorLogIDRe = regexp.MustCompile(`\[id "(\d+)"\]`)

// errorLogIDs returns the sorted distinct rule ids of an error-log file and
// its lines. A missing file is an empty log.
func errorLogIDs(t *testing.T, path string) ([]string, []string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		t.Fatalf("read error log: %v", err)
	}
	seen := map[string]bool{}
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		lines = append(lines, line)
		for _, m := range errorLogIDRe.FindAllStringSubmatch(line, -1) {
			seen[m[1]] = true
		}
	}
	var ids []string
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, lines
}

func hasID(ids []string, id string) bool {
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}

// s25Env starts the engine with an error log in a fresh directory.
func s25Env(t *testing.T, extra map[string]string) (*httptest.Server, string) {
	t.Helper()
	errLog := filepath.Join(t.TempDir(), "error.log")
	env := map[string]string{"KORTEX_ERROR_LOG": errLog}
	for k, v := range extra {
		env[k] = v
	}
	srv, _ := newEnv(t, env)
	return srv, errLog
}

// s25Do sends one request with Host localhost and a browser User-Agent and
// returns the status and the body.
func s25Do(t *testing.T, srv *httptest.Server, method, target string, hdr map[string]string, body string) (int, string) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, srv.URL+target, rd)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = "localhost"
	req.Header.Set("User-Agent", browserUA)
	req.Header.Set("Accept", "*/*")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func s25Config(t *testing.T, srv *httptest.Server) map[string]any {
	t.Helper()
	status, body := s25Do(t, srv, "GET", "/__kortex/config", nil, "")
	if status != 200 {
		t.Fatalf("config: status %d", status)
	}
	var cfg map[string]any
	if err := json.Unmarshal([]byte(body), &cfg); err != nil {
		t.Fatalf("config is not JSON: %v: %s", err, body)
	}
	return cfg
}

// E49: with KORTEX_ERROR_LOG set, every matched rule that has the log action
// writes one line in the ModSecurity error-log form to that file: in blocking
// mode, in DetectionOnly mode (where the request is forwarded and nothing
// else records the match) and in worker mode. A request that matches nothing
// writes nothing.
func TestE49ErrorLogListsMatchedRules(t *testing.T) {
	attack := "/?q=" + url.QueryEscape(s25XSS)
	cases := []struct {
		name       string
		env        map[string]string
		method     string
		target     string
		body       string
		wantStatus int
		wantIDs    []string
	}{
		{"blocking, query", nil, "GET", attack, "", 403, []string{"941100", "949110"}},
		{"detection-only, query", map[string]string{"KORTEX_RULE_ENGINE": "DetectionOnly"}, "GET", attack, "", 200, []string{"941100"}},
		{"detection-only, body", map[string]string{"KORTEX_RULE_ENGINE": "DetectionOnly"}, "POST", "/", "q=" + url.QueryEscape(s25XSS), 200, []string{"941100"}},
		{"worker mode, body", map[string]string{"KORTEX_WORKER_MODE": "on"}, "POST", "/", "q=" + url.QueryEscape(s25XSS), 403, []string{"941100", "949110"}},
		{"worker mode, detection-only, body", map[string]string{"KORTEX_WORKER_MODE": "on", "KORTEX_RULE_ENGINE": "DetectionOnly"}, "POST", "/", "q=" + url.QueryEscape(s25XSS), 200, []string{"941100"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv, errLog := s25Env(t, c.env)
			hdr := map[string]string{}
			if c.body != "" {
				hdr["Content-Type"] = "application/x-www-form-urlencoded"
			}
			status, _ := s25Do(t, srv, c.method, c.target, hdr, c.body)
			if status != c.wantStatus {
				t.Fatalf("E49 [%s]: want status %d, got %d", c.name, c.wantStatus, status)
			}
			ids, lines := errorLogIDs(t, errLog)
			for _, want := range c.wantIDs {
				if !hasID(ids, want) {
					t.Fatalf("E49 [%s]: error log has no line for rule %s (ids %v, %d lines)", c.name, want, ids, len(lines))
				}
			}
			for _, line := range lines {
				if !strings.Contains(line, `[msg "`) || !errorLogIDRe.MatchString(line) {
					t.Fatalf("E49 [%s]: line is not in the error-log form: %q", c.name, line)
				}
			}
			t.Logf("E49 [%s]: status %d, %d lines, ids %v", c.name, status, len(lines), ids)
		})
	}
	t.Run("benign request writes nothing", func(t *testing.T) {
		srv, errLog := s25Env(t, nil)
		if status, _ := s25Do(t, srv, "GET", "/?q=hello", nil, ""); status != 200 {
			t.Fatalf("E49 benign: want 200, got %d", status)
		}
		if ids, lines := errorLogIDs(t, errLog); len(lines) != 0 {
			t.Fatalf("E49 benign: %d error-log lines, ids %v", len(lines), ids)
		}
	})
	t.Run("path is on the config page", func(t *testing.T) {
		srv, errLog := s25Env(t, nil)
		if got := s25Config(t, srv)["error_log"]; got != errLog {
			t.Fatalf("E49: config error_log = %v, want %q", got, errLog)
		}
	})
}

// E50: KORTEX_CRS_TEST_SETUP=on renders the CRS regression suite's setup:
// the marker rule 999999 (a request with an X-CRS-Test header logs the
// header value and is matched by no other rule) and the limits of the
// suite's rule 900005 (shown here by 920370, argument longer than 400).
func TestE50CRSTestSetup(t *testing.T) {
	on := map[string]string{"KORTEX_CRS_TEST_SETUP": "on", "KORTEX_RULE_ENGINE": "DetectionOnly"}
	attack := "/?q=" + url.QueryEscape(s25XSS)

	t.Run("marker request logs the marker and nothing else", func(t *testing.T) {
		srv, errLog := s25Env(t, on)
		status, _ := s25Do(t, srv, "GET", attack, map[string]string{"X-CRS-Test": "marker-1f2e3d"}, "")
		if status != 200 {
			t.Fatalf("E50 marker: want 200, got %d", status)
		}
		ids, lines := errorLogIDs(t, errLog)
		if len(ids) != 1 || ids[0] != "999999" {
			t.Fatalf("E50 marker: want only rule 999999 in the error log, got %v", ids)
		}
		if len(lines) != 1 || !strings.Contains(lines[0], "X-CRS-Test marker-1f2e3d") {
			t.Fatalf("E50 marker: want one line with the marker value, got %q", lines)
		}
	})
	t.Run("marker rule also holds in blocking mode", func(t *testing.T) {
		srv, errLog := s25Env(t, map[string]string{"KORTEX_CRS_TEST_SETUP": "on"})
		status, _ := s25Do(t, srv, "GET", attack, map[string]string{"X-CRS-Test": "marker-77"}, "")
		ids, _ := errorLogIDs(t, errLog)
		if status != 200 || len(ids) != 1 || ids[0] != "999999" {
			t.Fatalf("E50 marker, blocking: want 200 and only 999999, got %d %v", status, ids)
		}
	})
	t.Run("the same attack without the marker header is logged", func(t *testing.T) {
		srv, errLog := s25Env(t, on)
		s25Do(t, srv, "GET", attack, nil, "")
		ids, _ := errorLogIDs(t, errLog)
		if !hasID(ids, "941100") || hasID(ids, "999999") {
			t.Fatalf("E50 canary: want 941100 and no 999999, got %v", ids)
		}
	})
	longArg := "/?a=" + strings.Repeat("a", 401)
	t.Run("suite limits are set", func(t *testing.T) {
		srv, errLog := s25Env(t, on)
		s25Do(t, srv, "GET", longArg, nil, "")
		ids, _ := errorLogIDs(t, errLog)
		if !hasID(ids, "920370") {
			t.Fatalf("E50 limits: a 401-character argument must match 920370 (tx.arg_length=400), got %v", ids)
		}
		if got := s25Config(t, srv)["crs_test_setup"]; got != true {
			t.Fatalf("E50: config crs_test_setup = %v, want true", got)
		}
	})
	t.Run("a 400-character argument is within the limit", func(t *testing.T) {
		srv, errLog := s25Env(t, on)
		s25Do(t, srv, "GET", "/?a="+strings.Repeat("a", 400), nil, "")
		if ids, _ := errorLogIDs(t, errLog); hasID(ids, "920370") {
			t.Fatalf("E50 limits: 400 characters must not match 920370, got %v", ids)
		}
	})
}

// E51 (guard for E50): without the switch nothing of the suite's setup is
// loaded. The marker header does not protect a request (an attack carrying
// it is blocked by the usual rule and 999999 is not among the matched
// rules), the suite's limits are not set, and only the exact value "on"
// turns the switch on. It reads the block page, not the error log, so it
// holds before and after E49.
func TestE51CRSTestSetupIsOffByDefault(t *testing.T) {
	attack := "/?q=" + url.QueryEscape(s25XSS)
	for _, value := range []string{"", "off", "1", "true", "ON"} {
		t.Run(fmt.Sprintf("KORTEX_CRS_TEST_SETUP=%q", value), func(t *testing.T) {
			env := map[string]string{}
			if value != "" {
				env["KORTEX_CRS_TEST_SETUP"] = value
			}
			srv, _ := newEnv(t, env)
			status, body := s25Do(t, srv, "GET", attack, map[string]string{"X-CRS-Test": "marker-1"}, "")
			if status != 403 || !strings.Contains(body, "kortex-decision=block") {
				t.Fatalf("E51: an attack with the marker header must be blocked, got %d %q", status, body)
			}
			if backendHit {
				t.Fatalf("E51: the attack reached the backend")
			}
			if !strings.Contains(body, "941100") || strings.Contains(body, "999999") {
				t.Fatalf("E51: want 941100 and no 999999 among the matched rules, got %q", body)
			}
			if status, body := s25Do(t, srv, "GET", "/?a="+strings.Repeat("a", 401), nil, ""); status != 200 {
				t.Fatalf("E51: a 401-character argument must pass without the suite's limits, got %d %q", status, body)
			}
			if got, present := s25Config(t, srv)["crs_test_setup"]; present && got != false {
				t.Fatalf("E51: config crs_test_setup = %v, want false", got)
			}
		})
	}
}

// ---- step-25 T3: what the rules are told about the request -----------------

// s25Raw sends a raw request to the engine and returns the status.
func s25Raw(t *testing.T, srv *httptest.Server, raw string) int {
	t.Helper()
	status, _ := rawExchange(t, srv.Listener.Addr().String(), raw)
	return status
}

// s25AuditRequests returns the request section of every audit entry.
func s25AuditRequests(t *testing.T, auditFile string) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(auditFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("read audit log: %v", err)
	}
	var out []map[string]any
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, `{"transaction"`) {
			continue
		}
		var doc struct {
			Transaction struct {
				Request map[string]any `json:"request"`
			} `json:"transaction"`
		}
		if err := json.Unmarshal([]byte(line), &doc); err != nil {
			t.Fatalf("audit line does not parse: %v", err)
		}
		out = append(out, doc.Transaction.Request)
	}
	return out
}

// E52: the rules are given the request line as it was sent: the request
// target unchanged (an absolute-form target without a path is an invalid
// request line for CRS 920100, CRS test 920100-16) and the protocol of the
// request (HTTP/1.0 stays HTTP/1.0 in the audit entry, with the HTTP/ prefix).
func TestE52RulesSeeTheRequestLineAsSent(t *testing.T) {
	t.Run("absolute-form target without a path matches 920100", func(t *testing.T) {
		srv, errLog := s25Env(t, map[string]string{"KORTEX_RULE_ENGINE": "DetectionOnly"})
		status := s25Raw(t, srv, "GET http://localhost HTTP/1.1\r\nHost: localhost\r\nUser-Agent: "+browserUA+"\r\nAccept: */*\r\n\r\n")
		ids, _ := errorLogIDs(t, errLog)
		if status != 200 || !hasID(ids, "920100") {
			t.Fatalf("E52: want 200 and 920100 in the error log, got %d %v", status, ids)
		}
	})
	t.Run("origin-form target is a valid request line", func(t *testing.T) {
		srv, errLog := s25Env(t, map[string]string{"KORTEX_RULE_ENGINE": "DetectionOnly"})
		status := s25Raw(t, srv, "GET /a/b?x=1 HTTP/1.1\r\nHost: localhost\r\nUser-Agent: "+browserUA+"\r\nAccept: */*\r\n\r\n")
		ids, _ := errorLogIDs(t, errLog)
		if status != 200 || hasID(ids, "920100") {
			t.Fatalf("E52 guard: want 200 and no 920100, got %d %v", status, ids)
		}
	})
	for _, proto := range []string{"HTTP/1.0", "HTTP/1.1"} {
		t.Run("protocol "+proto+" reaches the audit entry", func(t *testing.T) {
			dir := t.TempDir()
			audit := filepath.Join(dir, "audit.log")
			srv, _ := newEnv(t, map[string]string{"KORTEX_AUDIT_LOG": audit})
			target := "/p?q=" + url.QueryEscape(s25XSS)
			status := s25Raw(t, srv, "GET "+target+" "+proto+"\r\nHost: localhost\r\nUser-Agent: "+browserUA+"\r\nAccept: */*\r\n\r\n")
			if status != 403 {
				t.Fatalf("E52: want 403, got %d", status)
			}
			reqs := s25AuditRequests(t, audit)
			if len(reqs) != 1 {
				t.Fatalf("E52: want 1 audit entry, got %d", len(reqs))
			}
			if got := reqs[0]["protocol"]; got != proto {
				t.Fatalf("E52: audit protocol = %v, want %q", got, proto)
			}
			if got := reqs[0]["uri"]; got != target {
				t.Fatalf("E52: audit uri = %v, want %q", got, target)
			}
		})
	}
}

// E53: a Transfer-Encoding header is shown to the rules. Go's net/http takes
// it out of the header map, so the engine has to hand it over itself; CRS
// 920171 (GET or HEAD with Transfer-Encoding, CRS tests 920171-2 and -3)
// can only match if it does. In-process and in worker mode.
func TestE53RulesSeeTransferEncoding(t *testing.T) {
	raw := func(method string) string {
		return method + " /te HTTP/1.1\r\nHost: localhost\r\nUser-Agent: " + browserUA +
			"\r\nAccept: */*\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
	}
	for _, mode := range []struct {
		name string
		env  map[string]string
	}{
		{"in-process", map[string]string{"KORTEX_RULE_ENGINE": "DetectionOnly"}},
		{"worker", map[string]string{"KORTEX_RULE_ENGINE": "DetectionOnly", "KORTEX_WORKER_MODE": "on"}},
	} {
		t.Run(mode.name+", GET with Transfer-Encoding matches 920171", func(t *testing.T) {
			srv, errLog := s25Env(t, mode.env)
			status := s25Raw(t, srv, raw("GET"))
			ids, _ := errorLogIDs(t, errLog)
			if status != 200 || !hasID(ids, "920171") {
				t.Fatalf("E53 [%s]: want 200 and 920171, got %d %v", mode.name, status, ids)
			}
		})
		t.Run(mode.name+", POST with Transfer-Encoding does not", func(t *testing.T) {
			srv, errLog := s25Env(t, mode.env)
			status := s25Raw(t, srv, raw("POST"))
			ids, _ := errorLogIDs(t, errLog)
			if status != 200 || hasID(ids, "920171") {
				t.Fatalf("E53 guard [%s]: want 200 and no 920171, got %d %v", mode.name, status, ids)
			}
		})
	}
}

// E54: the rules see the Host header the request has, and none when it has
// none. HTTP/1.0 without a Host line is CRS 920280 (missing Host, CRS test
// 920280-1); an empty Host line is CRS 920290 (empty Host); a normal Host is
// neither. With a body the same holds in worker mode.
func TestE54RulesSeeTheHostHeaderAsSent(t *testing.T) {
	head := "User-Agent: " + browserUA + "\r\nAccept: */*\r\n"
	body := "a=1"
	post := "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 3\r\n"
	cases := []struct {
		name    string
		raw     string
		want    string
		wantNot string
	}{
		{"HTTP/1.0 without Host", "GET /h HTTP/1.0\r\n" + head + "\r\n", "920280", "920290"},
		{"empty Host line", "GET /h HTTP/1.1\r\nHost:\r\n" + head + "\r\n", "920290", "920280"},
		{"normal Host", "GET /h HTTP/1.1\r\nHost: localhost\r\n" + head + "\r\n", "", "920280,920290"},
		{"HTTP/1.0 without Host, body", "POST /h HTTP/1.0\r\n" + head + post + "\r\n" + body, "920280", "920290"},
		{"empty Host line, body", "POST /h HTTP/1.1\r\nHost:\r\n" + head + post + "\r\n" + body, "920290", "920280"},
	}
	for _, mode := range []struct {
		name string
		env  map[string]string
	}{
		{"in-process", map[string]string{"KORTEX_RULE_ENGINE": "DetectionOnly"}},
		{"worker", map[string]string{"KORTEX_RULE_ENGINE": "DetectionOnly", "KORTEX_WORKER_MODE": "on"}},
	} {
		for _, c := range cases {
			t.Run(mode.name+", "+c.name, func(t *testing.T) {
				srv, errLog := s25Env(t, mode.env)
				status := s25Raw(t, srv, c.raw)
				ids, _ := errorLogIDs(t, errLog)
				if status != 200 {
					t.Fatalf("E54 [%s, %s]: want 200, got %d", mode.name, c.name, status)
				}
				if c.want != "" && !hasID(ids, c.want) {
					t.Fatalf("E54 [%s, %s]: want %s, got %v", mode.name, c.name, c.want, ids)
				}
				for _, not := range strings.Split(c.wantNot, ",") {
					if hasID(ids, not) {
						t.Fatalf("E54 [%s, %s]: %s must not match, got %v", mode.name, c.name, not, ids)
					}
				}
			})
		}
	}
}

// E55: CRS 942130 (SQL tautology) gets no REQUEST_BODY target. Its chained
// rule compares the two words captured by the last variable that matched,
// and the added target is evaluated last, so on a form body the chain judged
// the raw body instead of the argument. The first "word = word" of a raw
// form body is the name=value pair itself, which is never a tautology: the
// rule could not match in a form body at all (CRS test 942130-7,
// a=42 like 42). The other chain-starting rules keep their target: E24 needs
// it on 932240.
func TestE55TautologyRuleKeepsItsOwnTargets(t *testing.T) {
	pl2 := map[string]string{"KORTEX_RULE_ENGINE": "DetectionOnly", "KORTEX_BLOCKING_PARANOIA": "2", "KORTEX_DETECTION_PARANOIA": "2"}
	tautology := "a=42%20like%2042"
	t.Run("canary: tautology in the query string matches 942130", func(t *testing.T) {
		srv, errLog := s25Env(t, pl2)
		s25Do(t, srv, "GET", "/?"+tautology, nil, "")
		if ids, _ := errorLogIDs(t, errLog); !hasID(ids, "942130") {
			t.Fatalf("E55 canary: want 942130, got %v", ids)
		}
	})
	t.Run("tautology in a form body matches 942130", func(t *testing.T) {
		srv, errLog := s25Env(t, pl2)
		s25Do(t, srv, "POST", "/post", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, tautology)
		if ids, _ := errorLogIDs(t, errLog); !hasID(ids, "942130") {
			t.Fatalf("E55: want 942130 for a tautology in a form body, got %v", ids)
		}
	})
	t.Run("942130 is not in the target updates, 932240 still is", func(t *testing.T) {
		ids, err := requestBodyTargetUpdates(rulesDirForTests())
		if err != nil {
			t.Fatalf("E55: %v", err)
		}
		has := map[int]bool{}
		for _, id := range ids {
			has[id] = true
		}
		if has[942130] || !has[932240] || len(ids) != 165 {
			t.Fatalf("E55: want 165 target updates without 942130 and with 932240, got %d updates, 942130 %t, 932240 %t",
				len(ids), has[942130], has[932240])
		}
	})
}
