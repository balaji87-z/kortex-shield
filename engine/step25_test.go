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
