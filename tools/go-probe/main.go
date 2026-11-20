// Step-14 T5 (DIAGNOSTIC): coraza v3.7.0 loaded as a LIBRARY with CRS 4.25.2,
// same limits/modes as the nginx runs. Probes:
//   (a) 140,000-byte JSON body        (b) 477 KB text/plain body with timing
//   (c) 20 T6 swap samples, recorded + swapped   (d) 5 plain controls
// Prints statuses, timings and rule-ID counts only — never request values.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

var ruleIDRe = regexp.MustCompile(`^9\d{5}$`)

type wcpSample struct {
	ID          string            `json:"id"`
	Method      string            `json:"method"`
	Path        string            `json:"path"`
	Query       string            `json:"query"`
	Body        string            `json:"body"`
	ContentType string            `json:"content_type"`
	Headers     map[string]string `json:"headers"`
}

func buildWAF(rulesDir string) (coraza.WAF, error) {
	cfg := coraza.NewWAFConfig().
		WithDirectives(strings.Join([]string{
			"SecRuleEngine On",
			"SecRequestBodyAccess On",
			"SecRequestBodyLimit 13107200",
			"SecRequestBodyNoFilesLimit 131072",
			"SecRequestBodyLimitAction Reject",
			"SecResponseBodyAccess Off",
			fmt.Sprintf("Include %s/crs-setup.conf", rulesDir),
			fmt.Sprintf("Include %s/owasp-crs/rules/*.conf", rulesDir),
		}, "\n"))
	return coraza.NewWAF(cfg)
}

// runSample feeds one sample through phases 0-2 and returns (status, elapsed,
// ruleIDs). status 403 = interruption, 200 = passed, 413 = body-limit reject.
func runSample(waf coraza.WAF, s wcpSample) (int, time.Duration, []string) {
	start := time.Now()
	tx := waf.NewTransaction()
	defer tx.Close()

	tx.ProcessConnection("127.0.0.1", 12345, "127.0.0.1", 3000)
	uri := s.Path
	if s.Query != "" {
		uri += "?" + s.Query
	}
	tx.ProcessURI(uri, s.Method, "HTTP/1.1")
	for k, v := range s.Headers {
		if strings.EqualFold(k, "Content-Length") ||
			strings.EqualFold(k, "Content-Type") || strings.EqualFold(k, "Transfer-Encoding") {
			continue
		}
		tx.AddRequestHeader(k, v)
	}
	// in-library there is no connector to add Host; the container runs get
	// Host from http.client (localhost), so mirror that here
	if s.Headers["Host"] == "" {
		tx.AddRequestHeader("Host", "localhost")
	}
	if s.ContentType != "" {
		tx.AddRequestHeader("Content-Type", s.ContentType)
	}
	if s.Body != "" {
		tx.AddRequestHeader("Content-Length", fmt.Sprint(len(s.Body)))
	}
	if it := tx.ProcessRequestHeaders(); it != nil {
		return it.Status, time.Since(start), matchedIDs(tx)
	}
	if s.Body != "" {
		it, _, err := tx.WriteRequestBody([]byte(s.Body))
		if it != nil {
			return it.Status, time.Since(start), matchedIDs(tx)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "write body error %s: %v\n", s.ID, err)
			return 0, time.Since(start), matchedIDs(tx)
		}
	}
	if it, err := tx.ProcessRequestBody(); it != nil {
		return it.Status, time.Since(start), matchedIDs(tx)
	} else if err != nil {
		fmt.Fprintf(os.Stderr, "process body error %s: %v\n", s.ID, err)
		return 0, time.Since(start), matchedIDs(tx)
	}
	return 200, time.Since(start), matchedIDs(tx)
}

func matchedIDs(tx types.Transaction) []string {
	var ids []string
	for _, mr := range tx.MatchedRules() {
		r := mr.Rule()
		if r == nil {
			continue
		}
		id := fmt.Sprint(r.ID())
		if ruleIDRe.MatchString(id) {
			ids = append(ids, id)
		}
	}
	return ids
}

type job struct {
	ID       string `json:"id"`
	Method   string `json:"method"`
	Path     string `json:"path"`
	Query    string `json:"query"`
	CT       string `json:"ct"`
	BodyFile string `json:"body_file"`
	Reps     int    `json:"reps"`
}

func loadAvg() string {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return "unavailable"
	}
	return strings.TrimSpace(string(b))
}

func main() {
	rulesDir := flag.String("rules", "crs", "directory with crs-setup.conf and owasp-crs/rules/")
	manifest := flag.String("manifest", "", "JSONL manifest of samples to run (probe c)")
	bodyFile := flag.String("body-file", "", "raw body file for probe (b)")
	bodyCT := flag.String("body-ct", "text/plain", "content type for -body-file")
	bodyLen := flag.Int("json-bytes", 0, "probe (a): build a JSON body of this many bytes")
	controls := flag.Bool("controls", false, "probe (d): run 5 plain controls")
	jobsFile := flag.String("jobs", "", "JSON array of jobs (step-15 T4 batch mode)")
	flag.Parse()

	waf, err := buildWAF(*rulesDir)
	if err != nil {
		fmt.Println("BLOCKED: waf build failed:", err)
		os.Exit(2)
	}

	if *jobsFile != "" { // step-15 T4 batch mode
		raw, err := os.ReadFile(*jobsFile)
		if err != nil {
			fmt.Println("BLOCKED: jobs file:", err)
			os.Exit(2)
		}
		var jobs []job
		if err := json.Unmarshal(raw, &jobs); err != nil {
			fmt.Println("BLOCKED: jobs decode:", err)
			os.Exit(2)
		}
		fmt.Printf("load_avg_start: %s\n", loadAvg())
		for _, j := range jobs {
			raw, err := os.ReadFile(j.BodyFile)
			if err != nil {
				fmt.Printf("job %s BLOCKED body read: %v\n", j.ID, err)
				continue
			}
			s := wcpSample{ID: j.ID, Method: j.Method, Path: j.Path, Query: j.Query,
				Body: string(raw), ContentType: j.CT, Headers: map[string]string{"Host": "localhost"}}
			reps := j.Reps
			if reps == 0 {
				reps = 3
			}
			for r := 1; r <= reps; r++ {
				st, el, ids := runSample(waf, s)
				det := make([]string, 0)
				for _, id := range ids {
					if id[:3] != "900" && id[:3] != "901" && id[:3] != "949" && id[:3] != "980" {
						det = append(det, id)
					}
				}
				fmt.Printf("job %s rep=%d status=%d elapsed_ms=%.1f rules=%v\n",
					j.ID, r, st, float64(el.Microseconds())/1000.0, det)
			}
		}
		fmt.Printf("load_avg_end: %s\n", loadAvg())
		return
	}

	switch {
	case *bodyLen > 0: // probe (a)
		payload := strings.Repeat("A", *bodyLen-12)
		body := fmt.Sprintf(`{"q":"%s"}`, payload)
		s := wcpSample{ID: fmt.Sprintf("json-%d", *bodyLen), Method: "POST", Path: "/",
			Body: body, ContentType: "application/json",
			Headers: map[string]string{"Host": "localhost"}}
		st, el, ids := runSample(waf, s)
		fmt.Printf("probe-a json-bytes=%d status=%d elapsed_ms=%.1f rules=%v\n",
			*bodyLen, st, float64(el.Microseconds())/1000.0, ids)
	case *bodyFile != "": // probe (b)
		raw, err := os.ReadFile(*bodyFile)
		if err != nil {
			fmt.Println("BLOCKED: body file:", err)
			os.Exit(2)
		}
		s := wcpSample{ID: "body-file", Method: "POST", Path: "/", Body: string(raw),
			ContentType: *bodyCT, Headers: map[string]string{"Host": "localhost"}}
		st, el, ids := runSample(waf, s)
		fmt.Printf("probe-b bytes=%d ct=%s status=%d elapsed_ms=%.1f rules=%v\n",
			len(raw), *bodyCT, st, float64(el.Microseconds())/1000.0, ids)
	case *manifest != "": // probe (c)
		f, err := os.Open(*manifest)
		if err != nil {
			fmt.Println("BLOCKED: manifest:", err)
			os.Exit(2)
		}
		defer f.Close()
		dec := json.NewDecoder(f)
		blocked, passed, errored := 0, 0, 0
		for {
			var s wcpSample
			if err := dec.Decode(&s); err == io.EOF {
				break
			} else if err != nil {
				fmt.Println("BLOCKED: manifest decode:", err)
				os.Exit(2)
			}
			st, el, ids := runSample(waf, s)
			switch {
			case st == 200:
				passed++
			case st == 0:
				errored++
			default:
				blocked++
			}
			fmt.Printf("probe-c %s status=%d elapsed_ms=%.1f rules=%v\n", s.ID, st,
				float64(el.Microseconds())/1000.0, ids)
		}
		fmt.Printf("probe-c summary manifest=%s blocked=%d passed=%d errored=%d\n",
			*manifest, blocked, passed, errored)
	case *controls: // probe (d)
		ctrls := []wcpSample{
			{ID: "ctl-get", Method: "GET", Path: "/", Headers: map[string]string{"Host": "localhost"}},
			{ID: "ctl-get-q", Method: "GET", Path: "/", Query: "q=1", Headers: map[string]string{"Host": "localhost"}},
			{ID: "ctl-post-urlenc", Method: "POST", Path: "/", Body: "q=1",
				ContentType: "application/x-www-form-urlencoded", Headers: map[string]string{"Host": "localhost"}},
			{ID: "ctl-post-text", Method: "POST", Path: "/", Body: "hello",
				ContentType: "text/plain", Headers: map[string]string{"Host": "localhost"}},
			{ID: "ctl-get-missing", Method: "GET", Path: "/missing", Headers: map[string]string{"Host": "localhost"}},
		}
		for _, s := range ctrls {
			st, el, ids := runSample(waf, s)
			fmt.Printf("probe-d %s status=%d elapsed_ms=%.1f rules=%v\n", s.ID, st,
				float64(el.Microseconds())/1000.0, ids)
		}
	default:
		fmt.Println("no probe selected")
		os.Exit(1)
	}
}
