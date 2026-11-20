// Step-16 T2 acceptance tests (rule 40: committed FAILING before the fix).
//
// Root cause being fixed (step-15 T6 diff, step-16 T1, PROVEN): the engine
// did not mirror the connector image's body-processor selection rules
// (coraza.conf ids 200000 XML / 200001 JSON) or its body-parse-failure deny
// rules (200002 REQBODY_ERROR, 200003 multipart strict, 200007 &ARGS>=1000,
// all deny status 400). Without 200001, CRS 901340 forces the body variable
// and coraza v3.7.0 (transaction.go, ProcessRequestBody) falls back to the
// URLENCODED processor for application/json bodies, so ARGS/ARGS_NAMES hold
// the raw JSON text (e.g. ARGS_NAMES matched `{"email":` in the engine audit
// for sqli-304cb2e9-login) instead of the parsed JSON values. That both
// missed detections the connector made and produced detections the
// connector did not make.
//
// The tables below are the step-15 T6 differing ids per dataset/PL cell with
// the CONNECTOR's outcome for each (true = connector blocked). After the fix
// the engine must agree with the connector on every id. Ids excluded from a
// table are listed in the comment with their class.
//
// E10 engine matches the connector on the attacks-v0 JSON diff ids (PL1+PL2)
// E11 malformed JSON body denied 400 like the connector (rule 200002)
// E12 JSON body with >= 1000 arguments denied 400 like the connector (rule 200007)
// E13 XML body traversal blocked via the XML processor (rule 200000 -> 930110)
// E14 engine matches the connector on the benign-hard-v0 JSON diff ids (PL1+PL2)
// E15 engine matches the connector on the benign-browse-v1 PL2 engine-only JSON ids
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// dataDirForTests mirrors rulesDirForTests: tests run from engine/.
func dataDirForTests() string {
	if _, err := os.Stat("../data/attacks-v0/manifest.jsonl"); err == nil {
		return ".."
	}
	return "."
}

// manifestSample is the subset of the frozen manifest the tests need.
type manifestSample struct {
	ID          string `json:"id"`
	Method      string `json:"method"`
	Path        string `json:"path"`
	Query       string `json:"query"`
	Body        string `json:"body"`
	ContentType string `json:"content_type"`
}

func loadManifestSamples(t *testing.T, dataset string, ids map[string]bool) map[string]manifestSample {
	t.Helper()
	f, err := os.Open(dataDirForTests() + "/data/" + dataset + "/manifest.jsonl")
	if err != nil {
		t.Fatalf("open manifest: %v", err)
	}
	defer f.Close()
	out := map[string]manifestSample{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1024*1024), 8*1024*1024)
	for sc.Scan() {
		var s manifestSample
		if err := json.Unmarshal(sc.Bytes(), &s); err != nil {
			t.Fatalf("bad manifest line: %v", err)
		}
		// map[string]bool: a false value (engine must PASS) is still a
		// wanted id — check presence, not the value
		if _, want := ids[s.ID]; want {
			out[s.ID] = s
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan manifest: %v", err)
	}
	for id := range ids {
		if _, ok := out[id]; !ok {
			t.Fatalf("id %q not in %s manifest", id, dataset)
		}
	}
	return out
}

// sendSample mirrors the runner's request construction (kortex_eval/runner.py):
// verbatim method and request line, Accept-Encoding: identity,
// X-Kortex-Sample-Id, recorded content type, body as-is.
func sendSample(t *testing.T, srv *httptest.Server, s manifestSample) (int, string) {
	t.Helper()
	target := s.Path
	if s.Query != "" {
		target += "?" + s.Query
	}
	var req *http.Request
	var err error
	if s.Method == "POST" || s.Body != "" {
		req, err = http.NewRequest("POST", srv.URL+target, strings.NewReader(s.Body))
	} else {
		req, err = http.NewRequest(s.Method, srv.URL+target, nil)
	}
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("X-Kortex-Sample-Id", s.ID)
	if s.ContentType != "" {
		req.Header.Set("Content-Type", s.ContentType)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, string(b)
}

// parityCheck sends every id in the table and compares the engine's block
// decision with the connector's recorded outcome.
func parityCheck(t *testing.T, srv *httptest.Server, dataset string, want map[string]bool) {
	t.Helper()
	samples := loadManifestSamples(t, dataset, want)
	mismatch := 0
	for id, wantBlock := range want {
		s := samples[id]
		status, body := sendSample(t, srv, s)
		gotBlock := status == 403 && strings.Contains(body, "kortex-decision=block")
		if gotBlock != wantBlock {
			mismatch++
			if mismatch <= 10 {
				t.Errorf("parity %s %s: want block=%v, got status=%d block=%v", dataset, id, wantBlock, status, gotBlock)
			}
		}
	}
	if mismatch > 0 {
		t.Fatalf("%s: %d/%d parity mismatches (first 10 shown)", dataset, mismatch, len(want))
	}
}

// postJSON sends a POST with an explicit content type and returns status+body.
func postJSON(t *testing.T, srv *httptest.Server, id, ct, body string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest("POST", srv.URL+"/rest/user/login", strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Kortex-Sample-Id", id)
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, string(b)
}

// --- E10: attacks-v0 JSON diff ids must match the connector ------------------
// PL1 table: 65 ids (55 ref-only misses + 10 engine-only false blocks).
// PL2 table: 14 ids, all engine-only false blocks. Two T6 PL2 diff ids are
// excluded: command-injection-036c522d-q (GET, query-carried) and
// command-injection-036c522d-login (JSON POST whose payload carries %XX).
// Both were passed by the T6 ref run but the CURRENT PL2 connector container
// blocks both with 920230 (DIAGNOSTIC replays,
// docs/logs/step16-t1-920230-replay.txt), so the T6 ref artifacts for them
// are not reproducible; they are counted UNEXPLAINED in reports/step-16.md
// and re-measured by the T2 re-run.
func TestE10AttacksV0JSONDiffParityPL1(t *testing.T) {
	srv, _ := newEnv(t, nil)
	parityCheck(t, srv, "attacks-v0", wantAttacksV0PL1)
}

func TestE10AttacksV0JSONDiffParityPL2(t *testing.T) {
	srv, _ := newEnv(t, map[string]string{
		"KORTEX_BLOCKING_PARANOIA":  "2",
		"KORTEX_DETECTION_PARANOIA": "2",
	})
	parityCheck(t, srv, "attacks-v0", wantAttacksV0PL2)
}

// --- E11: malformed JSON denied 400 like the connector (rule 200002) ---------
func TestE11MalformedJSONDenied400LikeConnector(t *testing.T) {
	srv, _ := newEnv(t, nil)
	resp, body := postJSON(t, srv, "e11-badjson", "application/json", `{not json`)
	if resp.StatusCode != 400 {
		t.Fatalf("E11: want 400 deny (rule 200002), got %d body=%q", resp.StatusCode, body)
	}
	if backendHit {
		t.Fatalf("E11: denied request must not reach the backend")
	}
}

// --- E12: JSON with >= 1000 args denied 400 like the connector (200007) ------
func TestE12JSONThousandArgsDenied400LikeConnector(t *testing.T) {
	srv, _ := newEnv(t, nil)
	var sb strings.Builder
	sb.WriteString("{")
	for i := 0; i < 1000; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, `"k%d":"v"`, i)
	}
	sb.WriteString("}")
	resp, body := postJSON(t, srv, "e12-args", "application/json", sb.String())
	if resp.StatusCode != 400 {
		t.Fatalf("E12: want 400 deny (rule 200007), got %d body=%q", resp.StatusCode, body)
	}
	if backendHit {
		t.Fatalf("E12: denied request must not reach the backend")
	}
}

// --- E13: XML body traversal blocked via the XML processor (200000) ----------
// The urlencoded fallback leaves ARGS empty for a body with no '=' or '&',
// so pre-fix this blocks only via mangled ARGS_NAMES rules (930120/932160);
// the assertion on 930110 makes the test fail until the XML processor exists.
func TestE13XMLBodyTraversalBlockedViaXMLProcessor(t *testing.T) {
	srv, _ := newEnv(t, nil)
	resp, body := postJSON(t, srv, "e13-xml", "text/xml", `<a>../../etc/passwd</a>`)
	if resp.StatusCode != 403 {
		t.Fatalf("E13: want 403 block, got %d body=%q", resp.StatusCode, body)
	}
	if !strings.Contains(body, "kortex-decision=block") {
		t.Fatalf("E13: body missing block marker: %q", body)
	}
	if !strings.Contains(body, "930110") && !strings.Contains(body, "930100") {
		t.Fatalf("E13: block not via the XML-variable rules 930100/930110: %q", body)
	}
	if backendHit {
		t.Fatalf("E13: blocked request must not reach the backend")
	}
}

// --- E14: benign-hard-v0 JSON diff ids must match the connector --------------
// PL1 table: 23 ids (18 engine-only false blocks + 5 ref-only misses).
// PL2 table: 51 ids, all engine-only false blocks.
func TestE14BenignHardJSONDiffParityPL1(t *testing.T) {
	srv, _ := newEnv(t, nil)
	parityCheck(t, srv, "benign-hard-v0", wantBenignHardPL1)
}

func TestE14BenignHardJSONDiffParityPL2(t *testing.T) {
	srv, _ := newEnv(t, map[string]string{
		"KORTEX_BLOCKING_PARANOIA":  "2",
		"KORTEX_DETECTION_PARANOIA": "2",
	})
	parityCheck(t, srv, "benign-hard-v0", wantBenignHardPL2)
}

// --- E15: benign-browse-v1 PL2 engine-only JSON ids must pass ----------------
// 90 ids; the 60 ref-only 920420 ids of the same cell are the documented C4
// design difference (engine allows content types the connector's policy
// forbids) and are deliberately NOT in this table.
func TestE15BenignBrowsePL2EngineOnlyJSONPass(t *testing.T) {
	srv, _ := newEnv(t, map[string]string{
		"KORTEX_BLOCKING_PARANOIA":  "2",
		"KORTEX_DETECTION_PARANOIA": "2",
	})
	parityCheck(t, srv, "benign-browse-v1", wantBenignBrowsePL2EngineOnly)
}

var wantAttacksV0PL1 = map[string]bool{
	"command-injection-036c522d-login": false,
	"command-injection-1bff845a-login": true,
	"command-injection-1e054ad2-login": true,
	"command-injection-43aaa6fe-login": false,
	"command-injection-498d017a-login": true,
	"command-injection-55090590-login": true,
	"command-injection-5dd90c56-login": false,
	"command-injection-77a634bd-login": true,
	"command-injection-86b08086-login": true,
	"command-injection-9255e799-login": false,
	"command-injection-933f7004-login": false,
	"command-injection-9a990e35-login": true,
	"command-injection-ae105740-login": true,
	"command-injection-b336a991-login": true,
	"command-injection-c754be48-login": true,
	"command-injection-cd3079a9-login": true,
	"command-injection-d090c063-login": true,
	"command-injection-d1400c1b-login": false,
	"command-injection-d62a0c50-login": true,
	"command-injection-dc2932d5-login": true,
	"command-injection-ea885b41-login": true,
	"command-injection-edd1a45b-login": true,
	"command-injection-f7d36638-login": false,
	"path-traversal-58195129-login": true,
	"path-traversal-8aab46a5-login": true,
	"path-traversal-d6aad809-login": false,
	"sqli-06acab32-login": true,
	"sqli-07a2ed1e-login": true,
	"sqli-0933fb66-login": true,
	"sqli-0c1567f5-login": true,
	"sqli-0ee59083-login": true,
	"sqli-180d12ba-login": true,
	"sqli-1c13e2dc-login": true,
	"sqli-1db92de8-login": true,
	"sqli-1e018b13-login": true,
	"sqli-27f94926-login": true,
	"sqli-304cb2e9-login": false,
	"sqli-32d32940-login": true,
	"sqli-382abb8b-login": true,
	"sqli-43319db8-login": true,
	"sqli-4cab31b0-login": true,
	"sqli-57e105b4-login": true,
	"sqli-59730505-login": true,
	"sqli-6e47f23b-login": true,
	"sqli-7f62f3e0-login": true,
	"sqli-85738caa-login": true,
	"sqli-8c187a93-login": true,
	"sqli-906b8603-login": true,
	"sqli-91485dbb-login": true,
	"sqli-a2035700-login": true,
	"sqli-a77cd69b-login": true,
	"sqli-b0c12141-login": true,
	"sqli-bde4f6b2-login": true,
	"sqli-beca71f8-login": true,
	"sqli-c6072953-login": true,
	"sqli-c9fe3605-login": true,
	"sqli-cba0a4a7-login": true,
	"sqli-d5e8c63e-login": true,
	"sqli-eb4fafe8-login": false,
	"sqli-ebf229cf-login": true,
	"sqli-ed725292-login": true,
	"sqli-ef11b83d-login": true,
	"sqli-ef753d10-login": true,
	"sqli-f0b4d8ab-login": true,
	"sqli-fb72118c-login": true,
}
var wantAttacksV0PL2 = map[string]bool{
	"command-injection-10bd76c8-login": false,
	"command-injection-156de42b-login": false,
	"command-injection-2b64c6d9-login": false,
	"command-injection-6b31c08e-login": false,
	"command-injection-9255e799-login": false,
	"command-injection-9fdd7094-login": false,
	"command-injection-a2b61937-login": false,
	"command-injection-a41e115e-login": false,
	"command-injection-d51e34a4-login": false,
	"command-injection-f48aa068-login": false,
	"command-injection-f7d36638-login": false,
	"sqli-52109349-login": false,
	"sqli-730d16ce-login": false,
	"sqli-925997bb-login": false,
}
var wantBenignHardPL1 = map[string]bool{
	"hardben-0a7d3e69-login": false,
	"hardben-19c254d4-login": false,
	"hardben-1cf6dcc9-login": true,
	"hardben-273b3ad4-login": true,
	"hardben-2cec0287-login": false,
	"hardben-30066792-login": false,
	"hardben-33f16716-login": false,
	"hardben-37a01385-login": false,
	"hardben-3b33a427-login": false,
	"hardben-5c420414-login": false,
	"hardben-70895718-login": false,
	"hardben-8b7a2259-login": false,
	"hardben-939def6e-login": false,
	"hardben-978edf99-login": false,
	"hardben-a7842989-login": false,
	"hardben-a903d870-login": false,
	"hardben-ac35b46d-login": true,
	"hardben-d3ef2fc4-login": false,
	"hardben-d85ddaae-login": true,
	"hardben-e20f3562-login": false,
	"hardben-e45aeda9-login": true,
	"hardben-e8a60a97-login": false,
	"hardben-f5f4a0bc-login": false,
}
var wantBenignHardPL2 = map[string]bool{
	"hardben-034b2004-login": false,
	"hardben-0a7d3e69-login": false,
	"hardben-0dea1f45-login": false,
	"hardben-174363cd-login": false,
	"hardben-19c254d4-login": false,
	"hardben-1a8940de-login": false,
	"hardben-2cec0287-login": false,
	"hardben-30066792-login": false,
	"hardben-32e972b9-login": false,
	"hardben-33277e22-login": false,
	"hardben-33f16716-login": false,
	"hardben-348c1afb-login": false,
	"hardben-37a01385-login": false,
	"hardben-3a25df55-login": false,
	"hardben-3b33a427-login": false,
	"hardben-476a4888-login": false,
	"hardben-4b26bf86-login": false,
	"hardben-5425008b-login": false,
	"hardben-57359002-login": false,
	"hardben-65ad5876-login": false,
	"hardben-70895718-login": false,
	"hardben-76ee7785-login": false,
	"hardben-882a2a3f-login": false,
	"hardben-8836c945-login": false,
	"hardben-8b7a2259-login": false,
	"hardben-939def6e-login": false,
	"hardben-978edf99-login": false,
	"hardben-a4694ca4-login": false,
	"hardben-a4926260-login": false,
	"hardben-a69dfed7-login": false,
	"hardben-a7842989-login": false,
	"hardben-a86106e3-login": false,
	"hardben-a8e0c78a-login": false,
	"hardben-afcf055c-login": false,
	"hardben-b9115dfd-login": false,
	"hardben-bf3d56a0-login": false,
	"hardben-c0218512-login": false,
	"hardben-d15f5884-login": false,
	"hardben-d3ef2fc4-login": false,
	"hardben-d5a06b16-login": false,
	"hardben-da381db0-login": false,
	"hardben-db65e666-login": false,
	"hardben-dde21246-login": false,
	"hardben-e5aea8de-login": false,
	"hardben-e6e62496-login": false,
	"hardben-e8a60a97-login": false,
	"hardben-efa26c15-login": false,
	"hardben-f5f4a0bc-login": false,
	"hardben-f676fa00-login": false,
	"hardben-f6ca0404-login": false,
	"hardben-f91f5dae-login": false,
}
var wantBenignBrowsePL2EngineOnly = map[string]bool{
	"browse-02c008b9f3ba": false,
	"browse-035e98519bb6": false,
	"browse-08bc426f5841": false,
	"browse-09ef9bec9572": false,
	"browse-0ab126265b38": false,
	"browse-0d3aa2ae781f": false,
	"browse-0eb179c9a407": false,
	"browse-0f2b766495fc": false,
	"browse-0f88f2e4962c": false,
	"browse-1d8eecec72c5": false,
	"browse-1e27fb15d3d9": false,
	"browse-21d761df3dad": false,
	"browse-25229be0a7c7": false,
	"browse-25a78c9d23b3": false,
	"browse-2946258beb54": false,
	"browse-29578eb9fda9": false,
	"browse-29fc6e48058c": false,
	"browse-2aad47f30ef9": false,
	"browse-2c1cddd97de5": false,
	"browse-2c2c9ea4c6a3": false,
	"browse-2f389400d51f": false,
	"browse-3030dd36c8d7": false,
	"browse-30ce46282d8e": false,
	"browse-33857f88bb8d": false,
	"browse-373d645a7016": false,
	"browse-39ad082d8a88": false,
	"browse-3a6075697a11": false,
	"browse-3a822d828e51": false,
	"browse-3ac7cef67e1d": false,
	"browse-3b71a52f5bda": false,
	"browse-3c0574b92a5e": false,
	"browse-3e1bead0cee9": false,
	"browse-3f4b758325bc": false,
	"browse-3fa6e642f6c1": false,
	"browse-4142911a587a": false,
	"browse-42f9cd0b80a4": false,
	"browse-4304574c2d32": false,
	"browse-4386c383a728": false,
	"browse-552dc08ef01e": false,
	"browse-558f7b543d43": false,
	"browse-5881e5abdaa6": false,
	"browse-5887b3fbd8f4": false,
	"browse-5e1e52ea8f8d": false,
	"browse-66ff0d7e7618": false,
	"browse-73c0c6ccaf55": false,
	"browse-754470027cd8": false,
	"browse-75a390129922": false,
	"browse-7c835ff0ce28": false,
	"browse-88fafa1c2e9e": false,
	"browse-891b61124033": false,
	"browse-913200783ae1": false,
	"browse-923a928a7d20": false,
	"browse-94b425b16a0a": false,
	"browse-991f26ea8d23": false,
	"browse-9ed5e6085f9a": false,
	"browse-a0332dc68fba": false,
	"browse-a2642a351e0b": false,
	"browse-a298bed927d7": false,
	"browse-a47517bc4855": false,
	"browse-a8daba86e0de": false,
	"browse-ab74497d2fbc": false,
	"browse-acd5d1f813ac": false,
	"browse-ae16cc10287d": false,
	"browse-ae640b00fc5c": false,
	"browse-aeb47bab0eea": false,
	"browse-af7e865d6268": false,
	"browse-b5cd863d4ec8": false,
	"browse-b940805dd399": false,
	"browse-bc9b5b118d0e": false,
	"browse-bd6e1352326e": false,
	"browse-c26d25dc9da2": false,
	"browse-c2fd342e0e02": false,
	"browse-c2fe847a9819": false,
	"browse-c3b8bd0cbd38": false,
	"browse-c5bf36e75022": false,
	"browse-ca1a86d74bc0": false,
	"browse-ca4bfc28c78e": false,
	"browse-d304f351aedc": false,
	"browse-d4683b54e6fb": false,
	"browse-d8bcb1335c03": false,
	"browse-d93c8f615d37": false,
	"browse-dea205f6c340": false,
	"browse-e22e46558cd2": false,
	"browse-e3054bc51dac": false,
	"browse-e51e2b03dbf1": false,
	"browse-e52deb60aff9": false,
	"browse-e8679c70c47b": false,
	"browse-f041dae4557d": false,
	"browse-f336a1909eef": false,
	"browse-f4a599ac14ab": false,
}
