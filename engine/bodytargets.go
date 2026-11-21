// Step-18 T4: body parsing fidelity.
//
// Gap (step-17 T1, PROVEN): the URLENCODED body processor splits the raw
// body on '&' and the first '=' (coraza v3.7.0 bodyprocessors/urlencoded.go,
// urlutil.ParseQuery), so a payload that spans the split boundary is only
// ever scanned as separate name/value fragments. CRS rules scan single
// variables, so such payloads are missed on every carrier whose body is
// parsed by the URLENCODED processor: real application/x-www-form-urlencoded
// bodies AND the text/plain, octet-stream and unknown content types that
// fall back to it (CRS 901340 forces the body variable; coraza falls back to
// URLENCODED when no processor was selected).
//
// Fix: REQUEST_BODY carries the full raw body - the URLENCODED processor
// sets it itself (coraza bodyprocessors/urlencoded.go), and only the
// URLENCODED and RAW processors do (JSON, XML and multipart never populate
// REQUEST_BODY, so an added REQUEST_BODY target matches nothing there).
// Every inbound CRS rule that inspects parsed argument values now ALSO
// inspects the raw body, via the CRS-documented tuning directive
// SecRuleUpdateTargetById (coraza v3.7.0 internal/seclang/directives.go).
// Targets are only ADDED: no CRS file is edited, no rule is excluded or
// removed (rules 5/17 respected).
//
// Scope (documented in docs/engine-design.md before the re-runs): the
// payload-scanning families REQUEST-930..REQUEST-944 (LFI, RFI, RCE, PHP,
// SSRF, XSS, SQLi, session fixation, Java). REQUEST-920 protocol-structure
// rules are out of scope: their ARGS checks are size/count/encoding-structure
// checks where the raw body is not an argument value (adding it would change
// size/count semantics and run URL-encoding validators over bodies that are
// not URL-encoded). REQUEST-921 is out of scope for the same reason (E26,
// held-out WCP evidence): its ARGS checks test DECODED argument values for
// CRLF smuggling; literal CRLF inside a raw body is normal multi-line
// content, so the added target manufactured false positives (921150 in 72%
// of the WCP PL1 gained ids of the first pass).
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var (
	bodyTargetIDRe    = regexp.MustCompile(`id:['"]?(\d{6})`)
	bodyTargetPhase1  = regexp.MustCompile(`phase:1([^0-9]|$)`)
	bodyTargetSecRule = regexp.MustCompile(`^SecRule\s+(\S+)\s+"`)
)

// requestBodyTargetUpdates returns the sorted ids of inbound CRS rules that
// inspect ARGS-family variables (the split output) but not REQUEST_BODY, run
// in phase 2 or later, and are not chain-inner rules (SecRuleUpdateTargetById
// addresses rules by id; chain members after the starter have no id of their
// own). Counted (&ARGS) and size (ARGS_COMBINED_SIZE) targets are skipped:
// adding REQUEST_BODY there would change count/size semantics rather than add
// a payload scan.
func requestBodyTargetUpdates(rulesDir string) ([]int, error) {
	dir := filepath.Join(rulesDir, "owasp-crs", "rules")
	files, err := filepath.Glob(filepath.Join(dir, "REQUEST-9*.conf"))
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no CRS REQUEST-9*.conf files under %s", dir)
	}
	seen := map[int]bool{}
	var ids []int
	for _, f := range files {
		base := filepath.Base(f)
		fam := strings.Split(base, "-")[1]
		if !strings.HasPrefix(fam, "93") && !strings.HasPrefix(fam, "94") {
			continue
		}
		logical, err := logicalRuleLines(f)
		if err != nil {
			return nil, err
		}
		prevChain := false
		for _, line := range logical {
			m := bodyTargetSecRule.FindStringSubmatch(line)
			if m == nil {
				prevChain = false
				continue
			}
			vars := m[1]
			inner := prevChain
			prevChain = strings.HasSuffix(strings.TrimSpace(line), "chain")
			if inner {
				continue
			}
			idm := bodyTargetIDRe.FindStringSubmatch(line)
			if idm == nil {
				continue
			}
			var id int
			if _, err := fmt.Sscanf(idm[1], "%d", &id); err != nil {
				continue
			}
			if id < 930000 || id > 949999 {
				continue
			}
			if seen[id] {
				continue
			}
			tokens := strings.Split(vars, "|")
			hasArgs, hasBody := false, false
			counted := false
			for _, tok := range tokens {
				norm := strings.TrimLeft(tok, "!&")
				if strings.HasPrefix(norm, "ARGS") {
					if strings.HasPrefix(tok, "&") {
						counted = true
					}
					if norm == "ARGS_COMBINED_SIZE" {
						counted = true
					}
					hasArgs = true
				}
				if strings.Contains(norm, "REQUEST_BODY") {
					hasBody = true
				}
			}
			if !hasArgs || hasBody || counted {
				continue
			}
			if bodyTargetPhase1.MatchString(line) {
				continue
			}
			seen[id] = true
			ids = append(ids, id)
		}
	}
	sort.Ints(ids)
	return ids, nil
}

// logicalRuleLines joins backslash-continued lines so each SecRule (with its
// actions, possibly thousands of characters of generated regex) is one line.
func logicalRuleLines(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	var buf strings.Builder
	for _, line := range strings.Split(string(data), "\n") {
		t := strings.TrimRight(line, "\r")
		if strings.HasSuffix(t, "\\") {
			buf.WriteString(t[:len(t)-1])
			buf.WriteString(" ")
			continue
		}
		buf.WriteString(t)
		out = append(out, buf.String())
		buf.Reset()
	}
	if buf.Len() > 0 {
		out = append(out, buf.String())
	}
	return out, nil
}

// renderBodyTargetUpdates renders the SecRuleUpdateTargetById block. It must
// be placed AFTER the CRS Include: the directive looks up already-loaded
// rules (coraza internal/seclang/directives.go).
func renderBodyTargetUpdates(ids []int) string {
	if len(ids) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n# step-18 T4 (body parsing fidelity): every inbound CRS rule that inspects\n")
	b.WriteString("# parsed argument values (ARGS family) now also inspects the whole raw body\n")
	b.WriteString("# (REQUEST_BODY), via the CRS-documented SecRuleUpdateTargetById directive.\n")
	b.WriteString("# Targets are only added; no CRS file is edited and no rule is excluded.\n")
	b.WriteString("# Scope and rationale: docs/engine-design.md (step-18 T4).\n")
	for _, id := range ids {
		fmt.Fprintf(&b, "SecRuleUpdateTargetById %d \"REQUEST_BODY\"\n", id)
	}
	return b.String()
}
