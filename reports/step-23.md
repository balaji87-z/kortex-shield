# Step-23 report

Host and versions (rule 43: the host and the image set did not change since
step 22; no container image was used in this step). macOS 27.0 (26A425),
Darwin 27.0.0 arm64, Apple M6 12 cores; go1.27.4 darwin/arm64; Python
3.15.2, pytest 9.2.0. Docker: not used. No network: every `go` command ran
with `GOPROXY=off` against the local module cache. Engine: coraza v3.8.1
**with the step-23 patch** (engine/third_party/coraza-v3.8.1-kortex) + CRS
4.25.2 (engine/RULES.sha256 unchanged). Engine binaries: stock coraza,
engine at 7cc62a5, sha256 4165ad52...213d015 (comparisons only); patched,
built from ed48b1e, 5f539ac2...198251 (flip run); final, built from
4d56170 / 1313eea / c2b069b (no engine change between them), 4bf1d57e...b42578
(wcp runs, overload, parsing differential). Rule 29: every run log carries
the engine's `/__kortex/config` output; excerpts below.

The step-23 brief is the instructor's message; it is not a file in the
repository. Work was done in the checkout `~/work/kortex-shield-work`; the
wcp manifests and the fixture body are not committed (rules 25, 51) and
were read from the first checkout after a hash check (shown in the logs).
Nothing was pushed.

- Summary: framing refusals are logged (E35); coraza is patched to walk collections in key order, so 2,000 replays give one
  outcome (stock: 1,564 / 436) and in-process vs worker has 0 rule-id set diffs in 60,000 pairs; magic-byte event is log-only
  (14 + 2 events); real 503 overload seen; parsing slice: 61 cases, engine never the laxer side; Go 55/0/5 (60/0/0), pytest 234/0/4.

- Task table:

| task | status | evidence |
|---|---|---|
| T1 framing events: failing test, fix, Go suite | done; Go 50 PASS / 0 FAIL / 5 SKIP after it | docs/logs/step23-e35-failing.log, step23-e35-passing.log, step23-t1-go-test.log; commits a21491a, 7cc62a5 |
| T2 vendored coraza patch, replace in go.mod, diff committed, design note | done | engine/third_party/coraza-v3.8.1-kortex.patch, docs/engine-design.md, docs/logs/step23-coraza-vendor-check.txt, step23-coraza-own-tests.txt; commits b69492e, ed48b1e |
| T2 failing test first: syn-chain and syn-dup, 2,000 replays each, PL2 | done: failing on stock, passing with the patch | docs/logs/step23-e37-failing.log, step23-e37-passing.log, step23-t2-go-test.log |
| T2 flip_repro 5 x 500 at PL2 | done: 0 flips per round in every repeat | docs/logs/step23-flip-pl2.txt, docs/logs/runs/s23-flip-pl2/; commit 41b6035 |
| T2 in-process vs worker parity on the four wcp runs, rule-id set differences | done: 0 differences in 60,000 pairs | docs/logs/step23-parity.txt, docs/logs/runs/s23-parity/; commit 1313eea |
| T3 magic-byte event, log-only, test first, counts on v0 and v1 | done: 14 and 2 events | docs/logs/step23-e40-failing.log, step23-e40-passing.log, step23-t3-go-test.log, step23-magic-analysis.txt; commits 611508d, cf79759 |
| T4 four wcp sets in worker mode with engine_decision; parity diff with the full fail-closed worst-case set | done: 0 status diffs, 0 worst-case-set diffs | docs/logs/step23-parity.txt; commits 4d56170, 1313eea |
| T4 one real 503 overload through the runner with concurrent workers | done (DIAGNOSTIC): 46 of 48 and 47 of 48 | docs/logs/step23-overload-DIAGNOSTIC.txt; commit c2b069b |
| T5 strict parsing differential, first slice | done: 61 cases, counts and disagreement list below | docs/logs/step23-parsing-diff.txt, docs/logs/runs/s23-parsing-diff/results.jsonl; commit 9754a0d |
| T6 docs | done | docs/baseline-v1.8.md, docs/engine-design.md, docs/engine-evidence.md, docs/acceptance.md, docs/block-discriminator.md, this report |
| Final suites | done: Go 55 PASS / 0 FAIL / 5 SKIP; with fixture 60 / 0 / 0; pytest 234 passed, 0 failed, 4 skipped | docs/logs/step23-final-go-test.log, step23-final-go-test-with-fixture.log, step23-final-pytest.log |

- Raw evidence (key numbers in the body per rule 31; outputs trimmed where
  marked):

## T1. Framing refusals write an event

Before: the gate (engine/listener.go) wrote the 400 and nothing else,
against what engine/events.go and docs/block-discriminator.md say (found in
step 22, C6). Test E35 first (commit a21491a), five refusal cases over a
raw socket; E36 is the canary (a passed request writes no framing event).

```
# step-23 T1: E35/E36 before the fix, at 73ae5af9c25a0cb8e4df2fb0de8f04bee298ffb9 plus engine/step23_test.go, 2026-11-28T03:36:14Z, go version go1.27.4 darwin/arm64
$ cd engine && GOPROXY=off go test -buildvcs=false -count=1 -v -run "TestE35|TestE36" ./...
    step23_test.go:77: E35: want exactly 1 framing event for the refused request, got 0 (events: [])
    step23_test.go:77: E35: want exactly 1 framing event for the refused request, got 0 (events: [])
    step23_test.go:77: E35: want exactly 1 framing event for the refused request, got 0 (events: [])
    step23_test.go:77: E35: want exactly 1 framing event for the refused request, got 0 (events: [])
    step23_test.go:77: E35: want exactly 1 framing event for the refused request, got 0 (events: [])
--- FAIL: TestE35FramingRefusalLogsEvent (0.10s)
    --- FAIL: TestE35FramingRefusalLogsEvent/e35-conflict (0.06s)
    --- FAIL: TestE35FramingRefusalLogsEvent/e35-duplicate (0.01s)
    --- FAIL: TestE35FramingRefusalLogsEvent/e35-te-cl (0.01s)
    --- FAIL: TestE35FramingRefusalLogsEvent/e35-nul (0.01s)
    --- FAIL: TestE35FramingRefusalLogsEvent/no-sample-id (0.01s)
--- PASS: TestE36PassedRequestWritesNoFramingEvent (0.01s)
FAIL
FAIL	kortexshield/engine	0.539s
FAIL
# exit status of go test: 1
```

Fix (commit 7cc62a5): the gate writes one event before it answers
(decision `framing`, status 400, reason = the gate's reason, sample id read
from the raw head). `main()` and the tests build the gate through one
constructor, `newGatedListener`, so the test covers what main runs.

```
# step-23 T1: E35/E36 with the fix (working tree on a21491ae190906327c56886bf9314b3fca38aa18), 2026-11-28T03:36:53Z, go version go1.27.4 darwin/arm64
$ cd engine && GOPROXY=off go test -buildvcs=false -count=1 -v -run "TestE35|TestE36|TestE1Dup|TestE2TE|TestE3Raw" ./...
--- PASS: TestE1DuplicateContentLengthRejected (0.06s)
--- PASS: TestE2TEWithCLRejected (0.01s)
--- PASS: TestE3RawNulInQueryRejected (0.01s)
--- PASS: TestE35FramingRefusalLogsEvent (0.04s)
    --- PASS: TestE35FramingRefusalLogsEvent/e35-conflict (0.01s)
    --- PASS: TestE35FramingRefusalLogsEvent/e35-duplicate (0.01s)
    --- PASS: TestE35FramingRefusalLogsEvent/e35-te-cl (0.01s)
    --- PASS: TestE35FramingRefusalLogsEvent/e35-nul (0.01s)
    --- PASS: TestE35FramingRefusalLogsEvent/no-sample-id (0.01s)
--- PASS: TestE36PassedRequestWritesNoFramingEvent (0.01s)
ok  	kortexshield/engine	0.467s
# exit status of go test: 0
```

Go suite after the fix (docs/logs/step23-t1-go-test.log): **50 PASS, 0
FAIL, 5 SKIP** (`ok kortexshield/engine 51.125s`; the 5 skips are the
fixture tests E16, E17, E19, E20, E21).

- Cause of the missing event: PROVEN by the fix (rule 44). The gate had no
  call to the event logger; with the call added, the same five requests
  write exactly one event each, and E36 shows the event does not appear
  for a request the gate passes.
- In the T5 runs below all 12 gate refusals carry their event.
- Not changed: a connection whose head cannot be read (timeout, head over
  65,536 bytes) is closed without an answer and without an event.

## T2. Deterministic matching: patched coraza

**Design note first** (docs/engine-design.md, commit b69492e, before the
patch was built), **failing tests first** (same commit). E37 is the test
asked for; E38 and E39 are mine (see Deviations). Each replay has its own
sample id; the rule-id set of a replay is read from the engine's audit
log; a 503 is set aside and capped at 10% (the lesson of E30); none
occurred.

```
# step-23 T2: E37/E38/E39 on stock coraza v3.8.1, at 7cc62a57f8f43aba14a543f96fdb6c41a32b2242 plus the new tests, 2026-11-28T03:39:15Z, go version go1.27.4 darwin/arm64, github.com/corazawaf/coraza/v3 v3.8.1, load at start: load averages: 1.80 1.92 2.18
$ cd engine && GOPROXY=off go test -buildvcs=false -count=1 -v -run "TestE37|TestE38|TestE39" ./...
    step23_test.go:290: E37 [syn-chain]: 2000 replays of one unchanged request gave 2 distinct (status, rule-id set) outcomes, want 1 (503s set aside: 0):
            x436: status 200 rules []
            x1564: status 403 rules [942130,949110]
    step23_test.go:290: E37 [syn-dup]: 2000 replays of one unchanged request gave 2 distinct (status, rule-id set) outcomes, want 1 (503s set aside: 0):
            x1701: status 403 rules [941100,941110,941160,941320,941390,942131,942430,949110]
            x299: status 403 rules [941100,941110,941160,941320,942131,942430,949110]
--- FAIL: TestE37UnchangedRequestMatchesTheSameEveryTime (6.32s)
    --- FAIL: TestE37UnchangedRequestMatchesTheSameEveryTime/syn-chain (2.35s)
    --- FAIL: TestE37UnchangedRequestMatchesTheSameEveryTime/syn-dup (3.97s)
    step23_test.go:303: E38 [filter-then-note]: 300 replays of one unchanged request gave 2 distinct (status, rule-id set) outcomes, want 1 (503s set aside: 0):
            x72: status 200 rules []
            x228: status 403 rules [942130,949110]
--- FAIL: TestE38MemberOrderDoesNotChangeTheDecision (1.48s)
    step23_test.go:323: E39 [tautology-key-sorts-first]: 300 replays of one unchanged request gave 2 distinct (status, rule-id set) outcomes, want 1 (503s set aside: 0):
            x230: status 200 rules []
            x70: status 403 rules [942130,949110]
--- FAIL: TestE39TautologySortedFirstIsDecidedTheSameEveryTime (0.76s)
FAIL
FAIL	kortexshield/engine	8.982s
FAIL
# exit status of go test: 1
# load at end: load averages: 1.73 1.91 2.18

```

So on stock coraza v3.8.1 the tautology request was blocked 1,564 times
and **passed 436 times** in 2,000 replays, and the repeated-key request
lost rule 941390 in 299 of 2,000.

The patch (commit ed48b1e), in full, engine/third_party/coraza-v3.8.1-kortex.patch
(+30 / -5 lines; sha256 b2d44618...5330ad):

```
# kortex-shield patch to github.com/corazawaf/coraza/v3 v3.8.1 (step 23, docs/engine-design.md).
# Map-backed collections are walked in ascending key order.
# Generated and checked by tools/step23_coraza_vendor.py.
--- /dev/null
+++ b/internal/collections/kortex_sorted.go
@@ -0,0 +1,20 @@
+// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
+// SPDX-License-Identifier: Apache-2.0
+
+// kortex-shield patch (step 23): not part of coraza v3.8.1.
+
+package collections
+
+import "sort"
+
+// sortedKeys returns the keys of a collection's map in ascending order, so
+// that FindAll and FindRegex hand rules the same variables in the same order
+// on every call instead of Go's random map order.
+func sortedKeys(m map[string][]keyValue) []string {
+	keys := make([]string, 0, len(m))
+	for k := range m {
+		keys = append(keys, k)
+	}
+	sort.Strings(keys)
+	return keys
+}
--- a/internal/collections/map.go
+++ b/internal/collections/map.go
@@ -67,7 +67,8 @@
 	n := 0
 	// Collect matching data slices in a single pass to avoid evaluating the regex twice per key.
 	var matched [][]keyValue
-	for k, data := range c.data {
+	for _, k := range sortedKeys(c.data) {
+		data := c.data[k]
 		if key.MatchString(k) {
 			n += len(data)
 			matched = append(matched, data)
@@ -133,7 +134,8 @@
 	buf := make([]corazarules.MatchData, n)
 	result := make([]types.MatchData, n)
 	i := 0
-	for _, data := range c.data {
+	for _, k := range sortedKeys(c.data) {
+		data := c.data[k]
 		for _, d := range data {
 			buf[i] = corazarules.MatchData{
 				Variable_: c.variable,
--- a/internal/collections/named.go
+++ b/internal/collections/named.go
@@ -104,7 +104,8 @@
 	n := 0
 	// Collect matching data slices in a single pass to avoid evaluating the regex twice per key.
 	var matched [][]keyValue
-	for k, data := range c.collection.data {
+	for _, k := range sortedKeys(c.collection.data) {
+		data := c.collection.data[k]
 		if key.MatchString(k) {
 			n += len(data)
 			matched = append(matched, data)
@@ -163,7 +164,8 @@
 	buf := make([]corazarules.MatchData, n)
 	res := make([]types.MatchData, n)
 	i := 0
-	for _, data := range c.collection.data {
+	for _, k := range sortedKeys(c.collection.data) {
+		data := c.collection.data[k]
 		for _, d := range data {
 			buf[i] = corazarules.MatchData{
 				Variable_: c.variable,
@@ -186,7 +188,8 @@
 	res.WriteString(c.variable.Name())
 	res.WriteString(": ")
 	firstOccurrence := true
-	for _, data := range c.collection.data {
+	for _, k := range sortedKeys(c.collection.data) {
+		data := c.collection.data[k]
 		for _, d := range data {
 			if !firstOccurrence {
 				res.WriteString(",")
```

`engine/go.mod` gets one line, `replace github.com/corazawaf/coraza/v3 =>
./third_party/coraza-v3.8.1-kortex`; go.sum is unchanged. The vendored
directory holds the non-test `.go` files of the 25 coraza packages the
engine imports, plus go.mod, go.sum and LICENSE (200 files, 818,014
bytes). Proof that it is coraza v3.8.1 plus this patch and nothing else:

```
# step-23 T2: vendored coraza copy checked against the Go module cache, 2026-11-28T03:43:17Z
$ .venv/bin/python tools/step23_coraza_vendor.py check
module: /Users/ivan/go/pkg/mod/github.com/corazawaf/coraza/v3@v3.8.1
copy:   engine/third_party/coraza-v3.8.1-kortex: 200 file(s), 818014 bytes
byte-identical to the module: 197; differing: 2 ['internal/collections/map.go', 'internal/collections/named.go']; new: 1 ['internal/collections/kortex_sorted.go']; module files of these packages not copied: 0
patch:  engine/third_party/coraza-v3.8.1-kortex.patch: +30 -5 lines, sha256 b2d446186311785d360ec5db35d9d1e05caa7ffd3e381ae0d7c3b9f7355330ad
vendor check: OK
# exit status: 0
$ grep -n replace engine/go.mod; (cd engine && GOPROXY=off go list -m github.com/corazawaf/coraza/v3)
28:replace github.com/corazawaf/coraza/v3 => ./third_party/coraza-v3.8.1-kortex
github.com/corazawaf/coraza/v3 v3.8.1 => ./third_party/coraza-v3.8.1-kortex
```

With the patch:

```
# step-23 T2: E37/E38/E39 with the patched coraza (working tree on b69492e7638ac451f913c7f2f48021287146d370), 2026-11-28T03:40:57Z, go version go1.27.4 darwin/arm64, github.com/corazawaf/coraza/v3 v3.8.1 => ./third_party/coraza-v3.8.1-kortex, load at start: load averages: 1.36 1.74 2.08
$ cd engine && GOPROXY=off go test -buildvcs=false -count=1 -v -run "TestE37|TestE38|TestE39" ./...
    step23_test.go:290: E37 [syn-chain]: 2000 replays, 503s set aside: 0, one outcome:
            x2000: status 403 rules [942130,949110]
    step23_test.go:290: E37 [syn-dup]: 2000 replays, 503s set aside: 0, one outcome:
            x2000: status 403 rules [941100,941110,941160,941320,941390,942131,942430,949110]
--- PASS: TestE37UnchangedRequestMatchesTheSameEveryTime (6.39s)
    --- PASS: TestE37UnchangedRequestMatchesTheSameEveryTime/syn-chain (2.39s)
    --- PASS: TestE37UnchangedRequestMatchesTheSameEveryTime/syn-dup (3.99s)
    step23_test.go:303: E38 [filter-then-note]: 300 replays, 503s set aside: 0, one outcome:
            x300: status 403 rules [942130,949110]
    step23_test.go:304: E38 [note-then-filter]: 300 replays, 503s set aside: 0, one outcome:
            x300: status 403 rules [942130,949110]
--- PASS: TestE38MemberOrderDoesNotChangeTheDecision (1.54s)
    step23_test.go:323: E39 [tautology-key-sorts-first]: 300 replays, 503s set aside: 0, one outcome:
            x300: status 200 rules []
--- PASS: TestE39TautologySortedFirstIsDecidedTheSameEveryTime (0.75s)
PASS
ok  	kortexshield/engine	9.102s
# exit status of go test: 0
# load at end: load averages: 1.47 1.75 2.08

```

| request | stock coraza v3.8.1 | patched |
|---|---|---|
| E37 syn-chain, 2,000 replays | 1,564 x 403 [942130, 949110]; 436 x 200 | 2,000 x 403 [942130, 949110] |
| E37 syn-dup, 2,000 replays | 1,701 x 403 with 941390; 299 x 403 without | 2,000 x 403, one set of 8 rule ids |
| E38 filter-then-note, 300 | 228 x 403; 72 x 200 | 300 x 403 (and 300 x 403 for note-then-filter) |
| E39 tautology key sorts first, 300 | 230 x 200; 70 x 403 | **300 x 200 (passed every time)** |

- PROVEN (rule 44) that the iteration order was the cause of both kinds of
  variation in these requests: the two builds differ in the patch only
  (vendor check above), and the outcome changes from two to one. Had the
  order not been the cause, the patched build would still vary.
- **The limit, measured (rule 41): repeatable is not the same as caught.**
  E39's body is `{"anote":"1=1","zfilter":"color=blue"}`. CRS 942130's
  chained rule compares the captures of the last matching variable; in key
  order that is the harmless member, so the tautology is passed in 300 of
  300 replays. On the stock library it was blocked 70 times of 300 by
  chance. ModSecurity 3.0.17 passes the same shape (step-22 F2b). This is
  the rule's weakness made stable, not a new hole, but it is now a
  reliable bypass shape for 942130 at PL2 and is listed under Questions.
- Go suite with the patch (docs/logs/step23-t2-go-test.log): **53 PASS, 0
  FAIL, 5 SKIP** (`ok kortexshield/engine 63.423s`).
- coraza's own tests (not asked for): on a full copy of the module with
  the committed patch applied by `patch -p1`, 8 packages pass, as they do
  unpatched. The patch file therefore applies cleanly to the release.

```
# step-23 T2: coraza v3.8.1's own tests on a full copy of the module with the committed patch applied (out/s23-coraza-full, not committed), 2026-11-28T04:19:15Z, go version go1.27.4 darwin/arm64, GOPROXY=off
$ patch -p1 < engine/third_party/coraza-v3.8.1-kortex.patch   (in a copy of $GOMODCACHE/github.com/corazawaf/coraza/v3@v3.8.1, go.work removed)
$ go test -count=1 ./internal/collections/ ./internal/corazawaf/ ./internal/seclang/ ./internal/bodyprocessors/ ./internal/operators/ ./internal/transformations/ ./internal/actions/ .
ok  	github.com/corazawaf/coraza/v3/internal/collections	0.311s
ok  	github.com/corazawaf/coraza/v3/internal/corazawaf	0.311s
ok  	github.com/corazawaf/coraza/v3/internal/seclang	0.311s
ok  	github.com/corazawaf/coraza/v3/internal/bodyprocessors	0.722s
ok  	github.com/corazawaf/coraza/v3/internal/operators	0.303s
ok  	github.com/corazawaf/coraza/v3/internal/transformations	0.228s
ok  	github.com/corazawaf/coraza/v3/internal/actions	0.261s
ok  	github.com/corazawaf/coraza/v3	0.274s
# exit status of go test: 0
# the same packages on the unpatched module copy:
ok  	github.com/corazawaf/coraza/v3/internal/collections	0.228s
ok  	github.com/corazawaf/coraza/v3/internal/corazawaf	0.331s
ok  	github.com/corazawaf/coraza/v3/internal/seclang	0.315s
ok  	github.com/corazawaf/coraza/v3/internal/bodyprocessors	0.605s
ok  	github.com/corazawaf/coraza/v3/internal/operators	0.327s
ok  	github.com/corazawaf/coraza/v3/internal/transformations	0.253s
ok  	github.com/corazawaf/coraza/v3/internal/actions	0.287s
ok  	github.com/corazawaf/coraza/v3	0.301s
# exit status of go test: 0
```

**flip_repro, 5 x 500 rounds at PL2** (commit 41b6035).
`GOPROXY=off FLIP_STEP=23 STUB_PORT=13004 WCP_V0_MANIFEST=<first checkout>/data/benign-wcp-v0/manifest.jsonl
bash tools/run_step22_flip.sh 2 500 5 "localhost 127.0.0.1"`; tools/flip_repro.py unchanged.

```
== step-23 flip_repro, 2026-11-28T03:43:25Z, macOS 27.0 Darwin 27.0.0 arm64, go version go1.27.4 darwin/arm64, Python 3.15.2
== git ed48b1eb9ee69355cc5c3c6dc0437320e4b7173d, engine/ paths changed in the working tree: 1
== coraza module of engine/: github.com/corazawaf/coraza/v3 v3.8.1 => ./third_party/coraza-v3.8.1-kortex
== engine binary sha256 5f539ac2258da281fe0fe735eca12f16e82e2eecf8cfe0564f4fe500ae198251 built from ed48b1eb9ee69355cc5c3c6dc0437320e4b7173d with go version go1.27.4 darwin/arm64
host=localhost rep=1 :: rounds=500 flip_rounds=0 flips/round=0.0000 per_sample={'wcp-62cd1bd36bf7': 0, 'wcp-b6f2246ef4b8': 0} wall_s=3.6
host=localhost rep=2 :: rounds=500 flip_rounds=0 flips/round=0.0000 per_sample={'wcp-62cd1bd36bf7': 0, 'wcp-b6f2246ef4b8': 0} wall_s=3.8
host=localhost rep=3 :: rounds=500 flip_rounds=0 flips/round=0.0000 per_sample={'wcp-62cd1bd36bf7': 0, 'wcp-b6f2246ef4b8': 0} wall_s=3.8
host=localhost rep=4 :: rounds=500 flip_rounds=0 flips/round=0.0000 per_sample={'wcp-62cd1bd36bf7': 0, 'wcp-b6f2246ef4b8': 0} wall_s=3.6
host=localhost rep=5 :: rounds=500 flip_rounds=0 flips/round=0.0000 per_sample={'wcp-62cd1bd36bf7': 0, 'wcp-b6f2246ef4b8': 0} wall_s=3.9
host=127.0.0.1 rep=1 :: rounds=500 flip_rounds=0 flips/round=0.0000 per_sample={'wcp-62cd1bd36bf7': 0, 'wcp-b6f2246ef4b8': 0} wall_s=3.7
host=127.0.0.1 rep=2 :: rounds=500 flip_rounds=0 flips/round=0.0000 per_sample={'wcp-62cd1bd36bf7': 0, 'wcp-b6f2246ef4b8': 0} wall_s=3.7
host=127.0.0.1 rep=3 :: rounds=500 flip_rounds=0 flips/round=0.0000 per_sample={'wcp-62cd1bd36bf7': 0, 'wcp-b6f2246ef4b8': 0} wall_s=3.7
host=127.0.0.1 rep=4 :: rounds=500 flip_rounds=0 flips/round=0.0000 per_sample={'wcp-62cd1bd36bf7': 0, 'wcp-b6f2246ef4b8': 0} wall_s=3.4
host=127.0.0.1 rep=5 :: rounds=500 flip_rounds=0 flips/round=0.0000 per_sample={'wcp-62cd1bd36bf7': 0, 'wcp-b6f2246ef4b8': 0} wall_s=3.1
host=localhost all repeats: rounds=2500 rounds with a flip=0 flips/round=0.0000 statuses={'403': 5000}
host=localhost engine events (no sample id): 1 distinct (decision, status, rule ids)
host=localhost engine events wcp-62cd1bd36bf7-fliprepro: 1 distinct (decision, status, rule ids)
host=localhost engine events wcp-b6f2246ef4b8-fliprepro: 1 distinct (decision, status, rule ids)
host=127.0.0.1 all repeats: rounds=2500 rounds with a flip=0 flips/round=0.0000 statuses={'403': 5000}
host=127.0.0.1 engine events (no sample id): 1 distinct (decision, status, rule ids)
host=127.0.0.1 engine events wcp-62cd1bd36bf7-fliprepro: 1 distinct (decision, status, rule ids)
host=127.0.0.1 engine events wcp-b6f2246ef4b8-fliprepro: 1 distinct (decision, status, rule ids)
```

DIAGNOSTIC positive control (rules 34, 47), same script with
`FLIP_CONTROL=coraza370`: a scratch copy of engine/ with the replace
dropped and coraza v3.7.0 required.

```
== DIAGNOSTIC scratch engine coraza module: github.com/corazawaf/coraza/v3 v3.7.0
== DIAGNOSTIC scratch engine sha256 027d3f7d564c2bec6fb2cce1ee2c12328c06b08ec2d2ac3e5032f0143e0b342b; .go files that differ from engine/: 1; diff of go.mod against engine/go.mod:
< require github.com/corazawaf/coraza/v3 v3.8.1
> require github.com/corazawaf/coraza/v3 v3.7.0
host=localhost rep=1: rounds=500 rounds with a 200 (flip)=147 flips/round=0.2940 statuses={'200': 154, '403': 846}
host=localhost rep=2: rounds=500 rounds with a 200 (flip)=148 flips/round=0.2960 statuses={'200': 165, '403': 835}
host=localhost rep=3: rounds=500 rounds with a 200 (flip)=146 flips/round=0.2920 statuses={'200': 155, '403': 845}
host=localhost rep=4: rounds=500 rounds with a 200 (flip)=148 flips/round=0.2960 statuses={'200': 157, '403': 843}
host=localhost rep=5: rounds=500 rounds with a 200 (flip)=152 flips/round=0.3040 statuses={'200': 164, '403': 836}
host=localhost all repeats: rounds=2500 rounds with a flip=741 flips/round=0.2964 statuses={'200': 795, '403': 4205}
host=127.0.0.1 rep=1: rounds=500 rounds with a 200 (flip)=113 flips/round=0.2260 statuses={'200': 115, '403': 885}
host=127.0.0.1 rep=2: rounds=500 rounds with a 200 (flip)=119 flips/round=0.2380 statuses={'200': 125, '403': 875}
host=127.0.0.1 rep=3: rounds=500 rounds with a 200 (flip)=105 flips/round=0.2100 statuses={'200': 110, '403': 890}
host=127.0.0.1 rep=4: rounds=500 rounds with a 200 (flip)=119 flips/round=0.2380 statuses={'200': 126, '403': 874}
host=127.0.0.1 rep=5: rounds=500 rounds with a 200 (flip)=117 flips/round=0.2340 statuses={'200': 123, '403': 877}
host=127.0.0.1 all repeats: rounds=2500 rounds with a flip=573 flips/round=0.2292 statuses={'200': 599, '403': 4401}
```

| engine | Host | flips per round, repeats 1 to 5 | rounds with a flip | answers |
|---|---|---|---|---|
| patched coraza v3.8.1 (step 23) | localhost | 0.0000, 0.0000, 0.0000, 0.0000, 0.0000 | 0 of 2,500 | 5,000 x 403 |
| patched coraza v3.8.1 (step 23) | 127.0.0.1 | 0.0000, 0.0000, 0.0000, 0.0000, 0.0000 | 0 of 2,500 | 5,000 x 403 |
| DIAGNOSTIC coraza v3.7.0 scratch build | localhost | 0.2940, 0.2960, 0.2920, 0.2960, 0.3040 | 741 of 2,500 | 4,205 x 403, 795 x 200 |
| DIAGNOSTIC coraza v3.7.0 scratch build | 127.0.0.1 | 0.2260, 0.2380, 0.2100, 0.2380, 0.2340 | 573 of 2,500 | 4,401 x 403, 599 x 200 |

- Same result as on stock v3.8.1 in step 22 (0 of 2,500): these two
  samples stopped flipping with the v3.8.1 bump, and the patch keeps it so.
  One rule-id set per sample in 2,500 replays on each Host form.
- The control still flips after the script change (the replace has to be
  dropped for it, or the "v3.7.0" build would silently be the patched
  v3.8.1); `.go files that differ: 1` in its log line is the vendored
  directory removed from the scratch copy.

**In-process vs worker parity on the four wcp runs** (commit 1313eea) is
reported with T4 below, since the same eight runs serve both. The T2
numbers: **0 rule-id set differences between the two modes in 60,000 pairs**
(step 22: 3 ids in each parity run), 0 status differences. Against the
stock-coraza in-process runs of step 22 (C2), per sample: 0 status
differences, 0 outcome differences, 1 rule-id set difference
(wcp-7b0bdeda7bc7, PL2: rule 942130 in the stock replay only; blocked
either way). Classification (rule 39): DESIGN, order by key, documented
before the run; the property it relies on (one outcome per request) is
measured by E37 and by the 0 differences between two independent replays
of 60,000 samples. With the stock library that id's rule-id set varied
between replays (step-22 F1: 110 against 90 in 200), so this single
difference cannot be attributed to the patch rather than to that
variation, and is not claimed to be.

**Cost of the patch (rule 38: raw timings).** One sort of the key list per
FindAll / FindRegex call.

| measurement | stock | patched |
|---|---|---|
| E37 syn-chain, 2,000 replays, test wall time | 2.35 s | 2.39 s |
| E37 syn-dup, 2,000 replays | 3.97 s | 3.99 s |
| benign-wcp-v0 PL1 in-process run (run.json), load at start / end | 142 s, 4.85 / 7.81 | 141 s, 4.67 / 3.71 |
| benign-wcp-v0 PL2 | 239 s, 6.42 / 3.43 | 243 s, 3.26 / 3.53 |
| benign-wcp-v1 PL1 | 68 s, 7.26 / 6.42 | 67 s, 3.46 / 3.71 |
| benign-wcp-v1 PL2 | 116 s, 3.32 / 1.93 | 117 s, 2.74 / 2.39 |

No difference is visible at this resolution. The stock runs are the
step-22 C2 runs, made hours earlier under a different host load, so this
is not a controlled comparison; a controlled timing is NOT MEASURED.

## T3. Compressed-looking body without Content-Encoding: log-only event

Design note first (docs/engine-design.md), failing test first (commit
611508d). E40: 5 magic prefixes (gzip `1f 8b 08`; zlib `78 01`, `78 5e`,
`78 9c`, `78 da`) x 3 engine set-ups (blocking, DetectionOnly, worker
mode). Each case first sends a control body (first byte changed), requires
200 and no event, then the magic body, and requires the same status, the
backend reached, and exactly one event. E41 is the narrowness guard.

```
# step-23 T3: E40/E41 before the implementation, at 41b6035d91eb910b719f68b03e486e6f71588e0f plus the new tests, 2026-11-28T03:44:54Z, go version go1.27.4 darwin/arm64
$ cd engine && GOPROXY=off go test -buildvcs=false -count=1 -v -run "TestE40|TestE41" ./...
--- FAIL: TestE40CompressedLookingBodyIsLoggedNeverBlocked (0.74s)
--- PASS: TestE41CompressedBodyEventIsNarrow (0.01s)
FAIL
FAIL	kortexshield/engine	1.091s
FAIL
# exit status of go test: 1
[trimmed: 15 lines 'E40: want exactly one compressed-body event of kind ..., got []' and the 15 '--- FAIL' subtest lines: blocking, detection-only and worker x gzip, zlib-7801, zlib-785e, zlib-789c, zlib-78da]
```

```
# step-23 T3: E40/E41 with the implementation (working tree on 611508d9f346ecda994d28de5737858c5915c3c3), 2026-11-28T03:45:19Z, go version go1.27.4 darwin/arm64
$ cd engine && GOPROXY=off go test -buildvcs=false -count=1 -v -run "TestE40|TestE41" ./...
--- PASS: TestE40CompressedLookingBodyIsLoggedNeverBlocked (0.75s)
--- PASS: TestE41CompressedBodyEventIsNarrow (0.01s)
ok  	kortexshield/engine	1.080s
# exit status of go test: 0
```

Implementation (commit cf79759): `compressedMagic()` in engine/proxy.go,
called once on the bytes the engine has read, before the size checks;
event `would_reject`, status 0, reason
`compressed-body-without-content-encoding:gzip` or `:zlib`. Nothing else
reads its result, so it cannot block; E40 shows the answer equals the
control's in all 15 cases. Go suite after it
(docs/logs/step23-t3-go-test.log): **55 PASS, 0 FAIL, 5 SKIP**.

**Event count on benign-wcp-v0 and v1** (from the eight runs of T4;
docs/logs/step23-magic-analysis.txt, counts only, rule 51):

| dataset | samples | events | kind | first bytes | content type, method | size (bytes) | outcome of those samples |
|---|---|---|---|---|---|---|---|
| benign-wcp-v0 | 20,000 | 14 | zlib 14, gzip 0 | `78 01` x 14 | text/plain, POST | 132 to 7,425 (median 1,215) | waf_block 14 of 14 at PL1 and at PL2 |
| benign-wcp-v1 | 10,000 | 2 | zlib 2, gzip 0 | `78 01` x 2 | text/plain, POST | 294 and 1,190 | waf_block 2 of 2 at PL1 and at PL2 |

```
# step-23 T3: bodies behind the compressed-body events of the wcp runs (counts only, rule 51), 2026-11-28T04:07:56Z, at 4d56170e952e7b9e96d151c42d9067427a980ca7
$ .venv/bin/python tools/step23_magic_analysis.py docs/logs/runs/s23-parity/benign-wcp-v0-inprocess-pl1/events.index.jsonl <local manifest of benign-wcp-v0>
samples with a compressed-body event: 14 {'zlib': 14}
   content types: {'text/plain': 14}; methods: {'POST': 14}
   magic bytes matched (hex): {'7801': 14}
   body size in bytes: min 132, median 1215, max 7425
   handed to zlib: {'not a complete stream': 14}
$ .venv/bin/python tools/step23_magic_analysis.py docs/logs/runs/s23-parity/benign-wcp-v0-worker-pl1/events.index.jsonl <local manifest of benign-wcp-v0>
samples with a compressed-body event: 14 {'zlib': 14}
   content types: {'text/plain': 14}; methods: {'POST': 14}
   magic bytes matched (hex): {'7801': 14}
   body size in bytes: min 132, median 1215, max 7425
   handed to zlib: {'not a complete stream': 14}
$ .venv/bin/python tools/step23_magic_analysis.py docs/logs/runs/s23-parity/benign-wcp-v0-inprocess-pl2/events.index.jsonl <local manifest of benign-wcp-v0>
samples with a compressed-body event: 14 {'zlib': 14}
   content types: {'text/plain': 14}; methods: {'POST': 14}
   magic bytes matched (hex): {'7801': 14}
   body size in bytes: min 132, median 1215, max 7425
   handed to zlib: {'not a complete stream': 14}
$ .venv/bin/python tools/step23_magic_analysis.py docs/logs/runs/s23-parity/benign-wcp-v0-worker-pl2/events.index.jsonl <local manifest of benign-wcp-v0>
samples with a compressed-body event: 14 {'zlib': 14}
   content types: {'text/plain': 14}; methods: {'POST': 14}
   magic bytes matched (hex): {'7801': 14}
   body size in bytes: min 132, median 1215, max 7425
   handed to zlib: {'not a complete stream': 14}
$ .venv/bin/python tools/step23_magic_analysis.py docs/logs/runs/s23-parity/benign-wcp-v1-inprocess-pl1/events.index.jsonl <local manifest of benign-wcp-v1>
samples with a compressed-body event: 2 {'zlib': 2}
   content types: {'text/plain': 2}; methods: {'POST': 2}
   magic bytes matched (hex): {'7801': 2}
   body size in bytes: min 294, median 742, max 1190
   handed to zlib: {'not a complete stream': 2}
$ .venv/bin/python tools/step23_magic_analysis.py docs/logs/runs/s23-parity/benign-wcp-v1-worker-pl1/events.index.jsonl <local manifest of benign-wcp-v1>
samples with a compressed-body event: 2 {'zlib': 2}
   content types: {'text/plain': 2}; methods: {'POST': 2}
   magic bytes matched (hex): {'7801': 2}
   body size in bytes: min 294, median 742, max 1190
   handed to zlib: {'not a complete stream': 2}
$ .venv/bin/python tools/step23_magic_analysis.py docs/logs/runs/s23-parity/benign-wcp-v1-inprocess-pl2/events.index.jsonl <local manifest of benign-wcp-v1>
samples with a compressed-body event: 2 {'zlib': 2}
   content types: {'text/plain': 2}; methods: {'POST': 2}
   magic bytes matched (hex): {'7801': 2}
   body size in bytes: min 294, median 742, max 1190
   handed to zlib: {'not a complete stream': 2}
$ .venv/bin/python tools/step23_magic_analysis.py docs/logs/runs/s23-parity/benign-wcp-v1-worker-pl2/events.index.jsonl <local manifest of benign-wcp-v1>
samples with a compressed-body event: 2 {'zlib': 2}
   content types: {'text/plain': 2}; methods: {'POST': 2}
   magic bytes matched (hex): {'7801': 2}
   body size in bytes: min 294, median 742, max 1190
   handed to zlib: {'not a complete stream': 2}
# the same sample ids in all four runs of a dataset?
benign-wcp-v0: distinct id sets across the four runs: 1; ids: 14; outcomes of those ids: {'inprocess-pl1': {'waf_block': 14}, 'inprocess-pl2': {'waf_block': 14}}
benign-wcp-v1: distinct id sets across the four runs: 1; ids: 2; outcomes of those ids: {'inprocess-pl1': {'waf_block': 2}, 'inprocess-pl2': {'waf_block': 2}}
```

- The count is the same in in-process and worker mode and at both
  paranoia levels, and it is the same 14 and the same 2 sample ids in all
  four runs of each dataset.
- All 16 are blocked by the rules already, so on these datasets the event
  marks nothing that passes today, and enforcing it would add no new block
  (potential false positive) here. That says nothing about traffic where
  such a body is clean enough to pass (cell K of step 22).
- As replayed, none of the 16 bodies is a complete zlib stream. HYPOTHESIS,
  not tested: the original requests carried real zlib streams and the
  dataset's text storage altered the bytes after the header. UNVERIFIED.
- No `x^` collision (78 5e) and no gzip magic occurred in 30,000 samples.
- NOT MEASURED: the event on the attack datasets, and on bodies the engine
  does not read (Content-Length above the total limit).

## T4. Worker-mode evidence and the full worst-case set

`GOPROXY=off STUB_PORT=13004 WCP_DATA_DIR=<first checkout>/data bash tools/run_step23_parity.sh`
(docs/logs/step23-parity.txt; durable files docs/logs/runs/s23-parity/,
commit 1313eea). Eight runs: benign-wcp-v0 and v1, PL1 and PL2, in-process
and worker mode (pool 3, spares 1), one engine process and one audit log
per run, runner `--workers 1`, requests to `localhost`. The engine is the
final one (T1 + T2 + T3).

Rule 29, per run (two of eight shown; the others differ in paranoia level
and mode only):

```
== benign-wcp-v0-inprocess-pl1 rule29 2026-11-28T03:47:48Z load: load averages: 4.67 4.75 3.55: {"rule_engine": "On", "blocking_paranoia": 1, "detection_paranoia": 1, "max_body_bytes": 13107200, "max_inspected_bytes": 131072, "engine_time_budget_ms": 2000, "allowed_methods": "GET HEAD POST OPTIONS", "max_inflight_body": 8, "max_inflight_body_large": 2, "body_lane_threshold": 65536, "worker_mode": false} [other keys trimmed]
== benign-wcp-v1-worker-pl2 rule29 2026-11-28T04:05:22Z load: load averages: 2.20 2.79 3.06: {"rule_engine": "On", "blocking_paranoia": 2, "detection_paranoia": 2, "max_body_bytes": 13107200, "max_inspected_bytes": 131072, "engine_time_budget_ms": 2000, "allowed_methods": "GET HEAD POST OPTIONS", "max_inflight_body": 8, "max_inflight_body_large": 2, "body_lane_threshold": 65536, "worker_mode": true} [other keys trimmed]
```

```
== 2026-11-28T03:47:46Z, macOS 27.0 Darwin 27.0.0 arm64, go version go1.27.4 darwin/arm64, Python 3.15.2, load at start: load averages: 5.07 4.83 3.57
== git 4d56170e952e7b9e96d151c42d9067427a980ca7, tracked paths changed in the working tree: 0
== coraza module of engine/: github.com/corazawaf/coraza/v3 v3.8.1 => ./third_party/coraza-v3.8.1-kortex
vendor check: OK
== manifest /Users/ivan/work/kortex-shield-dev/data/benign-wcp-v0/manifest.jsonl sha256 c8ce11f26406df96d55e5a1cc6186bcbf648cb29bd628081dd834c6ccf1329d1 (frozen: c8ce11f26406df96d55e5a1cc6186bcbf648cb29bd628081dd834c6ccf1329d1)
== manifest /Users/ivan/work/kortex-shield-dev/data/benign-wcp-v1/manifest.jsonl sha256 049b7dea33aac475c4ef7f05c8644da610ad311a84862ef3b88d33a37dc8b5c0 (frozen: 049b7dea33aac475c4ef7f05c8644da610ad311a84862ef3b88d33a37dc8b5c0)
== engine binary sha256 4bf1d57e805c872c660c3f61807e9d8d3d329069e4cd1a41c39b643474b42578 built from 4d56170e952e7b9e96d151c42d9067427a980ca7 with go version go1.27.4 darwin/arm64
== benign-wcp-v0-inprocess-pl1 events: 20015 events {'block': 2236, 'content-encoding': 19, 'limit': 28, 'pass': 17717, 'would_reject': 15}; compressed-body events 14 {'zlib': 14}; framing events 0 {}; kept 62
== benign-wcp-v0-worker-pl1 events: 20015 events {'block': 2236, 'content-encoding': 19, 'limit': 28, 'pass': 17717, 'would_reject': 15}; compressed-body events 14 {'zlib': 14}; framing events 0 {}; kept 62
== diff benign-wcp-v0 PL1 (a=inprocess b=worker):
samples compared: 20000 (a=20000 b=20000 only-a=0 only-b=0)
status counts a: {200: 17716, 400: 52, 403: 2184, 413: 28, 415: 19, None: 1}
status counts b: {200: 17716, 400: 52, 403: 2184, 413: 28, 415: 19, None: 1}
status diffs: 0
worst-case set a: 2284/20000 (error=1 blocked=2184 deny_status=52 inconsistent=0 fail_closed_413=28 fail_closed_415=19 fail_closed_400=0 fail_closed_503_timeout=0 fail_closed_503_overload=0)
worst-case set b: 2284/20000 (error=1 blocked=2184 deny_status=52 inconsistent=0 fail_closed_413=28 fail_closed_415=19 fail_closed_400=0 fail_closed_503_timeout=0 fail_closed_503_overload=0)
worst-case set diffs: 0 (only-a 0 only-b 0)
== benign-wcp-v1-inprocess-pl1 events: 10003 events {'block': 1116, 'limit': 17, 'pass': 8868, 'would_reject': 2}; compressed-body events 2 {'zlib': 2}; framing events 0 {}; kept 19
== benign-wcp-v1-worker-pl1 events: 10003 events {'block': 1116, 'limit': 17, 'pass': 8868, 'would_reject': 2}; compressed-body events 2 {'zlib': 2}; framing events 0 {}; kept 19
== diff benign-wcp-v1 PL1 (a=inprocess b=worker):
samples compared: 10000 (a=10000 b=10000 only-a=0 only-b=0)
status counts a: {200: 8867, 400: 25, 403: 1091, 413: 17}
status counts b: {200: 8867, 400: 25, 403: 1091, 413: 17}
status diffs: 0
worst-case set a: 1133/10000 (error=0 blocked=1091 deny_status=25 inconsistent=0 fail_closed_413=17 fail_closed_415=0 fail_closed_400=0 fail_closed_503_timeout=0 fail_closed_503_overload=0)
worst-case set b: 1133/10000 (error=0 blocked=1091 deny_status=25 inconsistent=0 fail_closed_413=17 fail_closed_415=0 fail_closed_400=0 fail_closed_503_timeout=0 fail_closed_503_overload=0)
worst-case set diffs: 0 (only-a 0 only-b 0)
== benign-wcp-v0-inprocess-pl2 events: 20014 events {'block': 8919, 'content-encoding': 19, 'limit': 28, 'pass': 11034, 'would_reject': 14}; compressed-body events 14 {'zlib': 14}; framing events 0 {}; kept 61
== benign-wcp-v0-worker-pl2 events: 20014 events {'block': 8919, 'content-encoding': 19, 'limit': 28, 'pass': 11034, 'would_reject': 14}; compressed-body events 14 {'zlib': 14}; framing events 0 {}; kept 61
== diff benign-wcp-v0 PL2 (a=inprocess b=worker):
samples compared: 20000 (a=20000 b=20000 only-a=0 only-b=0)
status counts a: {200: 11033, 400: 52, 403: 8867, 413: 28, 415: 19, None: 1}
status counts b: {200: 11033, 400: 52, 403: 8867, 413: 28, 415: 19, None: 1}
status diffs: 0
worst-case set a: 8967/20000 (error=1 blocked=8866 deny_status=52 inconsistent=1 fail_closed_413=28 fail_closed_415=19 fail_closed_400=0 fail_closed_503_timeout=0 fail_closed_503_overload=0)
worst-case set b: 8967/20000 (error=1 blocked=8866 deny_status=52 inconsistent=1 fail_closed_413=28 fail_closed_415=19 fail_closed_400=0 fail_closed_503_timeout=0 fail_closed_503_overload=0)
worst-case set diffs: 0 (only-a 0 only-b 0)
== benign-wcp-v1-inprocess-pl2 events: 10003 events {'block': 4463, 'limit': 17, 'pass': 5521, 'would_reject': 2}; compressed-body events 2 {'zlib': 2}; framing events 0 {}; kept 19
== benign-wcp-v1-worker-pl2 events: 10003 events {'block': 4463, 'limit': 17, 'pass': 5521, 'would_reject': 2}; compressed-body events 2 {'zlib': 2}; framing events 0 {}; kept 19
== diff benign-wcp-v1 PL2 (a=inprocess b=worker):
samples compared: 10000 (a=10000 b=10000 only-a=0 only-b=0)
status counts a: {200: 5520, 400: 25, 403: 4438, 413: 17}
status counts b: {200: 5520, 400: 25, 403: 4438, 413: 17}
status diffs: 0
worst-case set a: 4480/10000 (error=0 blocked=4438 deny_status=25 inconsistent=0 fail_closed_413=17 fail_closed_415=0 fail_closed_400=0 fail_closed_503_timeout=0 fail_closed_503_overload=0)
worst-case set b: 4480/10000 (error=0 blocked=4438 deny_status=25 inconsistent=0 fail_closed_413=17 fail_closed_415=0 fail_closed_400=0 fail_closed_503_timeout=0 fail_closed_503_overload=0)
worst-case set diffs: 0 (only-a 0 only-b 0)
== load at end: load averages: 3.00 2.86 3.05
benign-wcp-v0 PL1 inprocess: n=20000 waf_block=2184 waf_deny_status=52 inconsistent=0 error=1 waf_fail_closed_413=28 waf_fail_closed_415=19 waf_fail_closed_400=0 waf_fail_closed_503_timeout=0 waf_fail_closed_503_overload=0 waf_pass=17716 other=0
    FP rate best case (errors, deny_status, inconsistent, fail-closed answers not flagged) 2184/20000 = 10.92%; worst case (all flagged) 2284/20000 = 11.42%
    rule 18: 2236 audit entries; rule ids in >=20% of them: 949110=2184, 932370=466
benign-wcp-v0 PL1 worker: n=20000 waf_block=2184 waf_deny_status=52 inconsistent=0 error=1 waf_fail_closed_413=28 waf_fail_closed_415=19 waf_fail_closed_400=0 waf_fail_closed_503_timeout=0 waf_fail_closed_503_overload=0 waf_pass=17716 other=0
    FP rate best case (errors, deny_status, inconsistent, fail-closed answers not flagged) 2184/20000 = 10.92%; worst case (all flagged) 2284/20000 = 11.42%
    rule 18: 2236 audit entries; rule ids in >=20% of them: 949110=2184, 932370=466
benign-wcp-v0 PL1 rule-id sets, in-process vs worker: 0 ids differ of 20000
benign-wcp-v0 PL2 inprocess: n=20000 waf_block=8866 waf_deny_status=52 inconsistent=1 error=1 waf_fail_closed_413=28 waf_fail_closed_415=19 waf_fail_closed_400=0 waf_fail_closed_503_timeout=0 waf_fail_closed_503_overload=0 waf_pass=11033 other=0
    FP rate best case (errors, deny_status, inconsistent, fail-closed answers not flagged) 8866/20000 = 44.33%; worst case (all flagged) 8967/20000 = 44.84%
    rule 18: 8919 audit entries; rule ids in >=20% of them: 949110=8867, 931130=5853, 942430=4987, 942200=4269, 942370=3239, 942340=3087, 942330=1913, 932200=1834
benign-wcp-v0 PL2 worker: n=20000 waf_block=8866 waf_deny_status=52 inconsistent=1 error=1 waf_fail_closed_413=28 waf_fail_closed_415=19 waf_fail_closed_400=0 waf_fail_closed_503_timeout=0 waf_fail_closed_503_overload=0 waf_pass=11033 other=0
    FP rate best case (errors, deny_status, inconsistent, fail-closed answers not flagged) 8866/20000 = 44.33%; worst case (all flagged) 8967/20000 = 44.84%
    rule 18: 8919 audit entries; rule ids in >=20% of them: 949110=8867, 931130=5853, 942430=4987, 942200=4269, 942370=3239, 942340=3087, 942330=1913, 932200=1834
benign-wcp-v0 PL2 rule-id sets, in-process vs worker: 0 ids differ of 20000
benign-wcp-v1 PL1 inprocess: n=10000 waf_block=1091 waf_deny_status=25 inconsistent=0 error=0 waf_fail_closed_413=17 waf_fail_closed_415=0 waf_fail_closed_400=0 waf_fail_closed_503_timeout=0 waf_fail_closed_503_overload=0 waf_pass=8867 other=0
    FP rate best case (errors, deny_status, inconsistent, fail-closed answers not flagged) 1091/10000 = 10.91%; worst case (all flagged) 1133/10000 = 11.33%
    rule 18: 1116 audit entries; rule ids in >=20% of them: 949110=1091
benign-wcp-v1 PL1 worker: n=10000 waf_block=1091 waf_deny_status=25 inconsistent=0 error=0 waf_fail_closed_413=17 waf_fail_closed_415=0 waf_fail_closed_400=0 waf_fail_closed_503_timeout=0 waf_fail_closed_503_overload=0 waf_pass=8867 other=0
    FP rate best case (errors, deny_status, inconsistent, fail-closed answers not flagged) 1091/10000 = 10.91%; worst case (all flagged) 1133/10000 = 11.33%
    rule 18: 1116 audit entries; rule ids in >=20% of them: 949110=1091
benign-wcp-v1 PL1 rule-id sets, in-process vs worker: 0 ids differ of 10000
benign-wcp-v1 PL2 inprocess: n=10000 waf_block=4438 waf_deny_status=25 inconsistent=0 error=0 waf_fail_closed_413=17 waf_fail_closed_415=0 waf_fail_closed_400=0 waf_fail_closed_503_timeout=0 waf_fail_closed_503_overload=0 waf_pass=5520 other=0
    FP rate best case (errors, deny_status, inconsistent, fail-closed answers not flagged) 4438/10000 = 44.38%; worst case (all flagged) 4480/10000 = 44.80%
    rule 18: 4463 audit entries; rule ids in >=20% of them: 949110=4438, 931130=2931, 942430=2466, 942200=2073, 942370=1558, 942340=1456, 942330=930, 932200=905
benign-wcp-v1 PL2 worker: n=10000 waf_block=4438 waf_deny_status=25 inconsistent=0 error=0 waf_fail_closed_413=17 waf_fail_closed_415=0 waf_fail_closed_400=0 waf_fail_closed_503_timeout=0 waf_fail_closed_503_overload=0 waf_pass=5520 other=0
    FP rate best case (errors, deny_status, inconsistent, fail-closed answers not flagged) 4438/10000 = 44.38%; worst case (all flagged) 4480/10000 = 44.80%
    rule 18: 4463 audit entries; rule ids in >=20% of them: 949110=4438, 931130=2931, 942430=2466, 942200=2073, 942370=1558, 942340=1456, 942330=930, 932200=905
benign-wcp-v1 PL2 rule-id sets, in-process vs worker: 0 ids differ of 10000
== stock coraza (step-22 C2, in-process) against patched coraza (step 23, in-process), per sample
benign-wcp-v0 PL1: 20000 ids; status diffs 0; outcome diffs 0; rule-id set diffs 0
benign-wcp-v0 PL2: 20000 ids; status diffs 0; outcome diffs 0; rule-id set diffs 1
    rules wcp-7b0bdeda7bc7: only stock ['942130'] only patched []
    rule-id set diffs by shape: only stock ['942130'] / only patched [] x1
benign-wcp-v1 PL1: 10000 ids; status diffs 0; outcome diffs 0; rule-id set diffs 0
benign-wcp-v1 PL2: 10000 ids; status diffs 0; outcome diffs 0; rule-id set diffs 0
```

| dataset | PL | status diffs, in-process vs worker | worst-case set in-process | worst-case set worker | worst-case set diffs | rule-id set diffs |
|---|---|---|---|---|---|---|
| benign-wcp-v0 | 1 | 0 of 20,000 | 2,284 | 2,284 | 0 | 0 |
| benign-wcp-v0 | 2 | 0 of 20,000 | 8,967 | 8,967 | 0 | 0 |
| benign-wcp-v1 | 1 | 0 of 10,000 | 1,133 | 1,133 | 0 | 0 |
| benign-wcp-v1 | 2 | 0 of 10,000 | 4,480 | 4,480 | 0 | 0 |

Rates, benign-labelled natural traffic (rule 14: nothing merged; rule 46:
every block or refusal is a potential false positive), denominator all
samples, the one errored v0 sample flagged in the worst case only (rules
20, 21, 30), identical in both modes:

| dataset | PL | waf_block | fail-closed 413 | fail-closed 415 | fail-closed 400 / 503 timeout / 503 overload | deny_status | inconsistent | error | best case | worst case (headline) |
|---|---|---|---|---|---|---|---|---|---|---|
| benign-wcp-v0 | 1 | 2,184 | 28 | 19 | 0 / 0 / 0 | 52 | 0 | 1 | 2,184 = 10.92% | 2,284 = 11.42% |
| benign-wcp-v0 | 2 | 8,866 | 28 | 19 | 0 / 0 / 0 | 52 | 1 | 1 | 8,866 = 44.33% | 8,967 = 44.84% |
| benign-wcp-v1 | 1 | 1,091 | 17 | 0 | 0 / 0 / 0 | 25 | 0 | 0 | 1,091 = 10.91% | 1,133 = 11.33% |
| benign-wcp-v1 | 2 | 4,438 | 17 | 0 | 0 / 0 / 0 | 25 | 0 | 0 | 4,438 = 44.38% | 4,480 = 44.80% |

- This closes the two NOT MEASURED items of step 22: worker-mode runs now
  carry `engine_decision` (the parity diff printed NOT MEASURED for the
  fail-closed classes before), and the worst-case sets with those classes
  are equal in the two modes, per sample.
- The numbers are those of the step-22 close-out: the step-23 engine moved
  no status on these datasets.
- Rule 18/24: PL2, both sets, both modes: 931130, 942430, 942200, 942370,
  942340, 942330, 932200 on 20% or more of the audit entries (949110 is the
  blocking evaluation rule); PL1 v0: 932370 on 466 of 2,236. Same list as
  in step 22; not re-examined.
- The one inconsistent sample (wcp-67cb71cd0c38) and the one error
  (wcp-6b0bf5e43122) are the ids of step 22, in both modes.
- Framing events in the eight runs: 0 (the runner cannot send what the
  gate refuses).

**One real 503 overload through the runner** (DIAGNOSTIC, rule 34; commit
c2b069b). `GOPROXY=off STUB_PORT=13004 bash tools/run_step23_overload.sh`:
runner `--workers 8` (rule 13 says 1; that is the point of this run), 48
hand-written benign POSTs of 100,000 bytes (large lane), the standard
limits (small lane 8, large lane 2, threshold 65,536, budget 2,000 ms), no
test hook.

```
== DIAGNOSTIC-overload-inprocess-pl1-workers8 rule29 2026-11-28T04:08:20Z load: load averages: 2.66 2.79 3.01: {"rule_engine": "On", "blocking_paranoia": 1, "detection_paranoia": 1, "max_body_bytes": 13107200, "max_inspected_bytes": 131072, "engine_time_budget_ms": 2000, "allowed_methods": "GET HEAD POST OPTIONS", "max_inflight_body": 8, "max_inflight_body_large": 2, "body_lane_threshold": 65536, "worker_mode": false} [other keys trimmed]
== DIAGNOSTIC-overload-worker-pl1-workers8 rule29 2026-11-28T04:08:23Z load: load averages: 2.69 2.79 3.01: {"rule_engine": "On", "blocking_paranoia": 1, "detection_paranoia": 1, "max_body_bytes": 13107200, "max_inspected_bytes": 131072, "engine_time_budget_ms": 2000, "allowed_methods": "GET HEAD POST OPTIONS", "max_inflight_body": 8, "max_inflight_body_large": 2, "body_lane_threshold": 65536, "worker_mode": true} [other keys trimmed]
# Step-23 T4 DIAGNOSTIC: 503 overload through the runner with concurrent workers
== 2026-11-28T04:08:19Z, git 1313eea962ae3a44bd9e0a7141d2ae1bbad4698e, tracked paths changed: 0, go version go1.27.4 darwin/arm64, Python 3.15.2, load at start: load averages: 2.66 2.79 3.01
== manifest (hand-written, not committed): 48 POST /form requests, content type ['application/x-www-form-urlencoded'], size in bytes [99992, 99993, 99994, 99995, 99996, 99997], ids ovl-00 to ovl-47
== engine binary sha256 4bf1d57e805c872c660c3f61807e9d8d3d329069e4cd1a41c39b643474b42578 built from 1313eea962ae3a44bd9e0a7141d2ae1bbad4698e with go version go1.27.4 darwin/arm64
== DIAGNOSTIC-overload-inprocess-pl1-workers8 stats after run: {"inflight_small":0,"inflight_large":0,"abandoned_running":0,"kills":0,"overloads":46,"refused_before_inspection":0,"penalised_clients":0,"client_inflight_small":0,"client_inflight_large":0,"workers":{"pool":0,"busy":0,"spares":0,"recycled":0}}
== DIAGNOSTIC-overload-inprocess-pl1-workers8 kortex_eval.crs_audit and kortex_eval.outcome output:
crs_audit: 0 audit entr(ies) -> out/s23-DIAGNOSTIC-overload-inprocess-pl1-workers8/audit.jsonl
waf_fail_closed_503_overload: 46
waf_pass: 2
== DIAGNOSTIC-overload-inprocess-pl1-workers8 events: 49 events {'overload': 46, 'pass': 3}; compressed-body events 0 {}; framing events 0 {}; kept 46
   responses by (status, engine_decision): (200, None)=2, (503, 'overload')=46
   overload events by reason: in-flight body-processing cap reached=46
   run.json: {"load_avg_start": [2.66, 2.79, 3.01], "load_avg_end": [2.69, 2.79, 3.01], "total_samples": 48, "responses_ok": 48, "blocked": 0, "error_count": 0}
== DIAGNOSTIC-overload-worker-pl1-workers8 stats after run: {"inflight_small":0,"inflight_large":0,"abandoned_running":0,"kills":0,"overloads":47,"refused_before_inspection":0,"penalised_clients":0,"client_inflight_small":0,"client_inflight_large":0,"workers":{"pool":4,"busy":0,"spares":4,"recycled":0}}
== DIAGNOSTIC-overload-worker-pl1-workers8 kortex_eval.crs_audit and kortex_eval.outcome output:
crs_audit: 0 audit entr(ies) -> out/s23-DIAGNOSTIC-overload-worker-pl1-workers8/audit.jsonl
waf_fail_closed_503_overload: 47
waf_pass: 1
== DIAGNOSTIC-overload-worker-pl1-workers8 events: 49 events {'overload': 47, 'pass': 2}; compressed-body events 0 {}; framing events 0 {}; kept 47
   responses by (status, engine_decision): (200, None)=1, (503, 'overload')=47
   overload events by reason: in-flight body-processing cap reached=23, per-client in-flight cap=24
   run.json: {"load_avg_start": [2.69, 2.79, 3.01], "load_avg_end": [2.69, 2.79, 3.01], "total_samples": 48, "responses_ok": 48, "blocked": 0, "error_count": 0}
S23-OVERLOAD-DONE
```

| mode | requests | 503 overload (waf_fail_closed_503_overload) | passed | reasons in the engine events |
|---|---|---|---|---|
| in-process | 48 | 46 | 2 | in-flight body-processing cap reached 46 |
| worker | 48 | 47 | 1 | in-flight body-processing cap reached 23, per-client in-flight cap 24 |

- MEASURED: a real `503 kortex-decision=overload` is recorded by the runner
  and classified by kortex_eval, in both modes. The engine's own counter
  agrees (`overloads` 46 and 47 on /__kortex/stats).
- These are counts of an effect on a chosen load, not a rate (rule 35). It
  does show how little gets through when one client sends eight large
  bodies at once: 2 of 48 and 1 of 48.

## T5. Strict parsing differential, first slice

`GOPROXY=off bash tools/run_step23_parsing_diff.sh` (commit 9754a0d;
docs/logs/step23-parsing-diff.txt; per-case records in
docs/logs/runs/s23-parsing-diff/results.jsonl). Local backends only (rule
6): tools/step23_parsing_backend.py (Python http.server; body = the FIRST
Content-Length, chunked not decoded, path and query decoded with
urllib.parse) on 127.0.0.1:13011, and tools/parsing-diff-gobackend (Go
net/http, stdlib only) on 127.0.0.1:13012. Each backend runs once behind
its own engine (in-process, blocking, PL1) and is also sent the same bytes
directly. 61 hand-written raw requests, sent over a raw socket.

```
== engine-before-python rule29 2026-11-28T04:10:25Z load: load averages: 2.27 2.57 2.89: {"rule_engine": "On", "blocking_paranoia": 1, "detection_paranoia": 1, "max_body_bytes": 13107200, "max_inspected_bytes": 131072, "engine_time_budget_ms": 2000, "allowed_methods": "GET HEAD POST OPTIONS", "max_inflight_body": 8, "max_inflight_body_large": 2, "body_lane_threshold": 65536, "worker_mode": false} [other keys trimmed]
# Step-23 T5: strict-parsing differential, first slice
== 2026-11-28T04:10:23Z, macOS 27.0 Darwin 27.0.0 arm64, go version go1.27.4 darwin/arm64, Python 3.15.2, system python3 for the backend: Python 3.15.2
== git c2b069b973e11563b5502573554650d41809f722, tracked paths changed in the working tree: 0
== coraza module of engine/: github.com/corazawaf/coraza/v3 v3.8.1 => ./third_party/coraza-v3.8.1-kortex
== engine binary sha256 4bf1d57e805c872c660c3f61807e9d8d3d329069e4cd1a41c39b643474b42578 built from c2b069b973e11563b5502573554650d41809f722 with go version go1.27.4 darwin/arm64
== go backend binary sha256 00a0d73fcaa31838886a0ee6cf6c519aedda2564169758d157702e3943cbd5aa
== python backend answers: {"backend": "python-http.server", "method": "GET", "target": "/ping", "path_raw"
== go backend answers:     {"backend":"go-net/http","method":"GET","target":"/ping","path_raw":"/ping","pat
== cases: 61 hand-written requests; content-length 19, overlong 11, percent 14, transfer-encoding 17
== engine decision per family (engine in front of the Python backend / in front of the Go backend)
   content-length [python]: 400 (no marker) 9, 400 framing 5, forwarded 5
   content-length [go]: 400 (no marker) 9, 400 framing 5, forwarded 5
   overlong [python]: 403 block 9, forwarded 2
   overlong [go]: 403 block 9, forwarded 2
   percent [python]: 400 (no marker) 3, 403 block 7, forwarded 4
   percent [go]: 400 (no marker) 3, 403 block 7, forwarded 4
   transfer-encoding [python]: 400 framing 7, 501 (no marker) 5, 503 timeout 2, forwarded 3
   transfer-encoding [go]: 400 framing 7, 501 (no marker) 5, 503 timeout 2, forwarded 3
== the engine decided the same in front of both backends in 61 of 61 cases
== who decided in the engine (python-backed run)
   HTTP parser of the engine (400, no marker, no event) 12, HTTP parser of the engine (501, no marker, no event) 5, engine 503 timeout (event) 2, forwarded 14, framing gate (400, event) 12, rule block (403, event) 16
   refused by the engine's HTTP parser without a kortex marker and without an event: 17: cl-list-same, cl-list-conflict, cl-plus, cl-hex, cl-negative, cl-empty, cl-non-numeric, cl-underscore, cl-space-before-colon, te-dup, te-dup-identity, te-list-identity, te-gzip-chunked, te-xchunked, pct-path-short, pct-path-nonhex, pct-path-bare
== each backend given the same bytes directly
   python: accepts 61 of 61; statuses {'200': 61}; accepted with bytes left on the connection 26
   go: accepts 37 of 61; statuses {'200': 37, '400': 17, '501': 7}; accepted with bytes left on the connection 3
== engine vs python backend: 50 of 61 cases disagree; agree 11; by class: engine-refuses-backend-accepts 47, view-differs 3
   cl-dup-same [content-length] engine-refuses-backend-accepts: engine 400 framing; backend alone accepts: body 5 bytes (content-length-first), 0 bytes left on the connection
   cl-dup-small-first [content-length] engine-refuses-backend-accepts: engine 400 framing; backend alone accepts: body 5 bytes (content-length-first), 6 bytes left on the connection
   cl-dup-large-first [content-length] engine-refuses-backend-accepts: engine 400 framing; backend alone accepts: body 11 bytes (content-length-first), 0 bytes left on the connection
   cl-dup-case [content-length] engine-refuses-backend-accepts: engine 400 framing; backend alone accepts: body 5 bytes (content-length-first), 6 bytes left on the connection
   cl-list-same [content-length] engine-refuses-backend-accepts: engine 400 (no marker); backend alone accepts: body 0 bytes (content-length-unparsable), 5 bytes left on the connection
   cl-list-conflict [content-length] engine-refuses-backend-accepts: engine 400 (no marker); backend alone accepts: body 0 bytes (content-length-unparsable), 11 bytes left on the connection
   cl-plus [content-length] engine-refuses-backend-accepts: engine 400 (no marker); backend alone accepts: body 5 bytes (content-length-first), 0 bytes left on the connection
   cl-hex [content-length] engine-refuses-backend-accepts: engine 400 (no marker); backend alone accepts: body 0 bytes (content-length-unparsable), 5 bytes left on the connection
   cl-negative [content-length] engine-refuses-backend-accepts: engine 400 (no marker); backend alone accepts: body 0 bytes (content-length-negative), 5 bytes left on the connection
   cl-empty [content-length] engine-refuses-backend-accepts: engine 400 (no marker); backend alone accepts: body 0 bytes (content-length-unparsable), 5 bytes left on the connection
   cl-non-numeric [content-length] engine-refuses-backend-accepts: engine 400 (no marker); backend alone accepts: body 0 bytes (content-length-unparsable), 5 bytes left on the connection
   cl-underscore [content-length] engine-refuses-backend-accepts: engine 400 (no marker); backend alone accepts: body 11 bytes (content-length-first), 0 bytes left on the connection
   cl-space-before-colon [content-length] engine-refuses-backend-accepts: engine 400 (no marker); backend alone accepts: body 0 bytes (none), 5 bytes left on the connection
   cl-space-before-colon-dup [content-length] engine-refuses-backend-accepts: engine 400 framing; backend alone accepts: body 5 bytes (content-length-first), 6 bytes left on the connection
   te-control [transfer-encoding] view-differs: engine forwarded; body_len: through engine 5, direct 0; body_sha256
   te-then-cl [transfer-encoding] engine-refuses-backend-accepts: engine 400 framing; backend alone accepts: body 5 bytes (content-length-first), 10 bytes left on the connection
   cl-then-te [transfer-encoding] engine-refuses-backend-accepts: engine 400 framing; backend alone accepts: body 5 bytes (content-length-first), 10 bytes left on the connection
   te-dup [transfer-encoding] engine-refuses-backend-accepts: engine 501 (no marker); backend alone accepts: body 0 bytes (none), 15 bytes left on the connection
   te-dup-identity [transfer-encoding] engine-refuses-backend-accepts: engine 501 (no marker); backend alone accepts: body 0 bytes (none), 15 bytes left on the connection
   te-list-identity [transfer-encoding] engine-refuses-backend-accepts: engine 501 (no marker); backend alone accepts: body 0 bytes (none), 15 bytes left on the connection
   te-gzip-chunked [transfer-encoding] engine-refuses-backend-accepts: engine 501 (no marker); backend alone accepts: body 0 bytes (none), 15 bytes left on the connection
   te-case [transfer-encoding] view-differs: engine forwarded; body_len: through engine 5, direct 0; body_sha256
   te-xchunked [transfer-encoding] engine-refuses-backend-accepts: engine 501 (no marker); backend alone accepts: body 0 bytes (none), 15 bytes left on the connection
   te-xchunked-cl [transfer-encoding] engine-refuses-backend-accepts: engine 400 framing; backend alone accepts: body 5 bytes (content-length-first), 0 bytes left on the connection
   te-space-before-colon [transfer-encoding] engine-refuses-backend-accepts: engine 400 framing; backend alone accepts: body 0 bytes (none), 15 bytes left on the connection
   te-tab [transfer-encoding] engine-refuses-backend-accepts: engine 400 framing; backend alone accepts: body 5 bytes (content-length-first), 10 bytes left on the connection
   te-obs-fold [transfer-encoding] engine-refuses-backend-accepts: engine 400 framing; backend alone accepts: body 5 bytes (content-length-first), 10 bytes left on the connection
   te-identity-cl [transfer-encoding] engine-refuses-backend-accepts: engine 400 framing; backend alone accepts: body 5 bytes (content-length-first), 0 bytes left on the connection
   te-chunk-ext [transfer-encoding] view-differs: engine forwarded; body_len: through engine 5, direct 0; body_sha256
   te-chunk-hex-prefix [transfer-encoding] engine-refuses-backend-accepts: engine 503 timeout; backend alone accepts: body 0 bytes (none), 17 bytes left on the connection
   te-chunk-lf-only [transfer-encoding] engine-refuses-backend-accepts: engine 503 timeout; backend alone accepts: body 0 bytes (none), 11 bytes left on the connection
   pct-path-short [percent] engine-refuses-backend-accepts: engine 400 (no marker); backend alone accepts: body 0 bytes (none), 0 bytes left on the connection
   pct-path-nonhex [percent] engine-refuses-backend-accepts: engine 400 (no marker); backend alone accepts: body 0 bytes (none), 0 bytes left on the connection
   pct-path-bare [percent] engine-refuses-backend-accepts: engine 400 (no marker); backend alone accepts: body 0 bytes (none), 0 bytes left on the connection
   pct-path-nul [percent] engine-refuses-backend-accepts: engine 403 block; backend alone accepts: body 0 bytes (none), 0 bytes left on the connection
   pct-query-nul [percent] engine-refuses-backend-accepts: engine 403 block; backend alone accepts: body 0 bytes (none), 0 bytes left on the connection
   pct-query-u [percent] engine-refuses-backend-accepts: engine 403 block; backend alone accepts: body 0 bytes (none), 0 bytes left on the connection
   pct-query-double [percent] engine-refuses-backend-accepts: engine 403 block; backend alone accepts: body 0 bytes (none), 0 bytes left on the connection
   pct-canary-control [percent] engine-refuses-backend-accepts: engine 403 block; backend alone accepts: body 0 bytes (none), 0 bytes left on the connection
   pct-canary-broken-tail [percent] engine-refuses-backend-accepts: engine 403 block; backend alone accepts: body 0 bytes (none), 0 bytes left on the connection
   pct-canary-broken-inside [percent] engine-refuses-backend-accepts: engine 403 block; backend alone accepts: body 0 bytes (none), 0 bytes left on the connection
   ovl-path-slash-pct [overlong] engine-refuses-backend-accepts: engine 403 block; backend alone accepts: body 0 bytes (none), 0 bytes left on the connection
   ovl-path-dot-pct [overlong] engine-refuses-backend-accepts: engine 403 block; backend alone accepts: body 0 bytes (none), 0 bytes left on the connection
   ovl-path-3byte-pct [overlong] engine-refuses-backend-accepts: engine 403 block; backend alone accepts: body 0 bytes (none), 0 bytes left on the connection
   ovl-path-raw [overlong] engine-refuses-backend-accepts: engine 403 block; backend alone accepts: body 0 bytes (none), 0 bytes left on the connection
   ovl-query-canary-pct [overlong] engine-refuses-backend-accepts: engine 403 block; backend alone accepts: body 0 bytes (none), 0 bytes left on the connection
   ovl-query-canary-raw [overlong] engine-refuses-backend-accepts: engine 403 block; backend alone accepts: body 0 bytes (none), 0 bytes left on the connection
   ovl-query-canary-3byte [overlong] engine-refuses-backend-accepts: engine 403 block; backend alone accepts: body 0 bytes (none), 0 bytes left on the connection
   ovl-path-canary-pct [overlong] engine-refuses-backend-accepts: engine 403 block; backend alone accepts: body 0 bytes (none), 0 bytes left on the connection
   ovl-path-canary-control [overlong] engine-refuses-backend-accepts: engine 403 block; backend alone accepts: body 0 bytes (none), 0 bytes left on the connection
== engine vs go backend: 23 of 61 cases disagree; agree 38; by class: engine-refuses-backend-accepts 23
   cl-dup-same [content-length] engine-refuses-backend-accepts: engine 400 framing; backend alone accepts: body 5 bytes (content-length), 0 bytes left on the connection
   te-then-cl [transfer-encoding] engine-refuses-backend-accepts: engine 400 framing; backend alone accepts: body 5 bytes (transfer-encoding:chunked), 0 bytes left on the connection
   cl-then-te [transfer-encoding] engine-refuses-backend-accepts: engine 400 framing; backend alone accepts: body 5 bytes (transfer-encoding:chunked), 0 bytes left on the connection
   te-tab [transfer-encoding] engine-refuses-backend-accepts: engine 400 framing; backend alone accepts: body 5 bytes (transfer-encoding:chunked), 0 bytes left on the connection
   te-obs-fold [transfer-encoding] engine-refuses-backend-accepts: engine 400 framing; backend alone accepts: body 5 bytes (transfer-encoding:chunked), 0 bytes left on the connection
   te-chunk-hex-prefix [transfer-encoding] engine-refuses-backend-accepts: engine 503 timeout; backend alone accepts: body 0 bytes (transfer-encoding:chunked), 12 bytes left on the connection
   te-chunk-lf-only [transfer-encoding] engine-refuses-backend-accepts: engine 503 timeout; backend alone accepts: body 0 bytes (transfer-encoding:chunked), 9 bytes left on the connection
   pct-path-nul [percent] engine-refuses-backend-accepts: engine 403 block; backend alone accepts: body 0 bytes (none), 0 bytes left on the connection
   pct-query-nul [percent] engine-refuses-backend-accepts: engine 403 block; backend alone accepts: body 0 bytes (none), 0 bytes left on the connection
   pct-query-u [percent] engine-refuses-backend-accepts: engine 403 block; backend alone accepts: body 0 bytes (none), 0 bytes left on the connection
   pct-query-double [percent] engine-refuses-backend-accepts: engine 403 block; backend alone accepts: body 0 bytes (none), 0 bytes left on the connection
   pct-canary-control [percent] engine-refuses-backend-accepts: engine 403 block; backend alone accepts: body 0 bytes (none), 0 bytes left on the connection
   pct-canary-broken-tail [percent] engine-refuses-backend-accepts: engine 403 block; backend alone accepts: body 0 bytes (none), 0 bytes left on the connection
   pct-canary-broken-inside [percent] engine-refuses-backend-accepts: engine 403 block; backend alone accepts: body 0 bytes (none), 0 bytes left on the connection
   ovl-path-slash-pct [overlong] engine-refuses-backend-accepts: engine 403 block; backend alone accepts: body 0 bytes (none), 0 bytes left on the connection
   ovl-path-dot-pct [overlong] engine-refuses-backend-accepts: engine 403 block; backend alone accepts: body 0 bytes (none), 0 bytes left on the connection
   ovl-path-3byte-pct [overlong] engine-refuses-backend-accepts: engine 403 block; backend alone accepts: body 0 bytes (none), 0 bytes left on the connection
   ovl-path-raw [overlong] engine-refuses-backend-accepts: engine 403 block; backend alone accepts: body 0 bytes (none), 0 bytes left on the connection
   ovl-query-canary-pct [overlong] engine-refuses-backend-accepts: engine 403 block; backend alone accepts: body 0 bytes (none), 0 bytes left on the connection
   ovl-query-canary-raw [overlong] engine-refuses-backend-accepts: engine 403 block; backend alone accepts: body 0 bytes (none), 0 bytes left on the connection
   ovl-query-canary-3byte [overlong] engine-refuses-backend-accepts: engine 403 block; backend alone accepts: body 0 bytes (none), 0 bytes left on the connection
   ovl-path-canary-pct [overlong] engine-refuses-backend-accepts: engine 403 block; backend alone accepts: body 0 bytes (none), 0 bytes left on the connection
   ovl-path-canary-control [overlong] engine-refuses-backend-accepts: engine 403 block; backend alone accepts: body 0 bytes (none), 0 bytes left on the connection
== the two backends, given the same bytes directly, differ from EACH OTHER (one refuses, or they read a different body) in 31 of 61 cases; the engine refuses 28 of them and forwards 3 with its own framing: te-control, te-case, te-chunk-ext
== canary cases: 9; forwarded by the engine: 0; blocked 403: 9
== log-only events of the engine (python-backed run), by reason
   invalid-percent-sequence-in-query 3
== engine stats at end (python-backed): {"inflight_small":0,"inflight_large":0,"abandoned_running":0,"kills":0,"overloads":0,"refused_before_inspection":0,"penalised_clients":0,"client_inflight_small":0,"client_inflight_large":0,"workers":{"pool":0,"busy":0,"spares":0,"recycled":0}}
== engine stats at end (go-backed):     {"inflight_small":0,"inflight_large":0,"abandoned_running":0,"kills":0,"overloads":0,"refused_before_inspection":0,"penalised_clients":0,"client_inflight_small":0,"client_inflight_large":0,"workers":{"pool":0,"busy":0,"spares":0,"recycled":0}}
S23-PARSING-DIFF-DONE
```

Counts (cases are chosen, so these are counts of cases, never a rate; rule
35):

| family | cases | forwarded | framing gate 400 | rule block 403 | body read 503 | engine's HTTP parser 400 / 501 |
|---|---|---|---|---|---|---|
| Content-Length | 19 | 5 | 5 | 0 | 0 | 9 |
| Transfer-Encoding | 17 | 3 | 7 | 0 | 2 | 5 |
| invalid percent | 14 | 4 | 0 | 7 | 0 | 3 |
| overlong UTF-8 | 11 | 2 | 0 | 9 | 0 | 0 |
| all | 61 | 14 | 12 | 16 | 2 | 17 |

| backend | accepts the bytes directly | cases where engine and backend disagree | engine refuses, backend accepts | engine forwards, backend refuses | both accept, backend sees something else through the engine | canary reaches the backend |
|---|---|---|---|---|---|---|
| Python http.server | 61 of 61 | 50 | 47 | 0 | 3 | 0 |
| Go net/http | 37 of 61 | 23 | 23 | 0 | 0 | 0 |

The list of disagreements is the block above (one line per case and
backend). Grouped:

- Engine refuses, Python backend accepts (47): every case the engine does
  not forward. The Python backend accepts all 61; in 26 of them it leaves
  bytes on the connection after the body it read (for example
  `cl-dup-small-first`: body 5 bytes, 6 left; `te-then-cl`: body 5 bytes,
  10 left), which on a kept-alive connection would be read as the next
  request.
- Both accept, different view (3, Python only): `te-control`, `te-case`,
  `te-chunk-ext`. The engine reads the chunked body and forwards 5 bytes
  with a Content-Length; the Python backend alone reads no body and leaves
  the chunks on the connection.
- Engine refuses, Go backend accepts (23): 16 rule blocks (the request is
  well-formed HTTP; the rules object to its content); 5 framing-gate
  refusals that Go accepts (`cl-dup-same`: two equal Content-Length;
  `te-then-cl`, `cl-then-te`, `te-tab`, `te-obs-fold`: Go lets
  Transfer-Encoding win over Content-Length); 2 malformed chunked bodies
  (`te-chunk-hex-prefix`, `te-chunk-lf-only`) where the engine answers
  503 on the body read error and the Go backend answers 200 having read 0
  body bytes.
- Agreement: Python 11 cases (all forwarded, same view), Go 38 cases (14
  forwarded with the same view, 24 refused by both).
- **In no case is the engine the laxer side**: 0 cases where it forwards
  something a backend refuses, 0 cases where a backend behind the engine
  reads a body, path or query other than the one the engine forwarded
  apart from the 3 re-framed chunked bodies, and 0 of the 9 canary cases
  forwarded.
- The two backends differ from each other in 31 of 61 cases (one refuses,
  or they read a different body); the engine refuses 28 of those and
  forwards the other 3 with its own framing, so behind the engine both
  backends are handed the same thing.

Findings beyond the counts:

- **17 refusals come from Go's HTTP parser inside the engine**, not from
  the engine's code: 9 Content-Length shapes (`5, 5`, `5, 11`, `+5`, `0x5`,
  `-1`, empty, `abc`, `1_1`, a space before the colon), 5 Transfer-Encoding
  shapes (repeated, `identity, chunked`, `gzip, chunked`, `xchunked`), 3
  invalid percent escapes in the path. The client gets Go's plain `400 Bad
  Request` or `501 Unsupported transfer encoding`: no kortex-decision
  line, no event, no audit entry. The behaviour is fail-closed, but the
  engine does not announce it and kortex_eval would count such an answer
  by status only (a 400 without marker and without audit entry is
  `waf_pass`). Classification (rule 39): BUG (missing marker and event),
  NOT FIXED in this step: it is outside the six tasks (rule 1); see
  Questions. It did not occur in the wcp runs (every 400 there carries the
  engine's `block` decision).
- Overlong UTF-8 in the path writes no log-only event: the checks cover
  the query and urlencoded bodies only. `ovl-path-nul-pct` (`/a%C0%80b`)
  is forwarded with no event. Invalid percent escapes in the query do
  write theirs (3 of 3).
- Canary (rule 47): the plain controls are blocked (`pct-canary-control`
  on 941100 / 941110 / 941390, `ovl-path-canary-control` on 941110 /
  941390). The overlong forms are blocked on 941390 only, the `alert(`
  call in my canary, not on the tag: the engine does not turn an overlong
  `<` into `<`. Neither does either backend (Python decodes it to U+FFFD,
  Go keeps the raw bytes), so nothing reaches them as `<script>`. A
  backend that does decode overlong forms was not in this slice, and a
  canary without the `alert(` text was not sent: NOT MEASURED.
- Backend-only observation: for an invalid percent escape in the query
  the Python backend keeps the literal text (`a%zzb`) and Go's query
  parser drops the pair. The engine forwards the raw query unchanged.

## Final suites

At 9754a0d (the last commit that changes code), one after another, nothing
else running on my side.

| suite | passed | failed | skipped | time |
|---|---|---|---|---|
| Go, fixture not set | 55 | 0 | 5 (E16, E17, E19, E20, E21) | 62.676 s |
| Go, with the recorded wcp fixture, `-timeout 900s` | 60 | 0 | 0 | 336.432 s |
| pytest | 234 | 0 | 4 | 60.07 s |

```
# step-23 final Go suite at 9754a0dbed8933d318796644f8c22bf2b96f98bf (paths changed under engine/: 0), 2026-11-28T04:11:04Z, go version go1.27.4 darwin/arm64, github.com/corazawaf/coraza/v3 v3.8.1 => ./third_party/coraza-v3.8.1-kortex, load at start: load averages: 2.27 2.53 2.86
$ cd engine && GOPROXY=off go test -buildvcs=false -count=1 -v ./...
--- SKIP: TestE16BodyProcessingBoundedByTimeBudget (0.00s)
--- SKIP: TestE17AbandonedCallOwnsTransaction (0.00s)
--- SKIP: TestE19OverloadCapImmediate (0.01s)
--- SKIP: TestE20OverloadRecovery (0.01s)
--- SKIP: TestE21BenignPromptOnCapReachedEngine (0.01s)
            worker_test.go:381: T3g: killed worker pid 13061; parent CPU 89.164ms -> 89.318ms (+154µs) over 1.2s after the kill
    worker_test.go:427: T3o: with a busy parent T3g failed as it must: worker_test.go:383: T3g: parent CPU grew by 1.189629s in 1.2s after the kill (limit 150ms)
            worker_test.go:381: T3g: killed worker pid 13619; parent CPU 80.523ms -> 80.56ms (+37µs) over 1.2s after the kill
ok  	kortexshield/engine	62.676s
# exit status of go test: 0
# load at end: load averages: 2.64 2.59 2.85

# step-23 final Go suite at 9754a0dbed8933d318796644f8c22bf2b96f98bf (paths changed under engine/: 0), 2026-11-28T04:12:07Z, go version go1.27.4 darwin/arm64, github.com/corazawaf/coraza/v3 v3.8.1 => ./third_party/coraza-v3.8.1-kortex, load at start: load averages: 2.64 2.59 2.85
$ cd engine && GOPROXY=off KORTEX_TEST_WCP_BODY=/Users/ivan/work/kortex-shield-dev/out/step14-t5/wcp-80a49c991b2d.body go test -buildvcs=false -count=1 -timeout 900s -v ./...
--- PASS: TestE20OverloadRecovery (265.18s)
            worker_test.go:381: T3g: killed worker pid 31109; parent CPU 83.557ms -> 83.613ms (+56µs) over 1.2s after the kill
    worker_test.go:427: T3o: with a busy parent T3g failed as it must: worker_test.go:383: T3g: parent CPU grew by 1.191995s in 1.2s after the kill (limit 150ms)
            worker_test.go:381: T3g: killed worker pid 31136; parent CPU 86.053ms -> 86.079ms (+26µs) over 1.2s after the kill
ok  	kortexshield/engine	336.432s
# exit status of go test: 0
# load at end: load averages: 5.24 4.71 3.79

# step-23 final Python suite at 9754a0dbed8933d318796644f8c22bf2b96f98bf (tracked files modified: 2: docs only), 2026-11-28T04:18:02Z, Python 3.15.2, pytest 9.2.0, load at start: load averages: 4.43 4.56 3.76
$ .venv/bin/python -m pytest -q -rs
SKIPPED [1] tests/test_record_benign.py:9: could not import 'playwright': No module named 'playwright'
SKIPPED [1] tests/test_outcome.py:78: smoke run artifacts not present
SKIPPED [1] tests/test_outcome.py:96: smoke run artifacts not present
SKIPPED [1] tests/test_outcome.py:161: step-05 hard PL2 run output not present
234 passed, 4 skipped in 60.07s (0:01:00)
# exit status of pytest: 0
# load at end: load averages: 3.60 4.28 3.70
```

The 4 Python skips are the same as before (playwright not installed, 3
missing run artifacts). Step 22 ended at Go 48 / 0 / 5 and 53 / 0 / 0, and
pytest 222 / 0 / 4: +7 Go tests (E35 to E41), +12 Python tests
(tests/test_step23_tools.py).

## Pre-push scan (rule 51)

Nothing was pushed. The eleven step-23 commits before this one were
scanned as a range and this commit as staged content.

```
$ bash tools/prepush_scan.sh --range origin/main..HEAD; echo "exit=$?"
[trimmed: 14 "large file" notes, all under docs/logs/runs/s23-parity/; largest benign-wcp-v0-worker-pl2/outcomes.jsonl (3734653 bytes)]
prepush: OK, 304 blob(s) in origin/main..HEAD scanned
exit=0
$ git add docs reports; bash tools/prepush_scan.sh; echo "exit=$?"
prepush: OK, 10 staged path(s) scanned
exit=0
```

Committed run files hold ids, statuses, timings, outcomes, scores, rule
ids, engine decisions and event reasons only. Raw audit logs, parsed
audit.jsonl, the wcp manifests and the generated overload manifest stay
under gitignored out/ or in the first checkout. The vendored coraza code
is Apache-2.0 and carries its LICENSE file. Commits of the step, oldest
first: a21491a, 7cc62a5 (T1); b69492e, ed48b1e, 41b6035 (T2); 611508d,
cf79759 (T3); 4d56170, 1313eea, c2b069b (T4, with the T2 parity and the T3
counts); 9754a0d (T5); and the commit that holds this report and the docs
(T6).

## NOT MEASURED in this step

- The attack datasets with the patched engine (recall, per-family
  numbers): not re-run. The step-22 note that a recall figure from one
  replay carries noise is answered for the two synthetic requests and the
  60,000 wcp pairs only.
- The Coraza connector and ModSecurity images against the patched engine:
  no container was run in this step. Rule-id parity against them is
  expected to stop being exact for order-dependent requests (HYPOTHESIS,
  from the design), not measured.
- A controlled timing of the patch (the table in T2 compares runs made
  under different host load).
- E37 in worker mode: the test is in-process. Worker mode is covered by
  the wcp parity runs only (0 rule-id set differences).
- E35 in a run through the runner: the runner cannot send what the gate
  refuses; the event is shown by the Go test and by the 12 gate refusals
  of T5.
- The compressed-body event on the attack datasets, on bodies above the
  total size limit, and for zlib streams with a window below 32K or a
  preset dictionary (not flagged by design).
- 503 overload in a rule-13 run (runner at 1 worker): cannot occur; the
  DIAGNOSTIC run with 8 workers is the only evidence.
- The parsing differential at PL2, in worker mode, in DetectionOnly mode,
  through the runner, and against any backend other than the two local
  ones (nginx, Node, Java, IIS-style decoders). Request-line shapes, header
  names, HTTP/1.0, pipelining and chunk trailers are not in this slice.
- A canary without the `alert(` text for the overlong forms (T5).
- The Go suite with the fixture after each task: run once, at the end.
- The CRS regression suite against the patched copy (coraza's own unit
  tests of 8 packages were run and pass).

- Deviations from instructions:
  - The eight wcp runs were made once, with the final engine (T1 + T2 +
    T3), and serve three tasks: T2's parity, T3's event counts and T4's
    worker-mode evidence. T2's parity was therefore measured at the T3
    commit, not at the T2 commit. T3 is log-only (E40 requires the same
    answer as the control), and the runs show 0 status differences against
    the stock-coraza runs, so the T3 change did not move a decision on
    these datasets.
  - T2: besides the E37 test asked for I added E38 (member order) and E39
    (the tautology whose key sorts first, logged, not required to block).
    The patch also orders `NamedCollectionNames.String()`, as the step-22
    `sorted` build did; it is not needed for matching.
  - T2: "vendor" is a partial copy: the non-test Go files of the 25 coraza
    packages the engine imports, not the whole module. The vendor check
    shows each copied file is byte-identical to the module except the two
    patched ones.
  - T2: flip_repro was also run against Host 127.0.0.1 and with the v3.7.0
    control (not asked for). tools/run_step22_flip.sh was changed for it
    (`FLIP_STEP`, the replace dropped for the control); the step-22 logs
    are untouched.
  - T3: "zlib magic bytes" is read as the four pairs of a 32K-window stream
    without a preset dictionary (`78 01 / 5e / 9c / da`), and gzip as
    `1f 8b 08`. Other legal zlib headers are not flagged because they
    collide with ordinary text; documented before the code. The event is
    written when the body is read, whatever the later decision.
  - T3: the analysis of the 16 flagged bodies read the local manifests and
    handed the bodies to zlib; only counts are printed and committed.
  - T4: the overload run uses the runner with 8 workers (rule 13 says 1),
    as the task asks; it is labelled DIAGNOSTIC and gives no baseline
    number.
  - T5: the Python backend's body rule (first Content-Length, chunked not
    decoded) is my choice of "what a Python http.server sees"; http.server
    itself reads no body. The differential was run twice: the first run's
    harness did not decode chunked answers and showed the two 503 timeout
    answers without their marker; the committed log is the second run.
  - Rule 39 for T5: engine against backend differences are classified
    DESIGN where the engine refuses on purpose (framing gate, rules,
    re-framing of forwarded requests; docs/engine-design.md) and BUG, not
    fixed, for the 17 unannounced parser refusals. None is UNEXPLAINED.
  - No network: `GOPROXY=off` for every go command; the v3.7.0 control and
    the Go backend built from the module cache and the standard library.
    Nothing was reported upstream.
  - Rule 13 (container force-recreated) does not apply to the host engine;
    each run had a fresh engine process.
  - README.md was not updated (not in the list of T6).
  - Rule 8: T1, T2 and T3 have a test commit and a code commit each; the
    evidence runs and T5 have their own commits (11 commits before the
    one that holds this report and the docs).

- UNVERIFIED items:
  - Whether the 16 bodies behind the compressed-body events were real zlib
    streams in the original traffic (HYPOTHESIS above).
  - Whether any earlier dataset run contains an answer of the engine's
    HTTP parser (400 / 501 without marker) that was counted as waf_pass.
    The eight wcp runs of this step have none (all 308 status-400 answers
    carry the `block` decision; no 501). Earlier runs and the attack
    datasets were not checked.
  - Why the stock library passed syn-chain 436 times of 2,000 here and 69
    of 200 in step 22 (22% against 35%). Both are far from 0; the split of
    Go's map order between two keys is not something I looked into.
  - That the patch has no effect outside the four Find functions and
    `String()`: shown by the diff and by coraza's own tests of 8 packages,
    not by the CRS regression suite.
  - Carried from step 22 and not touched: the items of its UNVERIFIED list
    (the 6 ids blocked now but not in steps 18/19, connector rule-id sets,
    the first T2 recording, the E20 duration, port 13000's stub).

- Questions for instructor:
  - The 942130 shape of E39. With ordered iteration a tautology under a key
    that sorts before a harmless `x=y` member is passed every time at PL2
    (before: at random). Options: (a) accept and document, as ModSecurity
    behaves the same; (b) report the rule weakness to the CRS project;
    (c) change the patch to arrival order, which would match ModSecurity's
    semantics but needs the collections to remember insertion order (a
    larger patch); (d) an engine-side check for the tautology. Which?
  - The 17 refusals by Go's HTTP parser carry no kortex marker and no
    event (T5). Options: (a) extend the framing gate to refuse these
    shapes itself, with marker and event (test first); (b) leave them to
    Go and have kortex_eval treat an engine 400 / 501 without marker as a
    refusal; (c) document only. Until then a dataset sample with, say, an
    invalid percent escape in its path is answered 400 by the engine and
    counted as waf_pass.
  - Overlong UTF-8 and invalid percent checks do not look at the path.
    Extend the log-only checks to the path?
  - The compressed-body event: 16 events in 30,000 benign samples, all
    already blocked. Keep it log-only, widen it (other zlib headers collide
    with text), or drop it?
  - The engine's `timeout` decision also covers a body it cannot read (a
    malformed chunk: reason `body-read-error`), so kortex_eval calls it
    waf_fail_closed_503_timeout. Give it its own decision?
  - Report the iteration-order defect upstream to coraza (this step had no
    network)? The patch file applies to the v3.8.1 release as is.
  - Still open from step 22: 503 overload in the worst case of a
    false-positive rate; `flagged` in predictions.jsonl = 403 only;
    400 / 503 classes in the diff tool's set; decoding gzip instead of
    415; a real rate limit; pool size for eight attacker addresses; worker
    mode as default; the history rewrite.
