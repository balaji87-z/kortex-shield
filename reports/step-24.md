# Step-24 report

Host and versions (rule 43: the host and the image set did not change since
step 23; no container image was used in this step). macOS 27.0 (26A425),
Darwin 27.0.0 arm64, Apple M6 12 cores; go1.27.4 darwin/arm64; Python
3.15.2, pytest 9.2.0. Docker: not used. No network: every `go` command ran
with `GOPROXY=off` against the local module cache. Engine: coraza v3.8.1
with the step-23 patch (engine/third_party/coraza-v3.8.1-kortex) + CRS
4.25.2 (engine/RULES.sha256 unchanged). Engine binary of every run of this
step: sha256 3aef0168...96cc79 (engine code of 40c57ad; the same hash from
95208d9, 40e4519, 50dcb27 and 7316418). DIAGNOSTIC stock-coraza build of the
same code: 59389735...22a25c4. Rule 29: every run log carries the engine's
`/__kortex/config` output; one is quoted below.

The step-24 brief is the instructor's message ("next step 24, fix 2 first
and then move"): fix item 2 of the step-23 questions (the 17 refusals of
Go's HTTP parser that the engine did not announce), then go on to what
step 23 left NOT MEASURED, the attack datasets on the patched engine. It is
not a file in the repository. Work was done in the checkout
`~/work/kortex-shield-work`; the wcp manifests and the fixture body are not
committed (rules 25, 51) and were read from the first checkout after a hash
check (shown in the logs). Nothing was pushed.

- Summary: the gate now refuses, with the framing marker and an event, what Go's parser used to answer unannounced (33 cases;
  the 61-case differential has 0 such answers, was 17); two holes of the framing gate found on the way (bare LF, connection reuse)
  are fixed test-first; own datasets on the patched engine: attacks-v0 954 and 1,024 of 1,054, patch changes no sample; wcp
  unchanged; Go 62/0/5 (67/0/0 with fixture), pytest 242/0/4.

- Task table:

| task | status | evidence |
|---|---|---|
| T1 parser refusals announced: failing test, design note, fix, Go suite | done; Go 59 PASS / 0 FAIL / 5 SKIP after it | docs/logs/step24-e42-failing.log, step24-e42-passing.log, step24-e45-DIAGNOSTIC-gate-without-expect-check.log, step24-t1-go-test.log; commits 323ed49, a9dad86 |
| T2 two framing-gate holes found while building T1 (bare LF, connection reuse): failing tests, design note, fix | done; Go 62 PASS / 0 FAIL / 5 SKIP after it | docs/logs/step24-e46-e48-failing.log, step24-e46-e48-passing.log, step24-repeat-30x.log, step24-t2-go-test.log; commits 5cd6fc2, 40c57ad |
| T3 parsing differential re-run on the fixed engine, per-case comparison with step 23 | done: 0 answers without a marker (was 17), 44 of 61 cases unchanged | docs/logs/step24-parsing-diff.txt, step24-parsing-diff-vs-step23.txt, docs/logs/runs/s24-parsing-diff/; commits 95208d9, 8dec3c0 |
| T4 own datasets on the step-24 engine (plan first), recall and potential false positives, parity in-process / worker, DIAGNOSTIC stock coraza and numeric Host | done | docs/plan-step24-own-datasets.md, docs/logs/step24-own-datasets*.txt, step24-own-summary.txt, docs/logs/runs/s24-own/; commits 40e4519, 3c51a4c |
| T5 wcp datasets re-run as a check on the gate change | done: 0 differences against step 23 in 60,000 pairs | docs/logs/step24-parity.txt, docs/logs/runs/s24-parity/; commits 50dcb27, 7316418 |
| T6 docs | done | docs/baseline-v1.9.md, docs/engine-design.md, docs/engine-evidence.md, docs/acceptance.md (E42 to E48), docs/block-discriminator.md, this report |
| Final suites | done: Go 62 PASS / 0 FAIL / 5 SKIP; with fixture 67 / 0 / 0; pytest 242 passed, 0 failed, 4 skipped | docs/logs/step24-final-go-test.log, step24-final-go-test-with-fixture.log, step24-final-pytest.log |

- Raw evidence (key numbers in the body per rule 31; outputs trimmed where
  marked):

## T1. Refusals of Go's HTTP parser are made by the gate

Classification (rule 39): BUG, from step 23. Cause, PROVEN (rules 33, 44):
net/http inside the engine answers these heads before the engine's handler
runs. The discriminating experiment is in test E42 itself: each case is
first sent to a bare net/http server whose handler records being called;
the handler is not called and net/http answers 400 or above. The same bytes
sent to the engine before the fix got that same bare answer; after the fix
the gate answers.

Design (docs/engine-design.md, committed with the failing test in 323ed49):
the gate gives the head it already holds to Go's own `http.ReadRequest`,
then repeats the checks net/http's server makes before calling a handler
(version, Host, header names and values, more than 500 header lines,
Expect). A failing head gets the gate's usual answer, `400
kortex-decision=framing`, and one `framing` event with reason
`parser:<class>` from a fixed word list (Go's error text quotes request
bytes and is never logged). kortex_eval already classifies that answer as
`waf_fail_closed_400`; kortex_eval is unchanged (rule 5).

Test first. 33 cases: the 17 of step 23, 15 further shapes of the same
layer (missing / duplicate / malformed Host, HTTP/2.0, HTTP/0.9, malformed
version, short request line, invalid method, relative target, header
without colon, space or control byte in a header name, control byte in a
value, 501 header lines, unknown Expect) and one refused head that also
carries an XSS payload. E43 (13 well-formed neighbours still reach the
handler) and E44 (canary: the same shapes with an XSS payload are blocked
403) are guards.

```
# step-24 T1: E42 failing before the fix (E43, E44 guards pass)
# 2026-11-28T04:42:47Z git 0f52fec82482500554672540d2c19d26c37e5a3c go version go1.27.4 darwin/arm64
# cd engine && go test -count=1 -run 'TestE42|TestE43|TestE44' -v .
--- FAIL: TestE42ParserRefusalsAreAnnounced (0.55s)
--- PASS: TestE43ParserGateLetsWellFormedRequestsThrough (0.05s)
--- PASS: TestE44RequestsPastTheParserGateAreInspected (0.02s)
FAIL
FAIL	kortexshield/engine	0.943s
FAIL
exit=1
```

What net/http answered on the bare server (the premise of each case) and
what the engine answered before the fix, counted from the same log:

```
  24 x bare net/http answers 400, handler not run
   5 x bare net/http answers 501, handler not run
   2 x bare net/http answers 505, handler not run
   1 x bare net/http answers 431, handler not run
   1 x bare net/http answers 417, handler not run

  20 x E42: want 400 with body "400 kortex-decision=framing", got 400 "400 Bad Request"
   5 x E42: want 400 with body "400 kortex-decision=framing", got 501 "Unsupported transfer encoding"
   2 x E42: want 400 with body "400 kortex-decision=framing", got 400 "400 Bad Request: invalid header name"
   2 x E42: want 400 with body "400 kortex-decision=framing", got 505 "505 HTTP Version Not Supported: unsupported protocol version"
   1 x E42: want 400 with body "400 kortex-decision=framing", got 400 "400 Bad Request: missing required Host header"
   1 x E42: want 400 with body "400 kortex-decision=framing", got 400 "400 Bad Request: malformed Host header"
   1 x E42: want 400 with body "400 kortex-decision=framing", got 431 "431 Request Header Fields Too Large"
   1 x E42: want 400 with body "400 kortex-decision=framing", got 417 ""
```

After the fix (commit a9dad86):

```
# step-24 T1: E42 passing after the fix; E43, E44 guards; E45 seeded differential
# 2026-11-28T04:47:36Z git 323ed4987b41349c91486edb0f8b61bbb3f8bcf4 + working tree (fix); go version go1.27.4 darwin/arm64
# cd engine && go test -count=1 -run 'TestE42|TestE43|TestE44|TestE45' -v .
--- PASS: TestE42ParserRefusalsAreAnnounced (0.57s)
--- PASS: TestE43ParserGateLetsWellFormedRequestsThrough (0.04s)
--- PASS: TestE44RequestsPastTheParserGateAreInspected (0.01s)
    step24_test.go:428: heads compared 19257 (not sent, no blank line: 743; no answer from net/http: 0); net/http refused 11890 map[400:10815 417:421 501:654]; parserGate refused 11890; mismatches 0
    step24_test.go:430: parserGate reasons: parser:content-length 542, parser:expect 421, parser:header-line 4276, parser:header-name 404, parser:host-duplicate 973, parser:host-malformed 311, parser:host-missing 322, parser:http-version 2364, parser:method 509, parser:request-line 419, parser:request-target 695, parser:transfer-encoding 654
--- PASS: TestE45ParserGateAgreesWithNetHTTPOnDamagedHeads (1.69s)
ok  	kortexshield/engine	2.541s
exit=0
```

E45 is a seeded differential written with the fix (it calls the new
function, so it could not exist before): 20,000 heads made from 5
well-formed ones by 1 to 3 random edits, each sent to a bare net/http
server and given to the gate. 19,257 compared (743 had lost their blank
line and are never seen by the gate), 11,890 refused by both, 7,367 passed
by both, 0 decided differently. It found a real mistake while the fix was
being written: the first version of the Expect check used a different token
test from net/http's and disagreed on 3 of 3,799 heads of an earlier
generator (seen in a scratch run that was not kept; the committed
DIAGNOSTIC below shows the same class). That the test can fail (rule 44) is
shown by running it against a gate with its Expect check switched off:

```
# step-24 T1 DIAGNOSTIC: E45 run against a parser gate with its Expect check switched off (scratch edit, not committed)
# shows that E45 fails when the gate misses a check net/http makes (rule 44)
# 2026-11-28T04:47:26Z git 323ed4987b41349c91486edb0f8b61bbb3f8bcf4 + working tree; go version go1.27.4 darwin/arm64
# cd engine && go test -count=1 -run TestE45 -v .
    step24_test.go:428: heads compared 19257 (not sent, no blank line: 743; no answer from net/http: 0); net/http refused 11890 map[400:10815 417:421 501:654]; parserGate refused 11469; mismatches 421
    step24_test.go:432: E45: 421 of 19257 heads decided differently by parserGate and net/http
--- FAIL: TestE45ParserGateAgreesWithNetHTTPOnDamagedHeads (1.67s)
```

Status change (documented before the code): requests net/http answered
501, 505, 417 or 431 now get 400, the one status the gate uses.

Go suite after T1: docs/logs/step24-t1-go-test.log, 59 PASS, 0 FAIL, 5 SKIP
(`ok kortexshield/engine 63.898s`).

## T2. Two holes in the framing gate (found while building T1)

Both are BUG (rule 39), both existed before this step, both PROVEN by the
failing tests below (committed in 5cd6fc2 before the fix 40c57ad). In both,
a request the gate refuses when sent normally was forwarded to the backend.
It was still inspected by the rules and forwarded with the engine's own
framing (one Content-Length for the bytes it read).

1. Bare LF (E46). The gate split the head on CRLF; Go's parser also ends a
   line at a bare LF. A Content-Length or Transfer-Encoding line after a
   bare LF was invisible to the gate. Premises proven per case: the CRLF
   form is refused by the gate, and bare net/http runs its handler for the
   LF form. Fix: the framing checks are repeated on the header block as
   Go's MIME reader returns it. Bare LF itself is not refused (guard E47).
2. Connection reuse (E48). The gate judges the first request of a
   connection. `OPTIONS *` (answered by net/http itself) and the two
   `/__kortex/` admin paths left the connection open, and a second request
   on it was never gated. Fix: keep-alive is off on the engine's server,
   built by one function (`newEngineServer`) in main() and in the tests.

```
# step-24 T2: E46 and E48 failing before the fix (E47 guard passes)
# 2026-11-28T04:49:55Z git a9dad860122747670ab2de8bd46cd7389abebd4e + step24_test.go; go version go1.27.4 darwin/arm64
# cd engine && go test -count=1 -run 'TestE46|TestE47|TestE48' -v .
    step24_test.go:493: E46: the LF form reached the backend (engine answered 200 "stub-ok")
    step24_test.go:493: E46: the LF form reached the backend (engine answered 200 "stub-ok")
    step24_test.go:493: E46: the LF form reached the backend (engine answered 200 "stub-ok")
    step24_test.go:493: E46: the LF form reached the backend (engine answered 200 "stub-ok")
--- FAIL: TestE46FramingChecksSeeLinesEndedByBareLF (0.06s)
    --- FAIL: TestE46FramingChecksSeeLinesEndedByBareLF/e46-lf-te-cl (0.00s)
    --- FAIL: TestE46FramingChecksSeeLinesEndedByBareLF/e46-one-lf-te-cl (0.00s)
    --- FAIL: TestE46FramingChecksSeeLinesEndedByBareLF/e46-one-lf-cl-te (0.00s)
    --- FAIL: TestE46FramingChecksSeeLinesEndedByBareLF/e46-one-lf-dup-cl (0.00s)
--- PASS: TestE47BareLFWithoutFramingProblemIsStillForwarded (0.01s)
    --- PASS: TestE47BareLFWithoutFramingProblemIsStillForwarded/e47-lf-chunked (0.00s)
    --- PASS: TestE47BareLFWithoutFramingProblemIsStillForwarded/e47-one-lf-get (0.00s)
    --- PASS: TestE47BareLFWithoutFramingProblemIsStillForwarded/e47-one-lf-cl (0.00s)
    step24_test.go:579: E48: the second request on the connection reached the backend (2 responses read)
    step24_test.go:579: E48: the second request on the connection reached the backend (2 responses read)
    step24_test.go:579: E48: the second request on the connection reached the backend (2 responses read)
    step24_test.go:579: E48: the second request on the connection reached the backend (2 responses read)
    step24_test.go:579: E48: the second request on the connection reached the backend (2 responses read)
    step24_test.go:579: E48: the second request on the connection reached the backend (2 responses read)
--- FAIL: TestE48SecondRequestOnAConnectionIsNeverServed (0.02s)
    --- FAIL: TestE48SecondRequestOnAConnectionIsNeverServed/e48-options-asterisk-te-cl (0.00s)
    --- FAIL: TestE48SecondRequestOnAConnectionIsNeverServed/e48-options-asterisk-plain-get (0.00s)
    --- FAIL: TestE48SecondRequestOnAConnectionIsNeverServed/e48-admin-config-te-cl (0.00s)
    --- FAIL: TestE48SecondRequestOnAConnectionIsNeverServed/e48-admin-config-plain-get (0.00s)
    --- FAIL: TestE48SecondRequestOnAConnectionIsNeverServed/e48-admin-stats-te-cl (0.00s)
    --- FAIL: TestE48SecondRequestOnAConnectionIsNeverServed/e48-admin-stats-plain-get (0.00s)
FAIL
FAIL	kortexshield/engine	0.388s
FAIL
exit=1
```

After the fix:

```
# step-24 T2: E46 and E48 passing after the fix; E47 guard
# 2026-11-28T04:51:02Z git 5cd6fc26c0f999d869048ca38813a8ade059ebfb + working tree (fix); go version go1.27.4 darwin/arm64
# cd engine && go test -count=1 -run 'TestE46|TestE47|TestE48' -v .
--- PASS: TestE46FramingChecksSeeLinesEndedByBareLF (0.04s)
--- PASS: TestE47BareLFWithoutFramingProblemIsStillForwarded (0.01s)
--- PASS: TestE48SecondRequestOnAConnectionIsNeverServed (0.01s)
ok  	kortexshield/engine	0.367s
exit=0
```

Repeatability of the new tests (rule 48):

```
# step-24: E42-E44 and E46-E48 repeated 30 times in one process (rule 48), at 7316418f19c96c006f10dd74f283f46084a88306, 2026-11-28T05:29:01Z, go version go1.27.4 darwin/arm64
$ cd engine && go test -count=30 -run 'TestE42|TestE43|TestE44|TestE46|TestE47|TestE48' -v .
  27 --- PASS: TestE42ParserRefusalsAreAnnounced (0.52s)
   2 --- PASS: TestE42ParserRefusalsAreAnnounced (0.53s)
   1 --- PASS: TestE42ParserRefusalsAreAnnounced (0.57s)
  28 --- PASS: TestE43ParserGateLetsWellFormedRequestsThrough (0.02s)
   1 --- PASS: TestE43ParserGateLetsWellFormedRequestsThrough (0.06s)
   1 --- PASS: TestE43ParserGateLetsWellFormedRequestsThrough (0.07s)
  28 --- PASS: TestE44RequestsPastTheParserGateAreInspected (0.01s)
   2 --- PASS: TestE44RequestsPastTheParserGateAreInspected (0.03s)
  28 --- PASS: TestE46FramingChecksSeeLinesEndedByBareLF (0.01s)
   1 --- PASS: TestE46FramingChecksSeeLinesEndedByBareLF (0.02s)
   1 --- PASS: TestE46FramingChecksSeeLinesEndedByBareLF (0.04s)
  28 --- PASS: TestE47BareLFWithoutFramingProblemIsStillForwarded (0.01s)
   1 --- PASS: TestE47BareLFWithoutFramingProblemIsStillForwarded (0.02s)
   1 --- PASS: TestE47BareLFWithoutFramingProblemIsStillForwarded (0.04s)
  29 --- PASS: TestE48SecondRequestOnAConnectionIsNeverServed (0.01s)
   1 --- PASS: TestE48SecondRequestOnAConnectionIsNeverServed (0.02s)
   1 ok  	kortexshield/engine	18.168s
   1 PASS
# exit status of go test: 0
```

Go suite after T2: docs/logs/step24-t2-go-test.log, 62 PASS, 0 FAIL, 5 SKIP
(`ok kortexshield/engine 64.385s`).

What `OPTIONS *` does on the fixed engine (DIAGNOSTIC, hand-written
requests, local engine): still answered 200 by net/http, uninspected, no
event, not forwarded; the connection is now closed after it, so the second
request is not read.

```
# step-24 DIAGNOSTIC: what the step-24 engine does with OPTIONS * (hand-written requests over a raw socket to the local engine)
== 2026-11-28T05:29:33Z git 7316418f19c96c006f10dd74f283f46084a88306
== engine binary sha256 3aef01688c82106ba2ffc1839ec86bc2a0f4ffe55fa4e5404d82b4593596cc79 built from 7316418f19c96c006f10dd74f283f46084a88306 with go version go1.27.4 darwin/arm64
== options-asterisk: 70 request bytes; responses on the connection: 1; status line 'HTTP/1.1 200 OK'; headers ['Content-Length: 0', 'Date: Sat, 28 Nov 2026 05:29:34 GMT', 'Connection: close']; body b''
== options-asterisk with an XSS payload in a header: 102 request bytes; responses on the connection: 1; status line 'HTTP/1.1 200 OK'; headers ['Content-Length: 0', 'Date: Sat, 28 Nov 2026 05:29:34 GMT', 'Connection: close']; body b''
== control: the same header on GET /: 98 request bytes; responses on the connection: 1; status line 'HTTP/1.1 403 Forbidden'; headers ['Date: Sat, 28 Nov 2026 05:29:34 GMT', 'Content-Length: 480', 'Content-Type: text/plain; charset=utf-8', 'Connection: close']; body b'403 kortex-decision=block rules=900000,900001,900110,900990,'
== options-asterisk followed by GET /second on the same connection: 142 request bytes; responses on the connection: 1; status line 'HTTP/1.1 200 OK'; headers ['Content-Length: 0', 'Date: Sat, 28 Nov 2026 05:29:34 GMT', 'Connection: close']; body b''
== engine events, by sample id:
   : decision pass, status 0, reason forwarding
   optstar-3: decision block, status 403, reason rules=900000,900001,900110,900990,900200,901111,901115,901130,901140,901141,901142,901143,901162,901168,901163,901164,901165,901171,901510,901167,901169,901170,901180,901200,901340,901400,911013,913013,920013,921013,930013,931013,932013,933013,934013,941010,941013,942013,943013,94 [cut]
== engine stats at end: {"inflight_small":0,"inflight_large":0,"abandoned_running":0,"kills":0,"overloads":0,"refused_before_inspection":0,"penalised_clients":0,"client_inflight_small":0,"client_inflight_large":0,"workers":{"pool":0,"busy":0,"spares":0,"recycled":0}}
```

## T3. The parsing differential on the fixed engine

The same 61 hand-written cases and the same two local backends as step 23
(rule 6: local only; rule 35: chosen cases, counts only).

```
# Step-24: strict-parsing differential, first slice (the 61 cases of step-23 T5)
== 2026-11-28T04:53:19Z, macOS 27.0 Darwin 27.0.0 arm64, go version go1.27.4 darwin/arm64, Python 3.15.2, system python3 for the backend: Python 3.15.2
== git 95208d9a2fa969d362b2da219acd509ed2734421, tracked paths changed in the working tree: 0
== coraza module of engine/: github.com/corazawaf/coraza/v3 v3.8.1 => ./third_party/coraza-v3.8.1-kortex
== engine binary sha256 3aef01688c82106ba2ffc1839ec86bc2a0f4ffe55fa4e5404d82b4593596cc79 built from 95208d9a2fa969d362b2da219acd509ed2734421 with go version go1.27.4 darwin/arm64
== go backend binary sha256 00a0d73fcaa31838886a0ee6cf6c519aedda2564169758d157702e3943cbd5aa
== python backend answers: {"backend": "python-http.server", "method": "GET", "target": "/ping", "path_raw"
== go backend answers:     {"backend":"go-net/http","method":"GET","target":"/ping","path_raw":"/ping","pat
== cases: 61 hand-written requests; content-length 19, overlong 11, percent 14, transfer-encoding 17
== engine decision per family (engine in front of the Python backend / in front of the Go backend)
   content-length [python]: 400 framing 14, forwarded 5
   content-length [go]: 400 framing 14, forwarded 5
   overlong [python]: 403 block 9, forwarded 2
   overlong [go]: 403 block 9, forwarded 2
   percent [python]: 400 framing 3, 403 block 7, forwarded 4
   percent [go]: 400 framing 3, 403 block 7, forwarded 4
   transfer-encoding [python]: 400 framing 12, 503 timeout 2, forwarded 3
   transfer-encoding [go]: 400 framing 12, 503 timeout 2, forwarded 3
== the engine decided the same in front of both backends in 61 of 61 cases
== who decided in the engine (python-backed run)
   engine 503 timeout (event) 2, forwarded 14, framing gate (400, event) 29, rule block (403, event) 16
   refused by the engine's HTTP parser without a kortex marker and without an event: 0: 
   framing answers: 29; framing events by reason: conflicting-content-length 4, duplicate-content-length 1, parser:content-length 8, parser:header-name 1, parser:request-target 3, parser:transfer-encoding 5, transfer-encoding-with-content-length 7; framing answers without a framing event: 0
== each backend given the same bytes directly
   python: accepts 61 of 61; statuses {'200': 61}; accepted with bytes left on the connection 26
   go: accepts 37 of 61; statuses {'200': 37, '400': 17, '501': 7}; accepted with bytes left on the connection 3
== the two backends, given the same bytes directly, differ from EACH OTHER (one refuses, or they read a different body) in 31 of 61 cases; the engine refuses 28 of them and forwards 3 with its own framing: te-control, te-case, te-chunk-ext
== canary cases: 9; forwarded by the engine: 0; blocked 403: 9
== log-only events of the engine (python-backed run), by reason
   invalid-percent-sequence-in-query 3
== engine stats at end (python-backed): {"inflight_small":0,"inflight_large":0,"abandoned_running":0,"kills":0,"overloads":0,"refused_before_inspection":0,"penalised_clients":0,"client_inflight_small":0,"client_inflight_large":0,"workers":{"pool":0,"busy":0,"spares":0,"recycled":0}}
== engine stats at end (go-backed):     {"inflight_small":0,"inflight_large":0,"abandoned_running":0,"kills":0,"overloads":0,"refused_before_inspection":0,"penalised_clients":0,"client_inflight_small":0,"client_inflight_large":0,"workers":{"pool":0,"busy":0,"spares":0,"recycled":0}}
== engine vs python backend: 50 of 61 cases disagree; agree 11; by class: engine-refuses-backend-accepts 47, view-differs 3
== engine vs go backend: 23 of 61 cases disagree; agree 38; by class: engine-refuses-backend-accepts 23
```

Per case against the step-23 run (python-backed engine; the go-backed
engine changed in the same 17 cases the same way):

```
# step-24 T3: the 61 parsing-differential cases, step-23 engine (c2b069b) against the step-24 engine (95208d9), case by case
# .venv/bin/python tools/step24_parsing_compare.py docs/logs/runs/s23-parsing-diff/results.jsonl docs/logs/runs/s24-parsing-diff/results.jsonl
== cases in both runs: 61; in one run only: 0
== engine in front of the python backend: answer changed in 17 of 61 cases, unchanged in 44
   12 x  400 no marker  ->  400 kortex-decision=framing
   5 x  501 no marker  ->  400 kortex-decision=framing
== disagreement classes against the python backend changed in 0 of 61 cases
== engine in front of the go backend: answer changed in 17 of 61 cases, unchanged in 44
   12 x  400 no marker  ->  400 kortex-decision=framing
   5 x  501 no marker  ->  400 kortex-decision=framing
== disagreement classes against the go backend changed in 0 of 61 cases
== before: refused with no kortex marker: 17: cl-empty, cl-hex, cl-list-conflict, cl-list-same, cl-negative, cl-non-numeric, cl-plus, cl-space-before-colon, cl-underscore, pct-path-bare, pct-path-nonhex, pct-path-short, te-dup, te-dup-identity, te-gzip-chunked, te-list-identity, te-xchunked
== after: refused with no kortex marker: 0
```

The 17 cases:

```
   cl-list-same: 400 no marker, no event  ->  400 kortex-decision=framing, event parser:content-length
   cl-list-conflict: 400 no marker, no event  ->  400 kortex-decision=framing, event parser:content-length
   cl-plus: 400 no marker, no event  ->  400 kortex-decision=framing, event parser:content-length
   cl-hex: 400 no marker, no event  ->  400 kortex-decision=framing, event parser:content-length
   cl-negative: 400 no marker, no event  ->  400 kortex-decision=framing, event parser:content-length
   cl-empty: 400 no marker, no event  ->  400 kortex-decision=framing, event parser:content-length
   cl-non-numeric: 400 no marker, no event  ->  400 kortex-decision=framing, event parser:content-length
   cl-underscore: 400 no marker, no event  ->  400 kortex-decision=framing, event parser:content-length
   cl-space-before-colon: 400 no marker, no event  ->  400 kortex-decision=framing, event parser:header-name
   te-dup: 501 no marker, no event  ->  400 kortex-decision=framing, event parser:transfer-encoding
   te-dup-identity: 501 no marker, no event  ->  400 kortex-decision=framing, event parser:transfer-encoding
   te-list-identity: 501 no marker, no event  ->  400 kortex-decision=framing, event parser:transfer-encoding
   te-gzip-chunked: 501 no marker, no event  ->  400 kortex-decision=framing, event parser:transfer-encoding
   te-xchunked: 501 no marker, no event  ->  400 kortex-decision=framing, event parser:transfer-encoding
   pct-path-short: 400 no marker, no event  ->  400 kortex-decision=framing, event parser:request-target
   pct-path-nonhex: 400 no marker, no event  ->  400 kortex-decision=framing, event parser:request-target
   pct-path-bare: 400 no marker, no event  ->  400 kortex-decision=framing, event parser:request-target
```

- Before: engine forwards 14, framing gate 12, rule block 16, body-read 503
  2, parser 17 unannounced. After: forwards 14, framing gate 29, rule block
  16, body-read 503 2, unannounced 0. 29 framing answers, 29 framing events.
- Disagreements with the backends are unchanged: Python backend 50 of 61
  (47 engine refuses, 3 re-framed), Go backend 23 (all engine refuses);
  0 canaries of 9 reach a backend.
- The new shapes of this step (bare LF, connection reuse, Host, version,
  Expect, header count) are NOT MEASURED in the differential against real
  backends; they are tested on the engine by E42, E46 and E48.

## T4. Our own datasets on the step-24 engine

Plan committed before the runs (docs/plan-step24-own-datasets.md, 40e4519).
First engine runs of these datasets with Host `localhost`. "attack" means
"listed under this family in the public source", not "verified exploitable"
(rule 11).

```
# Step-24 T4: own datasets, patched engine
== 2026-11-28T04:57:49Z, macOS 27.0 Darwin 27.0.0 arm64, go version go1.27.4 darwin/arm64, Python 3.15.2, load at start: load averages: 4.88 3.55 2.84
== git 40e451981abc7ec16b5dd12b99fb278b2b570ebf, tracked paths changed in the working tree: 0
== manifest data/attacks-v0/manifest.jsonl sha256 5b6a844d9521082428725b6de6b8921a6c0bdc8606e362b5046af633d4fa8540 (frozen: 5b6a844d9521082428725b6de6b8921a6c0bdc8606e362b5046af633d4fa8540), 1054 requests
== manifest data/attacks-ct-v0/manifest.jsonl sha256 69d0447c5b33ca63e37c2993e8c7e87add2a16d56dd89201978883905f923251 (frozen: 69d0447c5b33ca63e37c2993e8c7e87add2a16d56dd89201978883905f923251), 320 requests
== manifest data/encoding-diff-v0/manifest.jsonl sha256 ff00384d33018f45d95bde0d3cfa2c0eab184c94558ec1d24e527baa6ea27e5c (frozen: ff00384d33018f45d95bde0d3cfa2c0eab184c94558ec1d24e527baa6ea27e5c), 192 requests
== manifest data/benign-browse-v1/manifest.jsonl sha256 950a683bf776ef637691514f1dab809fddd2de757bacdff3dc9cb1f30af3b085 (frozen: 950a683bf776ef637691514f1dab809fddd2de757bacdff3dc9cb1f30af3b085), 774 requests
== manifest data/benign-hard-v0/manifest.jsonl sha256 65bdfc69022c5b026815acacd033d1e005fadc9c2e7000745614bd903a01d78b (frozen: 65bdfc69022c5b026815acacd033d1e005fadc9c2e7000745614bd903a01d78b), 180 requests
== coraza module of engine/: github.com/corazawaf/coraza/v3 v3.8.1 => ./third_party/coraza-v3.8.1-kortex
vendor check: OK
== engine binary sha256 3aef01688c82106ba2ffc1839ec86bc2a0f4ffe55fa4e5404d82b4593596cc79 built from 40e451981abc7ec16b5dd12b99fb278b2b570ebf with go version go1.27.4 darwin/arm64
== load at end: load averages: 5.92 4.09 3.08
S24-OWN-main-DONE
```

Effective config of the first run (rule 29; all 20 runs of the main log print theirs):

```
== attacks-v0-inprocess-pl1 rule29 2026-11-28T04:57:50Z load: load averages: 4.88 3.55 2.84: {"backend_url":"http://127.0.0.1:13004","rule_engine":"On","blocking_paranoia":1,"detection_paranoia":1,"max_body_bytes":13107200,"max_inspected_bytes":131072,"engine_time_budget_ms":2000,"rules_dir":"/Users/ivan/work/kortex-shield-work/engine/crs","listen_addr":"127.0.0.1:8097","events_file":"/Users/ivan/work/kortex-shield-work/out/s22-s24-attacks-v0-inprocess-pl1.events.jsonl","audit_log":"/Users/ivan/work/kortex-shield-work/out/s22-s24-attacks-v0-inprocess-pl1.audit.log","allowed_methods":"GET HEAD POST OPTIONS","max_inflight_body":8,"max_inflight_body_large":2,"body_lane_threshold":65536,"worker_mode":false,"client_max_inflight":0,"client_max_inflight_small":4,"client_max_inflight_large":1,"request_body_target_updates":166}
[... 19 more lines of the same kind, in the log]
```

Tables (tools/step24_own_summary.py; in-process and worker lines are equal
in every cell):

```
# step-24 T4: own datasets on the step-24 engine, tables (runs: docs/logs/step24-own-datasets*.txt)
# 2026-11-28T05:00:02Z git 40e451981abc7ec16b5dd12b99fb278b2b570ebf
# .venv/bin/python tools/step24_own_summary.py docs/logs/runs/s24-own docs/logs/runs/s21-t3-parity

== PL1: rates and counts per run
attacks-v0-inprocess-pl1: requests 1054, distinct payloads 527; outcomes: waf_block 954, waf_pass 100
    recall best case (only waf_block) 954/1054 = 90.51%; worst case (every outcome that is not a pass) 954/1054 = 90.51%  [IN-SAMPLE for the REQUEST_BODY target choice of step 18]
    per family, blocked of requests: command-injection 224/300, path-traversal 298/300, sqli 132/154, xss 300/300
    rule 18: 954 audit entries; rule ids in >=20% of them: 949110=954, 930120=318, 941390=310, 941120=302, 941100=290, 941160=250, 930100=234
attacks-v0-worker-pl1: requests 1054, distinct payloads 527; outcomes: waf_block 954, waf_pass 100
    recall best case (only waf_block) 954/1054 = 90.51%; worst case (every outcome that is not a pass) 954/1054 = 90.51%  [IN-SAMPLE for the REQUEST_BODY target choice of step 18]
    per family, blocked of requests: command-injection 224/300, path-traversal 298/300, sqli 132/154, xss 300/300
    rule 18: 954 audit entries; rule ids in >=20% of them: 949110=954, 930120=318, 941390=310, 941120=302, 941100=290, 941160=250, 930100=234
attacks-ct-v0-inprocess-pl1: requests 320, distinct payloads 40; outcomes: waf_block 292, waf_pass 28
    recall best case (only waf_block) 292/320 = 91.25%; worst case (every outcome that is not a pass) 292/320 = 91.25%  [IN-SAMPLE for the REQUEST_BODY target choice of step 18]
    per family, blocked of requests: command-injection 59/80, path-traversal 80/80, sqli 73/80, xss 80/80
    rule 18: 292 audit entries; rule ids in >=20% of them: 949110=292, 941390=88, 941120=80, 930120=80, 942100=72, 941100=72, 930100=72, 941160=64
attacks-ct-v0-worker-pl1: requests 320, distinct payloads 40; outcomes: waf_block 292, waf_pass 28
    recall best case (only waf_block) 292/320 = 91.25%; worst case (every outcome that is not a pass) 292/320 = 91.25%  [IN-SAMPLE for the REQUEST_BODY target choice of step 18]
    per family, blocked of requests: command-injection 59/80, path-traversal 80/80, sqli 73/80, xss 80/80
    rule 18: 292 audit entries; rule ids in >=20% of them: 949110=292, 941390=88, 941120=80, 930120=80, 942100=72, 941100=72, 930100=72, 941160=64
encoding-diff-v0-inprocess-pl1: requests 192, distinct payloads 16; outcomes: error 10, waf_block 137, waf_pass 45
    blocked 137 of 192; not passed 147 of 192 (chosen cases: counts, not a rate, rule 35)
    per family, blocked of requests: command-injection 24/48, path-traversal 40/48, sqli 37/48, xss 36/48
    rule 18: 137 audit entries; rule ids in >=20% of them: 949110=137, 930120=40, 942100=37, 941120=36, 941100=36, 941160=36, 930100=30
encoding-diff-v0-worker-pl1: requests 192, distinct payloads 16; outcomes: error 10, waf_block 137, waf_pass 45
    blocked 137 of 192; not passed 147 of 192 (chosen cases: counts, not a rate, rule 35)
    per family, blocked of requests: command-injection 24/48, path-traversal 40/48, sqli 37/48, xss 36/48
    rule 18: 137 audit entries; rule ids in >=20% of them: 949110=137, 930120=40, 942100=37, 941120=36, 941100=36, 941160=36, 930100=30
benign-browse-v1-inprocess-pl1: requests 774, distinct endpoints 313; outcomes: waf_block 124, waf_pass 650
    potential false positives (natural benign, held-out): best case (only waf_block) 124/774 = 16.02%; worst case (every outcome that is not a pass) 124/774 = 16.02%
    rule 18: 124 audit entries; rule ids in >=20% of them: 949110=124, 911100=120
benign-browse-v1-worker-pl1: requests 774, distinct endpoints 313; outcomes: waf_block 124, waf_pass 650
    potential false positives (natural benign, held-out): best case (only waf_block) 124/774 = 16.02%; worst case (every outcome that is not a pass) 124/774 = 16.02%
    rule 18: 124 audit entries; rule ids in >=20% of them: 949110=124, 911100=120
benign-hard-v0-inprocess-pl1: requests 180, distinct endpoints 2; outcomes: waf_block 22, waf_pass 158
    potential false positives (hard benign, held-out): best case (only waf_block) 22/180 = 12.22%; worst case (every outcome that is not a pass) 22/180 = 12.22%
    rule 18: 22 audit entries; rule ids in >=20% of them: 949110=22, 932260=10, 942100=6, 932235=6
benign-hard-v0-worker-pl1: requests 180, distinct endpoints 2; outcomes: waf_block 22, waf_pass 158
    potential false positives (hard benign, held-out): best case (only waf_block) 22/180 = 12.22%; worst case (every outcome that is not a pass) 22/180 = 12.22%
    rule 18: 22 audit entries; rule ids in >=20% of them: 949110=22, 932260=10, 942100=6, 932235=6

== PL2: rates and counts per run
attacks-v0-inprocess-pl2: requests 1054, distinct payloads 527; outcomes: waf_block 1024, waf_pass 30
    recall best case (only waf_block) 1024/1054 = 97.15%; worst case (every outcome that is not a pass) 1024/1054 = 97.15%  [IN-SAMPLE for the REQUEST_BODY target choice of step 18]
    per family, blocked of requests: command-injection 276/300, path-traversal 300/300, sqli 148/154, xss 300/300
    rule 18: 1024 audit entries; rule ids in >=20% of them: 949110=1024, 930120=318, 941390=310, 941120=302, 942370=294, 941100=290, 942520=278, 941160=250, 932236=248, 941320=244, 930100=234
attacks-v0-worker-pl2: requests 1054, distinct payloads 527; outcomes: waf_block 1024, waf_pass 30
    recall best case (only waf_block) 1024/1054 = 97.15%; worst case (every outcome that is not a pass) 1024/1054 = 97.15%  [IN-SAMPLE for the REQUEST_BODY target choice of step 18]
    per family, blocked of requests: command-injection 276/300, path-traversal 300/300, sqli 148/154, xss 300/300
    rule 18: 1024 audit entries; rule ids in >=20% of them: 949110=1024, 930120=318, 941390=310, 941120=302, 942370=294, 941100=290, 942520=278, 941160=250, 932236=248, 941320=244, 930100=234
attacks-ct-v0-inprocess-pl2: requests 320, distinct payloads 40; outcomes: waf_block 313, waf_pass 7
    recall best case (only waf_block) 313/320 = 97.81%; worst case (every outcome that is not a pass) 313/320 = 97.81%  [IN-SAMPLE for the REQUEST_BODY target choice of step 18]
    per family, blocked of requests: command-injection 73/80, path-traversal 80/80, sqli 80/80, xss 80/80
    rule 18: 313 audit entries; rule ids in >=20% of them: 949110=313, 942520=128, 942370=104, 941390=88, 932240=80, 941120=80, 941320=80, 930120=80, 942430=73, 942100=72, 941100=72, 930100=72, 942180=64, 941160=64
attacks-ct-v0-worker-pl2: requests 320, distinct payloads 40; outcomes: waf_block 313, waf_pass 7
    recall best case (only waf_block) 313/320 = 97.81%; worst case (every outcome that is not a pass) 313/320 = 97.81%  [IN-SAMPLE for the REQUEST_BODY target choice of step 18]
    per family, blocked of requests: command-injection 73/80, path-traversal 80/80, sqli 80/80, xss 80/80
    rule 18: 313 audit entries; rule ids in >=20% of them: 949110=313, 942520=128, 942370=104, 941390=88, 932240=80, 941120=80, 941320=80, 930120=80, 942430=73, 942100=72, 941100=72, 930100=72, 942180=64, 941160=64
encoding-diff-v0-inprocess-pl2: requests 192, distinct payloads 16; outcomes: error 10, waf_block 147, waf_pass 35
    blocked 147 of 192; not passed 157 of 192 (chosen cases: counts, not a rate, rule 35)
    per family, blocked of requests: command-injection 34/48, path-traversal 40/48, sqli 37/48, xss 36/48
    rule 18: 147 audit entries; rule ids in >=20% of them: 949110=147, 942520=73, 942430=60, 942370=54, 920230=41, 930120=40, 942100=37, 942180=36, 941120=36, 941100=36, 941160=36, 930100=30
encoding-diff-v0-worker-pl2: requests 192, distinct payloads 16; outcomes: error 10, waf_block 147, waf_pass 35
    blocked 147 of 192; not passed 157 of 192 (chosen cases: counts, not a rate, rule 35)
    per family, blocked of requests: command-injection 34/48, path-traversal 40/48, sqli 37/48, xss 36/48
    rule 18: 147 audit entries; rule ids in >=20% of them: 949110=147, 942520=73, 942430=60, 942370=54, 920230=41, 930120=40, 942100=37, 942180=36, 941120=36, 941100=36, 941160=36, 930100=30
benign-browse-v1-inprocess-pl2: requests 774, distinct endpoints 313; outcomes: waf_block 124, waf_pass 650
    potential false positives (natural benign, held-out): best case (only waf_block) 124/774 = 16.02%; worst case (every outcome that is not a pass) 124/774 = 16.02%
    rule 18: 124 audit entries; rule ids in >=20% of them: 949110=124, 911100=120
benign-browse-v1-worker-pl2: requests 774, distinct endpoints 313; outcomes: waf_block 124, waf_pass 650
    potential false positives (natural benign, held-out): best case (only waf_block) 124/774 = 16.02%; worst case (every outcome that is not a pass) 124/774 = 16.02%
    rule 18: 124 audit entries; rule ids in >=20% of them: 949110=124, 911100=120
benign-hard-v0-inprocess-pl2: requests 180, distinct endpoints 2; outcomes: waf_block 78, waf_pass 102
    potential false positives (hard benign, held-out): best case (only waf_block) 78/180 = 43.33%; worst case (every outcome that is not a pass) 78/180 = 43.33%
    rule 18: 78 audit entries; rule ids in >=20% of them: 949110=78, 932236=34, 931130=16
benign-hard-v0-worker-pl2: requests 180, distinct endpoints 2; outcomes: waf_block 78, waf_pass 102
    potential false positives (hard benign, held-out): best case (only waf_block) 78/180 = 43.33%; worst case (every outcome that is not a pass) 78/180 = 43.33%
    rule 18: 78 audit entries; rule ids in >=20% of them: 949110=78, 932236=34, 931130=16
```

Key numbers:

| dataset | requests / distinct | PL1 | PL2 |
|---|---|---|---|
| attacks-v0 (IN-SAMPLE for the REQUEST_BODY target choice) | 1,054 / 527 payloads | recall best case 954/1,054 = 90.51%, worst case the same | 1,024/1,054 = 97.15% |
| attacks-ct-v0 (IN-SAMPLE, same choice) | 320 / 40 payloads | 292/320 = 91.25% | 313/320 = 97.81% |
| encoding-diff-v0 (counts only, rule 35) | 192 / 16 payloads | blocked 137, never sent 10, passed 45 | blocked 147, never sent 10, passed 35 |
| benign-browse-v1 (natural, held-out) | 774 / 313 endpoints | potential false positives 124/774 = 16.02% best and worst case | 124/774 = 16.02% |
| benign-hard-v0 (hard, held-out) | 180 / 2 endpoints | 22/180 = 12.22% | 78/180 = 43.33% |

- No deny_status, inconsistent or fail-closed outcome, and no framing
  event, in any of the 20 runs (rule 30: all zero). The 10 errors of
  encoding-diff-v0 are requests the Python client refuses to build
  (`InvalidURL`, a raw space in the query): never sent, the same 10 ids as
  in step 21.
- Rule 18/24: benign-browse-v1, 911100 in 120 of 124 audit entries at both
  levels; the 120 are the dataset's 90 PUT and 30 DELETE requests and the
  engine allows GET HEAD POST OPTIONS: CONFIG-MISMATCH. The other 4 blocks
  are GET requests with 932260 (PL1) or 932236, 932239, 932260 (PL2).
- Natural and hard benign inputs are reported apart (rule 14).

Parity per sample id and the two DIAGNOSTIC comparisons (per-id lines of
the numeric-Host run, which only list the added 920350, are in the log):

```
== parity per sample id: in-process against worker (patched engine)
attacks-v0 PL1
    in-process against worker: 1054 sample ids; status differs in 0; worst-case set differs in 0; rule-id set differs in 0
attacks-ct-v0 PL1
    in-process against worker: 320 sample ids; status differs in 0; worst-case set differs in 0; rule-id set differs in 0
encoding-diff-v0 PL1
    in-process against worker: 192 sample ids; status differs in 0; worst-case set differs in 0; rule-id set differs in 0
benign-browse-v1 PL1
    in-process against worker: 774 sample ids; status differs in 0; worst-case set differs in 0; rule-id set differs in 0
benign-hard-v0 PL1
    in-process against worker: 180 sample ids; status differs in 0; worst-case set differs in 0; rule-id set differs in 0
attacks-v0 PL2
    in-process against worker: 1054 sample ids; status differs in 0; worst-case set differs in 0; rule-id set differs in 0
attacks-ct-v0 PL2
    in-process against worker: 320 sample ids; status differs in 0; worst-case set differs in 0; rule-id set differs in 0
encoding-diff-v0 PL2
    in-process against worker: 192 sample ids; status differs in 0; worst-case set differs in 0; rule-id set differs in 0
benign-browse-v1 PL2
    in-process against worker: 774 sample ids; status differs in 0; worst-case set differs in 0; rule-id set differs in 0
benign-hard-v0 PL2
    in-process against worker: 180 sample ids; status differs in 0; worst-case set differs in 0; rule-id set differs in 0

== DIAGNOSTIC stock coraza v3.8.1 (same commit, replace dropped), in-process: counts, then per sample id against the patched in-process run
attacks-v0-inprocess-pl1-DIAGNOSTIC-stock: requests 1054, distinct payloads 527; outcomes: waf_block 954, waf_pass 100
    patched against stock: 1054 sample ids; status differs in 0; worst-case set differs in 0; rule-id set differs in 0
attacks-ct-v0-inprocess-pl1-DIAGNOSTIC-stock: requests 320, distinct payloads 40; outcomes: waf_block 292, waf_pass 28
    patched against stock: 320 sample ids; status differs in 0; worst-case set differs in 0; rule-id set differs in 0
encoding-diff-v0-inprocess-pl1-DIAGNOSTIC-stock: requests 192, distinct payloads 16; outcomes: error 10, waf_block 137, waf_pass 45
    patched against stock: 192 sample ids; status differs in 0; worst-case set differs in 0; rule-id set differs in 0
benign-browse-v1-inprocess-pl1-DIAGNOSTIC-stock: requests 774, distinct endpoints 313; outcomes: waf_block 124, waf_pass 650
    patched against stock: 774 sample ids; status differs in 0; worst-case set differs in 0; rule-id set differs in 0
benign-hard-v0-inprocess-pl1-DIAGNOSTIC-stock: requests 180, distinct endpoints 2; outcomes: waf_block 22, waf_pass 158
    patched against stock: 180 sample ids; status differs in 0; worst-case set differs in 0; rule-id set differs in 0
attacks-v0-inprocess-pl2-DIAGNOSTIC-stock: requests 1054, distinct payloads 527; outcomes: waf_block 1024, waf_pass 30
    patched against stock: 1054 sample ids; status differs in 0; worst-case set differs in 0; rule-id set differs in 0
attacks-ct-v0-inprocess-pl2-DIAGNOSTIC-stock: requests 320, distinct payloads 40; outcomes: waf_block 313, waf_pass 7
    patched against stock: 320 sample ids; status differs in 0; worst-case set differs in 0; rule-id set differs in 0
encoding-diff-v0-inprocess-pl2-DIAGNOSTIC-stock: requests 192, distinct payloads 16; outcomes: error 10, waf_block 147, waf_pass 35
    patched against stock: 192 sample ids; status differs in 0; worst-case set differs in 0; rule-id set differs in 0
benign-browse-v1-inprocess-pl2-DIAGNOSTIC-stock: requests 774, distinct endpoints 313; outcomes: waf_block 124, waf_pass 650
    patched against stock: 774 sample ids; status differs in 0; worst-case set differs in 0; rule-id set differs in 0
benign-hard-v0-inprocess-pl2-DIAGNOSTIC-stock: requests 180, distinct endpoints 2; outcomes: waf_block 78, waf_pass 102
    patched against stock: 180 sample ids; status differs in 0; worst-case set differs in 0; rule-id set differs in 0

== DIAGNOSTIC numeric Host (requests to 127.0.0.1), patched engine, in-process, PL1: counts, then per sample id against the Host-localhost run
attacks-v0-inprocess-pl1-DIAGNOSTIC-numeric-host: requests 1054, distinct payloads 527; outcomes: waf_block 954, waf_pass 100
    Host localhost: audit entries 954, with rule 920350 (numeric Host): 0
    Host 127.0.0.1: audit entries 954, with rule 920350 (numeric Host): 954
    localhost against numeric: 1054 sample ids; status differs in 0; worst-case set differs in 0; rule-id set differs in 954
      ... and 914 more ids (all in the run files)
    step-21 run (stock coraza, 127.0.0.1) against today's numeric-Host run: status differs in 0 of 1054 sample ids
    step-21 run (stock coraza, 127.0.0.1) against today's Host-localhost run: status differs in 0 of 1054 sample ids
attacks-ct-v0-inprocess-pl1-DIAGNOSTIC-numeric-host: requests 320, distinct payloads 40; outcomes: waf_block 292, waf_pass 28
    Host localhost: audit entries 292, with rule 920350 (numeric Host): 0
    Host 127.0.0.1: audit entries 292, with rule 920350 (numeric Host): 292
    localhost against numeric: 320 sample ids; status differs in 0; worst-case set differs in 0; rule-id set differs in 292
      ... and 252 more ids (all in the run files)
    step-21 run (stock coraza, 127.0.0.1) against today's numeric-Host run: status differs in 0 of 320 sample ids
    step-21 run (stock coraza, 127.0.0.1) against today's Host-localhost run: status differs in 0 of 320 sample ids
encoding-diff-v0-inprocess-pl1-DIAGNOSTIC-numeric-host: requests 192, distinct payloads 16; outcomes: error 10, waf_block 137, waf_pass 45
    Host localhost: audit entries 137, with rule 920350 (numeric Host): 0
    Host 127.0.0.1: audit entries 137, with rule 920350 (numeric Host): 137
    localhost against numeric: 192 sample ids; status differs in 0; worst-case set differs in 0; rule-id set differs in 137
      ... and 97 more ids (all in the run files)
    step-21 run (stock coraza, 127.0.0.1) against today's numeric-Host run: status differs in 0 of 192 sample ids
    step-21 run (stock coraza, 127.0.0.1) against today's Host-localhost run: status differs in 0 of 192 sample ids
benign-browse-v1-inprocess-pl1-DIAGNOSTIC-numeric-host: requests 774, distinct endpoints 313; outcomes: waf_block 124, waf_pass 650
    Host localhost: audit entries 124, with rule 920350 (numeric Host): 0
    Host 127.0.0.1: audit entries 124, with rule 920350 (numeric Host): 124
    localhost against numeric: 774 sample ids; status differs in 0; worst-case set differs in 0; rule-id set differs in 124
      ... and 84 more ids (all in the run files)
    step-21 run (stock coraza, 127.0.0.1) against today's numeric-Host run: status differs in 0 of 774 sample ids
    step-21 run (stock coraza, 127.0.0.1) against today's Host-localhost run: status differs in 0 of 774 sample ids
benign-hard-v0-inprocess-pl1-DIAGNOSTIC-numeric-host: requests 180, distinct endpoints 2; outcomes: waf_block 22, waf_pass 158
    Host localhost: audit entries 22, with rule 920350 (numeric Host): 0
    Host 127.0.0.1: audit entries 22, with rule 920350 (numeric Host): 22
    localhost against numeric: 180 sample ids; status differs in 0; worst-case set differs in 0; rule-id set differs in 22
    step-21 run (stock coraza, 127.0.0.1) against today's numeric-Host run: status differs in 0 of 180 sample ids
    step-21 run (stock coraza, 127.0.0.1) against today's Host-localhost run: status differs in 0 of 180 sample ids
```

DIAGNOSTIC stock build (rule 34: no baseline, no parity number):

```
# Step-24 T4: own datasets, DIAGNOSTIC stock coraza v3.8.1
== git 40e451981abc7ec16b5dd12b99fb278b2b570ebf, tracked paths changed in the working tree: 2
== DIAGNOSTIC scratch engine coraza module: github.com/corazawaf/coraza/v3 v3.8.1
== DIAGNOSTIC scratch engine sha256 593897353c3559564bf6c8b55f23d852fde2a43112df65c30750cd04322a25c4; files that differ from engine/ other than go.mod, go.sum and third_party: 0; diff of go.mod against engine/go.mod:
< 
< replace github.com/corazawaf/coraza/v3 => ./third_party/coraza-v3.8.1-kortex
```

- In-process against worker, 5,040 pairs: 0 status, 0 worst-case-set, 0
  rule-id-set differences.
- Patched against stock coraza v3.8.1 (DIAGNOSTIC, one replay each), 5,040
  pairs: 0 status, 0 worst-case-set, 0 rule-id-set differences. The plan's
  20-fold replay of differing samples was not needed: none differed.
- Numeric Host at PL1 (DIAGNOSTIC): 920350 in every audit entry, in none
  with Host localhost, and 0 status differences in 2,520 requests. Against
  the step-21 runs (stock coraza, 127.0.0.1): 0 status differences in
  2,520 on either Host. So the step-21 counts stand at PL1. PL2 with a
  numeric Host: NOT MEASURED.

## T5. The wcp datasets as a check on the gate change

The step-23 script, run for step 24 (`PARITY_STEP=24`), compared per sample
with the step-23 runs.

```
# Step-24: in-process and worker-mode runs of the wcp datasets, PL1 and PL2
== 2026-11-28T05:00:43Z, macOS 27.0 Darwin 27.0.0 arm64, go version go1.27.4 darwin/arm64, Python 3.15.2, load at start: load averages: 4.09 3.96 3.16
== git 50dcb274403d55fe905f92e1cc863c0be49115e2, tracked paths changed in the working tree: 0
== coraza module of engine/: github.com/corazawaf/coraza/v3 v3.8.1 => ./third_party/coraza-v3.8.1-kortex
vendor check: OK
== manifest /Users/ivan/work/kortex-shield-dev/data/benign-wcp-v0/manifest.jsonl sha256 c8ce11f26406df96d55e5a1cc6186bcbf648cb29bd628081dd834c6ccf1329d1 (frozen: c8ce11f26406df96d55e5a1cc6186bcbf648cb29bd628081dd834c6ccf1329d1)
== manifest /Users/ivan/work/kortex-shield-dev/data/benign-wcp-v1/manifest.jsonl sha256 049b7dea33aac475c4ef7f05c8644da610ad311a84862ef3b88d33a37dc8b5c0 (frozen: 049b7dea33aac475c4ef7f05c8644da610ad311a84862ef3b88d33a37dc8b5c0)
== engine binary sha256 3aef01688c82106ba2ffc1839ec86bc2a0f4ffe55fa4e5404d82b4593596cc79 built from 50dcb274403d55fe905f92e1cc863c0be49115e2 with go version go1.27.4 darwin/arm64
== benign-wcp-v0-inprocess-pl1 events: 20015 events {'block': 2236, 'content-encoding': 19, 'limit': 28, 'pass': 17717, 'would_reject': 15}; compressed-body events 14 {'zlib': 14}; framing events 0 {}; kept 62
== benign-wcp-v0-worker-pl1 events: 20015 events {'block': 2236, 'content-encoding': 19, 'limit': 28, 'pass': 17717, 'would_reject': 15}; compressed-body events 14 {'zlib': 14}; framing events 0 {}; kept 62
== diff benign-wcp-v0 PL1 (a=inprocess b=worker):
status diffs: 0
worst-case set a: 2284/20000 (error=1 blocked=2184 deny_status=52 inconsistent=0 fail_closed_413=28 fail_closed_415=19 fail_closed_400=0 fail_closed_503_timeout=0 fail_closed_503_overload=0)
worst-case set b: 2284/20000 (error=1 blocked=2184 deny_status=52 inconsistent=0 fail_closed_413=28 fail_closed_415=19 fail_closed_400=0 fail_closed_503_timeout=0 fail_closed_503_overload=0)
worst-case set diffs: 0 (only-a 0 only-b 0)
== benign-wcp-v1-inprocess-pl1 events: 10003 events {'block': 1116, 'limit': 17, 'pass': 8868, 'would_reject': 2}; compressed-body events 2 {'zlib': 2}; framing events 0 {}; kept 19
== benign-wcp-v1-worker-pl1 events: 10003 events {'block': 1116, 'limit': 17, 'pass': 8868, 'would_reject': 2}; compressed-body events 2 {'zlib': 2}; framing events 0 {}; kept 19
== diff benign-wcp-v1 PL1 (a=inprocess b=worker):
status diffs: 0
worst-case set a: 1133/10000 (error=0 blocked=1091 deny_status=25 inconsistent=0 fail_closed_413=17 fail_closed_415=0 fail_closed_400=0 fail_closed_503_timeout=0 fail_closed_503_overload=0)
worst-case set b: 1133/10000 (error=0 blocked=1091 deny_status=25 inconsistent=0 fail_closed_413=17 fail_closed_415=0 fail_closed_400=0 fail_closed_503_timeout=0 fail_closed_503_overload=0)
worst-case set diffs: 0 (only-a 0 only-b 0)
== benign-wcp-v0-inprocess-pl2 events: 20014 events {'block': 8919, 'content-encoding': 19, 'limit': 28, 'pass': 11034, 'would_reject': 14}; compressed-body events 14 {'zlib': 14}; framing events 0 {}; kept 61
== benign-wcp-v0-worker-pl2 events: 20014 events {'block': 8919, 'content-encoding': 19, 'limit': 28, 'pass': 11034, 'would_reject': 14}; compressed-body events 14 {'zlib': 14}; framing events 0 {}; kept 61
== diff benign-wcp-v0 PL2 (a=inprocess b=worker):
status diffs: 0
worst-case set a: 8967/20000 (error=1 blocked=8866 deny_status=52 inconsistent=1 fail_closed_413=28 fail_closed_415=19 fail_closed_400=0 fail_closed_503_timeout=0 fail_closed_503_overload=0)
worst-case set b: 8967/20000 (error=1 blocked=8866 deny_status=52 inconsistent=1 fail_closed_413=28 fail_closed_415=19 fail_closed_400=0 fail_closed_503_timeout=0 fail_closed_503_overload=0)
worst-case set diffs: 0 (only-a 0 only-b 0)
== benign-wcp-v1-inprocess-pl2 events: 10003 events {'block': 4463, 'limit': 17, 'pass': 5521, 'would_reject': 2}; compressed-body events 2 {'zlib': 2}; framing events 0 {}; kept 19
== benign-wcp-v1-worker-pl2 events: 10003 events {'block': 4463, 'limit': 17, 'pass': 5521, 'would_reject': 2}; compressed-body events 2 {'zlib': 2}; framing events 0 {}; kept 19
== diff benign-wcp-v1 PL2 (a=inprocess b=worker):
status diffs: 0
worst-case set a: 4480/10000 (error=0 blocked=4438 deny_status=25 inconsistent=0 fail_closed_413=17 fail_closed_415=0 fail_closed_400=0 fail_closed_503_timeout=0 fail_closed_503_overload=0)
worst-case set b: 4480/10000 (error=0 blocked=4438 deny_status=25 inconsistent=0 fail_closed_413=17 fail_closed_415=0 fail_closed_400=0 fail_closed_503_timeout=0 fail_closed_503_overload=0)
worst-case set diffs: 0 (only-a 0 only-b 0)
== load at end: load averages: 3.58 3.93 3.75
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
== per sample against the in-process runs under docs/logs/runs/s23-parity:
== step-23 (docs/logs/runs/s23-parity, in-process) against step-24 (docs/logs/runs/s24-parity, in-process), per sample
benign-wcp-v0 PL1: 20000 ids; status diffs 0; outcome diffs 0; rule-id set diffs 0
benign-wcp-v0 PL2: 20000 ids; status diffs 0; outcome diffs 0; rule-id set diffs 0
benign-wcp-v1 PL1: 10000 ids; status diffs 0; outcome diffs 0; rule-id set diffs 0
benign-wcp-v1 PL2: 10000 ids; status diffs 0; outcome diffs 0; rule-id set diffs 0
S24-PARITY-DONE
```

- Against step 23, 60,000 pairs: 0 status, 0 outcome, 0 rule-id-set
  differences. 0 framing events in all eight runs: the gate refuses none of
  the 30,000 requests.
- Worst case (headline, benign-labelled external traffic, every block a
  potential false positive): benign-wcp-v0 (IN-SAMPLE for the 921
  exclusion) 2,284/20,000 = 11.42% at PL1 and 8,967/20,000 = 44.84% at PL2;
  benign-wcp-v1 1,133/10,000 = 11.33% and 4,480/10,000 = 44.80%. Best case
  2,184, 8,866, 1,091, 4,438. Errors 1 (v0), deny_status 52 / 25,
  inconsistent 0 / 1 (v0 PL2), fail-closed 413 28 / 17, 415 19 / 0, 400 and
  503 0.
- In-process against worker, 60,000 pairs: 0 status, 0 worst-case-set, 0
  rule-id-set differences.

## Final suites

```
# step-24 final Go suite at 7316418f19c96c006f10dd74f283f46084a88306 (paths changed under engine/: 0), 2026-11-28T05:20:55Z, go version go1.27.4 darwin/arm64, github.com/corazawaf/coraza/v3 v3.8.1 => ./third_party/coraza-v3.8.1-kortex, load at start: load averages: 3.79 3.97 3.76
$ cd engine && GOPROXY=off go test -buildvcs=false -count=1 -v ./...
PASS
ok  	kortexshield/engine	66.028s
# exit status of go test: 0
# load at end: load averages: 4.86 4.24 3.88

# step-24 final Go suite with the fixture body at 7316418f19c96c006f10dd74f283f46084a88306 (paths changed under engine/: 0), 2026-11-28T05:22:01Z, go version go1.27.4 darwin/arm64, github.com/corazawaf/coraza/v3 v3.8.1 => ./third_party/coraza-v3.8.1-kortex, load at start: load averages: 4.86 4.24 3.88
$ cd engine && KORTEX_TEST_WCP_BODY=<first checkout>/out/step14-t5/wcp-80a49c991b2d.body GOPROXY=off go test -buildvcs=false -count=1 -timeout 900s -v ./...
--- PASS: TestE20OverloadRecovery (269.68s)
PASS
ok  	kortexshield/engine	341.920s
# exit status of go test: 0
# load at end: load averages: 6.25 6.44 5.15

# step-24 final pytest at 7316418f19c96c006f10dd74f283f46084a88306, 2026-11-28T05:27:43Z, Python 3.15.2
$ .venv/bin/python -m pytest -q
.............................................................ss..s...... [ 29%]
........................................................................ [ 58%]
........................................................................ [ 88%]
.............................                                            [100%]
242 passed, 4 skipped in 59.27s
# exit status of pytest: 0
```

Commits of this step (local, not pushed):

```
7316418 step-24: T5 wcp datasets on the step-24 engine, in-process and worker, PL1 and PL2 - against the step-23 runs 0 status, 0 outcome and 0 rule-i [cut]
50dcb27 step-24: T5 tooling - the wcp parity script names its step and the earlier runs it compares with (PARITY_STEP, PARITY_REF), so a re-run keeps  [cut]
3c51a4c step-24: T4 own datasets on the step-24 engine, Host localhost - attacks-v0 blocked 954 of 1054 at PL1 and 1024 at PL2, attacks-ct-v0 292 and  [cut]
40e4519 step-24: T4 plan and tooling - our own five datasets on the step-24 engine (plan written before any run): 20 main runs (PL1, PL2, in-process,  [cut]
8dec3c0 step-24: T3 parsing differential on the fixed engine - the same 61 cases: 0 refused without a kortex marker (step 23: 17), 29 framing answers  [cut]
95208d9 step-24: T3 tooling - the parsing differential names its step (PARSING_STEP) and its summary counts framing events by reason and names framing [cut]
40c57ad step-24: T2 fix E46, E48 - the framing checks are repeated on the header block as Go's MIME reader returns it, so a Content-Length or Transfer [cut]
5cd6fc2 step-24: T2 failing tests E46, E48 and design note - two holes in the framing gate found while building T1: a header line after a bare LF is i [cut]
a9dad86 step-24: T1 fix E42 - the gate runs Go's own request parser and the checks net/http makes before a handler on the head it holds, and refuses w [cut]
323ed49 step-24: T1 failing test E42 and design note - a request that Go's net/http answers without running the handler must be refused by the gate wi [cut]
[plus the commit that adds this report and the docs]
```

- Deviations from instructions
  - The brief was two lines. I read "fix 2" as the first option I had
    offered for it (the gate refuses with marker and event) because the
    second option needed a change to kortex_eval (rule 5), and "then move"
    as the attack-dataset runs I had proposed. The task ids T1 to T6 are
    mine.
  - T2 was not asked for. The two holes were found while building T1, are
    in the same code, and rule 39 says a BUG is fixed test first; say so if
    you would rather have had them reported only.
  - E45 was not failing first: it calls `parserGate`, which the fix adds.
    Its ability to fail is shown by the DIAGNOSTIC run instead.
  - The fix of the sample id for bare-LF heads (`headSampleID`) is part of
    the T2 fix commit, found by E46.
  - Status of parser refusals is 400 where net/http used 501, 505, 417,
    431 (documented before the code).
  - engine/go.mod: `golang.org/x/net v0.58.0` moved from indirect to direct
    (the gate imports its `httpguts`); same version, already in the module
    cache, nothing downloaded.
  - Step-23 tools were given optional parameters instead of being copied
    (`PARSING_STEP`, `PARITY_STEP`, `PARITY_REF`, labels in
    step23_parity_vs_c2.py, one more summary line in
    step23_parsing_diff.py); defaults reproduce the step-23 behaviour and
    their tests still pass.
  - The T5 wcp re-run was not in the brief; it is the check that the gate
    change touches no real benign request.
  - Nothing was pushed.

- UNVERIFIED items
  - That the gate refuses every head net/http would refuse. Verified for
    the 33 cases of E42 and the 19,257 seeded heads of E45 on go1.27.4; any
    other shape, and any other Go version, is unverified. The checks after
    parsing are a copy of net/http's and can drift when Go changes.
  - That switching keep-alive off costs nothing. The handler already closed
    every connection it answered, so no change is expected for the runner
    (HYPOTHESIS); timing was NOT MEASURED.
  - The 10 never-sent requests of encoding-diff-v0: what the engine does
    with a raw space in the query is unverified by the datasets (a raw
    space makes the request line malformed for Go, so the gate should now
    answer 400 framing; not run).
  - Stock-coraza comparison on the own datasets is one replay against one
    replay; stock matching is not repeatable for some requests (step 22),
    so 0 differences is what these replays showed, not a proof for every
    replay.

- Questions for instructor
  1. `OPTIONS *`: net/http answers it 200 itself, uninspected and without
     an event (not forwarded). Leave it, hand it to the handler
     (`DisableGeneralOptionsHandler`), or refuse it at the gate?
  2. A head the gate cannot read (more than 65,536 bytes, or no blank line
     in 30 s) is closed with no answer and no event. Announce the oversize
     case with the framing marker and an event?
  3. Bare LF: now checked the way Go reads it and otherwise accepted.
     Refuse every bare-LF head instead (stricter; RFC 9112 allows either)?
  4. Parser refusals are all 400. Keep one status, or keep 501 / 505 / 417
     / 431 with the marker (needs new outcome mappings in kortex_eval)?
  5. A raw-socket runner for requests the Python client cannot send (the
     10 of encoding-diff-v0, and the new shapes against real backends)?
  6. benign-browse-v1: 120 of its 124 blocks are PUT / DELETE against the
     allowed-methods setting (CONFIG-MISMATCH, carried from earlier steps).
  7. Still open from step 23: the 942130 tautology shape under key order
     (accept, report to CRS, or arrival order); encoding checks on the
     path; keep, widen or drop the magic-byte event. From step 22: 503
     overload in the FP worst case, gzip decoding against 415, rate limit,
     pool size, worker mode as default, history rewrite, PR #1.
  8. Push these commits?
