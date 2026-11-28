# Step-27 report

Host and versions (rule 43: same host as steps 25 and 26; one image is new
in this step, so versions and digests are restated). macOS 27.0 (26A425),
Darwin 27.0.0 arm64, Apple M6 12 cores; go1.27.4 darwin/arm64; Python
3.15.2, pytest 9.2.0. Docker client 29.10.1, server 29.5.2 linux/arm64
(colima). Images:
`node@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293`
(node v20.20.2, llhttp 9.3.1; new, the Node backend of the differential),
`owasp/modsecurity-crs:4.25.2-nginx-lts@sha256:6296ce685cb88ba4012998b935b25dabbd9e0ff326088c1149447102544de661`
and
`ghcr.io/coreruleset/coraza-crs:4.25.2-nginx-lts@sha256:bfbfe70b4445c1ef1dc389c2de12cfdb194c9616746c33dc8a7131461c28f4a6`
(both for one DIAGNOSTIC run, OWASP_CRS/4.25.2 read inside each, rule 28).
Engine: changed in this step; the final runs use the binary sha256
a0618939...b50fd1a7 built from 70e6477; coraza v3.8.1 with the step-23
patch, CRS 4.25.2. Rule 29: every run log carries the effective
configuration read from the running engine; examples below. Network: one
page read (the CRS advisory GHSA-6jp8-c2w2-x7wr); nothing fetched into the
repository.

The step-27 brief is the instructor's "do all 4"; this is the third of the
four steps: finish the parsing work (acceptance A3, the four gate
questions of step 24, a raw-socket runner). Plan and design note written
and committed before code and runs: docs/plan-step27-parsing.md (65575af);
its addendum before the T5 changes (33f92f0). Steps 25 and 26 were pushed
before this step (origin/main e8bd17b).

- Summary: A3 measured for the first time and failing on the default configuration: 1 of 62 body cases gets a payload past the engine
  (an XML attribute value; CRS v4.25.2 skips attributes unless a variable is set, the two reference images pass it too; 0 with the new switch on).
  The gate now answers and logs everything it used to drop, one stalled connection no longer stops the listener, and the backend gets the bytes the rules judged. Ten new tests, datasets unchanged per sample.

- Task table:

| task | status | evidence |
|---|---|---|
| T0 plan, design note, config note, before code and runs | done | docs/plan-step27-parsing.md, docs/engine-design.md ("Step-27 additions"), docs/baseline-config.md (step 27); commit 65575af |
| T1 gate decisions, tests first: E57 to E62; E63 | done: 6 tests failing first, then passing; E63 passes on first run | engine/step27_test.go, engine/step27_e63_test.go, docs/logs/step27-e57-e60-failing.log, step27-e57-e62-passing.log, step27-e57-e62-x10.log, step27-e63.log; commits 52b4b42, 366a086, 33f92f0 |
| T2 raw-socket runner | done: 192 of 192 requests sent, 0 client errors; 0 differences from the Python client on the 182 it can send | tools/raw_runner.py (4 tests), tools/run_step27_raw.sh, tools/step27_raw_compare.sh, docs/logs/step27-raw-runner.txt, step27-raw-vs-python-client.txt, docs/logs/runs/s27-raw/; commit 7616436, re-run on the final engine |
| T3 head differential, second slice, three backends, PL1 and PL2 | done: 96 head cases, 0 canaries reach a backend, 0 second requests served, 0 refusals without marker or event | tools/step27_parsing_diff.py, tools/run_step27_parsing_diff.sh, tools/parsing-diff-nodebackend/, docs/logs/step27-parsing-diff.txt, step27-parsing-diff-classes.txt, step27-parsing-diff-vs-step24.txt, docs/logs/runs/s27-parsing-diff/; first run docs/logs/step27-parsing-diff-run1.txt (commit d22dc94) |
| T4 body differential, first slice | done: 62 body cases, **1 canary reaches a parser (`xml-attr`)**, 1 canary in a file part | same files |
| T5 (added by the plan addendum) what the differential found: E64, E65, E66; DIAGNOSTIC against the reference images; DIAGNOSTIC with the switch on | done: 3 tests failing first, then passing | engine/step27_forward_test.go, docs/logs/step27-e64-e66-failing.log, step27-e64-e66-passing.log, step27-DIAGNOSTIC-reference.txt, step27-parsing-diff-DIAGNOSTIC-xml-attr-inspect.txt; commits 33f92f0, 70e6477 |
| T6 datasets on the final engine, docs, report | done: 0 per-sample differences on seven datasets, attacks-v1 and the CRS suite | docs/logs/step27-own-datasets.txt, step27-own-vs-step25.txt, step27-parity.txt, step27-attacks-v1-engine.txt, step27-attacks-v1-vs-step26.txt, s27-ftw.txt, step27-ftw-vs-step25.txt; docs/baseline-v2.2.md, docs/engine-evidence.md, docs/acceptance.md (A3, E57 to E66), docs/block-discriminator.md |
| Final suites | done: Go 80 PASS / 0 FAIL / 5 SKIP; Go with the fixture 85 PASS / 0 FAIL / 0 SKIP; pytest 278 passed, 0 failed, 4 skipped | docs/logs/step27-t6-go-test.log, step27-t6-go-test-with-fixture.log, step27-t6-pytest.log |

## Raw evidence

Long lines are cut where marked `[...]`; the files named hold them in full.
The cases of the differential are hand-written and chosen, so everything
about them is a count, never a rate (rule 35).

### T1. The gate: E57 to E63 (tests first, rules 37, 40)

Failing before the changes (52b4b42; `=== RUN` lines left out):

```
# step-27 T1: E57, E58, E59, E60 failing before the changes
# 2026-11-28T16:29:21Z git 65575afcd3eb26931aa0c17e2695fbbd979f5e6e + step27_test.go; go version go1.27.4 darwin/arm64
# cd engine && go test -count=1 -run 'TestE57|TestE58|TestE59|TestE60' -v .
    step27_test.go:87: want 400 with body "400 kortex-decision=framing", got 200 ""
    step27_test.go:87: want 400 with body "400 kortex-decision=framing", got 200 ""
--- FAIL: TestE57OptionsAsteriskIsRefusedByTheGate (10.07s)
    --- FAIL: TestE57OptionsAsteriskIsRefusedByTheGate/e57-options-asterisk (10.00s)
    --- FAIL: TestE57OptionsAsteriskIsRefusedByTheGate/e57-options-asterisk-10 (0.00s)
    --- PASS: TestE57OptionsAsteriskIsRefusedByTheGate/guard:_OPTIONS_with_a_path_is_forwarded (0.00s)
    step27_test.go:119: E58: /__kortex/config must show head_timeout_ms 300, got {"backend_url":"http://127.0.0.1:54457","rule_engine":"On","blocking_paranoia":1,"detection_paranoia":1,"max_body_bytes":13107200,"max_inspected_bytes":131072,"engine_ti [...]
    step27_test.go:129: want 400 with body "400 kortex-decision=framing", got 0 ""
    step27_test.go:137: want 400 with body "400 kortex-decision=framing", got 0 ""
--- FAIL: TestE58UnreadableHeadIsAnsweredAndLogged (3.14s)
    --- FAIL: TestE58UnreadableHeadIsAnsweredAndLogged/the_limit_is_on_the_config_page (0.00s)
    --- FAIL: TestE58UnreadableHeadIsAnsweredAndLogged/head_over_65,536_bytes (0.00s)
    --- FAIL: TestE58UnreadableHeadIsAnsweredAndLogged/head_that_never_ends (3.00s)
    --- PASS: TestE58UnreadableHeadIsAnsweredAndLogged/guard:_a_head_that_arrives_in_two_pieces_within_the_limit_is_served (0.11s)
    step27_test.go:189: E59: want the request forwarded (200 from the stub), got 0 "" after 3.002081875s, backend hit false
    step27_test.go:189: E59: want the request forwarded (200 from the stub), got 0 "" after 3.002079333s, backend hit false
    step27_test.go:189: E59: want the request forwarded (200 from the stub), got 0 "" after 3.000394334s, backend hit false
    step27_test.go:189: E59: want the request forwarded (200 from the stub), got 0 "" after 3.000676084s, backend hit false
    step27_test.go:196: E59: want 403 kortex-decision=block, got 0 "" after 3.001072292s, backend hit false
--- FAIL: TestE59EndOfHeadIsReadAsGoReadsIt (15.05s)
    --- FAIL: TestE59EndOfHeadIsReadAsGoReadsIt/e59-all-lf (3.00s)
    --- FAIL: TestE59EndOfHeadIsReadAsGoReadsIt/e59-crlf-lines-lf-blank (3.00s)
    --- FAIL: TestE59EndOfHeadIsReadAsGoReadsIt/e59-lf-lines-crlf-blank (3.00s)
    --- FAIL: TestE59EndOfHeadIsReadAsGoReadsIt/e59-all-lf-body (3.00s)
    --- FAIL: TestE59EndOfHeadIsReadAsGoReadsIt/e59-all-lf-canary (3.00s)
    --- PASS: TestE59EndOfHeadIsReadAsGoReadsIt/e59-all-lf-te-cl (0.00s)
    step27_test.go:251: E60: bare net/http handler ran true (status 200), engine answered 400 "400 kortex-decision=framing" for "GET /a?q=1 HTTP/1.1\nHost: localhost\nAccept: */*\r\n\r\n"
    step27_test.go:244: E60: no answer within 3 s (waited 3.002052084s) for "GET /a?q=1 HTTP/1.1\r\nHost: localhost\r\nAccept: */*\n\r\n"; bare net/http: 200, handler ran true
    step27_test.go:244: E60: no answer within 3 s (waited 3.002086292s) for "GET /a?q=1 HTTP/1.1\nHost: localhost\r\nAccept: */*\n\r\n"; bare net/http: 200, handler ran true
    step27_test.go:244: E60: no answer within 3 s (waited 3.001397875s) for "GET /a?q=1 HTTP/1.1\r\nHost: localhost\nAccept: */*\n\r\n"; bare net/http: 200, handler ran true
    step27_test.go:244: E60: no answer within 3 s (waited 3.000070958s) for "GET /a?q=1 HTTP/1.1\nHost: localhost\nAccept: */*\n\r\n"; bare net/http: 200, handler ran true
    step27_test.go:244: E60: no answer within 3 s (waited 3.002077s) for "GET /a?q=1 HTTP/1.1\r\nHost: localhost\r\nAccept: */*\r\n\n"; bare net/http: 200, handler ran true
    step27_test.go:251: E60: bare net/http handler ran true (status 200), engine answered 400 "400 kortex-decision=framing" for "POST /form HTTP/1.1\nHost: localhost\nContent-Type: text/plain\nContent-Length: 5\r\n\r\nhello"
    step27_test.go:251: E60: bare net/http handler ran true (status 200), engine answered 400 "400 kortex-decision=framing" for "HEAD /x HTTP/1.0\nAccept: */*\r\n\r\n"
    step27_test.go:251: E60: bare net/http handler ran true (status 200), engine answered 400 "400 kortex-decision=framing" for "GET /b HTTP/1.1\nHost: localhost\nX-A: 1\nX-B: 2\r\n\r\n"
    step27_test.go:256: heads 88; not answered within 3 s: 66; decided differently from bare net/http: 4
    step27_test.go:258: E60: 66 of 88 heads not answered in time, 4 decided differently
--- FAIL: TestE60EveryLineEndingMixIsAnsweredLikeNetHTTP (198.22s)
FAIL
FAIL	kortexshield/engine	226.785s
FAIL

# step-27 T1: E61, E62 failing before the changes (found while writing E58: the gate reads heads inside the accept loop)
# 2026-11-28T16:35:16Z git 65575afcd3eb26931aa0c17e2695fbbd979f5e6e + step27_test.go; go version go1.27.4 darwin/arm64
# cd engine && go test -count=1 -run 'TestE61|TestE62' -v .
    step27_test.go:282: E61: a request sent while another connection holds an unfinished head: want 200 from the stub within 3 s, got 0 "" after 3.000891417s
--- FAIL: TestE61UnfinishedHeadDoesNotDelayOtherConnections (3.28s)
    step27_test.go:315: E62: want 503 kortex-decision=overload for the connection over the cap, got 0 "" after 3.002054083s, backend hit false
2026/11/28 08:35:28 httptest.Server blocked in Close after 5 seconds, waiting for connections:
--- FAIL: TestE62PendingHeadsAreCapped (30.04s)
FAIL
FAIL	kortexshield/engine	33.654s
FAIL
```

What the failing log says, per test:

- E57: `OPTIONS *` is answered 200 by net/http itself, with no event. The
  premise check (bare net/http answers it without running a handler) takes
  10 s per run because it waits for the idle connection.
- E58: a head over 65,536 bytes and a head that never ends get no answer
  (`got 0 ""`) and no event.
- E59, E60: a head whose blank line ends with a bare LF is not recognised
  as complete. 5 of 6 hand-written cases and 66 of 88 line-ending mixes
  got no answer within 3 s; 4 mixes were refused although net/http serves
  them.
- E61 (found while writing E58): with one connection holding an unfinished
  head, a second complete request gets no answer within 3 s. The gate read
  heads inside the accept loop.
- E62: the connections waiting in the gate had no cap.

Passing after the changes (366a086):

```
# step-27 T1: E57 to E62 passing after the changes
# 2026-11-28T16:37:06Z git 52b4b420645c593fdb057f0c89461dc2d566e376 + working tree (changes); go version go1.27.4 darwin/arm64
# cd engine && go test -count=1 -run 'TestE57|TestE58|TestE59|TestE60|TestE61|TestE62' -v .
--- PASS: TestE57OptionsAsteriskIsRefusedByTheGate (10.07s)
    --- PASS: TestE57OptionsAsteriskIsRefusedByTheGate/e57-options-asterisk (10.00s)
    --- PASS: TestE57OptionsAsteriskIsRefusedByTheGate/e57-options-asterisk-10 (0.00s)
    --- PASS: TestE57OptionsAsteriskIsRefusedByTheGate/guard:_OPTIONS_with_a_path_is_forwarded (0.00s)
--- PASS: TestE58UnreadableHeadIsAnsweredAndLogged (0.44s)
    --- PASS: TestE58UnreadableHeadIsAnsweredAndLogged/the_limit_is_on_the_config_page (0.00s)
    --- PASS: TestE58UnreadableHeadIsAnsweredAndLogged/head_over_65,536_bytes (0.00s)
    --- PASS: TestE58UnreadableHeadIsAnsweredAndLogged/head_that_never_ends (0.30s)
    --- PASS: TestE58UnreadableHeadIsAnsweredAndLogged/guard:_a_head_that_arrives_in_two_pieces_within_the_limit_is_served (0.11s)
--- PASS: TestE59EndOfHeadIsReadAsGoReadsIt (0.03s)
    --- PASS: TestE59EndOfHeadIsReadAsGoReadsIt/e59-all-lf (0.00s)
    --- PASS: TestE59EndOfHeadIsReadAsGoReadsIt/e59-crlf-lines-lf-blank (0.00s)
    --- PASS: TestE59EndOfHeadIsReadAsGoReadsIt/e59-lf-lines-crlf-blank (0.00s)
    --- PASS: TestE59EndOfHeadIsReadAsGoReadsIt/e59-all-lf-body (0.00s)
    --- PASS: TestE59EndOfHeadIsReadAsGoReadsIt/e59-all-lf-canary (0.00s)
    --- PASS: TestE59EndOfHeadIsReadAsGoReadsIt/e59-all-lf-te-cl (0.00s)
    step27_test.go:256: heads 88; not answered within 3 s: 0; decided differently from bare net/http: 0
--- PASS: TestE60EveryLineEndingMixIsAnsweredLikeNetHTTP (0.07s)
--- PASS: TestE61UnfinishedHeadDoesNotDelayOtherConnections (0.22s)
--- PASS: TestE62PendingHeadsAreCapped (0.24s)
PASS
ok  	kortexshield/engine	11.455s
```

Ten repeats of the six tests: 60 PASS, 0 FAIL
(docs/logs/step27-e57-e62-x10.log, last lines):

```
# step-27 T1: E57 to E62 ten times in one process (rule 48), 2026-11-28T16:38:54Z, git 52b4b420645c593fdb057f0c89461dc2d566e376 + working tree, go version go1.27.4 darwin/arm64, load at start: load av [...]
# cd engine && go test -count=10 -timeout 900s -run 'TestE57|TestE58|TestE59|TestE60|TestE61|TestE62' -v . (result lines of the top-level tests)
[...]
PASS
ok  	kortexshield/engine	110.340s
# load at end: load averages: 2.78 3.06 3.03
```

E63, E45 with bare-LF line endings (written after the fix, passes on its
first run; it is the plan's "heads that end with a bare-LF blank line are
added to E45", as a test of its own so that E45 stays as it was):

```
# step-27 T1: E63 (E45 with bare-LF line endings), engine d22dc94ab512e4b9749eecb736b4bbaab7fd36d7; 2026-11-28T17:14:08Z; go version go1.27.4 darwin/arm64
# cd engine && go test -run 'TestE45|TestE63' -count=1 -v .
    step24_test.go:428: heads compared 19257 (not sent, no blank line: 743; no answer from net/http: 0); net/http refused 11890 map[400:10815 417:421 501:654]; parserGate refused 11890; mismatches 0
    step24_test.go:430: parserGate reasons: parser:content-length 542, parser:expect 421, parser:header-line 4276, parser:header-name 404, parser:host-duplicate 973, parser:host-malformed 311, parser:host-missing 322, parser:http-version 2364, parser:method 509, parser:request-line 419, parser:request-target 695, parser:transfer-encoding 654
--- PASS: TestE45ParserGateAgreesWithNetHTTPOnDamagedHeads (1.62s)
    step27_e63_test.go:146: heads compared 19579 (not sent, no end of head: 421; no answer from net/http: 0); with a bare LF in the head 19170, of them ended by a blank line without CRLF CRLF 14832; net/http refused 11883 map[400:10803 417:405 501:673 505:2]; parserGate refused 11883; mismatches 0
    step27_e63_test.go:148: parserGate reasons: parser:content-length 518, parser:expect 405, parser:header-line 4326, parser:header-name 393, parser:host-duplicate 1025, parser:host-malformed 287, parser:host-missing 294, parser:http-version 2418, parser:method 511, parser:request-line 397, parser:request-target 636, parser:transfer-encoding 673
--- PASS: TestE63ParserGateAgreesWithNetHTTPOnDamagedHeadsWithBareLF (1.67s)
PASS
ok  	kortexshield/engine	3.526s
```

What changed in the engine for E57 to E62:

- `engine/listener.go`: every accepted connection is gated in its own
  goroutine; `pending_heads` counts them and `KORTEX_MAX_PENDING_HEADS`
  (default 256) caps them, one more gets `503 kortex-decision=overload`
  with an `overload` event, reason `pending-heads`. `headEnd` finds the
  end of the head as Go does (a blank line ended by LF or CRLF). A head
  over 65,536 bytes or one that does not end within
  `KORTEX_HEAD_TIMEOUT_MS` (default 30 s) is answered
  `400 kortex-decision=framing` with an event (`head-too-large`,
  `head-timeout`). `OPTIONS *` is refused (`parser:options-asterisk`).
- `engine/admin.go`: the CRLF view of the framing check no longer refuses
  a request line that ends with a bare LF; `/__kortex/config` shows
  `head_timeout_ms` and `max_pending_heads`, `/__kortex/stats` shows
  `pending_heads` (rule 50; E61 and E62 assert it returns to 0).

### T2. Raw-socket runner

`tools/raw_runner.py` writes each sample's bytes itself: method, path,
`?`, query and body as the manifest stores them, with no URL validation,
one connection per request, in the response format of
`kortex_eval.runner`. kortex_eval is not changed. Its 4 tests include: a
sample the Python client can send goes out as the bytes `http.client`
sends.

encoding-diff-v0 (frozen, 192 requests, 16 payloads) through the raw
runner on the final engine, in-process and worker, PL1 and PL2:

```
# Step-27 T2: encoding-diff-v0 through the raw-socket runner, engine in-process and worker, PL1 and PL2
== 2026-11-28T17:29:47Z, macOS 27.0 Darwin 27.0.0 arm64, go version go1.27.4 darwin/arm64, Python 3.15.2, load at start: load averages: 2.61 3.28 3.39
== git 70e6477dd29ef94e66d5909553d392e9d3394eea, tracked paths changed under engine/: 0
== manifest data/encoding-diff-v0/manifest.jsonl sha256 ff00384d33018f45d95bde0d3cfa2c0eab184c94558ec1d24e527baa6ea27e5c (frozen: ff00384d33018f45d95bde0d3cfa2c0eab184c94558ec1d24e527baa6ea27e5c), 192 requests
== encoding-diff-v0-raw-inprocess-pl1 raw runner: {"total_samples": 192, "responses_ok": 192, "blocked": 137, "error_count": 0}
waf_block: 137
waf_fail_closed_400: 10
waf_pass: 45
== encoding-diff-v0-raw-inprocess-pl1 events: 197 events {'block': 137, 'framing': 10, 'pass': 46, 'would_reject': 4}; compressed-body events 0 {}; framing events 10 {'parser:http-version': 10}; kept 14
== encoding-diff-v0-raw-worker-pl1 raw runner: {"total_samples": 192, "responses_ok": 192, "blocked": 137, "error_count": 0}
waf_block: 137
waf_fail_closed_400: 10
waf_pass: 45
== encoding-diff-v0-raw-worker-pl1 events: 197 events {'block': 137, 'framing': 10, 'pass': 46, 'would_reject': 4}; compressed-body events 0 {}; framing events 10 {'parser:http-version': 10}; kept 14
== encoding-diff-v0-raw-inprocess-pl2 raw runner: {"total_samples": 192, "responses_ok": 192, "blocked": 147, "error_count": 0}
waf_block: 147
waf_fail_closed_400: 10
waf_pass: 35
== encoding-diff-v0-raw-inprocess-pl2 events: 195 events {'block': 147, 'framing': 10, 'pass': 36, 'would_reject': 2}; compressed-body events 0 {}; framing events 10 {'parser:http-version': 10}; kept 12
== encoding-diff-v0-raw-worker-pl2 raw runner: {"total_samples": 192, "responses_ok": 192, "blocked": 147, "error_count": 0}
waf_block: 147
waf_fail_closed_400: 10
waf_pass: 35
== encoding-diff-v0-raw-worker-pl2 events: 195 events {'block': 147, 'framing': 10, 'pass': 36, 'would_reject': 2}; compressed-body events 0 {}; framing events 10 {'parser:http-version': 10}; kept 12
S27-RAW-DONE
```

Rule 29 for the first of the four runs (the other three are in the log):

```
== encoding-diff-v0-raw-inprocess-pl1 rule29 2026-11-28T17:29:48Z load: load averages: 2.61 3.28 3.39: {"backend_url":"http://127.0.0.1:13004","rule_engine":"On","blocking_paranoia":1,"detection_paranoia":1,"max_body_bytes":13107200,"max_inspected_bytes":131072,"engine_time_budget_ms":2000,"rules_dir":"/Users/ivan/work/kortex-shield-next/engine/crs","listen_addr":"127.0.0.1:8097","events_file":"/Users/ivan/work/kortex-shield-next/out/s22-s27-encoding-diff-v0-raw-inprocess-pl1.events.jsonl","audit_log":"/Users/ivan/work/kortex-shield-next/out/s22-s27-encoding-diff-v0-raw-inprocess-pl1.audit.log","allowed_methods":"GET HEAD POST OPTIONS","max_inflight_body":8,"max_inflight_body_large":2,"body_lane_threshold":65536,"worker_mode":false,"client_max_inflight":0,"client_max_inflight_small":4,"client_max_inflight_large":1,"request_body_target_updates":165,"error_log":"","crs_test_setup":false,"h [...]
== encoding-diff-v0-raw-inprocess-pl1 stats after run: {"inflight_small":0,"inflight_large":0,"abandoned_running":0,"kills":0,"overloads":0,"refused_before_inspection":0,"penalised_clients":0,"client_inflight_small":0,"client_inflight_large":0,"workers":{"pool":0,"busy":0,"spares":0,"recycled":0},"pending_heads":0}
```

Against the Python client's runs of the same engine, per sample id
(rule 32):

```
# step-27 T2: encoding-diff-v0, the Python client's runs (a, step-27 engine, docs/logs/runs/s27-own) against the raw-socket runner's runs (b, docs/logs/runs/s27-raw), per sample id
# 2026-11-28T17:50:29Z git 70e6477dd29ef94e66d5909553d392e9d3394eea
== encoding-diff-v0 PL1 inprocess (a=Python client b=raw runner):
# .venv/bin/python tools/step21_engine_diff.py docs/logs/runs/s27-own/encoding-diff-v0-inprocess-pl1 docs/logs/runs/s27-raw/encoding-diff-v0-raw-inprocess-pl1
samples compared: 192 (a=192 b=192 only-a=0 only-b=0)
status counts a: {200: 45, 403: 137, None: 10}
status counts b: {200: 45, 400: 10, 403: 137}
status diffs: 10
  encd-query-plain-command-injection-029d9cca: a=None b=400
  encd-query-plain-command-injection-05bbe7a8: a=None b=400
  encd-query-plain-command-injection-227cb8a4: a=None b=400
  encd-query-plain-sqli-6e47f23b: a=None b=400
  encd-query-plain-sqli-8c187a93: a=None b=400
  encd-query-plain-sqli-a2035700: a=None b=400
  encd-query-plain-xss-369d0b75: a=None b=400
  encd-query-plain-xss-545d1ff8: a=None b=400
  encd-query-plain-xss-56083d09: a=None b=400
  encd-query-plain-xss-784791cd: a=None b=400
  encd-query-plain-command-injection-029d9cca
  encd-query-plain-command-injection-05bbe7a8
  encd-query-plain-command-injection-227cb8a4
  encd-query-plain-sqli-6e47f23b
  encd-query-plain-sqli-8c187a93
  encd-query-plain-sqli-a2035700
  encd-query-plain-xss-369d0b75
  encd-query-plain-xss-545d1ff8
  encd-query-plain-xss-56083d09
  encd-query-plain-xss-784791cd
worst-case set a: 147/192 (error=10 blocked=137 deny_status=0 inconsistent=0 fail_closed_413=0 fail_closed_415=0 fail_closed_400=0 fail_closed_503_timeout=0 fail_closed_503_overload=0)
worst-case set b: 147/192 (error=0 blocked=137 deny_status=0 inconsistent=0 fail_closed_413=0 fail_closed_415=0 fail_closed_400=10 fail_closed_503_timeout=0 fail_closed_503_overload=0)
worst-case set diffs: 0 (only-a 0 only-b 0)
== encoding-diff-v0 PL1 worker (a=Python client b=raw runner):
# .venv/bin/python tools/step21_engine_diff.py docs/logs/runs/s27-own/encoding-diff-v0-worker-pl1 docs/logs/runs/s27-raw/encoding-diff-v0-raw-worker-pl1
samples compared: 192 (a=192 b=192 only-a=0 only-b=0)
status counts a: {200: 45, 403: 137, None: 10}
status counts b: {200: 45, 400: 10, 403: 137}
status diffs: 10
  encd-query-plain-command-injection-029d9cca: a=None b=400
  encd-query-plain-command-injection-05bbe7a8: a=None b=400
  encd-query-plain-command-injection-227cb8a4: a=None b=400
  encd-query-plain-sqli-6e47f23b: a=None b=400
  encd-query-plain-sqli-8c187a93: a=None b=400
  encd-query-plain-sqli-a2035700: a=None b=400
  encd-query-plain-xss-369d0b75: a=None b=400
  encd-query-plain-xss-545d1ff8: a=None b=400
  encd-query-plain-xss-56083d09: a=None b=400
  encd-query-plain-xss-784791cd: a=None b=400
  encd-query-plain-command-injection-029d9cca
  encd-query-plain-command-injection-05bbe7a8
  encd-query-plain-command-injection-227cb8a4
  encd-query-plain-sqli-6e47f23b
  encd-query-plain-sqli-8c187a93
  encd-query-plain-sqli-a2035700
  encd-query-plain-xss-369d0b75
  encd-query-plain-xss-545d1ff8
  encd-query-plain-xss-56083d09
  encd-query-plain-xss-784791cd
worst-case set a: 147/192 (error=10 blocked=137 deny_status=0 inconsistent=0 fail_closed_413=0 fail_closed_415=0 fail_closed_400=0 fail_closed_503_timeout=0 fail_closed_503_overload=0)
worst-case set b: 147/192 (error=0 blocked=137 deny_status=0 inconsistent=0 fail_closed_413=0 fail_closed_415=0 fail_closed_400=10 fail_closed_503_timeout=0 fail_closed_503_overload=0)
worst-case set diffs: 0 (only-a 0 only-b 0)
== encoding-diff-v0 PL2 inprocess (a=Python client b=raw runner):
# .venv/bin/python tools/step21_engine_diff.py docs/logs/runs/s27-own/encoding-diff-v0-inprocess-pl2 docs/logs/runs/s27-raw/encoding-diff-v0-raw-inprocess-pl2
samples compared: 192 (a=192 b=192 only-a=0 only-b=0)
status counts a: {200: 35, 403: 147, None: 10}
status counts b: {200: 35, 400: 10, 403: 147}
status diffs: 10
  encd-query-plain-command-injection-029d9cca: a=None b=400
  encd-query-plain-command-injection-05bbe7a8: a=None b=400
  encd-query-plain-command-injection-227cb8a4: a=None b=400
  encd-query-plain-sqli-6e47f23b: a=None b=400
  encd-query-plain-sqli-8c187a93: a=None b=400
  encd-query-plain-sqli-a2035700: a=None b=400
  encd-query-plain-xss-369d0b75: a=None b=400
  encd-query-plain-xss-545d1ff8: a=None b=400
  encd-query-plain-xss-56083d09: a=None b=400
  encd-query-plain-xss-784791cd: a=None b=400
  encd-query-plain-command-injection-029d9cca
  encd-query-plain-command-injection-05bbe7a8
  encd-query-plain-command-injection-227cb8a4
  encd-query-plain-sqli-6e47f23b
  encd-query-plain-sqli-8c187a93
  encd-query-plain-sqli-a2035700
  encd-query-plain-xss-369d0b75
  encd-query-plain-xss-545d1ff8
  encd-query-plain-xss-56083d09
  encd-query-plain-xss-784791cd
worst-case set a: 157/192 (error=10 blocked=147 deny_status=0 inconsistent=0 fail_closed_413=0 fail_closed_415=0 fail_closed_400=0 fail_closed_503_timeout=0 fail_closed_503_overload=0)
worst-case set b: 157/192 (error=0 blocked=147 deny_status=0 inconsistent=0 fail_closed_413=0 fail_closed_415=0 fail_closed_400=10 fail_closed_503_timeout=0 fail_closed_503_overload=0)
worst-case set diffs: 0 (only-a 0 only-b 0)
== encoding-diff-v0 PL2 worker (a=Python client b=raw runner):
# .venv/bin/python tools/step21_engine_diff.py docs/logs/runs/s27-own/encoding-diff-v0-worker-pl2 docs/logs/runs/s27-raw/encoding-diff-v0-raw-worker-pl2
samples compared: 192 (a=192 b=192 only-a=0 only-b=0)
status counts a: {200: 35, 403: 147, None: 10}
status counts b: {200: 35, 400: 10, 403: 147}
status diffs: 10
  encd-query-plain-command-injection-029d9cca: a=None b=400
  encd-query-plain-command-injection-05bbe7a8: a=None b=400
  encd-query-plain-command-injection-227cb8a4: a=None b=400
  encd-query-plain-sqli-6e47f23b: a=None b=400
  encd-query-plain-sqli-8c187a93: a=None b=400
  encd-query-plain-sqli-a2035700: a=None b=400
  encd-query-plain-xss-369d0b75: a=None b=400
  encd-query-plain-xss-545d1ff8: a=None b=400
  encd-query-plain-xss-56083d09: a=None b=400
  encd-query-plain-xss-784791cd: a=None b=400
  encd-query-plain-command-injection-029d9cca
  encd-query-plain-command-injection-05bbe7a8
  encd-query-plain-command-injection-227cb8a4
  encd-query-plain-sqli-6e47f23b
  encd-query-plain-sqli-8c187a93
  encd-query-plain-sqli-a2035700
  encd-query-plain-xss-369d0b75
  encd-query-plain-xss-545d1ff8
  encd-query-plain-xss-56083d09
  encd-query-plain-xss-784791cd
worst-case set a: 157/192 (error=10 blocked=147 deny_status=0 inconsistent=0 fail_closed_413=0 fail_closed_415=0 fail_closed_400=0 fail_closed_503_timeout=0 fail_closed_503_overload=0)
worst-case set b: 157/192 (error=0 blocked=147 deny_status=0 inconsistent=0 fail_closed_413=0 fail_closed_415=0 fail_closed_400=10 fail_closed_503_timeout=0 fail_closed_503_overload=0)
worst-case set diffs: 0 (only-a 0 only-b 0)
# rule-id sets per sample, Python client (a) against raw runner (b)
== encoding-diff-v0-inprocess-pl1: samples with an audit entry a=137 b=137; rule-id set differs for 0; ids gained in b: none; ids lost in b: none
== encoding-diff-v0-worker-pl1: samples with an audit entry a=137 b=137; rule-id set differs for 0; ids gained in b: none; ids lost in b: none
== encoding-diff-v0-inprocess-pl2: samples with an audit entry a=147 b=147; rule-id set differs for 0; ids gained in b: none; ids lost in b: none
== encoding-diff-v0-worker-pl2: samples with an audit entry a=147 b=147; rule-id set differs for 0; ids gained in b: none; ids lost in b: none
== total samples with a different rule-id set: 0
```

- All 192 requests are sent: 0 client errors (the Python client refuses to
  build 10, `encd-query-plain-*`, a raw space in the query).
- Those 10 are refused by the gate: `400 kortex-decision=framing`, event
  reason `parser:http-version`, outcome `waf_fail_closed_400`. They are
  never judged by the rules. Bare net/http refuses the same bytes.
- On the other 182 requests: 0 status differences and 0 rule-id-set
  differences between the two clients, in every mode and level.
- Counts (rule 35), raw runner: blocked 137 of 192 at PL1 and 147 at PL2,
  refused by the gate 10, passed 45 and 35; in-process equal to worker.

### T3 / T4. The parsing differential

158 hand-written requests: the 61 of step 23, 35 new head cases (bare LF,
two requests in one write, Host, HTTP version, Expect, request line, head
size) and 62 body cases (urlencoded, multipart, JSON, XML, content-type
confusion). Each body case carries the canary `<script>alert(1)</script>`
as the value of `q`; each of the four body kinds has a control with the
canary sent plainly, and three head cases are canaries of their family
(rule 47; 7 controls in all). Three backends, each behind its own engine process and
also alone: Python http.server, Go net/http, Node http (container, port on
127.0.0.1). Engine in-process, blocking, PL1 then PL2.

Classes: `engine-refuses-backend-accepts`, `engine-forwards-backend-refuses`,
`view-differs`, `canary-reaches-backend` (as in step 23),
`canary-reaches-parser` (A3's failure condition: forwarded, no rule
matched, a backend's body parser yields the canary in a field),
`canary-in-file-part`, `second-request-served`, and `engine_problem` (a
refusal without marker or event, or no answer).

There are three runs. Run 1 is the first reading, on the engine of the T1
fixes (7616436); what it showed led to T5. The final run is on the engine
with T5 (70e6477). The third is DIAGNOSTIC: the final engine with
`KORTEX_XML_ATTR_INSPECT=on`.

#### Run 1 (engine 7616436): what it showed

```
# Step-27: parsing differential, 61 step-23 cases, new head cases and body cases; three backends; PL1 and PL2
== 2026-11-28T17:04:13Z, macOS 27.0 Darwin 27.0.0 arm64, go version go1.27.4 darwin/arm64, Python 3.15.2, system python3 for the backend: Python 3.15.2
== git 7616436f73666a3b5f458e922be40a4d80afeb67, tracked paths changed under engine/: 0
== engine binary sha256 50e43c4f893f8294bce55efb1811741cd0cd3db1fd2f43cb5af38edcc352d3f8 built from 7616436f73666a3b5f458e922be40a4d80afeb67 with go version go1.27.4 darwin/arm64
== go backend binary sha256 efcdb0be0504f1063e58fc56d751a128f58b78977d8557c40efd98d1ef82a472
== node backend: image node@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293 id sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293, node v20.20.2 llhttp 9.3.1
== the engine decided the same in front of every backend in 158 of 158 cases
== engine refusals without a kortex marker or without an event, and requests with no answer: 1 cases
   blf-cr-only [python-backed]: 400 framing without an event
   blf-cr-only [go-backed]: 400 framing without an event
   blf-cr-only [node-backed]: 400 framing without an event
== canary controls: 7; blocked 403 in front of every backend: 7; not blocked: none
== canary-reaches-parser (A3's failure condition): 1 cases: xml-attr
== canary-reaches-backend (path or query): 0 cases: none
```

and, added to the same log after the run:

```

# run 1 of the differential, engine 7616436 (before E64 to E66). Kept as the first reading; the final run is docs/logs/step27-parsing-diff.txt.
# 2026-11-28T17:12:15Z .venv/bin/python tools/step27_pl_effect.py out/s22-s27-parsing-py-pl1.audit.log out/s22-s27-parsing-py-pl2.audit.log   (the audit logs of this run)
== rule 16: cases with an audit entry at PL1 84, at PL2 84, at both 84; matched rule-id set differs between PL1 and PL2 for 56 of 84
   rule ids matched at PL2 and in no case at PL1: 8: 920230, 920271, 941101, 941320, 942131, 942430, 942440, 942520
# blf-cr-only: the event exists with an empty sample id (the id line is glued to the Host line by a bare CR):
# grep -h '"sample_id":""' out/s22-s27-parsing-py-pl1.events.jsonl out/s22-s27-parsing-py-pl2.events.jsonl
{"ts":"2026-11-28T17:04:15.542762Z","sample_id":"","decision":"pass","status":0,"elapsed_ms":1.245,"reason":"forwarding"}
{"ts":"2026-11-28T17:04:43.096153Z","sample_id":"","decision":"framing","status":400,"elapsed_ms":0.059,"reason":"parser:header-line"}
{"ts":"2026-11-28T17:05:21.590418Z","sample_id":"","decision":"pass","status":0,"elapsed_ms":1.299,"reason":"forwarding"}
{"ts":"2026-11-28T17:05:49.52883Z","sample_id":"","decision":"framing","status":400,"elapsed_ms":0.080,"reason":"parser:header-line"}
# old 61 cases against step 24:
# .venv/bin/python tools/step24_parsing_compare.py docs/logs/runs/s24-parsing-diff/results.jsonl docs/logs/runs/s27-parsing-diff-run1/pl1/results.jsonl
== cases in both runs: 61; in one run only: 97: blf-all-lf, blf-blank-only, blf-body, blf-canary, blf-cr-only, blf-crlf-blank, blf-hidden-cl, ct-form-as-json, ct-form-as-text, ct-json-as-form, ct-json-as-text, ct-missing-form, ct-multipart-as-form, ct-two-headers, expect-100-body, expect-other, head [...]
== engine in front of the python backend: answer changed in 1 of 61 cases, unchanged in 60
   1 x  403 kortex-decision=block  ->  forwarded
   ovl-path-raw: 403 kortex-decision=block, event rules=900000,900001,900110,900990,900200,901111,901115,901130,901140,901141,901142,901143,901162,901168,901163,901164,901165,901171,901510,901167,901169,901170,901180,901200,901340,901400,911013,913013,920013,921013,930013,931013,932013,933013,934013 [...]
== disagreement classes against the python backend changed in 1 of 61 cases: ovl-path-raw
== engine in front of the go backend: answer changed in 1 of 61 cases, unchanged in 60
   1 x  403 kortex-decision=block  ->  forwarded
   ovl-path-raw: 403 kortex-decision=block, event rules=900000,900001,900110,900990,900200,901111,901115,901130,901140,901141,901142,901143,901162,901168,901163,901164,901165,901171,901510,901167,901169,901170,901180,901200,901340,901400,911013,913013,920013,921013,930013,931013,932013,933013,934013 [...]
== disagreement classes against the go backend changed in 1 of 61 cases: ovl-path-raw
== before: refused with no kortex marker: 0
== after: refused with no kortex marker: 0
```

Three things came out of it (plan addendum, written before any change):

1. `blf-cr-only` counted as "400 framing without an event". The event is
   there (`parser:header-line`, the two lines with an empty `sample_id`
   above): the id line is glued to the Host line by a bare CR, so the
   engine cannot read the id. The tool matched events by sample id only.
   Tool changed (events without an id are matched by their position in
   the events file; unit test); no engine change.
2. `ovl-path-raw`: blocked at step 24, forwarded now. Followed up in T5
   (E64).
3. `xml-attr`: `canary-reaches-parser`. Followed up in T5 (E66).

#### Final run (engine 70e6477)

Versions and the first of the six rule-29 lines (the other five are in the
log, one per engine process and level):

```
# Step-27: parsing differential, 61 step-23 cases, new head cases and body cases; three backends; PL1 and PL2
== 2026-11-28T17:25:18Z, macOS 27.0 Darwin 27.0.0 arm64, go version go1.27.4 darwin/arm64, Python 3.15.2, system python3 for the backend: Python 3.15.2
== git 70e6477dd29ef94e66d5909553d392e9d3394eea, tracked paths changed under engine/: 0
== engine binary sha256 a06189399ae4eeb5fa9510837576ce6cd26af2701ed56151b9dcd419b50fd1a7 built from 70e6477dd29ef94e66d5909553d392e9d3394eea with go version go1.27.4 darwin/arm64
== go backend binary sha256 efcdb0be0504f1063e58fc56d751a128f58b78977d8557c40efd98d1ef82a472
== node backend: image node@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293 id sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293, node v20.20.2 llhttp 9.3.1
== python backend answers: {"backend": "python-http.server", "method": "GET", "target": "/ping", 
== go backend answers: {"backend":"go-net/http","method":"GET","target":"/ping","path_raw":"/
== node backend answers: {"backend":"node-http","method":"GET","target":"/ping","path_raw":"/pi
== engine-before-python-pl1 rule29 2026-11-28T17:25:20Z load: load averages: 3.51 4.13 3.67: {"backend_url":"http://127.0.0.1:13011","rule_engine":"On","blocking_paranoia":1,"detection_paranoia":1,"max_body_bytes":13107200,"max_inspected_bytes":131072,"engine_time_budget_ms":2000,"rules_dir":"/Users/ivan/work/kortex-shield-next/engine/crs","listen_addr":"127.0.0.1:8101","events_file":"/Users/ivan/work/kortex-shield-next/out/s22-s27-parsing-py-pl1.events.jsonl","audit_log":"/Users/ivan/work/kortex-shield-next/out/s22-s27-parsing-py-pl1.audit.log","allowed_methods":"GET HEAD POST OPTIONS","max_inflight_body":8,"max_inflight_body_large":2,"body_lane_threshold":65536,"worker_mode":false,"client_max_inflight":0,"client_max_inflight_small":4,"client_max_inflight_large":1,"request_body_target_updates":165,"error_log":"","crs_test_setup":false,"head_timeout_ms":30000,"max_pending_heads":256,"xml [...]
```

PL1 summary:

```
== cases: 158 hand-written requests; step-23 cases 61, new head cases 35, body cases 62
== engine decision per family (engine in front of the python backend)
   bare-lf: 400 framing 2, 403 block 1, forwarded 4
   conn-reuse: forwarded 4
   content-length: 400 framing 14, forwarded 5
   content-type: 400 block 1, 403 block 6
   expect: 400 framing 1, 403 block 1
   head-size: 400 framing 2
   host: 400 framing 3, 403 block 2, forwarded 1
   json: 400 block 5, 403 block 11
   multipart: 400 block 4, 403 block 12, forwarded 2
   overlong: 403 block 8, forwarded 3
   percent: 400 framing 3, 403 block 7, forwarded 4
   request-line: 400 framing 4, 403 block 3
   transfer-encoding: 400 framing 12, 503 timeout 2, forwarded 3
   urlencoded: 403 block 12
   version: 400 framing 3, 403 block 3, forwarded 1
   xml: 400 block 1, 403 block 7, forwarded 1
== the engine decided the same in front of every backend in 158 of 158 cases
== engine refusals without a kortex marker or without an event, and requests with no answer: 0 cases
== cases whose event carries no sample id (the engine could not read the id line; the event is matched by its position in the events file): 1: blf-cr-only
== framing events by reason (python-backed): conflicting-content-length 4, duplicate-content-length 1, head-too-large 1, parser:content-length 8, parser:expect 1, parser:header-count 1, parser:header-line 1, parser:header-name 1, parser:host-duplicate 2, parser:host-missing 1, parser:http-version 4, parser:options-asterisk 1, parser:request-line 2, parser:request-target 3, parser:transfer-encoding 5, transfer-encodin [...]
== canary controls: 7; blocked 403 in front of every backend: 7; not blocked: none
== each backend given the same bytes directly
   python: accepts 150 of 158; statuses {'200': 150, '400': 2, '431': 2, '501': 2, '505': 1, 'no answer (no-response)': 1}
   go: accepts 121 of 158; statuses {'200': 122, '400': 26, '417': 1, '431': 1, '501': 7, '505': 1}
   node: accepts 110 of 158; statuses {'200': 110, '400': 45, '417': 1, '431': 1, 'no answer (no-response)': 1}
```

Classes per backend, the rows that are not plain refusals, and the
two-request cases, PL1 (the PL2 block of the file, lines 32 to 60, has the
same rows):

```
# step-27: classes of the final differential run and of the DIAGNOSTIC run with KORTEX_XML_ATTR_INSPECT=on; 2026-11-28T17:30:32Z
# .venv/bin/python tools/step27_diff_classes.py docs/logs/runs/s27-parsing-diff/pl1/results.jsonl docs/logs/runs/s27-parsing-diff/pl2/results.jsonl docs/logs/runs/s27-parsing-diff-DIAGNOSTIC-xml-attr-inspect/pl1/results.jsonl docs/logs/runs/s27-parsing-diff-DI [...]
== docs/logs/runs/s27-parsing-diff/pl1/results.jsonl: 158 cases
   go: canary-in-file-part 1, canary-reaches-parser 1, engine-refuses-backend-accepts 93
   node: engine-forwards-backend-refuses 9, engine-refuses-backend-accepts 91, view-differs 1
   python: canary-in-file-part 1, canary-reaches-parser 1, engine-refuses-backend-accepts 122, view-differs 4
   rows in a class other than engine-refuses-backend-accepts:
      cl-trailing-tab [content-length] node: engine-forwards-backend-refuses: backend alone answers 400
      cl-obs-fold [content-length] node: engine-forwards-backend-refuses: backend alone answers 400
      cl-short-body [content-length] node: engine-forwards-backend-refuses: backend alone answers 400
      te-control [transfer-encoding] python: view-differs: body_len: through engine 5, direct 0; body_sha256
      te-case [transfer-encoding] python: view-differs: body_len: through engine 5, direct 0; body_sha256
      te-chunk-ext [transfer-encoding] python: view-differs: body_len: through engine 5, direct 0; body_sha256
      ovl-path-raw [overlong] node: engine-forwards-backend-refuses: backend alone answers 400
      blf-all-lf [bare-lf] node: engine-forwards-backend-refuses: backend alone answers 400
      blf-blank-only [bare-lf] node: engine-forwards-backend-refuses: backend alone answers 400
      blf-crlf-blank [bare-lf] node: engine-forwards-backend-refuses: backend alone answers 400
      blf-body [bare-lf] node: engine-forwards-backend-refuses: backend alone answers 400
      reuse-get-smuggle [conn-reuse] node: engine-forwards-backend-refuses: backend alone answers 400
      host-absolute-diff [host] node: view-differs: path_decoded: through engine '/x', direct 'http://other.example/x'
      host-absolute-diff [host] python: view-differs: path_decoded: through engine '/x', direct 'http://other.example/x'
      mp-filename [multipart] go: canary-in-file-part: the canary is the content of a file part
      mp-filename [multipart] python: canary-in-file-part: the canary is the content of a file part
      xml-attr [xml] go: canary-reaches-parser: the backend's xml parser yields the canary
      xml-attr [xml] python: canary-reaches-parser: the backend's xml parser yields the canary
   two requests in one write (second-request-served means more than one answer or a pass event for the second):
      reuse-get-get: go status 200, answers 1, second passed on False, node status 200, answers 1, second passed on False, python status 200, answers 1, second passed on False
      reuse-get-smuggle: go status 200, answers 1, second passed on False, node status 200, answers 1, second passed on False, python status 200, answers 1, second passed on False
      reuse-post-cl: go status 200, answers 1, second passed on False, node status 200, answers 1, second passed on False, python status 200, answers 1, second passed on False
      reuse-keepalive: go status 200, answers 1, second passed on False, node status 200, answers 1, second passed on False, python status 200, answers 1, second passed on False
   second-request-served: 0 cases
```

Body cases, PL1 (what the engine did, what each backend's parser got):

```
== body cases: what the engine did and what each backend's parser got (through the engine when forwarded, else directly)
   ue-control: engine 403 block; python urlencoded: canary; go urlencoded: canary; node urlencoded: canary
   ue-dup-first: engine 403 block; python urlencoded: canary; go urlencoded: canary; node urlencoded: canary
   ue-dup-last: engine 403 block; python urlencoded: canary; go urlencoded: canary; node urlencoded: canary
   ue-semicolon: engine 403 block; python urlencoded: canary; go urlencoded error *errors.errorString: no canary; node urlencoded: canary
   ue-key-encoded: engine 403 block; python urlencoded: canary; go urlencoded: canary; node urlencoded: canary
   ue-plus: engine 403 block; python urlencoded: canary; go urlencoded: canary; node urlencoded: canary
   ue-double: engine 403 block; python urlencoded: no canary; go urlencoded: no canary; node urlencoded: no canary
   ue-utf7: engine 403 block; python urlencoded: no canary; go urlencoded: no canary; node urlencoded: no canary
   ue-ct-upper: engine 403 block; python urlencoded: canary; go urlencoded: canary; node urlencoded: canary
   ue-ct-param: engine 403 block; python urlencoded: canary; go urlencoded: canary; node urlencoded: canary
   ue-ct-space: engine 403 block; python urlencoded: canary; go urlencoded: canary; node urlencoded: canary
   ue-chunked: engine 403 block; python urlencoded: no canary; go urlencoded: canary; node urlencoded: canary
   mp-control: engine 403 block; python multipart: canary; go multipart: canary; node not-measured: no canary
   mp-boundary-quoted: engine 403 block; python multipart: canary; go multipart: canary; node not-measured: no canary
   mp-param-before: engine 403 block; python multipart: canary; go multipart: canary; node not-measured: no canary
   mp-param-after: engine 403 block; python multipart: canary; go multipart: canary; node not-measured: no canary
   mp-two-boundaries-last: engine 400 block; python multipart error ValueError: no canary; go multipart error *http.ProtocolError: no canary; node not-measured: no canary
   mp-two-boundaries-first: engine 400 block; python multipart: canary; go multipart error *http.ProtocolError: no canary; node not-measured: no canary
   mp-lf-lines: engine 403 block; python multipart: canary; go multipart: canary; node not-measured: no canary
   mp-no-final: engine 400 block; python multipart: canary; go multipart error *errors.errorString: no canary; node not-measured: no canary
   mp-name-unquoted: engine 403 block; python multipart: canary; go multipart: canary; node not-measured: no canary
   mp-two-names: engine 400 block; python multipart: canary; go multipart: no canary; node not-measured: no canary
   mp-filename: engine forwarded; python multipart: canary in file part; go multipart: canary in file part; node not-measured: no canary
   mp-filename-canary: engine forwarded; python multipart: no canary; go multipart: no canary; node not-measured: no canary
   mp-header-fold: engine 403 block; python multipart: canary; go multipart: canary; node not-measured: no canary
   mp-cd-case: engine 403 block; python multipart: canary; go multipart: canary; node not-measured: no canary
   mp-preamble: engine 403 block; python multipart: canary; go multipart: canary; node not-measured: no canary
   mp-ct-upper: engine 403 block; python multipart: canary; go multipart: canary; node not-measured: no canary
   mp-second-part: engine 403 block; python multipart: canary; go multipart: canary; node not-measured: no canary
   mp-part-utf7: engine 403 block; python multipart: no canary; go multipart: no canary; node not-measured: no canary
   json-control: engine 403 block; python json: canary; go json: canary; node json: canary
   json-unicode: engine 403 block; python json: canary; go json: canary; node json: canary
   json-slash: engine 403 block; python json: canary; go json: canary; node json: canary
   json-dup-first: engine 403 block; python json: no canary; go json: no canary; node json: no canary
   json-dup-last: engine 403 block; python json: canary; go json: canary; node json: canary
   json-bom: engine 400 block; python json: canary; go json error *json.SyntaxError: no canary; node json error SyntaxError: no canary
   json-trailing-comma: engine 400 block; python json error JSONDecodeError: no canary; go json error *json.SyntaxError: no canary; node json error SyntaxError: no canary
   json-comment: engine 400 block; python json error JSONDecodeError: no canary; go json error *json.SyntaxError: no canary; node json error SyntaxError: no canary
   json-nested: engine 403 block; python json: canary; go json: canary; node json: canary
   json-key: engine 403 block; python json: canary; go json: canary; node json: canary
   json-utf16: engine 400 block; python json: canary; go json error *json.SyntaxError: no canary; node json error SyntaxError: no canary
   json-utf16-bom: engine 400 block; python json: canary; go json error *json.SyntaxError: no canary; node json error SyntaxError: no canary
   json-ct-plus: engine 403 block; python json: canary; go json: canary; node json: canary
   json-ct-upper: engine 403 block; python json: canary; go json: canary; node json: canary
   json-ct-charset: engine 403 block; python json: canary; go json: canary; node json: canary
   json-leading-ws: engine 403 block; python json: canary; go json: canary; node json: canary
   xml-control: engine 403 block; python xml: canary; go xml: canary; node not-measured: no canary
   xml-cdata: engine 403 block; python xml: canary; go xml: canary; node not-measured: no canary
   xml-char-dec: engine 403 block; python xml: canary; go xml: canary; node not-measured: no canary
   xml-char-hex: engine 403 block; python xml: canary; go xml: canary; node not-measured: no canary
   xml-attr: engine forwarded; python xml: canary; go xml: canary; node not-measured: no canary
   xml-decl: engine 403 block; python xml: canary; go xml: canary; node not-measured: no canary
   xml-utf16: engine 400 block; python xml: canary; go xml error *xml.SyntaxError: no canary; node not-measured: no canary
   xml-ct-text: engine 403 block; python xml: canary; go xml: canary; node not-measured: no canary
   xml-ct-soap: engine 403 block; python xml: canary; go xml: canary; node not-measured: no canary
   ct-missing-form: engine 403 block; python none: no canary; go none: no canary; node none: no canary
   ct-form-as-json: engine 400 block; python json error JSONDecodeError: no canary; go json error *json.SyntaxError: no canary; node json error SyntaxError: no canary
   ct-json-as-form: engine 403 block; python urlencoded: canary; go urlencoded: canary; node urlencoded: canary
   ct-json-as-text: engine 403 block; python none: no canary; go none: no canary; node none: no canary
   ct-form-as-text: engine 403 block; python none: no canary; go none: no canary; node none: no canary
   ct-multipart-as-form: engine 403 block; python urlencoded: canary; go urlencoded error *errors.errorString: no canary; node urlencoded: canary
   ct-two-headers: engine 403 block; python none: no canary; go none: no canary; node none: no canary
== canary-reaches-parser (A3's failure condition): 1 cases: xml-attr
== canary-reaches-backend (path or query): 0 cases: none
```

Engine state after the cases and the proof that PL2 took effect (rule 16:
the cases are answered alike at both levels, so the levels are told apart
by the rule ids in the audit log):

```
== engine stats at end (port 8101): {"inflight_small":0,"inflight_large":0,"abandoned_running":0,"kills":0,"overloads":0,"refused_before_inspection":0,"penalised_clients":0,"client_inflight_small":0,"client_inflight_large":0,"workers":{"pool":0,"busy":0,"spares":0,"recycled":0},"pending_heads":0}

# .venv/bin/python tools/step27_pl_effect.py out/s22-s27-parsing-py-pl1.audit.log out/s22-s27-parsing-py-pl2.audit.log
== rule 16: cases with an audit entry at PL1 84, at PL2 84, at both 84; matched rule-id set differs between PL1 and PL2 for 56 of 84
   rule ids matched at PL2 and in no case at PL1: 8: 920230, 920271, 941101, 941320, 942131, 942430, 942440, 942520
== load at end: load averages: 2.27 3.35 3.41
S27-PARSING-DIFF-DONE
```

The 61 old cases against their step-24 result:

```
# step-27: the 61 step-23 cases, step-24 run (before) against the final step-27 run at PL1 (after); 2026-11-28T17:30:14Z
# .venv/bin/python tools/step24_parsing_compare.py docs/logs/runs/s24-parsing-diff/results.jsonl docs/logs/runs/s27-parsing-diff/pl1/results.jsonl
== engine in front of the python backend: answer changed in 1 of 61 cases, unchanged in 60
   1 x  403 kortex-decision=block  ->  forwarded
   ovl-path-raw: 403 kortex-decision=block, event rules=900000,900001,900110,900990,900200,901111,901115,901130,901140,901141,901142,901143,901162,901168,901163,901164,901165,901171,901510,901167,901169,901170,901180,901200,901340,901400,911013,913013,920013,9 [...]
== disagreement classes against the python backend changed in 1 of 61 cases: ovl-path-raw
== engine in front of the go backend: answer changed in 1 of 61 cases, unchanged in 60
   1 x  403 kortex-decision=block  ->  forwarded
   ovl-path-raw: 403 kortex-decision=block, event rules=900000,900001,900110,900990,900200,901111,901115,901130,901140,901141,901142,901143,901162,901168,901163,901164,901165,901171,901510,901167,901169,901170,901180,901200,901340,901400,911013,913013,920013,9 [...]
== disagreement classes against the go backend changed in 1 of 61 cases: ovl-path-raw
== before: refused with no kortex marker: 0
== after: refused with no kortex marker: 0
```

Reading of the final run:

- Every engine refusal carries the kortex marker and one event: 0 cases
  without, at PL1 and PL2, in front of all three backends. One event
  (`blf-cr-only`) carries no sample id.
- The engine decided the same in front of every backend: 158 of 158.
- Canary controls: 7 of 7 blocked with 403 in front of every backend.
- `canary-reaches-backend` (path or query): 0.
- `second-request-served`: 0. Of two requests in one write the engine
  answers the first and closes; no pass event for the second.
- `canary-reaches-parser`: **1 case, `xml-attr`**, at PL1 and PL2, on the
  two backends that have an XML parser (Go, Python). This is A3's failure
  condition; see T5.
- `canary-in-file-part`: 1 case, `mp-filename`. The canary is the content
  of an uploaded file; the engine forwards it and both multipart parsers
  hand it over as file content. CRS does not inspect file contents; this
  is not a parsing difference, and it is counted on its own.
- `mp-filename-canary` (the canary as the file name) is forwarded with no
  rule match. Go reads the name as `script>`, Python as
  `script>alert(1)</script`: neither is the canary as sent, so the tool
  does not put it in a class. Listed here because an attack string in a
  file name went through uninspected. Whether the reference images block
  it: NOT MEASURED.
- `engine-forwards-backend-refuses`: 9 cases, all on Node (bare-LF heads,
  a trailing tab or folded Content-Length line, a short body, the raw
  overlong path). For 8 of them the engine re-writes the head, so Node
  gets a request it accepts; for `ovl-path-raw` the engine now forwards
  the bytes as sent and Node answers 400 through the engine as it does
  alone. The canary control of the bare-LF family is blocked.
- `view-differs`: 3 chunked cases on Python (http.server does not decode
  chunked bodies itself; known since step 23) and `host-absolute-diff` on
  Python and Node (an absolute-form target is forwarded in origin form).
  `ovl-path-raw` is no longer in this class: before T5 the Python backend
  saw `%C0%AF` through the engine and raw bytes alone.
- `engine-refuses-backend-accepts`: 122 (Python), 93 (Go), 91 (Node). The
  engine refuses or blocks; the backend alone would accept.
- Old cases: 60 of 61 answered as at step 24; `ovl-path-raw` changed from
  blocked to forwarded (T5).

### T5. What the differential found: E64, E65, E66

Failing before the fixes (33f92f0):

```
# step-27 T5: tests E64 to E66 before the fix, engine 7616436f73666a3b5f458e922be40a4d80afeb67 plus the test file; 2026-11-28T17:13:47Z; go version go1.27.4 darwin/arm64
# cd engine && go test -run 'TestE64|TestE65|TestE66' -count=1 -v .
    step27_forward_test.go:102: E64 e64-overlong-raw: sent "/static/..\xc0\xaf..\xc0\xafetc/passwd", the backend received "/static/..%C0%AF..%C0%AFetc/passwd"
    step27_forward_test.go:102: E64 e64-utf8-raw: sent "/café/menu", the backend received "/caf%C3%A9/menu"
    step27_forward_test.go:102: E64 e64-latin1-raw: sent "/caf\xe9/menu?x=\xe9", the backend received "/caf%E9/menu?x=\xe9"
    step27_forward_test.go:102: E64 e64-quote: sent "/a\"b", the backend received "/a%22b"
    step27_forward_test.go:102: E64 e64-braces: sent "/a{b}c", the backend received "/a%7Bb%7Dc"
    step27_forward_test.go:102: E64 e64-caret: sent "/a^b", the backend received "/a%5Eb"
    step27_forward_test.go:102: E64 e64-backtick: sent "/a`b", the backend received "/a%60b"
    step27_forward_test.go:102: E64 e64-empty-query: sent "/aé?", the backend received "/a%C3%A9?"
    step27_forward_test.go:102: E64 e64-absolute: sent "/café/menu?x=1", the backend received "/caf%C3%A9/menu?x=1"
    step27_forward_test.go:105: inprocess: targets 11, forwarded in another spelling: 9
    step27_forward_test.go:102: E64 e64-overlong-raw: sent "/static/..\xc0\xaf..\xc0\xafetc/passwd", the backend received "/static/..%C0%AF..%C0%AFetc/passwd"
    step27_forward_test.go:102: E64 e64-utf8-raw: sent "/café/menu", the backend received "/caf%C3%A9/menu"
    step27_forward_test.go:102: E64 e64-latin1-raw: sent "/caf\xe9/menu?x=\xe9", the backend received "/caf%E9/menu?x=\xe9"
    step27_forward_test.go:102: E64 e64-quote: sent "/a\"b", the backend received "/a%22b"
    step27_forward_test.go:102: E64 e64-braces: sent "/a{b}c", the backend received "/a%7Bb%7Dc"
    step27_forward_test.go:102: E64 e64-caret: sent "/a^b", the backend received "/a%5Eb"
    step27_forward_test.go:102: E64 e64-backtick: sent "/a`b", the backend received "/a%60b"
    step27_forward_test.go:102: E64 e64-empty-query: sent "/aé?", the backend received "/a%C3%A9?"
    step27_forward_test.go:102: E64 e64-absolute: sent "/café/menu?x=1", the backend received "/caf%C3%A9/menu?x=1"
    step27_forward_test.go:105: worker: targets 11, forwarded in another spelling: 9
--- FAIL: TestE64BackendGetsTheRequestTargetTheRulesWereGiven (0.19s)
    --- FAIL: TestE64BackendGetsTheRequestTargetTheRulesWereGiven/inprocess (0.06s)
    --- FAIL: TestE64BackendGetsTheRequestTargetTheRulesWereGiven/worker (0.13s)
    step27_forward_test.go:130: E65: the request reached the backend (as "//a/caf%C3%A9")
--- FAIL: TestE65UnforwardableTargetIsRefused (0.01s)
    step27_forward_test.go:184: E66: /__kortex/config must show "xml_attr_inspect":false, got {"backend_url":"http://127.0.0.1:52035","rule_engine":"On","blocking_paranoia":1,"detection_paranoia":1,"max_body_bytes":13107200,"max_inspected_bytes":131072,"engine_time_budget_ms":2000,"rules_dir":"crs","listen_addr":"127.0.0.1:0","e [...]
    step27_forward_test.go:169: E66: payload in an attribute: want 403, got 200 "stub-ok"
    step27_forward_test.go:172: E66: want kortex-decision=block with rule 941100 and no backend hit, got "stub-ok", backend hit true
    step27_forward_test.go:184: E66: /__kortex/config must show "xml_attr_inspect":true, got {"backend_url":"http://127.0.0.1:52042","rule_engine":"On","blocking_paranoia":1,"detection_paranoia":1,"max_body_bytes":13107200,"max_inspected_bytes":131072,"engine_time_budget_ms":2000,"rules_dir":"crs","listen_addr":"127.0.0.1:0","ev [...]
    step27_forward_test.go:169: E66: payload in an attribute: want 403, got 200 "stub-ok"
    step27_forward_test.go:172: E66: want kortex-decision=block with rule 941100 and no backend hit, got "stub-ok", backend hit true
    step27_forward_test.go:184: E66: /__kortex/config must show "xml_attr_inspect":true, got {"backend_url":"http://127.0.0.1:52049","rule_engine":"On","blocking_paranoia":1,"detection_paranoia":1,"max_body_bytes":13107200,"max_inspected_bytes":131072,"engine_time_budget_ms":2000,"rules_dir":"crs","listen_addr":"127.0.0.1:0","ev [...]
--- FAIL: TestE66XMLAttributeInspectionSwitch (0.15s)
    --- FAIL: TestE66XMLAttributeInspectionSwitch/off_(default) (0.01s)
    --- FAIL: TestE66XMLAttributeInspectionSwitch/on (0.01s)
    --- FAIL: TestE66XMLAttributeInspectionSwitch/on,_worker_mode (0.12s)
FAIL
FAIL	kortexshield/engine	0.715s
FAIL
```

Passing after (70e6477), with ten repeats:

```
# step-27 T5: tests E64 to E66 after the fix (working tree on 33f92f0c24ce60fbce245d3722caa516dc5fabe8); 2026-11-28T17:22:32Z; go version go1.27.4 darwin/arm64
# cd engine && go test -run 'TestE64|TestE65|TestE66' -count=1 -v .
    step27_forward_test.go:105: inprocess: targets 11, forwarded in another spelling: 0
    step27_forward_test.go:105: worker: targets 11, forwarded in another spelling: 0
--- PASS: TestE64BackendGetsTheRequestTargetTheRulesWereGiven (0.22s)
    --- PASS: TestE64BackendGetsTheRequestTargetTheRulesWereGiven/inprocess (0.07s)
    --- PASS: TestE64BackendGetsTheRequestTargetTheRulesWereGiven/worker (0.14s)
--- PASS: TestE65UnforwardableTargetIsRefused (0.01s)
--- PASS: TestE66XMLAttributeInspectionSwitch (0.18s)
    --- PASS: TestE66XMLAttributeInspectionSwitch/off_(default) (0.01s)
    --- PASS: TestE66XMLAttributeInspectionSwitch/on (0.01s)
    --- PASS: TestE66XMLAttributeInspectionSwitch/on,_worker_mode (0.15s)
PASS
ok  	kortexshield/engine	0.630s
# ten repeats: go test -run 'TestE64|TestE65|TestE66' -count=10 -v .
top-level PASS lines: 30, FAIL lines: 0
PASS
ok  	kortexshield/engine	3.588s
```

**E64, the forwarded target (BUG, fixed).** Since step 25 the rules are
given the request target as sent; the request was still forwarded with
Go's re-encoded path. 9 of 11 test targets reached the backend in another
spelling than the one the rules judged, in both modes. PROVEN cause of the
`ovl-path-raw` change between step 24 and run 1: the experiment is E64
itself (the backend records the target it receives: `%C0%AF` before the
fix, the raw bytes after) together with the step-24 audit entry of the
case, which shows 930100, the rule written for the `%C0%AF` spelling. Fix:
the path and query go out as sent (`URL.Opaque`); the rules' view is not
touched. E65: a target that cannot go out unchanged (it starts with `//`
and holds a byte Go escapes) is refused, `400 kortex-decision=framing`,
reason `target-not-forwardable`.

After the fix `ovl-path-raw` is forwarded as sent. DIAGNOSTIC run against
the two pinned images (blocking, PL1):

```
# Step-27 DIAGNOSTIC: xml-attr and ovl-path-raw against the pinned reference images, blocking, PL1
== 2026-11-28T17:17:36Z, macOS 27.0 Darwin 27.0.0 arm64, git d22dc94ab512e4b9749eecb736b4bbaab7fd36d7
== docker client 29.10.1 server 29.5.2 linux/arm64
== modsec-DIAGNOSTIC 2026-11-28T17:17:38Z
   image: owasp/modsecurity-crs:4.25.2-nginx-lts@sha256:6296ce685cb88ba4012998b935b25dabbd9e0ff326088c1149447102544de661 id sha256:6296ce685cb88ba4012998b935b25dabbd9e0ff326088c1149447102544de661
   rules file: /opt/owasp-crs/rules/REQUEST-901-INITIALIZATION.conf
   version string: ver:'OWASP_CRS/4.25.2
   rule 901181 in it: 1
   lines that set tx.crs_xml_attr_inspect, outside the rules directory:
      /opt/owasp-crs/docs/CHANGES.md:29:- Fully opting out of XML attribute inspection (`tx.crs_xml_attr_inspect`) requires ModSecurity v2 >= v2.9.14, once <https://github.com/owasp-modsecurity/ModSecurity/issues/3591> is fixed upstream. Until then, `ctl:ruleR [...]
   (end of list)
   control (a query the image must block): GET /?control=' OR 1=1-- -> 403
   control (a plain request the image must pass): GET /hello -> 200
   modsec xml-control: 403   (the canary as element text)
   modsec xml-attr: 200   (the canary as an attribute value)
   modsec xml-sqli-control: 403   (an SQL injection payload as element text)
   modsec xml-sqli-attr: 200   (the same payload as an attribute value)
   modsec ovl-path-pct: 403   (path traversal with %C0%AF)
   modsec ovl-path-raw: 403   (path traversal with raw bytes C0 AF)
   rule ids per case, from the image's audit log (ids below 900000 and the CRS bookkeeping rules left out):
      xml-control: 941100, 941110, 941160, 941390
      xml-attr: no audit entry
      xml-sqli-control: 942100, 942190, 942270, 942360
      xml-sqli-attr: no audit entry
      ovl-path-pct: 930100
      ovl-path-raw: 930110
== coraza-DIAGNOSTIC 2026-11-28T17:17:52Z
   image: ghcr.io/coreruleset/coraza-crs:4.25.2-nginx-lts@sha256:bfbfe70b4445c1ef1dc389c2de12cfdb194c9616746c33dc8a7131461c28f4a6 id sha256:bfbfe70b4445c1ef1dc389c2de12cfdb194c9616746c33dc8a7131461c28f4a6
   rules file: /opt/coraza/owasp-crs/rules/REQUEST-901-INITIALIZATION.conf
   version string: ver:'OWASP_CRS/4.25.2
   rule 901181 in it: 1
   lines that set tx.crs_xml_attr_inspect, outside the rules directory:
   (end of list)
   control (a query the image must block): GET /?control=' OR 1=1-- -> 403
   control (a plain request the image must pass): GET /hello -> 200
   coraza xml-control: 403   (the canary as element text)
   coraza xml-attr: 200   (the canary as an attribute value)
   coraza xml-sqli-control: 403   (an SQL injection payload as element text)
   coraza xml-sqli-attr: 200   (the same payload as an attribute value)
   coraza ovl-path-pct: 403   (path traversal with %C0%AF)
   coraza ovl-path-raw: 200   (path traversal with raw bytes C0 AF)
   rule ids per case, from the image's audit log (ids below 900000 and the CRS bookkeeping rules left out):
      xml-control: 941100, 941110, 941160, 941390
      xml-attr: no audit entry
      xml-sqli-control: 942100, 942190, 942270, 942360
      xml-sqli-attr: no audit entry
      ovl-path-pct: 930100
      ovl-path-raw: no audit entry
S27-REFERENCE-DIAG-DONE

# DIAGNOSTIC probe, 2026-11-28T17:19Z: what coraza's t:utf8toUnicode (the engine's copy,
# engine/third_party/coraza-v3.8.1-kortex) makes of an overlong sequence. CRS 930110, the
# rule ModSecurity matched on ovl-path-raw, runs t:none,t:utf8toUnicode,t:urlDecodeUni,
# t:removeNulls,t:cmdLine and then looks for ../ between separators.
# Scratch test, written into internal/transformations/ for the run and removed again:
#   func TestZZProbeUtf8ToUnicodeOverlong(t *testing.T) {
#       for _, in := range []string{"/caf\xc3\xa9", "/static/..\xc0\xaf..\xc0\xafetc/passwd", "/a\xe0\x80\xafb"} {
#           out, changed, err := utf8ToUnicode(in)
#           t.Logf("utf8ToUnicode(%q) = %q changed=%v err=%v", in, out, changed, err)
#       }
#   }
# cd engine/third_party/coraza-v3.8.1-kortex && go test ./internal/transformations/ -run TestZZProbeUtf8ToUnicodeOverlong -count=1 -v
=== RUN   TestZZProbeUtf8ToUnicodeOverlong
    zz_probe_test.go:10: utf8ToUnicode("/café") = "/caf%u00e9" changed=true err=<nil>
    zz_probe_test.go:10: utf8ToUnicode("/static/..\xc0\xaf..\xc0\xafetc/passwd") = "/static/..%ufffd%ufffd..%ufffd%ufffdetc/passwd" changed=true err=<nil>
    zz_probe_test.go:10: utf8ToUnicode("/a\xe0\x80\xafb") = "/a%ufffd%ufffd%ufffdb" changed=true err=<nil>
--- PASS: TestZZProbeUtf8ToUnicodeOverlong (0.00s)
PASS
ok  	github.com/corazawaf/coraza/v3/internal/transformations	0.242s
```

- `ovl-path-raw`: the Coraza connector passes it (no audit entry), the
  ModSecurity image blocks it with CRS 930110. The engine now stands with
  the connector. Engine against ModSecurity: 1 request differs.
  HYPOTHESIS: 930110 runs `t:utf8toUnicode` first; coraza's version turns
  the overlong bytes into `%ufffd%ufffd` (the probe at the end of the log
  above), so no `/` appears; ModSecurity's version is not read here.
  Classified UNEXPLAINED (rule 39) until the ModSecurity half is shown.
- Both images block the percent-encoded spelling with 930100, as the
  engine does (`ovl-path-slash-pct` and the other `-pct` cases above).

**E66, XML attributes (not a difference from the reference; a bypass all
the same).** Both pinned images answer 200 to `xml-attr` and 403 to its
element-text control, with an SQL injection payload as well: the engine
does what the reference does. PROVEN cause on the engine: E66, where the
switch is the only difference between the two halves (off: forwarded; on:
blocked by 941100; the element-text canary is blocked either way). CRS
v4.25.2 removes the attribute target per transaction unless
`tx.crs_xml_attr_inspect` is set (rules 901180 / 901181), and neither
image sets it (the "lines that set" lists above are empty apart from a
changelog). `KORTEX_XML_ATTR_INSPECT=on` sets it. Default off.

DIAGNOSTIC run of the differential with the switch on (engine 70e6477):

```
# Step-27: parsing differential, 61 step-23 cases, new head cases and body cases; three backends; PL1 and PL2
== 2026-11-28T17:27:33Z, macOS 27.0 Darwin 27.0.0 arm64, go version go1.27.4 darwin/arm64, Python 3.15.2, system python3 for the backend: Python 3.15.2
== git 70e6477dd29ef94e66d5909553d392e9d3394eea, tracked paths changed under engine/: 0
== engine binary sha256 a06189399ae4eeb5fa9510837576ce6cd26af2701ed56151b9dcd419b50fd1a7 built from 70e6477dd29ef94e66d5909553d392e9d3394eea with go version go1.27.4 darwin/arm64
== engine-before-python-pl1 rule29 2026-11-28T17:27:35Z load: load averages: 3.85 3.66 3.52: {"backend_url":"http://127.0.0.1:13011","rule_engine":"On","blocking_paranoia":1,"detection_paranoia":1,"max_body_bytes":13107200,"max_inspected_bytes":131072,"engine_time_budget_ms":2000,"rules_dir":"/Users/ivan/work/kortex-shield-next/engine/crs","listen_addr":"127.0.0.1:8101","events_file":"/Users/ivan/work/kortex-shield-next/out/s22-s27-parsing-py-pl1.events.jsonl","audit_log":"/Users/ivan/work/kortex-shield-next/out/s22-s27-parsing-py-pl1.audit.log","allowed_methods":"GET HEAD POST OPTIONS","max_inflight_body":8,"max_inflight_body_large":2,"body_lane_threshold":65536,"worker_mode":false,"client_max_inflight":0,"client_max_inflight_small":4,"client_max_inflight_large":1,"request_body_target_updates":165,"error_log":"","crs_test_setup":false,"head_timeout_ms":30000,"max_pending_heads":256,"xml [...]
== engine refusals without a kortex marker or without an event, and requests with no answer: 0 cases
== canary controls: 7; blocked 403 in front of every backend: 7; not blocked: none
   xml-attr: engine 403 block; python xml: canary; go xml: canary; node not-measured: no canary
== canary-reaches-parser (A3's failure condition): 0 cases: none
== canary-reaches-backend (path or query): 0 cases: none
== engine refusals without a kortex marker or without an event, and requests with no answer: 0 cases
== canary controls: 7; blocked 403 in front of every backend: 7; not blocked: none
   xml-attr: engine 403 block; python xml: canary; go xml: canary; node not-measured: no canary
== canary-reaches-parser (A3's failure condition): 0 cases: none
== canary-reaches-backend (path or query): 0 cases: none
== rule 16: cases with an audit entry at PL1 85, at PL2 85, at both 85; matched rule-id set differs between PL1 and PL2 for 57 of 85
```

With the switch on: `canary-reaches-parser` 0 at PL1 and PL2; every other
row as in the final run (classes: docs/logs/step27-parsing-diff-classes.txt,
second half).

### T6. The datasets on the final engine (70e6477)

Our own datasets, in-process and worker, PL1 and PL2, against the step-25
runs per sample id (rule 32): status, worst-case set, rule-id sets.

```
# step-27: own datasets on the step-27 engine against the step-25 runs, per sample id (rule 32)
# 2026-11-28T17:50:29Z git 70e6477dd29ef94e66d5909553d392e9d3394eea
== attacks-v0 PL1 inprocess (a=step-25 b=step-27):
# .venv/bin/python tools/step21_engine_diff.py docs/logs/runs/s25-own/attacks-v0-inprocess-pl1 docs/logs/runs/s27-own/attacks-v0-inprocess-pl1
status diffs: 0
worst-case set diffs: 0 (only-a 0 only-b 0)
== attacks-v0 PL1 worker (a=step-25 b=step-27):
# .venv/bin/python tools/step21_engine_diff.py docs/logs/runs/s25-own/attacks-v0-worker-pl1 docs/logs/runs/s27-own/attacks-v0-worker-pl1
status diffs: 0
worst-case set diffs: 0 (only-a 0 only-b 0)
== attacks-v0 PL2 inprocess (a=step-25 b=step-27):
# .venv/bin/python tools/step21_engine_diff.py docs/logs/runs/s25-own/attacks-v0-inprocess-pl2 docs/logs/runs/s27-own/attacks-v0-inprocess-pl2
status diffs: 0
worst-case set diffs: 0 (only-a 0 only-b 0)
== attacks-v0 PL2 worker (a=step-25 b=step-27):
# .venv/bin/python tools/step21_engine_diff.py docs/logs/runs/s25-own/attacks-v0-worker-pl2 docs/logs/runs/s27-own/attacks-v0-worker-pl2
status diffs: 0
worst-case set diffs: 0 (only-a 0 only-b 0)
== attacks-ct-v0 PL1 inprocess (a=step-25 b=step-27):
# .venv/bin/python tools/step21_engine_diff.py docs/logs/runs/s25-own/attacks-ct-v0-inprocess-pl1 docs/logs/runs/s27-own/attacks-ct-v0-inprocess-pl1
status diffs: 0
worst-case set diffs: 0 (only-a 0 only-b 0)
== attacks-ct-v0 PL1 worker (a=step-25 b=step-27):
# .venv/bin/python tools/step21_engine_diff.py docs/logs/runs/s25-own/attacks-ct-v0-worker-pl1 docs/logs/runs/s27-own/attacks-ct-v0-worker-pl1
status diffs: 0
worst-case set diffs: 0 (only-a 0 only-b 0)
== attacks-ct-v0 PL2 inprocess (a=step-25 b=step-27):
# .venv/bin/python tools/step21_engine_diff.py docs/logs/runs/s25-own/attacks-ct-v0-inprocess-pl2 docs/logs/runs/s27-own/attacks-ct-v0-inprocess-pl2
status diffs: 0
worst-case set diffs: 0 (only-a 0 only-b 0)
== attacks-ct-v0 PL2 worker (a=step-25 b=step-27):
# .venv/bin/python tools/step21_engine_diff.py docs/logs/runs/s25-own/attacks-ct-v0-worker-pl2 docs/logs/runs/s27-own/attacks-ct-v0-worker-pl2
status diffs: 0
worst-case set diffs: 0 (only-a 0 only-b 0)
== encoding-diff-v0 PL1 inprocess (a=step-25 b=step-27):
# .venv/bin/python tools/step21_engine_diff.py docs/logs/runs/s25-own/encoding-diff-v0-inprocess-pl1 docs/logs/runs/s27-own/encoding-diff-v0-inprocess-pl1
status diffs: 0
worst-case set diffs: 0 (only-a 0 only-b 0)
== encoding-diff-v0 PL1 worker (a=step-25 b=step-27):
# .venv/bin/python tools/step21_engine_diff.py docs/logs/runs/s25-own/encoding-diff-v0-worker-pl1 docs/logs/runs/s27-own/encoding-diff-v0-worker-pl1
status diffs: 0
worst-case set diffs: 0 (only-a 0 only-b 0)
== encoding-diff-v0 PL2 inprocess (a=step-25 b=step-27):
# .venv/bin/python tools/step21_engine_diff.py docs/logs/runs/s25-own/encoding-diff-v0-inprocess-pl2 docs/logs/runs/s27-own/encoding-diff-v0-inprocess-pl2
status diffs: 0
worst-case set diffs: 0 (only-a 0 only-b 0)
== encoding-diff-v0 PL2 worker (a=step-25 b=step-27):
# .venv/bin/python tools/step21_engine_diff.py docs/logs/runs/s25-own/encoding-diff-v0-worker-pl2 docs/logs/runs/s27-own/encoding-diff-v0-worker-pl2
status diffs: 0
worst-case set diffs: 0 (only-a 0 only-b 0)
== benign-browse-v1 PL1 inprocess (a=step-25 b=step-27):
# .venv/bin/python tools/step21_engine_diff.py docs/logs/runs/s25-own/benign-browse-v1-inprocess-pl1 docs/logs/runs/s27-own/benign-browse-v1-inprocess-pl1
status diffs: 0
worst-case set diffs: 0 (only-a 0 only-b 0)
== benign-browse-v1 PL1 worker (a=step-25 b=step-27):
# .venv/bin/python tools/step21_engine_diff.py docs/logs/runs/s25-own/benign-browse-v1-worker-pl1 docs/logs/runs/s27-own/benign-browse-v1-worker-pl1
status diffs: 0
worst-case set diffs: 0 (only-a 0 only-b 0)
== benign-browse-v1 PL2 inprocess (a=step-25 b=step-27):
# .venv/bin/python tools/step21_engine_diff.py docs/logs/runs/s25-own/benign-browse-v1-inprocess-pl2 docs/logs/runs/s27-own/benign-browse-v1-inprocess-pl2
status diffs: 0
worst-case set diffs: 0 (only-a 0 only-b 0)
== benign-browse-v1 PL2 worker (a=step-25 b=step-27):
# .venv/bin/python tools/step21_engine_diff.py docs/logs/runs/s25-own/benign-browse-v1-worker-pl2 docs/logs/runs/s27-own/benign-browse-v1-worker-pl2
status diffs: 0
worst-case set diffs: 0 (only-a 0 only-b 0)
== benign-hard-v0 PL1 inprocess (a=step-25 b=step-27):
# .venv/bin/python tools/step21_engine_diff.py docs/logs/runs/s25-own/benign-hard-v0-inprocess-pl1 docs/logs/runs/s27-own/benign-hard-v0-inprocess-pl1
status diffs: 0
worst-case set diffs: 0 (only-a 0 only-b 0)
== benign-hard-v0 PL1 worker (a=step-25 b=step-27):
# .venv/bin/python tools/step21_engine_diff.py docs/logs/runs/s25-own/benign-hard-v0-worker-pl1 docs/logs/runs/s27-own/benign-hard-v0-worker-pl1
status diffs: 0
worst-case set diffs: 0 (only-a 0 only-b 0)
== benign-hard-v0 PL2 inprocess (a=step-25 b=step-27):
# .venv/bin/python tools/step21_engine_diff.py docs/logs/runs/s25-own/benign-hard-v0-inprocess-pl2 docs/logs/runs/s27-own/benign-hard-v0-inprocess-pl2
status diffs: 0
worst-case set diffs: 0 (only-a 0 only-b 0)
== benign-hard-v0 PL2 worker (a=step-25 b=step-27):
# .venv/bin/python tools/step21_engine_diff.py docs/logs/runs/s25-own/benign-hard-v0-worker-pl2 docs/logs/runs/s27-own/benign-hard-v0-worker-pl2
status diffs: 0
worst-case set diffs: 0 (only-a 0 only-b 0)
# rule-id sets per sample, step-25 runs (a) against step-27 runs (b)
# .venv/bin/python tools/step25_ruleid_diff.py docs/logs/runs/s25-own docs/logs/runs/s27-own <20 runs>
== attacks-v0-inprocess-pl1: samples with an audit entry a=954 b=954; rule-id set differs for 0; ids gained in b: none; ids lost in b: none
== attacks-v0-worker-pl1: samples with an audit entry a=954 b=954; rule-id set differs for 0; ids gained in b: none; ids lost in b: none
== attacks-v0-inprocess-pl2: samples with an audit entry a=1024 b=1024; rule-id set differs for 0; ids gained in b: none; ids lost in b: none
== attacks-v0-worker-pl2: samples with an audit entry a=1024 b=1024; rule-id set differs for 0; ids gained in b: none; ids lost in b: none
== attacks-ct-v0-inprocess-pl1: samples with an audit entry a=292 b=292; rule-id set differs for 0; ids gained in b: none; ids lost in b: none
== attacks-ct-v0-worker-pl1: samples with an audit entry a=292 b=292; rule-id set differs for 0; ids gained in b: none; ids lost in b: none
== attacks-ct-v0-inprocess-pl2: samples with an audit entry a=313 b=313; rule-id set differs for 0; ids gained in b: none; ids lost in b: none
== attacks-ct-v0-worker-pl2: samples with an audit entry a=313 b=313; rule-id set differs for 0; ids gained in b: none; ids lost in b: none
== encoding-diff-v0-inprocess-pl1: samples with an audit entry a=137 b=137; rule-id set differs for 0; ids gained in b: none; ids lost in b: none
== encoding-diff-v0-worker-pl1: samples with an audit entry a=137 b=137; rule-id set differs for 0; ids gained in b: none; ids lost in b: none
== encoding-diff-v0-inprocess-pl2: samples with an audit entry a=147 b=147; rule-id set differs for 0; ids gained in b: none; ids lost in b: none
== encoding-diff-v0-worker-pl2: samples with an audit entry a=147 b=147; rule-id set differs for 0; ids gained in b: none; ids lost in b: none
== benign-browse-v1-inprocess-pl1: samples with an audit entry a=124 b=124; rule-id set differs for 0; ids gained in b: none; ids lost in b: none
== benign-browse-v1-worker-pl1: samples with an audit entry a=124 b=124; rule-id set differs for 0; ids gained in b: none; ids lost in b: none
== benign-browse-v1-inprocess-pl2: samples with an audit entry a=124 b=124; rule-id set differs for 0; ids gained in b: none; ids lost in b: none
== benign-browse-v1-worker-pl2: samples with an audit entry a=124 b=124; rule-id set differs for 0; ids gained in b: none; ids lost in b: none
== benign-hard-v0-inprocess-pl1: samples with an audit entry a=22 b=22; rule-id set differs for 0; ids gained in b: none; ids lost in b: none
== benign-hard-v0-worker-pl1: samples with an audit entry a=22 b=22; rule-id set differs for 0; ids gained in b: none; ids lost in b: none
== benign-hard-v0-inprocess-pl2: samples with an audit entry a=78 b=78; rule-id set differs for 0; ids gained in b: none; ids lost in b: none
== benign-hard-v0-worker-pl2: samples with an audit entry a=78 b=78; rule-id set differs for 0; ids gained in b: none; ids lost in b: none
== total samples with a different rule-id set: 0
```

Rule 29 for one of the 20 runs, and its stats after the run (rule 50):

```
== attacks-v0-inprocess-pl1 rule29 2026-11-28T17:29:58Z load: load averages: 2.45 3.22 3.37: {"backend_url":"http://127.0.0.1:13004","rule_engine":"On","blocking_paranoia":1,"detection_paranoia":1,"max_body_bytes":13107200,"max_inspected_bytes":131072,"engine_time_budget_ms":2000,"rules_dir":"/Users/ivan/work/kortex-shield-next/engine/crs","listen_addr":"127.0.0.1:8097","events_file":"/Users/ivan/work/kortex-shield-next/out/s22-s27-attacks-v0-inprocess-pl1.events.jsonl","audit_log":"/Users/ivan/work/kortex-shield-next/out/s22-s27-attacks-v0-inprocess-pl1.audit.log","allowed_methods":"GET HEAD POST OPTIONS","max_inflight_body":8,"max_inflight_body_large":2,"body_lane_threshold":65536,"worker_mode":false,"client_max_inflight":0,"client_max_inflight_small":4,"client_max_inflight_large":1,"request_body_target_updates":165,"error_log":"","crs_test_setup":false,"head_timeout_ms":30000,"max_pen [...]
== attacks-v0-inprocess-pl1 stats after run: {"inflight_small":0,"inflight_large":0,"abandoned_running":0,"kills":0,"overloads":0,"refused_before_inspection":0,"penalised_clients":0,"client_inflight_small":0,"client_inflight_large":0,"workers":{"pool":0,"busy":0,"spares":0,"recycled":0},"pending_heads":0}
```

Rates (unchanged from baseline v2.0; natural benign and hard benign are
kept apart, rule 14; in-sample labels as printed):

```
attacks-v0-inprocess-pl1: requests 1054, distinct payloads 527; outcomes: waf_block 954, waf_pass 100
    recall best case (only waf_block) 954/1054 = 90.51%; worst case (every outcome that is not a pass) 954/1054 = 90.51%  [IN-SAMPLE for the REQUEST_BODY target choice of step 18]
    recall best case (only waf_block) 954/1054 = 90.51%; worst case (every outcome that is not a pass) 954/1054 = 90.51%  [IN-SAMPLE for the REQUEST_BODY target choice of step 18]
attacks-ct-v0-inprocess-pl1: requests 320, distinct payloads 40; outcomes: waf_block 292, waf_pass 28
    recall best case (only waf_block) 292/320 = 91.25%; worst case (every outcome that is not a pass) 292/320 = 91.25%  [IN-SAMPLE for the REQUEST_BODY target choice of step 18]
    recall best case (only waf_block) 292/320 = 91.25%; worst case (every outcome that is not a pass) 292/320 = 91.25%  [IN-SAMPLE for the REQUEST_BODY target choice of step 18]
encoding-diff-v0-inprocess-pl1: requests 192, distinct payloads 16; outcomes: error 10, waf_block 137, waf_pass 45
    blocked 137 of 192; not passed 147 of 192 (chosen cases: counts, not a rate, rule 35)
    blocked 137 of 192; not passed 147 of 192 (chosen cases: counts, not a rate, rule 35)
benign-browse-v1-inprocess-pl1: requests 774, distinct endpoints 313; outcomes: waf_block 124, waf_pass 650
    potential false positives (natural benign, held-out): best case (only waf_block) 124/774 = 16.02%; worst case (every outcome that is not a pass) 124/774 = 16.02%
    potential false positives (natural benign, held-out): best case (only waf_block) 124/774 = 16.02%; worst case (every outcome that is not a pass) 124/774 = 16.02%
benign-hard-v0-inprocess-pl1: requests 180, distinct endpoints 2; outcomes: waf_block 22, waf_pass 158
    potential false positives (hard benign, held-out): best case (only waf_block) 22/180 = 12.22%; worst case (every outcome that is not a pass) 22/180 = 12.22%
    potential false positives (hard benign, held-out): best case (only waf_block) 22/180 = 12.22%; worst case (every outcome that is not a pass) 22/180 = 12.22%
attacks-v0-inprocess-pl2: requests 1054, distinct payloads 527; outcomes: waf_block 1024, waf_pass 30
    recall best case (only waf_block) 1024/1054 = 97.15%; worst case (every outcome that is not a pass) 1024/1054 = 97.15%  [IN-SAMPLE for the REQUEST_BODY target choice of step 18]
    recall best case (only waf_block) 1024/1054 = 97.15%; worst case (every outcome that is not a pass) 1024/1054 = 97.15%  [IN-SAMPLE for the REQUEST_BODY target choice of step 18]
attacks-ct-v0-inprocess-pl2: requests 320, distinct payloads 40; outcomes: waf_block 313, waf_pass 7
    recall best case (only waf_block) 313/320 = 97.81%; worst case (every outcome that is not a pass) 313/320 = 97.81%  [IN-SAMPLE for the REQUEST_BODY target choice of step 18]
    recall best case (only waf_block) 313/320 = 97.81%; worst case (every outcome that is not a pass) 313/320 = 97.81%  [IN-SAMPLE for the REQUEST_BODY target choice of step 18]
encoding-diff-v0-inprocess-pl2: requests 192, distinct payloads 16; outcomes: error 10, waf_block 147, waf_pass 35
    blocked 147 of 192; not passed 157 of 192 (chosen cases: counts, not a rate, rule 35)
    blocked 147 of 192; not passed 157 of 192 (chosen cases: counts, not a rate, rule 35)
benign-browse-v1-inprocess-pl2: requests 774, distinct endpoints 313; outcomes: waf_block 124, waf_pass 650
    potential false positives (natural benign, held-out): best case (only waf_block) 124/774 = 16.02%; worst case (every outcome that is not a pass) 124/774 = 16.02%
    potential false positives (natural benign, held-out): best case (only waf_block) 124/774 = 16.02%; worst case (every outcome that is not a pass) 124/774 = 16.02%
benign-hard-v0-inprocess-pl2: requests 180, distinct endpoints 2; outcomes: waf_block 78, waf_pass 102
    potential false positives (hard benign, held-out): best case (only waf_block) 78/180 = 43.33%; worst case (every outcome that is not a pass) 78/180 = 43.33%
    potential false positives (hard benign, held-out): best case (only waf_block) 78/180 = 43.33%; worst case (every outcome that is not a pass) 78/180 = 43.33%
```

wcp (benign-labelled external traffic; every block is a potential false
positive, rule 46), in-process and worker, and per sample against the
step-25 runs:

```
== rate table (benign-labelled external traffic; every block is a potential false positive)
benign-wcp-v0 PL1 inprocess: n=20000 waf_block=2184 waf_deny_status=52 inconsistent=0 error=1 waf_fail_closed_413=28 waf_fail_closed_415=19 waf_fail_closed_400=0 waf_fail_closed_503_timeout=0 waf_fail_closed_503_overload=0 waf_pass=17716 other=0
    FP rate best case (errors, deny_status, inconsistent, fail-closed answers not flagged) 2184/20000 = 10.92%; worst case (all flagged) 2284/20000 = 11.42%
benign-wcp-v0 PL1 worker: n=20000 waf_block=2184 waf_deny_status=52 inconsistent=0 error=1 waf_fail_closed_413=28 waf_fail_closed_415=19 waf_fail_closed_400=0 waf_fail_closed_503_timeout=0 waf_fail_closed_503_overload=0 waf_pass=17716 other=0
    FP rate best case (errors, deny_status, inconsistent, fail-closed answers not flagged) 2184/20000 = 10.92%; worst case (all flagged) 2284/20000 = 11.42%
benign-wcp-v0 PL1 rule-id sets, in-process vs worker: 0 ids differ of 20000
benign-wcp-v0 PL2 inprocess: n=20000 waf_block=8866 waf_deny_status=52 inconsistent=1 error=1 waf_fail_closed_413=28 waf_fail_closed_415=19 waf_fail_closed_400=0 waf_fail_closed_503_timeout=0 waf_fail_closed_503_overload=0 waf_pass=11033 other=0
    FP rate best case (errors, deny_status, inconsistent, fail-closed answers not flagged) 8866/20000 = 44.33%; worst case (all flagged) 8967/20000 = 44.84%
benign-wcp-v0 PL2 worker: n=20000 waf_block=8866 waf_deny_status=52 inconsistent=1 error=1 waf_fail_closed_413=28 waf_fail_closed_415=19 waf_fail_closed_400=0 waf_fail_closed_503_timeout=0 waf_fail_closed_503_overload=0 waf_pass=11033 other=0
    FP rate best case (errors, deny_status, inconsistent, fail-closed answers not flagged) 8866/20000 = 44.33%; worst case (all flagged) 8967/20000 = 44.84%
benign-wcp-v0 PL2 rule-id sets, in-process vs worker: 0 ids differ of 20000
benign-wcp-v1 PL1 inprocess: n=10000 waf_block=1091 waf_deny_status=25 inconsistent=0 error=0 waf_fail_closed_413=17 waf_fail_closed_415=0 waf_fail_closed_400=0 waf_fail_closed_503_timeout=0 waf_fail_closed_503_overload=0 waf_pass=8867 other=0
    FP rate best case (errors, deny_status, inconsistent, fail-closed answers not flagged) 1091/10000 = 10.91%; worst case (all flagged) 1133/10000 = 11.33%
benign-wcp-v1 PL1 worker: n=10000 waf_block=1091 waf_deny_status=25 inconsistent=0 error=0 waf_fail_closed_413=17 waf_fail_closed_415=0 waf_fail_closed_400=0 waf_fail_closed_503_timeout=0 waf_fail_closed_503_overload=0 waf_pass=8867 other=0
    FP rate best case (errors, deny_status, inconsistent, fail-closed answers not flagged) 1091/10000 = 10.91%; worst case (all flagged) 1133/10000 = 11.33%
benign-wcp-v1 PL1 rule-id sets, in-process vs worker: 0 ids differ of 10000
benign-wcp-v1 PL2 inprocess: n=10000 waf_block=4438 waf_deny_status=25 inconsistent=0 error=0 waf_fail_closed_413=17 waf_fail_closed_415=0 waf_fail_closed_400=0 waf_fail_closed_503_timeout=0 waf_fail_closed_503_overload=0 waf_pass=5520 other=0
    FP rate best case (errors, deny_status, inconsistent, fail-closed answers not flagged) 4438/10000 = 44.38%; worst case (all flagged) 4480/10000 = 44.80%
benign-wcp-v1 PL2 worker: n=10000 waf_block=4438 waf_deny_status=25 inconsistent=0 error=0 waf_fail_closed_413=17 waf_fail_closed_415=0 waf_fail_closed_400=0 waf_fail_closed_503_timeout=0 waf_fail_closed_503_overload=0 waf_pass=5520 other=0
    FP rate best case (errors, deny_status, inconsistent, fail-closed answers not flagged) 4438/10000 = 44.38%; worst case (all flagged) 4480/10000 = 44.80%
benign-wcp-v1 PL2 rule-id sets, in-process vs worker: 0 ids differ of 10000
== step-25 (docs/logs/runs/s25-parity, in-process) against step-27 (docs/logs/runs/s27-parity, in-process), per sample
benign-wcp-v0 PL1: 20000 ids; status diffs 0; outcome diffs 0; rule-id set diffs 0
benign-wcp-v0 PL2: 20000 ids; status diffs 0; outcome diffs 0; rule-id set diffs 0
benign-wcp-v1 PL1: 10000 ids; status diffs 0; outcome diffs 0; rule-id set diffs 0
benign-wcp-v1 PL2: 10000 ids; status diffs 0; outcome diffs 0; rule-id set diffs 0
S27-PARITY-DONE
```

attacks-v1 (held-out, frozen) on the final engine, and per sample against
the step-26 runs:

```
# Step-27: attacks-v1 on the engine, blocking, PL1 and PL2, in-process and worker
== 2026-11-28T17:50:37Z, macOS 27.0 Darwin 27.0.0 arm64, go version go1.27.4 darwin/arm64, Python 3.15.2, load at start: load averages: 3.34 3.43 3.47
== git 70e6477dd29ef94e66d5909553d392e9d3394eea, tracked paths changed in the working tree: 15, under engine/: 0
== manifest data/attacks-v1/manifest.jsonl sha256 7a82a51622e311f26f00fffff1f39b718f1528d907a20da89e30372cc6723066 (frozen: 7a82a51622e311f26f00fffff1f39b718f1528d907a20da89e30372cc6723066), 2670 requests
== engine binary sha256 a06189399ae4eeb5fa9510837576ce6cd26af2701ed56151b9dcd419b50fd1a7 built from 70e6477dd29ef94e66d5909553d392e9d3394eea with go version go1.27.4 darwin/arm64
waf_block: 2214
waf_pass: 456
waf_block: 2214
waf_pass: 456
== diff attacks-v1 PL1 (a=inprocess b=worker):
status diffs: 0
worst-case set diffs: 0 (only-a 0 only-b 0)
waf_block: 2444
waf_pass: 226
waf_block: 2444
waf_pass: 226
== diff attacks-v1 PL2 (a=inprocess b=worker):
status diffs: 0
worst-case set diffs: 0 (only-a 0 only-b 0)
# step-27: attacks-v1 on the step-27 engine against the step-26 runs, per sample id (rule 32)
# 2026-11-28T17:51:00Z git 70e6477dd29ef94e66d5909553d392e9d3394eea
== attacks-v1-inprocess-pl1 (a=step-26 b=step-27):
# .venv/bin/python tools/step21_engine_diff.py docs/logs/runs/s26-engine/attacks-v1-inprocess-pl1 docs/logs/runs/s27-attacks-v1/attacks-v1-inprocess-pl1
status diffs: 0
worst-case set diffs: 0 (only-a 0 only-b 0)
== attacks-v1-worker-pl1 (a=step-26 b=step-27):
# .venv/bin/python tools/step21_engine_diff.py docs/logs/runs/s26-engine/attacks-v1-worker-pl1 docs/logs/runs/s27-attacks-v1/attacks-v1-worker-pl1
status diffs: 0
worst-case set diffs: 0 (only-a 0 only-b 0)
== attacks-v1-inprocess-pl2 (a=step-26 b=step-27):
# .venv/bin/python tools/step21_engine_diff.py docs/logs/runs/s26-engine/attacks-v1-inprocess-pl2 docs/logs/runs/s27-attacks-v1/attacks-v1-inprocess-pl2
status diffs: 0
worst-case set diffs: 0 (only-a 0 only-b 0)
== attacks-v1-worker-pl2 (a=step-26 b=step-27):
# .venv/bin/python tools/step21_engine_diff.py docs/logs/runs/s26-engine/attacks-v1-worker-pl2 docs/logs/runs/s27-attacks-v1/attacks-v1-worker-pl2
status diffs: 0
worst-case set diffs: 0 (only-a 0 only-b 0)
# rule-id sets per sample, step-26 runs (a) against step-27 runs (b)
== attacks-v1-inprocess-pl1: samples with an audit entry a=2214 b=2214; rule-id set differs for 0; ids gained in b: none; ids lost in b: none
== attacks-v1-worker-pl1: samples with an audit entry a=2214 b=2214; rule-id set differs for 0; ids gained in b: none; ids lost in b: none
== attacks-v1-inprocess-pl2: samples with an audit entry a=2444 b=2444; rule-id set differs for 0; ids gained in b: none; ids lost in b: none
== attacks-v1-worker-pl2: samples with an audit entry a=2444 b=2444; rule-id set differs for 0; ids gained in b: none; ids lost in b: none
== total samples with a different rule-id set: 0
```

The CRS v4.25.2 regression suite (A1) on the final engine, in-process and
worker, against the final step-25 runs per test:

```
# Step-25: CRS v4.25.2 regression suite, runs: engine-strict engine-worker
== 2026-11-28T17:51:00Z, macOS 27.0 Darwin 27.0.0 arm64, go version go1.27.4 darwin/arm64, load at start: load averages: 3.93 3.57 3.52
## run engine-strict: engine, in-process, no overrides
== engine-strict rule29 2026-11-28T17:51:02Z load: load averages: 3.93 3.57 3.52: {"backend_url":"http://127.0.0.1:13025","rule_engine":"DetectionOnly","blocking_paranoia":4,"detection_paranoia":4,"max_body_bytes":13107200,"max_inspected_bytes":131072,"engine_time_budget_ms":2000,"rules_dir":"/Users/ivan/work/kortex-shield-next/engine/crs","listen_addr":"127.0.0.1:18025","events_file":"/Users/ivan/work/kortex-shield- [...]
== engine-strict attempt 1: go-ftw aborted (exit 1, 'Error: retry-once') at test 959100-1, which failed twice; counted as failed, excluded, run restarted
== engine-strict attempt 2: go-ftw aborted (exit 1, 'Error: retry-once') at test 959100-3, which failed twice; counted as failed, excluded, run restarted
== engine-strict: tests listed 4987, run 4987, passed 4862, failed 125, ignored 0, skipped 0, forced-pass 0, forced-fail 0; pass rate (denominator: every test go-ftw lists as run, the ones that stopped it included) 4862/4987 = 97.49%; 2 of the failed tests stopped go-ftw (retry_once, failed twice) and were excluded from the restart: 959100-1 959100-3
== failed by rule file prefix: 901: 4, 920: 25, 922: 3, 932: 4, 942: 11, 950: 9, 951: 20, 952: 9, 953: 9, 954: 7, 955: 10, 956: 12, 959: 2
## run engine-worker: engine, worker mode, no overrides
== engine-worker rule29 2026-11-28T17:51:30Z load: load averages: 3.56 3.53 3.51: {"backend_url":"http://127.0.0.1:13025","rule_engine":"DetectionOnly","blocking_paranoia":4,"detection_paranoia":4,"max_body_bytes":13107200,"max_inspected_bytes":131072,"engine_time_budget_ms":2000,"rules_dir":"/Users/ivan/work/kortex-shield-next/engine/crs","listen_addr":"127.0.0.1:18025","events_file":"/Users/ivan/work/kortex-shield- [...]
== engine-worker attempt 1: go-ftw aborted (exit 1, 'Error: retry-once') at test 959100-1, which failed twice; counted as failed, excluded, run restarted
== engine-worker attempt 2: go-ftw aborted (exit 1, 'Error: retry-once') at test 959100-3, which failed twice; counted as failed, excluded, run restarted
== engine-worker: tests listed 4987, run 4987, passed 4862, failed 125, ignored 0, skipped 0, forced-pass 0, forced-fail 0; pass rate (denominator: every test go-ftw lists as run, the ones that stopped it included) 4862/4987 = 97.49%; 2 of the failed tests stopped go-ftw (retry_once, failed twice) and were excluded from the restart: 959100-1 959100-3
== failed by rule file prefix: 901: 4, 920: 25, 922: 3, 932: 4, 942: 11, 950: 9, 951: 20, 952: 9, 953: 9, 954: 7, 955: 10, 956: 12, 959: 2
== done 2026-11-28T17:52:00Z, load: load averages: 3.37 3.48 3.49
# step-27: the CRS v4.25.2 regression suite on the step-27 engine against the final step-25 runs, per test
# 2026-11-28T17:52:01Z git 70e6477dd29ef94e66d5909553d392e9d3394eea
$ .venv/bin/python tools/step25_ftw_summary.py diff docs/logs/runs/s25-ftw-fixed/engine-strict docs/logs/runs/s27-ftw/engine-strict
== engine-strict against engine-strict: 4987 test ids in the union, 0 with a different result, 0 with the same result and a different logged rule-id set
$ .venv/bin/python tools/step25_ftw_summary.py diff docs/logs/runs/s25-ftw-fixed/engine-worker docs/logs/runs/s27-ftw/engine-worker
== engine-worker against engine-worker: 4987 test ids in the union, 0 with a different result, 0 with the same result and a different logged rule-id set
$ .venv/bin/python tools/step25_ftw_summary.py diff docs/logs/runs/s27-ftw/engine-strict docs/logs/runs/s27-ftw/engine-worker
== engine-strict against engine-worker: 4987 test ids in the union, 0 with a different result, 0 with the same result and a different logged rule-id set
```

### Final suites

Go, engine at the final commit:

```
== 2026-11-28T17:52:26Z git 77f274a709cb19de422a2bdafdb7d1c7b37a5d53, tracked paths changed under engine/: 0; go version go1.27.4 darwin/arm64 load at start: load averages: 3.18 3.42 3.47
$ go test -count=1 -v -timeout 900s ./...
PASS
ok  	kortexshield/engine	78.708s
== exit 0 2026-11-28T17:53:46Z load at end: load averages: 1.81 2.95 3.28
80 PASS / 0 FAIL / 5 SKIP
```

Go with the wcp fixture body (the engine changed, so the fixture tests are
run again):

```
== 2026-11-28T17:54:06Z git 77f274a709cb19de422a2bdafdb7d1c7b37a5d53, tracked paths changed under engine/: 0; go version go1.27.4 darwin/arm64 load at start: load averages: 1.73 2.85 3.24
$ KORTEX_TEST_WCP_BODY=<fixture> go test -count=1 -v -timeout 900s ./...
PASS
ok  	kortexshield/engine	361.536s
== exit 0 2026-11-28T18:00:07Z load at end: load averages: 6.68 5.32 4.27
85 PASS / 0 FAIL / 0 SKIP
```

The 5 tests skipped without the fixture (all 5 run in the fixture run: 85
PASS, 0 SKIP):

```
--- SKIP: TestE16BodyProcessingBoundedByTimeBudget (0.00s)
--- SKIP: TestE17AbandonedCallOwnsTransaction (0.00s)
--- SKIP: TestE19OverloadCapImmediate (0.01s)
--- SKIP: TestE20OverloadRecovery (0.01s)
--- SKIP: TestE21BenignPromptOnCapReachedEngine (0.01s)
```

pytest:

```
== 2026-11-28T18:00:07Z git 77f274a709cb19de422a2bdafdb7d1c7b37a5d53 Python 3.15.2 load at start: load averages: 6.68 5.32 4.27
$ .venv/bin/python -m pytest -q
......................................................................ss [ 25%]
..s..................................................................... [ 51%]
........................................................................ [ 76%]
..............................................................----------------------------------------
.Exception occurred during processing of request from ('127.0.0.1', 56881)
..        [100%]
278 passed, 4 skipped in 62.67s (0:01:02)
== exit 0 2026-11-28T18:01:11Z load at end: load averages: 6.53 5.57 4.44
```

A first run of the Go suite after the T5 changes had 1 FAIL; the log is
kept (docs/logs/step27-t5-go-test-run1.log):

```
# NOTE (added after the run): this first run of the suite has 1 FAIL, TestT3iExplicitCapClampedToHalfLargeLane:
#   "dial tcp 127.0.0.1:63674: connect: can't assign requested address".
# It was started straight after ten repeats of E63 to E66 (docs/logs/step27-e63-e66-x10-port-exhaustion.log:
# E63 opens 19,579 connections per run; from the fourth repeat on every test fails with the same dial error).
# HYPOTHESIS: the host had no free local port left (16,384 ephemeral ports, closed sockets wait 30 s).
# Not a result of the engine change: the rerun, docs/logs/step27-t5-go-test.log, is 80 PASS / 0 FAIL / 5 SKIP.
```

Pre-push scan (rules 25, 51) over the commits of this step. It is run
once more over the whole range, this report included, before the push:

```
$ bash tools/prepush_scan.sh --range origin/main..HEAD | grep -v "large file"   (the 8 commits of this step before the last one; 10 informational "large file" notes left out, none over the 5 MB limit)
prepush: OK, 170 blob(s) in origin/main..HEAD scanned
$ bash tools/prepush_scan.sh   (staged: the files of the last commit, without this report)
prepush: OK, 7 staged path(s) scanned
```

## Deviations from instructions

1. **T5 was not in the plan.** The plan said that no rule or setting
   changes in response to a result. The first run of the differential
   found a bug in the engine's request path (E64) and a bypass the engine
   shares with the reference configuration (E66). A plan addendum was
   written and committed, with the failing tests, the design note and the
   config note, before any of the changes (33f92f0). E64 and E65 change
   no setting. E66 adds a switch that is off by default: the default
   configuration and every baseline number are as before, and the runs
   with the switch on are labelled DIAGNOSTIC.
2. **E61 and E62 were not in the plan either.** Found while writing E58:
   the gate read heads inside the accept loop, so one unfinished head
   stopped every other connection. Design and config notes were committed
   with the failing tests (52b4b42), before the fix.
3. **The differential was run three times, and the dataset runs twice.**
   Run 1 (engine 7616436) is kept beside the final run because it is the
   reading that led to T5. The own-dataset and wcp runs made on 7616436
   were replaced by the runs on the final engine and are not kept (as the
   addendum says); nothing is claimed from them. The raw runs of 7616436
   are in the history of commit 7616436; the files now hold the runs of
   the final engine.
4. **One tool was changed after its first run.** The differential counted
   `blf-cr-only` as a refusal without an event; the event exists with an
   empty sample id. The tool now also takes events without an id by their
   position in the events file (unit test added). The count of run 1 (1
   case) stands in its log; the final run counts 0.
5. **The plan's "heads that end with a bare-LF blank line are added to
   E45"** was done as a new test, E63, with its own seed, so that E45
   stays byte for byte what it was (rule 5 in spirit: no test changed).
6. **One probe before the plan** (hand-written requests to the local
   engine, quoted in the design note) informed the defaults of T1. Stated
   in the plan.
7. **One DIAGNOSTIC run was made while the addendum was being written**,
   before its commit: the two reference images on `xml-attr` and
   `ovl-path-raw`. It changed no engine code; its result is quoted in the
   addendum.
8. **A suite run failed and was repeated.** I ran ten repeats of E63 to
   E66 in one go; E63 opens 19,579 connections per run, and from the
   fourth repeat on every test failed with "can't assign requested
   address". The Go suite started straight after failed one test with the
   same error. HYPOTHESIS (not proven): the host ran out of local ports.
   Both logs are kept; the repeat of the suite is clean, and the ten
   repeats without E63 are 30 PASS. E63 and E45 should not be repeated in
   a loop on this host.
9. **Two step-25 and step-26 scripts got settable output paths**
   (`tools/step25_own_compare.sh`, `tools/run_step26_attacks_v1.sh`), with
   the old paths as defaults, so that this step could reuse them.
10. E57's premise check takes 10 s per run (it waits for bare net/http to
    close an idle connection).

## UNVERIFIED items

- **Why ModSecurity blocks `ovl-path-raw` and coraza does not.**
  ModSecurity's audit log names 930110; coraza's `t:utf8toUnicode` is
  shown to turn the overlong bytes into `%ufffd%ufffd`. What ModSecurity's
  transformation yields was not read or run. HYPOTHESIS.
- **The wording of CRS opt-in rule 900510.** crs-setup.conf.example is not
  in the repository; the engine renders its own `SecAction` with that id.
  The effect is measured (E66).
- **The CRS advisory and the rules file disagree on the LTS default** for
  XML attribute inspection (advisory: enabled; rules file of v4.25.2:
  removed unless set). Measured on the engine and both images: not
  inspected unless set. Which text is out of date was not looked into.
- **The cause of the failed suite run** (deviation 8): HYPOTHESIS.
- **Application frameworks.** A3 names "frameworks"; the three backends
  are HTTP stacks with standard-library parsers. Nothing is known from
  this step about Express, Django, Spring or any body-parsing library.
- **Node for multipart and XML**: NOT MEASURED (no standard parser).
- **`mp-filename-canary` on the reference images**: NOT MEASURED.
- **`KORTEX_XML_ATTR_INSPECT=on` on the datasets**: NOT MEASURED. It was
  run on the 158 cases only; its effect on benign XML traffic (new
  blocks, potential false positives) is unknown.
- **The cap on waiting heads under real load**: E62 tests it with a cap of
  2. The default of 256 was not load-tested.

## Questions for instructor

Defaults I chose are marked "default:"; each can be reversed.

1. **XML attributes (A3's one bypass).** default: the switch exists and is
   off, as in the reference images. Turning `KORTEX_XML_ATTR_INSPECT` on
   by default closes the bypass (0 of 62) and makes the engine differ from
   both reference images on XML attribute payloads; upstream ships the
   same inspection unconditionally from v4.28.0. It needs a run on the
   benign datasets first. Turn it on?
2. **The forwarded target (E64).** default: forward what was sent, so the
   rules and the backend see the same bytes and the rules' view of step 25
   stays. The other way, to judge and forward Go's re-encoded path, would
   block `ovl-path-raw` again (as at step 24 and as ModSecurity does) and
   would change what the rules see for every path with such bytes. Keep
   the default?
3. **`OPTIONS *`.** default: refused at the gate (E57). Keep?
4. **Unreadable heads.** default: answered `400 kortex-decision=framing`
   and logged (E58), with the 30 s limit as a setting. Keep?
5. **Bare LF.** default: still accepted when it hides no framing problem;
   the end of the head is read as Go reads it (E59, E60, E63). Node
   refuses such heads on its own; behind the engine it gets a re-written
   head. Keep accepting?
6. **One status for parser refusals.** default: 400 for all. Keep?
7. **The cap on waiting heads.** default: 256, global. One client can
   fill it. Build a per-client limit?
8. **The 10 raw-space requests of encoding-diff-v0.** They are refused by
   the gate and never judged by the rules (bare net/http refuses them
   too). Accept that as their result, or build a variant set the gate
   lets through?
9. **File contents and file names.** `mp-filename` (payload as file
   content) and `mp-filename-canary` (payload as file name) are forwarded;
   CRS does not inspect either at PL1 or PL2. In scope for A3, or a
   separate bar?
10. **Frameworks in scope.** default: HTTP stacks only. Add application
    frameworks (which ones) to A3's list?
11. **`ovl-path-raw` against ModSecurity** (1 request, UNEXPLAINED): worth
    a step to read ModSecurity's `utf8toUnicode` and decide whether the
    engine's coraza copy should follow it?
