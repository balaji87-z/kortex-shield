# Step-25 report

Host and versions (rule 43: the host did not change since step 24; no
container image was used in this step). macOS 27.0 (26A425), Darwin 27.0.0
arm64, Apple M6 12 cores; go1.27.4 darwin/arm64; Python 3.15.2, pytest
9.2.0. Docker: present on the host, not used. Network: used once, by
`tools/fetch/fetch_crs_regression.sh` (the CRS tarball and three Go tools);
every other `go` command ran with `GOPROXY=off`. Engine: coraza v3.8.1 with
the step-23 patch (engine/third_party/coraza-v3.8.1-kortex) + CRS 4.25.2
(engine/RULES.sha256 unchanged, 7c55eb49...16333d7). Engine binary of the
final runs: sha256 761ef5ad...702792fb (engine code of 497d585). Engine
binary of the first runs: c0ad8dd6...6887a4 (c1bb0c5). Rule 29: every run
log carries the engine's `/__kortex/config` output; one is quoted below.

The step-25 brief is the instructor's message "do all 4", answering the
four candidates offered for the next stage. They are done as steps 25 to
28 in the order offered; this is the first, acceptance A1, the CRS
regression suite against the engine. The brief is not a file in the
repository; the plan written from it is docs/plan-step25-crs-regression.md
(committed before any run). Work was done in the checkout
`~/work/kortex-shield-next`. The wcp manifests and the fixture body are not
committed (rules 25, 51) and were read from `~/work/kortex-shield-dev`.
Nothing was pushed.

- Summary: first run of the CRS v4.25.2 regression suite on the engine: 4,862 of 4,987 tests pass (97.49%), 125 fail, so A1 is
  failing; 0 unexplained (78 need response inspection, 19 the content-type allow-list, 15 REQUEST_BODY-target matches, 3 the gate, 10
  fail on stock coraza too). Five engine bugs fixed test-first; no dataset status changed. Go 70/0/5 (75 / 0 / 0 with fixture), pytest 252 passed, 0 failed, 4 skipped.

- Task table:

| task | status | evidence |
|---|---|---|
| T0 plan, config note, fetch script, before any run | done | docs/plan-step25-crs-regression.md, docs/baseline-config.md (step 25), tools/fetch/fetch_crs_regression.sh, docs/logs/step25-fetch.log; commit 1b4934d |
| T1 what the suite's runner needs from the engine: error log and suite setup, tests first | done; Go 65 PASS / 0 FAIL / 5 SKIP after it | docs/logs/step25-e49-e50-failing.log, step25-e49-e50-passing.log, step25-t1-go-test.log; commits 80ad1e3, c1bb0c5 |
| T2 first runs: reference, engine (strict, upstream overrides, worker, repeat, go-ftw 2.7.0), DIAGNOSTIC stock coraza, two more DIAGNOSTIC runs | done: engine 4,857 / 130, reference 4,970 / 17 | docs/logs/s25-ftw.txt, docs/logs/runs/s25-ftw/; commit 50daa06 |
| T3 BUG-class differences fixed, failing test first (E52 to E56) | done; Go 70 PASS / 0 FAIL / 5 SKIP after it (one earlier run had 1 FAIL, see UNVERIFIED) | docs/logs/step25-e52-e55-failing.log, step25-e55-revised-failing.log, step25-e52-e55-passing.log, step25-e56-failing.log, step25-e56-passing.log; commits f47d4a6, 3d52ae4, af5ab15, 6bb10b2, 497d585 |
| T4 the suite on the fixed engine, every failed test classified; own and wcp datasets against step 24 | done: 4,862 / 125, 0 UNEXPLAINED; 0 status diffs in 10,080 and 60,000 pairs | docs/logs/s25-ftw-fixed.txt, step25-ftw-final-diffs.txt, step25-failed-tests.txt, step25-failed-groups.txt, step25-failed-probe.txt, step25-own-vs-step24.txt, step25-parity.txt, docs/logs/runs/s25-ftw-fixed/, s25-own/, s25-parity/; commit faec538 and the T6 commit |
| T5 container images (Coraza connector, ModSecurity) on the suite | NOT MEASURED (not in the plan) | - |
| T6 docs and report | done | docs/baseline-v2.0.md, docs/engine-design.md, docs/engine-evidence.md, docs/acceptance.md (A1, E49 to E56), this report |
| Final suites | done: Go 70 PASS / 0 FAIL / 5 SKIP; with fixture 75 / 0 / 0; pytest 252 passed, 0 failed, 4 skipped | docs/logs/step25-t6-go-test.log, step25-t6-go-test-with-fixture.log, step25-t6-pytest.log |

## Raw evidence

Long lines are cut where marked `[...]`; the files named hold them in full.

### T0. Sources (rule 25)

CRS v4.25.2 tarball (Apache-2.0), go-ftw 2.1.0 and 2.7.0, albedo 0.3.0
(all Apache-2.0). Nothing of them is committed; the fetch script checks the
hashes.

```
# step-25: fetch of the CRS regression suite and its tools, 2026-11-28T05:54:14Z, git 4f53d03f6e544f1bc1c3c6153c7747dd71fb1d89, go version go1.27.4 darwin/arm64
# bash tools/fetch/fetch_crs_regression.sh
tarball sha256 a3ecf5d5b0f8001e2eaf2006448fc8e22d6b645d7fc1c71268be5b99a7395a2d ok
test files: 320 yaml, listing sha256 aec74fa450ee0b5f97d8a5e8edabeea06d0b78eaa7d3eebd6e0b85b137472e25 ok
coraza-overrides.yaml sha256 58c2ae7ad6412a71c9d4c61877ee7f210478ec3b0c15c07159196387cc0655ec ok
rules: identical to engine/crs/owasp-crs/rules
out/step25/bin210/go-ftw sha256 92f0db0de0665849866201fe9f337cf454105b35cb69c3fbe42d8535f7964652 github.com/coreruleset/go-ftw/v2 v2.1.0 h1:IGY5b8NI+1BWyrdoE8k0kpofgUtSQnMN/7b8yfB7E+4=
out/step25/bin/go-ftw sha256 9e592dc5df571a2d1899af36563ab0a4d53d62882da13d8a2b77d935b34fe59a github.com/coreruleset/go-ftw/v2 v2.7.0 h1:Zhq+RE83Nr8YH1DvjXMfyntrQryQNtzDxQ+AF4s7fCQ=
out/step25/bin/albedo sha256 f5c26773dfede739ff98845c9fe07915f5e6e8050acd1825b4f84818c5d973c7 github.com/coreruleset/albedo v0.3.0 h1:GC0CbI8/qzzBbiP95z7A+58pjlN8P5jheVrUwEfzRfQ=
```

### T1. Error log and suite setup (tests first)

go-ftw reads the WAF's log between two marker requests. The engine wrote
an audit entry only for requests that end in 4xx / 5xx, so in DetectionOnly
mode there was nothing to read. Added, both off by default:
`KORTEX_ERROR_LOG` and `KORTEX_CRS_TEST_SETUP=on`.

Failing before the implementation (E51 is a guard and passes):

```
# step-25 T1: E49 and E50 failing before the implementation (E51 guard passes)
# 2026-11-28T05:55:57Z git 1b4934db4a8bb6395e4821aa9fab9380cebdcdc4 + step25_test.go; go version go1.27.4 darwin/arm64
# cd engine && go test -count=1 -run 'TestE49|TestE50|TestE51' -v .
=== RUN   TestE49ErrorLogListsMatchedRules
=== RUN   TestE49ErrorLogListsMatchedRules/blocking,_query
    step25_test.go:152: E49 [blocking, query]: error log has no line for rule 941100 (ids [], 0 lines)
=== RUN   TestE49ErrorLogListsMatchedRules/detection-only,_query
    step25_test.go:152: E49 [detection-only, query]: error log has no line for rule 941100 (ids [], 0 lines)
=== RUN   TestE49ErrorLogListsMatchedRules/detection-only,_body
    step25_test.go:152: E49 [detection-only, body]: error log has no line for rule 941100 (ids [], 0 lines)
=== RUN   TestE49ErrorLogListsMatchedRules/worker_mode,_body
    step25_test.go:152: E49 [worker mode, body]: error log has no line for rule 941100 (ids [], 0 lines)
=== RUN   TestE49ErrorLogListsMatchedRules/worker_mode,_detection-only,_body
    step25_test.go:152: E49 [worker mode, detection-only, body]: error log has no line for rule 941100 (ids [], 0 lines)
=== RUN   TestE49ErrorLogListsMatchedRules/benign_request_writes_nothing
=== RUN   TestE49ErrorLogListsMatchedRules/path_is_on_the_config_page
    step25_test.go:175: E49: config error_log = <nil>, want "<tmp>/error.log"
--- FAIL: TestE49ErrorLogListsMatchedRules (0.33s)
    --- FAIL: TestE49ErrorLogListsMatchedRules/blocking,_query (0.04s)
    --- FAIL: TestE49ErrorLogListsMatchedRules/detection-only,_query (0.01s)
    --- FAIL: TestE49ErrorLogListsMatchedRules/detection-only,_body (0.01s)
    --- FAIL: TestE49ErrorLogListsMatchedRules/worker_mode,_body (0.12s)
    --- FAIL: TestE49ErrorLogListsMatchedRules/worker_mode,_detection-only,_body (0.12s)
    --- PASS: TestE49ErrorLogListsMatchedRules/benign_request_writes_nothing (0.01s)
    --- FAIL: TestE49ErrorLogListsMatchedRules/path_is_on_the_config_page (0.01s)
=== RUN   TestE50CRSTestSetup
=== RUN   TestE50CRSTestSetup/marker_request_logs_the_marker_and_nothing_else
    step25_test.go:196: E50 marker: want only rule 999999 in the error log, got []
=== RUN   TestE50CRSTestSetup/marker_rule_also_holds_in_blocking_mode
    step25_test.go:207: E50 marker, blocking: want 200 and only 999999, got 403 []
=== RUN   TestE50CRSTestSetup/the_same_attack_without_the_marker_header_is_logged
    step25_test.go:215: E50 canary: want 941100 and no 999999, got []
=== RUN   TestE50CRSTestSetup/suite_limits_are_set
    step25_test.go:224: E50 limits: a 401-character argument must match 920370 (tx.arg_length=400), got []
=== RUN   TestE50CRSTestSetup/a_400-character_argument_is_within_the_limit
--- FAIL: TestE50CRSTestSetup (0.04s)
    --- FAIL: TestE50CRSTestSetup/marker_request_logs_the_marker_and_nothing_else (0.01s)
    --- FAIL: TestE50CRSTestSetup/marker_rule_also_holds_in_blocking_mode (0.01s)
    --- FAIL: TestE50CRSTestSetup/the_same_attack_without_the_marker_header_is_logged (0.01s)
    --- FAIL: TestE50CRSTestSetup/suite_limits_are_set (0.01s)
    --- PASS: TestE50CRSTestSetup/a_400-character_argument_is_within_the_limit (0.01s)
=== RUN   TestE51CRSTestSetupIsOffByDefault
=== RUN   TestE51CRSTestSetupIsOffByDefault/KORTEX_CRS_TEST_SETUP=""
=== RUN   TestE51CRSTestSetupIsOffByDefault/KORTEX_CRS_TEST_SETUP="off"
=== RUN   TestE51CRSTestSetupIsOffByDefault/KORTEX_CRS_TEST_SETUP="1"
=== RUN   TestE51CRSTestSetupIsOffByDefault/KORTEX_CRS_TEST_SETUP="true"
=== RUN   TestE51CRSTestSetupIsOffByDefault/KORTEX_CRS_TEST_SETUP="ON"
--- PASS: TestE51CRSTestSetupIsOffByDefault (0.05s)
    --- PASS: TestE51CRSTestSetupIsOffByDefault/KORTEX_CRS_TEST_SETUP="" (0.01s)
    --- PASS: TestE51CRSTestSetupIsOffByDefault/KORTEX_CRS_TEST_SETUP="off" (0.01s)
    --- PASS: TestE51CRSTestSetupIsOffByDefault/KORTEX_CRS_TEST_SETUP="1" (0.01s)
    --- PASS: TestE51CRSTestSetupIsOffByDefault/KORTEX_CRS_TEST_SETUP="true" (0.01s)
    --- PASS: TestE51CRSTestSetupIsOffByDefault/KORTEX_CRS_TEST_SETUP="ON" (0.01s)
FAIL
FAIL	kortexshield/engine	0.721s
FAIL
```

Passing after it (result lines):

```
# step-25 T1: E49, E50 passing after the implementation; E51 guard
# 2026-11-28T05:56:44Z git 80ad1e3daa6021474b3b21217ed2223c2a321932 + working tree (implementation); go version go1.27.4 darwin/arm64
# cd engine && go test -count=1 -run 'TestE49|TestE50|TestE51' -v .
--- PASS: TestE49ErrorLogListsMatchedRules (0.33s)
--- PASS: TestE50CRSTestSetup (0.06s)
--- PASS: TestE51CRSTestSetupIsOffByDefault (0.06s)
PASS
ok  	kortexshield/engine	0.630s
```

### T2. First runs (engine at c1bb0c5)

Command per run, from the log: `go-ftw run --config <run>/.ftw.yaml -d
<CRS>/tests/regression/tests -o json --report-triggered-rules
--read-timeout 10s` (plus `--overrides <CRS>/tests/regression/coraza-overrides.yaml`
for the upstream runs). Script: `bash tools/run_step25_ftw.sh`.

```
# Step-25: CRS v4.25.2 regression suite, runs: ref-asis ref-strict ref-upstream engine-strict engine-upstream engine-worker engine-repeat engine-ftw270 stock
== 2026-11-28T06:09:58Z, macOS 27.0 Darwin 27.0.0 arm64, go version go1.27.4 darwin/arm64, load at start: load averages: 3.51 3.27 3.39
== git c1bb0c524506410623fe2a6357780e309250de3b, tracked paths changed in the working tree: 0
== fetch: tarball sha256 a3ecf5d5b0f8001e2eaf2006448fc8e22d6b645d7fc1c71268be5b99a7395a2d ok
== fetch: test files: 320 yaml, listing sha256 aec74fa450ee0b5f97d8a5e8edabeea06d0b78eaa7d3eebd6e0b85b137472e25 ok
== fetch: coraza-overrides.yaml sha256 58c2ae7ad6412a71c9d4c61877ee7f210478ec3b0c15c07159196387cc0655ec ok
== fetch: rules: identical to engine/crs/owasp-crs/rules
== fetch: out/step25/bin210/go-ftw sha256 92f0db0de0665849866201fe9f337cf454105b35cb69c3fbe42d8535f7964652 github.com/coreruleset/go-ftw/v2 v2.1.0 h1:IGY5b8NI+1BWyrdoE8k0kpofgUtSQnMN/7b8yfB7E+4=
== fetch: out/step25/bin/go-ftw sha256 9e592dc5df571a2d1899af36563ab0a4d53d62882da13d8a2b77d935b34fe59a github.com/coreruleset/go-ftw/v2 v2.7.0 h1:Zhq+RE83Nr8YH1DvjXMfyntrQryQNtzDxQ+AF4s7fCQ=
== fetch: out/step25/bin/albedo sha256 f5c26773dfede739ff98845c9fe07915f5e6e8050acd1825b4f84818c5d973c7 github.com/coreruleset/albedo v0.3.0 h1:GC0CbI8/qzzBbiP95z7A+58pjlN8P5jheVrUwEfzRfQ=
== rules set hash file engine/RULES.sha256: 7c55eb4938e6282d11e96ce431babefd6a076461a462dea9e4a9f3a1f16333d7
== reference binary sha256 bbaacf0d7572aa89ff8abe75db8f9f906753fd7b4ac5d9f01ef44d4d73fc7805: github.com/corazawaf/coraza/v3 v3.8.1 h1:dMV55FbMR2vOks/acrT43RShR+VkzU6jwp+XPdxay8o=; github.com/coreruleset/albedo v0.3.0 h1:GC0CbI8/qz [...]
== engine binary sha256 c0ad8dd6f06b17856710aab85dfa923d2c8c23866cbb32f4a6710f1d8f6887a4, coraza module: github.com/corazawaf/coraza/v3 v3.8.1 => ./third_party/coraza-v3.8.1-kortex
vendor check: OK
== ref-asis: tests listed 4987, run 4987, passed 4746, failed 241, ignored 0, skipped 0, forced-pass 0, forced-fail 0; pass rate (denominator: every test go-ftw lists as run, the ones that stopped it included) 4746/4987 = 95.17%
== failed by rule file prefix: 920: 14, 921: 3, 922: 3, 930: 3, 931: 1, 932: 34, 934: 6, 941: 32, 942: 48, 943: 1, 944: 96
== ref-strict: tests listed 4987, run 4987, passed 4970, failed 17, ignored 0, skipped 0, forced-pass 0, forced-fail 0; pass rate (denominator: every test go-ftw lists as run, the ones that stopped it included) 4970/4987 = 99.66%
== failed by rule file prefix: 920: 14, 922: 3
== ref-upstream: tests listed 4987, run 4987, passed 4975, failed 12, ignored 0, skipped 0, forced-pass 0, forced-fail 0; pass rate (denominator: every test go-ftw lists as run, the ones that stopped it included) 4975/4987 = 99.76%
== failed by rule file prefix: 920: 9, 922: 3
== engine-strict: tests listed 4987, run 4987, passed 4857, failed 130, ignored 0, skipped 0, forced-pass 0, forced-fail 0; pass rate (denominator: every test go-ftw lists as run, the ones that stopped it included) 4857/4987 = 97.39%; 2 of the failed tests stopped go-ftw (retry_once, failed twice) and were excluded from the rest [...]
== failed by rule file prefix: 901: 4, 920: 29, 922: 3, 932: 4, 942: 12, 950: 9, 951: 20, 952: 9, 953: 9, 954: 7, 955: 10, 956: 12, 959: 2
== engine events by decision: framing 63, pass 44842, would_reject 90
== engine-upstream: tests listed 4987, run 4987, passed 4858, failed 129, ignored 0, skipped 0, forced-pass 0, forced-fail 0; pass rate (denominator: every test go-ftw lists as run, the ones that stopped it included) 4858/4987 = 97.41%; 2 of the failed tests stopped go-ftw (retry_once, failed twice) and were excluded from the re [...]
== failed by rule file prefix: 901: 4, 920: 28, 922: 3, 932: 4, 942: 12, 950: 9, 951: 20, 952: 9, 953: 9, 954: 7, 955: 10, 956: 12, 959: 2
== engine events by decision: framing 63, pass 44842, would_reject 90
== engine-worker: tests listed 4987, run 4987, passed 4857, failed 130, ignored 0, skipped 0, forced-pass 0, forced-fail 0; pass rate (denominator: every test go-ftw lists as run, the ones that stopped it included) 4857/4987 = 97.39%; 2 of the failed tests stopped go-ftw (retry_once, failed twice) and were excluded from the rest [...]
== failed by rule file prefix: 901: 4, 920: 29, 922: 3, 932: 4, 942: 12, 950: 9, 951: 20, 952: 9, 953: 9, 954: 7, 955: 10, 956: 12, 959: 2
== engine events by decision: framing 63, pass 44842, would_reject 90
== engine-repeat: tests listed 4987, run 4987, passed 4857, failed 130, ignored 0, skipped 0, forced-pass 0, forced-fail 0; pass rate (denominator: every test go-ftw lists as run, the ones that stopped it included) 4857/4987 = 97.39%; 2 of the failed tests stopped go-ftw (retry_once, failed twice) and were excluded from the rest [...]
== failed by rule file prefix: 901: 4, 920: 29, 922: 3, 932: 4, 942: 12, 950: 9, 951: 20, 952: 9, 953: 9, 954: 7, 955: 10, 956: 12, 959: 2
== engine events by decision: framing 63, pass 44842, would_reject 90
== engine-ftw270: tests listed 4987, run 4987, passed 4856, failed 130, ignored 0, skipped 1, forced-pass 0, forced-fail 0; pass rate (denominator: every test go-ftw lists as run, the ones that stopped it included) 4856/4987 = 97.37%; 2 of the failed tests stopped go-ftw (retry_once, failed twice) and were excluded from the rest [...]
== failed by rule file prefix: 901: 4, 920: 29, 922: 3, 932: 4, 942: 12, 950: 9, 951: 20, 952: 9, 953: 9, 954: 7, 955: 10, 956: 12, 959: 2
== engine events by decision: framing 80, pass 46270, would_reject 97
== DIAGNOSTIC-stock: tests listed 4987, run 4987, passed 4857, failed 130, ignored 0, skipped 0, forced-pass 0, forced-fail 0; pass rate (denominator: every test go-ftw lists as run, the ones that stopped it included) 4857/4987 = 97.39%; 2 of the failed tests stopped go-ftw (retry_once, failed twice) and were excluded from the r [...]
== failed by rule file prefix: 901: 4, 920: 29, 922: 3, 932: 4, 942: 12, 950: 9, 951: 20, 952: 9, 953: 9, 954: 7, 955: 10, 956: 12, 959: 2
== engine events by decision: framing 63, pass 44842, would_reject 90
== DIAGNOSTIC-no-body-targets: tests listed 4987, run 4987, passed 4873, failed 114, ignored 0, skipped 0, forced-pass 0, forced-fail 0; pass rate (denominator: every test go-ftw lists as run, the ones that stopped it included) 4873/4987 = 97.71%; 2 of the failed tests stopped go-ftw (retry_once, failed twice) and were excluded  [...]
== failed by rule file prefix: 901: 4, 920: 29, 922: 3, 950: 9, 951: 20, 952: 9, 953: 9, 954: 7, 955: 10, 956: 12, 959: 2
== engine events by decision: framing 63, pass 44842, would_reject 90
== DIAGNOSTIC-no-900220: tests listed 4987, run 4987, passed 4876, failed 111, ignored 0, skipped 0, forced-pass 0, forced-fail 0; pass rate (denominator: every test go-ftw lists as run, the ones that stopped it included) 4876/4987 = 97.77%; 2 of the failed tests stopped go-ftw (retry_once, failed twice) and were excluded from t [...]
== failed by rule file prefix: 920: 14, 922: 3, 932: 4, 942: 12, 950: 9, 951: 20, 952: 9, 953: 9, 954: 7, 955: 10, 956: 12, 959: 2
== engine events by decision: framing 63, pass 44842, would_reject 90
```

The two DIAGNOSTIC builds that test a cause (rule 34: no baseline number;
scratch copies, the diff against engine/config.go is in the log):

```
== DIAGNOSTIC scratch engine no-body-targets sha256 7a6ba6e79b8b66ab7a63a2576c2eacb60a2856e4ff05bd431cee1702d7a5bb88; diff of config.go against engine/config.go:
192c192
< 	return base + renderBodyTargetUpdates(bodyTargets), nil
---
> 	return base, nil
== DIAGNOSTIC scratch engine no-900220 sha256 1904ceed7efb5f1dbf761bf49f0fb79c11c0b8746823fbcbdbea7a57d9f61399; diff of config.go against engine/config.go:
170d169
< SecRule REQUEST_HEADERS:Content-Type "@rx ^[^;\s]+" "id:900220,phase:1,pass,nolog,t:none,capture,setvar:'tx.allowed_request_content_type=|%%{tx.0}|'"
171a171
```

- Without the REQUEST_BODY target updates 16 failed tests pass (the 15
  negative tests below and 942130-7); without rule 900220, 19. No test goes
  the other way in either run.
- go-ftw 2.7.0 gives the same result for every test it sends. It refuses
  to send 921140-1 (skipped: 4,856 passed).
- The reference with coraza's harness as written fails 241; 224 of them
  pass once rule 900511 (`tx.crs_xml_attr_inspect=1`, in the CRS compose
  file, not in coraza's harness) is added. The engine runs have 900511.

### T3. Bugs the suite found (rule 39 BUG, rule 40 test first)

| test | what was wrong | found by |
|---|---|---|
| E52 | the rules got `r.URL.RequestURI()` and the constant `1.1`: an absolute-form target lost its scheme and host, HTTP/1.0 was recorded as 1.1 | CRS 920100-16 |
| E53 | the rules never saw Transfer-Encoding (net/http removes it from the header map) | CRS 920171-2, -3 |
| E54 | a request without a Host line was shown to the rules with an empty Host; in worker mode a request with a body got both 920280 and 920290 | CRS 920280-1 |
| E55 | the REQUEST_BODY target added in step 18 is evaluated last on CRS 942130, a chain starter, and replaces its captures: a tautology in a form body was not matched | CRS 942130-7 |
| E56 | in-process the handler added a second Content-Length to what the rules see; the worker got one | reading the code for E52 to E54 |

All five are PROVEN by a test that fails before the fix and passes after
it. E55 was first written for all 12 chain-starting rules; that form broke
E24 PL2, which needs the target on 932240, so it was narrowed to 942130
before any fix was committed (rule 5: no test is weakened).

Failing before the fixes:

```
# step-25 T3: E52, E53, E54, E55 failing before the fixes
# 2026-11-28T06:19:41Z git 50daa06bfa811832f97baaf0f9741e03a1d257ae + step25_test.go; go version go1.27.4 darwin/arm64
# cd engine && go test -count=1 -run 'TestE52|TestE53|TestE54|TestE55' -v .
=== RUN   TestE52RulesSeeTheRequestLineAsSent
=== RUN   TestE52RulesSeeTheRequestLineAsSent/absolute-form_target_without_a_path_matches_920100
    step25_test.go:321: E52: want 200 and 920100 in the error log, got 200 []
=== RUN   TestE52RulesSeeTheRequestLineAsSent/origin-form_target_is_a_valid_request_line
=== RUN   TestE52RulesSeeTheRequestLineAsSent/protocol_HTTP/1.0_reaches_the_audit_entry
    step25_test.go:347: E52: audit protocol = 1.1, want "HTTP/1.0"
=== RUN   TestE52RulesSeeTheRequestLineAsSent/protocol_HTTP/1.1_reaches_the_audit_entry
    step25_test.go:347: E52: audit protocol = 1.1, want "HTTP/1.1"
--- FAIL: TestE52RulesSeeTheRequestLineAsSent (0.09s)
    --- FAIL: TestE52RulesSeeTheRequestLineAsSent/absolute-form_target_without_a_path_matches_920100 (0.06s)
    --- PASS: TestE52RulesSeeTheRequestLineAsSent/origin-form_target_is_a_valid_request_line (0.01s)
    --- FAIL: TestE52RulesSeeTheRequestLineAsSent/protocol_HTTP/1.0_reaches_the_audit_entry (0.01s)
    --- FAIL: TestE52RulesSeeTheRequestLineAsSent/protocol_HTTP/1.1_reaches_the_audit_entry (0.01s)
=== RUN   TestE53RulesSeeTransferEncoding
=== RUN   TestE53RulesSeeTransferEncoding/in-process,_GET_with_Transfer-Encoding_matches_920171
    step25_test.go:377: E53 [in-process]: want 200 and 920171, got 200 []
=== RUN   TestE53RulesSeeTransferEncoding/in-process,_POST_with_Transfer-Encoding_does_not
=== RUN   TestE53RulesSeeTransferEncoding/worker,_GET_with_Transfer-Encoding_matches_920171
    step25_test.go:377: E53 [worker]: want 200 and 920171, got 200 []
=== RUN   TestE53RulesSeeTransferEncoding/worker,_POST_with_Transfer-Encoding_does_not
--- FAIL: TestE53RulesSeeTransferEncoding (0.25s)
    --- FAIL: TestE53RulesSeeTransferEncoding/in-process,_GET_with_Transfer-Encoding_matches_920171 (0.01s)
    --- PASS: TestE53RulesSeeTransferEncoding/in-process,_POST_with_Transfer-Encoding_does_not (0.01s)
    --- FAIL: TestE53RulesSeeTransferEncoding/worker,_GET_with_Transfer-Encoding_matches_920171 (0.12s)
    --- PASS: TestE53RulesSeeTransferEncoding/worker,_POST_with_Transfer-Encoding_does_not (0.12s)
=== RUN   TestE54RulesSeeTheHostHeaderAsSent
=== RUN   TestE54RulesSeeTheHostHeaderAsSent/in-process,_HTTP/1.0_without_Host
    step25_test.go:427: E54 [in-process, HTTP/1.0 without Host]: want 920280, got [920290 949110 980170]
=== RUN   TestE54RulesSeeTheHostHeaderAsSent/in-process,_empty_Host_line
=== RUN   TestE54RulesSeeTheHostHeaderAsSent/in-process,_normal_Host
=== RUN   TestE54RulesSeeTheHostHeaderAsSent/in-process,_HTTP/1.0_without_Host,_body
    step25_test.go:427: E54 [in-process, HTTP/1.0 without Host, body]: want 920280, got [920290 949110 980170]
=== RUN   TestE54RulesSeeTheHostHeaderAsSent/in-process,_empty_Host_line,_body
=== RUN   TestE54RulesSeeTheHostHeaderAsSent/worker,_HTTP/1.0_without_Host
    step25_test.go:427: E54 [worker, HTTP/1.0 without Host]: want 920280, got [920290 949110 980170]
=== RUN   TestE54RulesSeeTheHostHeaderAsSent/worker,_empty_Host_line
=== RUN   TestE54RulesSeeTheHostHeaderAsSent/worker,_normal_Host
=== RUN   TestE54RulesSeeTheHostHeaderAsSent/worker,_HTTP/1.0_without_Host,_body
    step25_test.go:431: E54 [worker, HTTP/1.0 without Host, body]: 920290 must not match, got [920280 920290 949110 980170]
=== RUN   TestE54RulesSeeTheHostHeaderAsSent/worker,_empty_Host_line,_body
    step25_test.go:431: E54 [worker, empty Host line, body]: 920280 must not match, got [920280 920290 949110 980170]
--- FAIL: TestE54RulesSeeTheHostHeaderAsSent (0.65s)
    --- FAIL: TestE54RulesSeeTheHostHeaderAsSent/in-process,_HTTP/1.0_without_Host (0.01s)
    --- PASS: TestE54RulesSeeTheHostHeaderAsSent/in-process,_empty_Host_line (0.01s)
    --- PASS: TestE54RulesSeeTheHostHeaderAsSent/in-process,_normal_Host (0.01s)
    --- FAIL: TestE54RulesSeeTheHostHeaderAsSent/in-process,_HTTP/1.0_without_Host,_body (0.01s)
    --- PASS: TestE54RulesSeeTheHostHeaderAsSent/in-process,_empty_Host_line,_body (0.01s)
    --- FAIL: TestE54RulesSeeTheHostHeaderAsSent/worker,_HTTP/1.0_without_Host (0.12s)
    --- PASS: TestE54RulesSeeTheHostHeaderAsSent/worker,_empty_Host_line (0.12s)
    --- PASS: TestE54RulesSeeTheHostHeaderAsSent/worker,_normal_Host (0.12s)
    --- FAIL: TestE54RulesSeeTheHostHeaderAsSent/worker,_HTTP/1.0_without_Host,_body (0.12s)
    --- FAIL: TestE54RulesSeeTheHostHeaderAsSent/worker,_empty_Host_line,_body (0.13s)
=== RUN   TestE55ChainRulesKeepTheirOwnTargets
=== RUN   TestE55ChainRulesKeepTheirOwnTargets/canary:_tautology_in_the_query_string_matches_942130
=== RUN   TestE55ChainRulesKeepTheirOwnTargets/tautology_in_a_form_body_matches_942130
    step25_test.go:459: E55: want 942130 for a tautology in a form body, got []
=== RUN   TestE55ChainRulesKeepTheirOwnTargets/no_chain_starter_is_in_the_target_updates
    step25_test.go:476: E55: want 154 target updates and no chain starter, got 166 updates, chain starters [931130 932200 932240 933150 941310 942130 942131 942200 942440 942521 943110 943120]
--- FAIL: TestE55ChainRulesKeepTheirOwnTargets (0.02s)
    --- PASS: TestE55ChainRulesKeepTheirOwnTargets/canary:_tautology_in_the_query_string_matches_942130 (0.01s)
    --- FAIL: TestE55ChainRulesKeepTheirOwnTargets/tautology_in_a_form_body_matches_942130 (0.01s)
    --- FAIL: TestE55ChainRulesKeepTheirOwnTargets/no_chain_starter_is_in_the_target_updates (0.00s)
FAIL
FAIL	kortexshield/engine	1.691s
FAIL
```

E55 as revised, failing before the fix, with E24 passing:

```
# step-25 T3: E55 as revised (942130 only; the first form, no target on any of the 12 chain starters, broke E24 PL2, which needs the target on 932240) failing before the fix
# 2026-11-28T06:23:08Z git f47d4a651f214ccea5abc19e03df4feab2bd0023 + step25_test.go; go version go1.27.4 darwin/arm64
# cd engine && go test -count=1 -run 'TestE55|TestE24' -v .
=== RUN   TestE24RawCarriersSplitDestroyedRCEBlocked
--- PASS: TestE24RawCarriersSplitDestroyedRCEBlocked (0.06s)
=== RUN   TestE24RawCarriersSplitDestroyedRCEBlockedPL2
--- PASS: TestE24RawCarriersSplitDestroyedRCEBlockedPL2 (0.01s)
=== RUN   TestE55TautologyRuleKeepsItsOwnTargets
=== RUN   TestE55TautologyRuleKeepsItsOwnTargets/canary:_tautology_in_the_query_string_matches_942130
=== RUN   TestE55TautologyRuleKeepsItsOwnTargets/tautology_in_a_form_body_matches_942130
    step25_test.go:461: E55: want 942130 for a tautology in a form body, got []
=== RUN   TestE55TautologyRuleKeepsItsOwnTargets/942130_is_not_in_the_target_updates,_932240_still_is
    step25_test.go:474: E55: want 165 target updates without 942130 and with 932240, got 166 updates, 942130 true, 932240 true
--- FAIL: TestE55TautologyRuleKeepsItsOwnTargets (0.03s)
    --- PASS: TestE55TautologyRuleKeepsItsOwnTargets/canary:_tautology_in_the_query_string_matches_942130 (0.01s)
    --- FAIL: TestE55TautologyRuleKeepsItsOwnTargets/tautology_in_a_form_body_matches_942130 (0.01s)
    --- FAIL: TestE55TautologyRuleKeepsItsOwnTargets/942130_is_not_in_the_target_updates,_932240_still_is (0.00s)
FAIL
FAIL	kortexshield/engine	0.418s
FAIL
```

E56 failing before its fix:

```
# step-25 T3: E56 failing before the fix
# 2026-11-28T06:32:25Z git faec538b9c5fd9a73ab110090fe8e8c61549244c + step25_test.go; go version go1.27.4 darwin/arm64
# cd engine && go test -count=1 -run 'TestE56' -v .
=== RUN   TestE56ContentLengthIsSeenOnce
=== RUN   TestE56ContentLengthIsSeenOnce/in-process
    step25_test.go:510: E56 [in-process]: want one Content-Length value 41 in the audit entry, got [41 41]
=== RUN   TestE56ContentLengthIsSeenOnce/worker
--- FAIL: TestE56ContentLengthIsSeenOnce (0.21s)
    --- FAIL: TestE56ContentLengthIsSeenOnce/in-process (0.04s)
    --- PASS: TestE56ContentLengthIsSeenOnce/worker (0.16s)
FAIL
FAIL	kortexshield/engine	0.509s
FAIL
```

Passing after the fixes (result lines):

```
# step-25 T3: E52 to E55 passing after the fixes
# 2026-11-28T06:23:20Z git 3d52ae45ef674c736d65733c944462b95d5aeff5 + working tree (fixes); go version go1.27.4 darwin/arm64
# cd engine && go test -count=1 -run 'TestE52|TestE53|TestE54|TestE55' -v .
--- PASS: TestE52RulesSeeTheRequestLineAsSent (0.08s)
--- PASS: TestE53RulesSeeTransferEncoding (0.30s)
--- PASS: TestE54RulesSeeTheHostHeaderAsSent (0.70s)
--- PASS: TestE55TautologyRuleKeepsItsOwnTargets (0.03s)
PASS
ok  	kortexshield/engine	1.294s
# step-25 T3: E56 passing after the fix (E52 to E55 again)
# 2026-11-28T06:32:48Z git 6bb10b2c1bcbbffd2c686353b1d84323b046fb14 + working tree (fix); go version go1.27.4 darwin/arm64
# cd engine && go test -count=1 -run 'TestE52|TestE53|TestE54|TestE55|TestE56' -v .
--- PASS: TestE52RulesSeeTheRequestLineAsSent (0.17s)
--- PASS: TestE53RulesSeeTransferEncoding (0.69s)
--- PASS: TestE54RulesSeeTheHostHeaderAsSent (1.06s)
--- PASS: TestE55TautologyRuleKeepsItsOwnTargets (0.04s)
--- PASS: TestE56ContentLengthIsSeenOnce (0.18s)
PASS
ok  	kortexshield/engine	2.451s
```

### T4. The suite on the fixed engine (497d585)

Rule 29, from the engine-strict run:

```
== engine-strict rule29 2026-11-28T06:39:51Z load: load averages: 3.33 3.67 3.64: {"backend_url":"http://127.0.0.1:13025","rule_engine":"DetectionOnly","blocking_paranoia":4,"detection_paranoia":4,"max_body_bytes":13107200,"max_inspected_bytes":131072,"engine_time_budget_ms":2000,"rules_dir":"/Users/ivan/work/kortex-shield-next/engine/crs","listen_addr":"127.0.0.1:18025","events_file":"/Users/ivan/work/kortex-shield-next/out/step25/runs/s25-ftw-fixed-engine-strict/events.jsonl","audit_log":"/Users/ivan/work/kortex-shield-next/out/step25/runs/s25-ftw-fixed-engine-strict/audit.log","allowed_methods":"GET HEAD POST OPTIONS","max_inflight_body":8,"max_inflight_body_large":2,"body_lane_threshold":65536,"worker_mode":false,"client_max_inflight":0,"client_max_inflight_small":4,"client_max_inflight_large":1,"request_body_target_updates":165,"error_log":"/Users/ivan/work/kortex-shield-next/out/step25/runs/s25-ftw-fixed-engine-strict/error.log","crs_test_setup":true}
```

```
# Step-25: CRS v4.25.2 regression suite, runs: engine-strict engine-upstream engine-worker engine-repeat stock
== 2026-11-28T06:39:48Z, macOS 27.0 Darwin 27.0.0 arm64, go version go1.27.4 darwin/arm64, load at start: load averages: 3.33 3.67 3.64
== git 497d585e8f0dfa49ba5f1fe71c12f8ec6071142e, tracked paths changed in the working tree: 2
== engine-strict attempt 1: go-ftw aborted (exit 1, 'Error: retry-once') at test 959100-1, which failed twice; counted as failed, excluded, run restarted
== engine-strict attempt 2: go-ftw aborted (exit 1, 'Error: retry-once') at test 959100-3, which failed twice; counted as failed, excluded, run restarted
== engine-strict go-ftw exit status 1 after 3 attempt(s), 29 s, exclude option: -e ^(959100-1|959100-3)$, stderr lines 1, load at end: load averages: 3.75 3.75 3.67
== engine-strict: tests listed 4987, run 4987, passed 4862, failed 125, ignored 0, skipped 0, forced-pass 0, forced-fail 0; pass rate (denominator: every test go-ftw lists as run, the ones that stopped it included) 4862/4987 = 97.49%; 2 of the failed tests stopped go-ftw (retry_once, failed twice) and were excluded from the rest [...]
== failed by rule file prefix: 901: 4, 920: 25, 922: 3, 932: 4, 942: 11, 950: 9, 951: 20, 952: 9, 953: 9, 954: 7, 955: 10, 956: 12, 959: 2
== engine events by decision: framing 21, pass 14950, would_reject 30
== engine-upstream attempt 1: go-ftw aborted (exit 1, 'Error: retry-once') at test 959100-1, which failed twice; counted as failed, excluded, run restarted
== engine-upstream attempt 2: go-ftw aborted (exit 1, 'Error: retry-once') at test 959100-3, which failed twice; counted as failed, excluded, run restarted
== engine-upstream go-ftw exit status 1 after 3 attempt(s), 31 s, exclude option: -e ^(959100-1|959100-3)$, stderr lines 1, load at end: load averages: 4.92 4.06 3.78
== engine-upstream: tests listed 4987, run 4987, passed 4863, failed 124, ignored 0, skipped 0, forced-pass 0, forced-fail 0; pass rate (denominator: every test go-ftw lists as run, the ones that stopped it included) 4863/4987 = 97.51%; 2 of the failed tests stopped go-ftw (retry_once, failed twice) and were excluded from the re [...]
== failed by rule file prefix: 901: 4, 920: 24, 922: 3, 932: 4, 942: 11, 950: 9, 951: 20, 952: 9, 953: 9, 954: 7, 955: 10, 956: 12, 959: 2
== engine events by decision: framing 21, pass 14950, would_reject 30
== engine-worker attempt 1: go-ftw aborted (exit 1, 'Error: retry-once') at test 959100-1, which failed twice; counted as failed, excluded, run restarted
== engine-worker attempt 2: go-ftw aborted (exit 1, 'Error: retry-once') at test 959100-3, which failed twice; counted as failed, excluded, run restarted
== engine-worker go-ftw exit status 1 after 3 attempt(s), 35 s, exclude option: -e ^(959100-1|959100-3)$, stderr lines 1, load at end: load averages: 7.42 4.75 4.04
== engine-worker: tests listed 4987, run 4987, passed 4862, failed 125, ignored 0, skipped 0, forced-pass 0, forced-fail 0; pass rate (denominator: every test go-ftw lists as run, the ones that stopped it included) 4862/4987 = 97.49%; 2 of the failed tests stopped go-ftw (retry_once, failed twice) and were excluded from the rest [...]
== failed by rule file prefix: 901: 4, 920: 25, 922: 3, 932: 4, 942: 11, 950: 9, 951: 20, 952: 9, 953: 9, 954: 7, 955: 10, 956: 12, 959: 2
== engine events by decision: framing 21, pass 14950, would_reject 30
== engine-repeat attempt 1: go-ftw aborted (exit 1, 'Error: retry-once') at test 959100-1, which failed twice; counted as failed, excluded, run restarted
== engine-repeat attempt 2: go-ftw aborted (exit 1, 'Error: retry-once') at test 959100-3, which failed twice; counted as failed, excluded, run restarted
== engine-repeat go-ftw exit status 1 after 3 attempt(s), 30 s, exclude option: -e ^(959100-1|959100-3)$, stderr lines 1, load at end: load averages: 5.90 4.65 4.03
== engine-repeat: tests listed 4987, run 4987, passed 4862, failed 125, ignored 0, skipped 0, forced-pass 0, forced-fail 0; pass rate (denominator: every test go-ftw lists as run, the ones that stopped it included) 4862/4987 = 97.49%; 2 of the failed tests stopped go-ftw (retry_once, failed twice) and were excluded from the rest [...]
== failed by rule file prefix: 901: 4, 920: 25, 922: 3, 932: 4, 942: 11, 950: 9, 951: 20, 952: 9, 953: 9, 954: 7, 955: 10, 956: 12, 959: 2
== engine events by decision: framing 21, pass 14950, would_reject 30
== DIAGNOSTIC-stock attempt 1: go-ftw aborted (exit 1, 'Error: retry-once') at test 959100-1, which failed twice; counted as failed, excluded, run restarted
== DIAGNOSTIC-stock attempt 2: go-ftw aborted (exit 1, 'Error: retry-once') at test 959100-3, which failed twice; counted as failed, excluded, run restarted
== DIAGNOSTIC-stock go-ftw exit status 1 after 3 attempt(s), 29 s, exclude option: -e ^(959100-1|959100-3)$, stderr lines 1, load at end: load averages: 4.86 4.51 4.00
== DIAGNOSTIC-stock: tests listed 4987, run 4987, passed 4862, failed 125, ignored 0, skipped 0, forced-pass 0, forced-fail 0; pass rate (denominator: every test go-ftw lists as run, the ones that stopped it included) 4862/4987 = 97.49%; 2 of the failed tests stopped go-ftw (retry_once, failed twice) and were excluded from the r [...]
== failed by rule file prefix: 901: 4, 920: 25, 922: 3, 932: 4, 942: 11, 950: 9, 951: 20, 952: 9, 953: 9, 954: 7, 955: 10, 956: 12, 959: 2
== engine events by decision: framing 21, pass 14950, would_reject 30
== done 2026-11-28T06:42:34Z, load: load averages: 4.86 4.51 4.00
```

The log's "tracked paths changed in the working tree: 2" are two files
under docs/ (docs/engine-design.md being written, and the previous
docs/logs/s25-ftw-fixed.txt removed for the re-run). Nothing under engine/
was changed: a build from the committed tree at 497d585 after the runs
(`cd engine && go build -buildvcs=false`, `git status --short engine`
empty) has the sha256 of the run binary, 761ef5ad...702792fb.

Per test id (rule 32). The last block compares the suite as committed
before the E56 fix with the final run:

```
# Step-25: per-test comparisons of the final suite runs (engine at 497d585e8f0dfa49ba5f1fe71c12f8ec6071142e)
== 2026-11-28T07:03:07Z

## table
| run | tests run | passed | failed | ignored | skipped | pass rate |
|---|---|---|---|---|---|---|
| engine-strict | 4987 | 4862 | 125 | 0 | 0 | 4862/4987 = 97.49% |
| engine-upstream | 4987 | 4863 | 124 | 0 | 0 | 4863/4987 = 97.51% |
| engine-worker | 4987 | 4862 | 125 | 0 | 0 | 4862/4987 = 97.49% |
| engine-repeat | 4987 | 4862 | 125 | 0 | 0 | 4862/4987 = 97.49% |
| DIAGNOSTIC-stock | 4987 | 4862 | 125 | 0 | 0 | 4862/4987 = 97.49% |

## diff engine-strict vs engine-worker
$ python3 tools/step25_ftw_summary.py diff docs/logs/runs/s25-ftw-fixed/engine-strict docs/logs/runs/s25-ftw-fixed/engine-worker
== engine-strict against engine-worker: 4987 test ids in the union, 0 with a different result, 0 with the same result and a different logged rule-id set

## diff engine-strict vs engine-repeat
$ python3 tools/step25_ftw_summary.py diff docs/logs/runs/s25-ftw-fixed/engine-strict docs/logs/runs/s25-ftw-fixed/engine-repeat
== engine-strict against engine-repeat: 4987 test ids in the union, 0 with a different result, 0 with the same result and a different logged rule-id set

## diff engine-strict vs DIAGNOSTIC-stock
$ python3 tools/step25_ftw_summary.py diff docs/logs/runs/s25-ftw-fixed/engine-strict docs/logs/runs/s25-ftw-fixed/DIAGNOSTIC-stock
== engine-strict against DIAGNOSTIC-stock: 4987 test ids in the union, 0 with a different result, 0 with the same result and a different logged rule-id set

## diff engine-strict vs engine-upstream
$ python3 tools/step25_ftw_summary.py diff docs/logs/runs/s25-ftw-fixed/engine-strict docs/logs/runs/s25-ftw-fixed/engine-upstream
== engine-strict against engine-upstream: 4987 test ids in the union, 3 with a different result, 0 with the same result and a different logged rule-id set
   failed -> success: 2
   success -> failed: 1
   920100-4: engine-strict success [911100, 949110, 980170] | engine-upstream failed [911100, 949110, 980170]
   920270-4: engine-strict failed [920270, 920271, 920272, 920274, 949110, 980170] | engine-upstream success [920270, 920271, 920272, 920274, 949110, 980170]
   920290-1: engine-strict failed [920290, 949110, 980170] | engine-upstream success [920290, 949110, 980170]

## diff first run (before the fixes) vs final: docs/logs/runs/s25-ftw/engine-strict vs docs/logs/runs/s25-ftw-fixed/engine-strict
== engine-strict against engine-strict: 4987 test ids in the union, 5 with a different result, 19 with the same result and a different logged rule-id set
   failed -> success: 5
   920100-16: engine-strict failed [] | engine-strict success [920100, 980170]
   920171-2: engine-strict failed [920273, 920640, 949110, 980170] | engine-strict success [920171, 920273, 920640, 949110, 980170]
   920171-3: engine-strict failed [920273, 920640, 949110, 980170] | engine-strict success [920171, 920273, 920640, 949110, 980170]
   920280-1: engine-strict failed [920290, 949110, 980170] | engine-strict success [920280, 949110, 980170]
   942130-7: engine-strict failed [920273, 949110, 980170] | engine-strict success [920273, 942130, 949110, 980170]
   920100-4 (success): only engine-strict [920350] | only engine-strict []
   920100-5 (failed): only engine-strict [] | only engine-strict [920100]
   920171-1 (success): only engine-strict [920180] | only engine-strict []
   920420-5 (failed): only engine-strict [942130] | only engine-strict []
   920420-6 (failed): only engine-strict [942130] | only engine-strict []
   920420-7 (failed): only engine-strict [942130] | only engine-strict []
   920610-2 (failed): only engine-strict [] | only engine-strict [920610, 949110, 980170]
   942100-1 (success): only engine-strict [] | only engine-strict [942130]
   942160-8 (success): only engine-strict [] | only engine-strict [942130]
   942200-3 (success): only engine-strict [942130] | only engine-strict []
   942210-81 (success): only engine-strict [] | only engine-strict [942130]
   942360-35 (success): only engine-strict [942130] | only engine-strict []
   942360-38 (success): only engine-strict [942130] | only engine-strict []
   942380-42 (success): only engine-strict [] | only engine-strict [942130]
   942440-2 (success): only engine-strict [] | only engine-strict [942130]
   942440-9 (success): only engine-strict [] | only engine-strict [942130]
```

Engine against the reference, per test: 118 tests have a different result
(113 pass on the reference and fail on the engine, 5 the other way) and
452 have the same result with a different logged rule-id set; the list is
at the end of docs/logs/step25-ftw-final-diffs.txt.

Every failed test in exactly one group, derived from the run files:

```
# step-25: every failed test of the final engine-strict run in exactly one group
# 2026-11-28T07:07:12Z git 497d585e8f0dfa49ba5f1fe71c12f8ec6071142e + tools/step25_ftw_summary.py (groups)
# the two DIAGNOSTIC runs are those of the first runs (engine at c1bb0c5); a test is in such a group when it still fails on the final engine and passes in the DIAGNOSTIC run
$ python3 tools/step25_ftw_summary.py groups docs/logs/runs/s25-ftw-fixed/engine-strict --probe docs/logs/step25-failed-probe.txt --diag 'passes without rule 900220 (DIAGNOSTIC)=docs/logs/runs/s25-ftw/DIAGNOSTIC-no-900220' --diag 'passes without the REQUEST_BODY targets (DIAGNOSTIC)=docs/logs/runs/s25-ftw/DIAGNOSTIC-no-body-targets' --ref docs/logs/runs/s25-ftw/ref-strict
== engine-strict: 125 failed tests
== response rule: 78: 950150-1 950150-2 950150-3 950150-4 950150-5 950150-6 950150-7 950150-8 950150-9 951110-1 951120-1 951130-1 951140-1 951150-1 951160-1 951170-1 951180-1 951190-1 951200-1 951210-1 951210-2 951220-1 951220-2 951230-1 951230-2 951240-1 951240-2 951250-1 951260-1 952110-1 952110-2 952110-3 952110-4 952110-5 952110-6 952110-7 952110-8 952110-9 953101-1 953101-2 953101-3 953101-4 953101-5 953120-1 953120-3 953120-5 953120-7 954100-1 954100-2 954100-3 954101-1 954101-2 954120-1 954120-2 955100-1 955100-2 955100-3 955110-1 955120-1 955120-2 955260-1 955400-1 955400-2 955400-3 956100-1 956100-2 956100-3 956100-4 956100-5 956100-6 956100-7 956100-8 956100-9 956110-1 956110-2 956110-3 959100-1 959100-3
== refused by the gate: 3: 920181-1 920430-5 920430-8
== passes without rule 900220 (DIAGNOSTIC): 19: 901360-3 901370-5 901370-6 901370-11 920420-2 920420-3 920420-4 920420-5 920420-6 920420-7 920420-8 920420-11 920420-12 920420-14 920420-15 920420-16 920420-17 920420-18 920420-21
== passes without the REQUEST_BODY targets (DIAGNOSTIC): 15: 932340-10 932340-11 932340-12 932340-13 942210-31 942210-44 942430-7 942431-2 942431-3 942431-6 942432-5 942440-16 942440-21 942440-22 942440-23
== failed by the reference too: 10: 920100-5 920100-8 920270-4 920274-1 920290-1 920610-2 920620-1 922130-1 922130-2 922130-7
== UNEXPLAINED: 0: 
== sum of the groups: 125

# response rules: tests in which go-ftw found a 95x rule id in the log, per rule file prefix (measured property of rule 41)
== docs/logs/runs/s25-ftw-fixed/engine-strict: {}, total (test, rule id) pairs 0, of 4987 tests
== docs/logs/runs/s25-ftw/ref-strict: {'950': 9, '951': 39, '952': 11, '953': 14, '954': 10, '955': 10, '956': 12, '959': 78}, total (test, rule id) pairs 183, of 4987 tests
```

Classification (rules 39, 41):

| group | tests | class | basis |
|---|---|---|---|
| response rule | 78 | DESIGN: the engine does not inspect responses (engine-design, step 25; stated in the plan before the run) | measured: go-ftw finds no 95x rule id in the engine's log in any of the 4,987 tests; the reference logs them and passes all 78. HYPOTHESIS that each of the 78 would pass with response inspection: not tested on the engine |
| passes without rule 900220 | 19 | DESIGN: no content-type allow-list (decision 0002 C4) | PROVEN: DIAGNOSTIC-no-900220, exactly these 19 change from failed to passed |
| passes without the REQUEST_BODY targets | 15 | DESIGN: the targets of step 18 scan the raw body | PROVEN: DIAGNOSTIC-no-body-targets, these 15 change from failed to passed. Each is a request the CRS project says must not match the rule: a potential false positive |
| refused by the gate | 3 | DESIGN: the gate answers before the rules (steps 15, 24) | measured: the per-test probe records `framing 400` for the test request (transfer-encoding-with-content-length, parser:http-version twice). The reference fails 920430-5 and -8 too |
| failed by the reference too | 10 | no difference to the reference | the reference fails the same 10. 6 of them expect status 400 where both answer 200 (the test text names Apache). For 920620-1 and 922130-1, -2, -7 the cause is a HYPOTHESIS: Go's header handling and coraza's multipart parser, not tested here |
| UNEXPLAINED | 0 | | |

The engine's own record of the 47 failed tests outside the response rules
(first lines; 3 `framing`, 44 `pass ... forwarding`):

```
# step-25: the engine's own record for each failed test outside the response rules
# 2026-11-28T06:42:36Z git 497d585e8f0dfa49ba5f1fe71c12f8ec6071142e, engine sha256 761ef5adacb501c596a0dc67b1df0ec3bdb9f50b8ca9330c0205c320702792fb, run docs/logs/runs/s25-ftw-fixed/engine-strict
| test | engine events for the test request (decision status reason) | statuses go-ftw received (markers and test) | result |
|---|---|---|---|
| 920181-1 | framing 400 transfer-encoding-with-content-length (3 events in all) | 200 400 200 | failed |
| 920430-5 | framing 400 parser:http-version (3 events in all) | 200 400 200 | failed |
| 920430-8 | framing 400 parser:http-version (3 events in all) | 200 400 200 | failed |
```

### T4. Our own datasets on the step-25 engine against step 24

`OWN_STEP=25 STUB_PORT=13004 bash tools/run_step24_datasets.sh main`, then
`bash tools/step25_own_compare.sh`. 20 runs, 10,080 pairs.

```
# step-25: own datasets on the step-25 engine against the step-24 runs, per sample id (rule 32)
# 2026-11-28T07:03:37Z git 497d585e8f0dfa49ba5f1fe71c12f8ec6071142e
== attacks-v0 PL1 inprocess (a=step-24 b=step-25):
status diffs: 0
worst-case set diffs: 0 (only-a 0 only-b 0)
== attacks-v0 PL1 worker (a=step-24 b=step-25):
status diffs: 0
worst-case set diffs: 0 (only-a 0 only-b 0)
== attacks-v0 PL2 inprocess (a=step-24 b=step-25):
status diffs: 0
worst-case set diffs: 0 (only-a 0 only-b 0)
== attacks-v0 PL2 worker (a=step-24 b=step-25):
status diffs: 0
worst-case set diffs: 0 (only-a 0 only-b 0)
== attacks-ct-v0 PL1 inprocess (a=step-24 b=step-25):
status diffs: 0
worst-case set diffs: 0 (only-a 0 only-b 0)
== attacks-ct-v0 PL1 worker (a=step-24 b=step-25):
status diffs: 0
worst-case set diffs: 0 (only-a 0 only-b 0)
== attacks-ct-v0 PL2 inprocess (a=step-24 b=step-25):
status diffs: 0
worst-case set diffs: 0 (only-a 0 only-b 0)
== attacks-ct-v0 PL2 worker (a=step-24 b=step-25):
status diffs: 0
worst-case set diffs: 0 (only-a 0 only-b 0)
== encoding-diff-v0 PL1 inprocess (a=step-24 b=step-25):
status diffs: 0
worst-case set diffs: 0 (only-a 0 only-b 0)
== encoding-diff-v0 PL1 worker (a=step-24 b=step-25):
status diffs: 0
worst-case set diffs: 0 (only-a 0 only-b 0)
== encoding-diff-v0 PL2 inprocess (a=step-24 b=step-25):
status diffs: 0
worst-case set diffs: 0 (only-a 0 only-b 0)
== encoding-diff-v0 PL2 worker (a=step-24 b=step-25):
status diffs: 0
worst-case set diffs: 0 (only-a 0 only-b 0)
== benign-browse-v1 PL1 inprocess (a=step-24 b=step-25):
status diffs: 0
worst-case set diffs: 0 (only-a 0 only-b 0)
== benign-browse-v1 PL1 worker (a=step-24 b=step-25):
status diffs: 0
worst-case set diffs: 0 (only-a 0 only-b 0)
== benign-browse-v1 PL2 inprocess (a=step-24 b=step-25):
status diffs: 0
worst-case set diffs: 0 (only-a 0 only-b 0)
== benign-browse-v1 PL2 worker (a=step-24 b=step-25):
status diffs: 0
worst-case set diffs: 0 (only-a 0 only-b 0)
== benign-hard-v0 PL1 inprocess (a=step-24 b=step-25):
status diffs: 0
worst-case set diffs: 0 (only-a 0 only-b 0)
== benign-hard-v0 PL1 worker (a=step-24 b=step-25):
status diffs: 0
worst-case set diffs: 0 (only-a 0 only-b 0)
== benign-hard-v0 PL2 inprocess (a=step-24 b=step-25):
status diffs: 0
worst-case set diffs: 0 (only-a 0 only-b 0)
== benign-hard-v0 PL2 worker (a=step-24 b=step-25):
status diffs: 0
worst-case set diffs: 0 (only-a 0 only-b 0)
== attacks-v0-inprocess-pl1: samples with an audit entry a=954 b=954; rule-id set differs for 0; ids gained in b: none; ids lost in b: none
== attacks-v0-worker-pl1: samples with an audit entry a=954 b=954; rule-id set differs for 0; ids gained in b: none; ids lost in b: none
== attacks-v0-inprocess-pl2: samples with an audit entry a=1024 b=1024; rule-id set differs for 0; ids gained in b: none; ids lost in b: none
== attacks-v0-worker-pl2: samples with an audit entry a=1024 b=1024; rule-id set differs for 0; ids gained in b: none; ids lost in b: none
== attacks-ct-v0-inprocess-pl1: samples with an audit entry a=292 b=292; rule-id set differs for 0; ids gained in b: none; ids lost in b: none
== attacks-ct-v0-worker-pl1: samples with an audit entry a=292 b=292; rule-id set differs for 0; ids gained in b: none; ids lost in b: none
== attacks-ct-v0-inprocess-pl2: samples with an audit entry a=313 b=313; rule-id set differs for 35; ids gained in b: {'942130': 7}; ids lost in b: {'942130': 28}
== attacks-ct-v0-worker-pl2: samples with an audit entry a=313 b=313; rule-id set differs for 35; ids gained in b: {'942130': 7}; ids lost in b: {'942130': 28}
== encoding-diff-v0-inprocess-pl1: samples with an audit entry a=137 b=137; rule-id set differs for 0; ids gained in b: none; ids lost in b: none
== encoding-diff-v0-worker-pl1: samples with an audit entry a=137 b=137; rule-id set differs for 0; ids gained in b: none; ids lost in b: none
== encoding-diff-v0-inprocess-pl2: samples with an audit entry a=147 b=147; rule-id set differs for 12; ids gained in b: {'942130': 12}; ids lost in b: none
== encoding-diff-v0-worker-pl2: samples with an audit entry a=147 b=147; rule-id set differs for 12; ids gained in b: {'942130': 12}; ids lost in b: none
== benign-browse-v1-inprocess-pl1: samples with an audit entry a=124 b=124; rule-id set differs for 0; ids gained in b: none; ids lost in b: none
== benign-browse-v1-worker-pl1: samples with an audit entry a=124 b=124; rule-id set differs for 0; ids gained in b: none; ids lost in b: none
== benign-browse-v1-inprocess-pl2: samples with an audit entry a=124 b=124; rule-id set differs for 0; ids gained in b: none; ids lost in b: none
== benign-browse-v1-worker-pl2: samples with an audit entry a=124 b=124; rule-id set differs for 0; ids gained in b: none; ids lost in b: none
== benign-hard-v0-inprocess-pl1: samples with an audit entry a=22 b=22; rule-id set differs for 0; ids gained in b: none; ids lost in b: none
== benign-hard-v0-worker-pl1: samples with an audit entry a=22 b=22; rule-id set differs for 0; ids gained in b: none; ids lost in b: none
== benign-hard-v0-inprocess-pl2: samples with an audit entry a=78 b=78; rule-id set differs for 0; ids gained in b: none; ids lost in b: none
== benign-hard-v0-worker-pl2: samples with an audit entry a=78 b=78; rule-id set differs for 0; ids gained in b: none; ids lost in b: none
```

Rates and counts (denominator: all requests; "attack" means "listed under
this family in the public source", rule 11; the benign sets are not merged,
rule 14; every block on them is a potential false positive, rule 46):

```

== PL1: rates and counts per run
attacks-v0-inprocess-pl1: requests 1054, distinct payloads 527; outcomes: waf_block 954, waf_pass 100
    recall best case (only waf_block) 954/1054 = 90.51%; worst case (every outcome that is not a pass) 954/1054 = 90.51%  [IN-SAMPLE for the REQUEST_BODY target choice of step 18]
    per family, blocked of requests: command-injection 224/300, path-traversal 298/300, sqli 132/154, xss 300/300
    rule 18: 954 audit entries; rule ids in >=20% of them: 949110=954, 930120=318, 941390=310, 941120=302, 941100=290, 941160=250, 930100=234
attacks-ct-v0-inprocess-pl1: requests 320, distinct payloads 40; outcomes: waf_block 292, waf_pass 28
    recall best case (only waf_block) 292/320 = 91.25%; worst case (every outcome that is not a pass) 292/320 = 91.25%  [IN-SAMPLE for the REQUEST_BODY target choice of step 18]
    per family, blocked of requests: command-injection 59/80, path-traversal 80/80, sqli 73/80, xss 80/80
    rule 18: 292 audit entries; rule ids in >=20% of them: 949110=292, 941390=88, 941120=80, 930120=80, 942100=72, 941100=72, 930100=72, 941160=64
encoding-diff-v0-inprocess-pl1: requests 192, distinct payloads 16; outcomes: error 10, waf_block 137, waf_pass 45
    blocked 137 of 192; not passed 147 of 192 (chosen cases: counts, not a rate, rule 35)
    per family, blocked of requests: command-injection 24/48, path-traversal 40/48, sqli 37/48, xss 36/48
    rule 18: 137 audit entries; rule ids in >=20% of them: 949110=137, 930120=40, 942100=37, 941100=36, 941120=36, 941160=36, 930100=30
benign-browse-v1-inprocess-pl1: requests 774, distinct endpoints 313; outcomes: waf_block 124, waf_pass 650
    potential false positives (natural benign, held-out): best case (only waf_block) 124/774 = 16.02%; worst case (every outcome that is not a pass) 124/774 = 16.02%
    rule 18: 124 audit entries; rule ids in >=20% of them: 949110=124, 911100=120
benign-hard-v0-inprocess-pl1: requests 180, distinct endpoints 2; outcomes: waf_block 22, waf_pass 158
    potential false positives (hard benign, held-out): best case (only waf_block) 22/180 = 12.22%; worst case (every outcome that is not a pass) 22/180 = 12.22%
    rule 18: 22 audit entries; rule ids in >=20% of them: 949110=22, 932260=10, 942100=6, 932235=6
== PL2: rates and counts per run
attacks-v0-inprocess-pl2: requests 1054, distinct payloads 527; outcomes: waf_block 1024, waf_pass 30
    recall best case (only waf_block) 1024/1054 = 97.15%; worst case (every outcome that is not a pass) 1024/1054 = 97.15%  [IN-SAMPLE for the REQUEST_BODY target choice of step 18]
    per family, blocked of requests: command-injection 276/300, path-traversal 300/300, sqli 148/154, xss 300/300
    rule 18: 1024 audit entries; rule ids in >=20% of them: 949110=1024, 930120=318, 941390=310, 941120=302, 942370=294, 941100=290, 942520=278, 941160=250, 932236=248, 941320=244, 930100=234
attacks-ct-v0-inprocess-pl2: requests 320, distinct payloads 40; outcomes: waf_block 313, waf_pass 7
    recall best case (only waf_block) 313/320 = 97.81%; worst case (every outcome that is not a pass) 313/320 = 97.81%  [IN-SAMPLE for the REQUEST_BODY target choice of step 18]
    per family, blocked of requests: command-injection 73/80, path-traversal 80/80, sqli 80/80, xss 80/80
    rule 18: 313 audit entries; rule ids in >=20% of them: 949110=313, 942520=128, 942370=104, 941390=88, 932240=80, 941320=80, 941120=80, 930120=80, 942430=73, 942100=72, 941100=72, 930100=72, 942180=64, 941160=64
encoding-diff-v0-inprocess-pl2: requests 192, distinct payloads 16; outcomes: error 10, waf_block 147, waf_pass 35
    blocked 147 of 192; not passed 157 of 192 (chosen cases: counts, not a rate, rule 35)
    per family, blocked of requests: command-injection 34/48, path-traversal 40/48, sqli 37/48, xss 36/48
    rule 18: 147 audit entries; rule ids in >=20% of them: 949110=147, 942520=73, 942430=60, 942370=54, 920230=41, 930120=40, 942100=37, 942180=36, 941100=36, 941120=36, 941160=36, 930100=30
benign-browse-v1-inprocess-pl2: requests 774, distinct endpoints 313; outcomes: waf_block 124, waf_pass 650
    potential false positives (natural benign, held-out): best case (only waf_block) 124/774 = 16.02%; worst case (every outcome that is not a pass) 124/774 = 16.02%
    rule 18: 124 audit entries; rule ids in >=20% of them: 949110=124, 911100=120
benign-hard-v0-inprocess-pl2: requests 180, distinct endpoints 2; outcomes: waf_block 78, waf_pass 102
    potential false positives (hard benign, held-out): best case (only waf_block) 78/180 = 43.33%; worst case (every outcome that is not a pass) 78/180 = 43.33%
    rule 18: 78 audit entries; rule ids in >=20% of them: 949110=78, 932236=34, 931130=16
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
```

The worker-mode runs are left out of this excerpt; their lines are the same
as the in-process ones (docs/logs/step25-own-summary.txt, and the parity
block above: 5,040 pairs, 0 differences of any kind).

### T4. The wcp datasets on the step-25 engine against step 24

`PARITY_STEP=25 PARITY_REF=docs/logs/runs/s24-parity PARITY_REF_NAME=step-24
WCP_DATA_DIR=$HOME/work/kortex-shield-dev/data STUB_PORT=13004 bash
tools/run_step23_parity.sh`

```
== rate table (benign-labelled external traffic; every block is a potential false positive)
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
== per sample against the in-process runs under docs/logs/runs/s24-parity:
== step-24 (docs/logs/runs/s24-parity, in-process) against step-25 (docs/logs/runs/s25-parity, in-process), per sample
benign-wcp-v0 PL1: 20000 ids; status diffs 0; outcome diffs 0; rule-id set diffs 0
benign-wcp-v0 PL2: 20000 ids; status diffs 0; outcome diffs 0; rule-id set diffs 3
    rules wcp-1748c143d540: only step-24 ['942130'] only step-25 []
    rules wcp-963a0020f247: only step-24 ['942130'] only step-25 []
    rules wcp-c902dbf3907a: only step-24 [] only step-25 ['942130']
    rule-id set diffs by shape: only step-24 ['942130'] / only step-25 [] x2; only step-24 [] / only step-25 ['942130'] x1
benign-wcp-v1 PL1: 10000 ids; status diffs 0; outcome diffs 0; rule-id set diffs 0
benign-wcp-v1 PL2: 10000 ids; status diffs 0; outcome diffs 0; rule-id set diffs 1
    rules wcp-2772e83687b1: only step-24 ['942130'] only step-25 []
    rule-id set diffs by shape: only step-24 ['942130'] / only step-25 [] x1
```

### Final suites

```
== 2026-11-28T07:03:50Z git 497d585e8f0dfa49ba5f1fe71c12f8ec6071142e go version go1.27.4 darwin/arm64 load at start: load averages: 3.80 3.87 3.80
$ go test -count=1 -v -timeout 900s ./...
# result lines counted with grep -c '^--- PASS|FAIL|SKIP': PASS 70 FAIL 0 SKIP 5
--- SKIP: TestE16BodyProcessingBoundedByTimeBudget (0.00s)
--- SKIP: TestE17AbandonedCallOwnsTransaction (0.00s)
--- SKIP: TestE19OverloadCapImmediate (0.01s)
--- SKIP: TestE20OverloadRecovery (0.01s)
--- SKIP: TestE21BenignPromptOnCapReachedEngine (0.01s)
ok  	kortexshield/engine	66.964s
== exit 0 2026-11-28T07:04:58Z load at end: load averages: 3.59 3.74 3.75

== 2026-11-28T07:05:46Z git 497d585e8f0dfa49ba5f1fe71c12f8ec6071142e go version go1.27.4 darwin/arm64 load at start: load averages: 3.55 3.69 3.73
$ KORTEX_TEST_WCP_BODY=<fixture> go test -count=1 -v -timeout 900s ./...
# result lines counted the same way: PASS 75 FAIL 0 SKIP 0
ok  	kortexshield/engine	347.887s
== exit 0 2026-11-28T07:11:35Z load at end: load averages: 7.81 6.89 5.28

== 2026-11-28T07:11:35Z git 497d585e8f0dfa49ba5f1fe71c12f8ec6071142e Python 3.15.2 load at start: load averages: 7.81 6.89 5.28
$ .venv/bin/python -m pytest -q
.............................................................ss..s...... [ 28%]
........................................................................ [ 56%]
........................................................................ [ 84%]
....................................----------------------------------------
.Exception occurred during processing of request from ('127.0.0.1', 55259)
..                                  [100%]
252 passed, 4 skipped in 60.09s (0:01:00)
== exit 0 2026-11-28T07:12:35Z load at end: load averages: 6.10 6.58 5.27
```

### The one failed Go run of T3, and what it is

The first full Go run after the E56 fix had 1 FAIL,
`TestT3dWorkerRecycleAfterN` (docs/logs/step25-t3b-go-test.log; that run
kept only the result lines, so its message is lost). Two more full runs and
the two final runs above have 0 FAIL. Repeating the one test 200 times
shows the failure and its message, on the step-25 engine and on the
step-24 engine (DIAGNOSTIC, scratch copy of `git archive 4f53d03 engine`):

```
# step-25: TestT3dWorkerRecycleAfterN 200 times in one process at 497d585e8f0dfa49ba5f1fe71c12f8ec6071142e, 2026-11-28T07:13:57Z, go version go1.27.4 darwin/arm64, load at start: load averages: 3.59 5.67 5.04
# cd engine && go test -count=200 -timeout 900s -run 'TestT3dWorkerRecycleAfterN' -v .
    testing.go:1619: TempDir RemoveAll cleanup: unlinkat /var/folders/nq/sk_8btb16995njvp54fs72180000gs/T/TestT3dWorkerRecycleAfterN1171040436/001: directory not empty
--- FAIL: TestT3dWorkerRecycleAfterN (0.15s)
    testing.go:1619: TempDir RemoveAll cleanup: unlinkat /var/folders/nq/sk_8btb16995njvp54fs72180000gs/T/TestT3dWorkerRecycleAfterN2352749991/001: directory not empty
--- FAIL: TestT3dWorkerRecycleAfterN (0.15s)
FAIL
FAIL	kortexshield/engine	31.141s
FAIL
# load at end: load averages: 3.62 5.48 4.99
# stderr lines of worker processes that started after the test's directory was removed (left out here): 'worker: rule load failed: invalid WAF config from audit log: open <tmp>/audit.log: no such file or directory' x 198, 'worker: audit touch failed: open <tmp [...]
# result: 2 FAIL of 200

# step-25 DIAGNOSTIC: the same test 200 times on the step-24 engine (git archive 4f53d03 engine, scratch copy), 2026-11-28T07:14:47Z, go version go1.27.4 darwin/arm64, load at start: load averages: 4.19 5.48 5.01
# cd <scratch>/engine && go test -count=200 -timeout 900s -run 'TestT3dWorkerRecycleAfterN' -v .
    testing.go:1619: TempDir RemoveAll cleanup: unlinkat /var/folders/nq/sk_8btb16995njvp54fs72180000gs/T/TestT3dWorkerRecycleAfterN3407415865/001: directory not empty
--- FAIL: TestT3dWorkerRecycleAfterN (0.14s)
FAIL
FAIL	kortexshield/engine	31.276s
FAIL
# load at end: load averages: 5.01 5.57 5.06
# stderr lines of worker processes that started after the test's directory was removed (left out here): 'worker: rule load failed: invalid WAF config from audit log: open <tmp>/audit.log: no such file or directory' x 199, 'worker: audit touch failed: open <tmp [...]
# result: 1 FAIL of 200

```

- It is not introduced by step 25: the step-24 engine fails the same way
  (1 of 200; step 25: 2 of 200). PROVEN for "exists before step 25" by the
  DIAGNOSTIC run; the rates are too small to compare.
- The assertion that fails is Go's cleanup of the test's temporary
  directory (`directory not empty`), not a status or a counter of the
  test. HYPOTHESIS for the cause: when the test ends, a worker process that
  the pool started as a replacement is still starting and creates its
  audit.log in the directory while it is being removed; the `worker: ...
  no such file or directory` lines are such workers arriving after the
  removal. Not tested by an experiment that would tell it apart from
  another cause.
- Not fixed in this step (rule 1). It means the Go suite can fail about
  once in a hundred runs of this test for a reason outside the tested
  behaviour, and that worker processes can outlive the engine's shutdown.
  See question 7.

## Deviations from instructions

1. Rule 17 and `ctl:ruleRemoveById`: the suite's marker rule 999999
   removes every rule for a request that carries the `X-CRS-Test` header.
   It is rendered only with `KORTEX_CRS_TEST_SETUP=on`, which no baseline,
   parity or dataset run sets (`crs_test_setup` on `/__kortex/config`
   proves it per run; E51 tests the off state). I read the instruction to
   run the suite as allowing it and wrote it into docs/baseline-config.md
   before the run. See question 1.
2. T3 was not in the brief. The suite showed four differences that are
   bugs of the engine (rule 39 says a BUG is fixed test first), and E56 was
   found while fixing them. The plan allows a fix "inside the request path
   the engine already has". Each has its failing test committed before the
   fix.
3. E55 was narrowed after its first form broke E24 PL2. The first form is
   in f47d4a6, the revised one in 3d52ae4; no fix was committed between
   them and no existing test was changed.
4. The reference is not coraza's harness unchanged: three
   `SecDefaultAction` lines of crs-setup.conf.example had to be removed
   (coraza refuses a second default action per phase), and rule 900511 was
   added for ref-strict and ref-upstream. The harness as written is
   reported as ref-asis (4,746 / 241).
5. go-ftw stops the whole run when a `retry_once` test fails twice
   (959100-1, 959100-3 on the engine). The script counts the test as
   failed, excludes it (`-e`) and restarts; the excluded ids are in each
   run's aborted.txt and in the log. The pass rate keeps them in the
   denominator.
6. The plan says the error logs are "kept compressed with the run". They
   are not committed: about 26 MB each, 1.25 MB compressed, 16 runs. Each
   run log has its line count, size and SHA-256; the committed evidence per
   run is go-ftw's own JSON output with the rule ids it found per test
   (`--report-triggered-rules`) and the engine's events in compact form.
7. The commit message of faec538 says the own datasets were compared in
   "5,040 pairs". The comparison covers 20 runs, 10,080 pairs (2,520
   requests, two levels, two modes). The result (0 differences) is the
   same. The message is not rewritten because the run logs name the commit
   hashes.
8. docs/logs/step25-t3-worker-tests-x6.log names commit b37631c. That is
   the E56 fix commit before it was amended to add log files (497d585);
   `git diff b37631c 497d585` shows only three added files under docs/logs.
9. One commit per task (rule 8) was kept as: failing tests and fixes in
   separate commits (rule 40), so T1 and T3 have more than one commit.

## UNVERIFIED items

- The suite against the Coraza connector and ModSecurity images: NOT
  MEASURED. The reference here is coraza the library behind Go's net/http,
  not the connector image.
- That the 78 response-rule tests would pass if the engine inspected
  responses: HYPOTHESIS, not tested on the engine.
- The causes of the 4 reference-shared failures 920620-1 and 922130-1, -2,
  -7: HYPOTHESIS.
- The 11 other chain-starting rules that keep the REQUEST_BODY target
  (931130, 932200, 932240, 933150, 941310, 942131, 942200, 942440, 942521,
  943110, 943120): whether one of them loses matches the way 942130 did is
  not tested. No CRS test shows it.
- What the 942130 change gives up: a tautology that the form split
  destroys was matched by 942130 through the raw body and no longer is by
  this rule. Measured only on our datasets: 942130 lost on 28 requests of
  attacks-ct-v0 at PL2 (gained on 7), and on 3 wcp requests (gained on 1);
  no status changed. Not measured on any other input.
- The suite in blocking mode, at paranoia levels 1 to 3, and with other
  CRS versions: NOT MEASURED.
- Timing: NOT MEASURED in this step.
- `TestT3dWorkerRecycleAfterN` fails about 1 time in 100 at cleanup
  (above). The cause is a HYPOTHESIS; whether a worker process can outlive
  a real engine shutdown (outside the tests) is not tested.
- pytest prints one `Exception occurred during processing of request` line
  on stderr during `tests/test_stub_backend.py::test_head_returns_200_no_body`
  (the stub backend's server, after the client closed a HEAD exchange); the
  test passes. The test and the stub are unchanged since step 24
  (`git diff 4f53d03 -- tests/test_stub_backend.py tools/stub_backend.py kortex_eval` is empty);
  the step-24 log kept stdout only, so whether the line appeared then is
  UNVERIFIED.

## Questions for instructor

1. Rule 17: is the marker rule 999999 (`ctl:ruleRemoveById=1-999999`,
   test-only switch) acceptable as done, or do you want the suite's log
   markers produced another way?
2. A1's pass condition is 100% and the engine is at 97.49%. 78 of the 125
   failures need response inspection (phases 3 and 4), which the engine
   does not have. Options: (a) build response inspection as its own step;
   (b) restate A1 as "100% of the request-rule tests" and list response
   inspection as a known limit. On the request rules alone the count is
   47 failed.
3. 19 failures come from having no content-type allow-list (decision 0002
   C4). Keep that decision, knowing CRS rule 920420 is inactive on the
   engine?
4. 15 failures are matches of the REQUEST_BODY targets on requests the CRS
   project wrote as benign for that rule. They are evidence against the
   step-18 choice from an independent source. Keep the targets, narrow
   them, or wait for the held-out attack set of step 26 to weigh recall
   against this?
5. The 3 gate refusals (Transfer-Encoding with Content-Length, an HTTP
   version Go does not parse): keep refusing before the rules? The suite
   expects the rules to see the first one.
6. 942130: accept the change (the rule again matches a tautology in a form
   body, and no longer matches through the raw body), or would you rather
   keep both by patching how coraza handles captures across targets?
7. `TestT3dWorkerRecycleAfterN` fails about once in a hundred runs at
   cleanup, on the step-24 engine too. I propose to find the cause and fix
   it test-first in step 28, where the engine's shutdown and failure
   behaviour are the subject. Agreed, or sooner?
