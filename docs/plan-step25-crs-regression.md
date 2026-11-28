# Step-25 plan: the CRS regression suite against the engine (written BEFORE any run)

Brief (instructor, 2026-11-27): "do all 4" of the four candidates offered
for the next stage. They are done as steps 25 to 28, in the order offered.
This step is the first: acceptance A1, "run the CRS regression suite
against our build", pass condition "100% of the suite"
(docs/acceptance.md). A1 has been `not started` since step 0. Since then
the engine got a patched coraza (step 23) and a gate that answers some
requests itself (steps 15, 23, 24), and baseline v1.9 lists "the CRS
regression suite on the patched coraza" as not measured.

No result of this suite on any build of the engine exists when this plan is
written. Nothing below was chosen after seeing one.

## Sources (rule 25: licence and source recorded before use)

| what | version | source | licence | hash |
|---|---|---|---|---|
| CRS regression tests | tag v4.25.2, commit b9818c3718bc75b99403aed6c4b23773004c5412 (tag object 89e96912...) | https://github.com/coreruleset/coreruleset/archive/refs/tags/v4.25.2.tar.gz, directory `tests/regression/tests` | Apache-2.0 (LICENSE in the tarball) | tarball sha256 a3ecf5d5b0f8001e2eaf2006448fc8e22d6b645d7fc1c71268be5b99a7395a2d; 320 yaml files, sha256 of the sorted `shasum -a 256` listing aec74fa450ee0b5f97d8a5e8edabeea06d0b78eaa7d3eebd6e0b85b137472e25 |
| CRS's own override list for Coraza | same tarball, `tests/regression/coraza-overrides.yaml` | same | Apache-2.0 | sha256 58c2ae7ad6412a71c9d4c61877ee7f210478ec3b0c15c07159196387cc0655ec |
| go-ftw (test runner) | v2.1.0, commit 734843e0003cd95f1635a12b17a8efccc8d98ec0: the version the CRS workflow pins at this tag (`.github/workflows/test.yml`, `GO_FTW_VERSION: '2.1.0'`) | `go install github.com/coreruleset/go-ftw/v2@v2.1.0` | Apache-2.0 | module h1:IGY5b8NI+1BWyrdoE8k0kpofgUtSQnMN/7b8yfB7E+4= |
| go-ftw, tool cross-check | v2.7.0, commit 5ea1f263c43b73b8346a782ce17a55f8a35a091e (latest release, 2026-11-24) | `go install github.com/coreruleset/go-ftw/v2@v2.7.0` | Apache-2.0 | module h1:Zhq+RE83Nr8YH1DvjXMfyntrQryQNtzDxQ+AF4s7fCQ= |
| albedo (the backend the suite expects) | v0.3.0, commit 3f7d0238b32d1f98059f5c70e0ffcafad514952c: the version in the CRS `tests/docker-compose.yml` at this tag | `go install github.com/coreruleset/albedo@v0.3.0` | Apache-2.0 | module h1:GC0CbI8/qzzBbiP95z7A+58pjlN8P5jheVrUwEfzRfQ= |
| Coraza's own harness for this suite (read, not run) | coraza v3.8.1, `testing/coreruleset/coreruleset_test.go`, `.ftw.yml`, `.ftw-overrides.yml` | https://github.com/corazawaf/coraza/tree/v3.8.1/testing/coreruleset | Apache-2.0 | read for the configuration only |

The rules the engine loads are the rules of the same tag: `diff -rq` of the
tarball's `rules/` against `engine/crs/owasp-crs/rules` reports no
difference (checked again by the run script, with `engine/RULES.sha256`).

Nothing of the tarball is committed. `tools/fetch/fetch_crs_regression.sh`
downloads it into gitignored `data/external/`, checks the hashes above and
installs the three tools into gitignored `out/step25/bin`. The tests are
hand-written attack and protocol samples of the CRS project; they hold no
recorded traffic (rule 51 does not apply; the pre-push scan runs anyway).
Every request is sent to the engine on localhost (rule 6).

By my count there are 4,997 `test_id` entries in the 320 files; the number
go-ftw reports is the one used in the report.

## How the suite is run (the CRS project's own procedure)

`tests/regression/README.md` and `tests/docker-compose.yml` of the tag:

- The WAF runs in DetectionOnly mode at paranoia level 4, with the settings
  of the README's rule 900005 (`crs_validate_utf8_encoding=1`,
  `arg_name_length=100`, `arg_length=400`, `total_arg_length=64000`,
  `max_num_args=255`, `max_file_size=64100`, `combined_file_sizes=65535`)
  and `crs_xml_attr_inspect=1` (rule 900511 in the compose file).
- go-ftw sends each test request between two marker requests that carry an
  `X-CRS-Test: <uuid>` header, then reads the WAF's log between the two
  markers and checks which rule ids were logged (`expect_ids`,
  `no_expect_ids`) and, for some tests, the status.
- The marker needs rule 999999, which logs the header value and switches
  every other rule off for the marker request (text taken from Coraza's
  harness, which says where it comes from: go-ftw PR 133).
- The backend is albedo, which answers anything and can be told what to
  answer (`/reflect`), for the response rules.

## What the engine needs for this (T1, test first, rules 37 and 40)

The engine writes one JSON audit entry per request that ends in 4xx / 5xx.
In DetectionOnly mode a request that matches rules is forwarded and
answered 200, so there is nothing for go-ftw to read. Two additions, both
off by default:

- **E49 `KORTEX_ERROR_LOG`**: a file that gets one line per matched rule
  with the `log` action, in the ModSecurity error-log form coraza produces
  (`MatchedRule.ErrorLog()`, the same call Coraza's own harness uses), in
  blocking and DetectionOnly mode, in-process and in worker mode. Unset: no
  file, nothing changes.
- **E50 `KORTEX_CRS_TEST_SETUP=on`**: adds rule 900005 (the setvars above,
  without the `ctl` actions: mode and paranoia stay with the engine's own
  settings), 900511 and the marker rule 999999 to the generated
  configuration, before the rule Include. Unset or any other value: the
  directives are not rendered, and a request with an `X-CRS-Test` header is
  judged like any other (guard test with an attack payload). The switch and
  the error-log path are printed at startup and on `/__kortex/config`
  (rule 29).

Rule 17 forbids `ctl:ruleRemove*` "unless a step explicitly allows them".
Rule 999999 has `ctl:ruleRemoveById=1-999999`. It is the suite's own
harness rule, it acts only on requests that carry the marker header, and it
is loaded only with the switch on, which no baseline or parity run sets. I
read the instruction to run the suite as allowing it; it is recorded in
docs/baseline-config.md before the run and listed under the report's
deviations and questions.

Nothing else in the engine is changed for the run: its gate, its limits
(13,107,200 / 131,072 bytes), its time budget (2,000 ms), its content-type
setting (900220) and its REQUEST_BODY targets stay as in baseline v1.9. The
engine does not look at responses (`SecResponseBodyAccess Off`, no phase 3
or 4 call in engine/proxy.go); that is not changed either, and what it
costs on this suite is measured.

## Runs

One engine process, one error log and one go-ftw process per run; albedo
restarted per run; go-ftw sends one request at a time. Tests address
`127.0.0.1` with `Host: localhost` in the test files; only the port is
overridden. The engine's `/__kortex/config` output is saved in each run's
log (rule 29).

| run | WAF | go-ftw | overrides | purpose |
|---|---|---|---|---|
| ref-strict | stock coraza v3.8.1 as Go middleware (`txhttp.WrapHandler`), Coraza's harness configuration (coraza.conf-recommended, rule 900005, 999999, crs-setup.conf.example), these rules, albedo in-process (`tools/crs-ftw-reference`) | 2.1.0 | none | what coraza itself scores with this runner on these tests |
| ref-upstream | same | 2.1.0 | CRS `coraza-overrides.yaml` | the figure the CRS project accepts for Coraza |
| engine-strict | engine at HEAD, in-process, DetectionOnly, PL4, test setup on | 2.1.0 | none | A1, headline |
| engine-upstream | same | 2.1.0 | CRS `coraza-overrides.yaml` | A1 with the CRS project's own allowances for Coraza |
| engine-worker | engine, worker mode | 2.1.0 | none | per-test parity with in-process |
| engine-repeat | as engine-strict | 2.1.0 | none | repeatability: per-test differences between two identical runs |
| engine-ftw270 | as engine-strict | 2.7.0 | none | does the runner version change a result |
| DIAGNOSTIC stock | the engine built in a scratch copy with the coraza `replace` dropped | 2.1.0 | none | per-test effect of the step-23 patch (rule 34: gives no baseline number) |

The container images (the Coraza connector and ModSecurity) are not run in
this step: NOT MEASURED. The reference above differs from the connector
(no nginx in front), so it says what coraza the library does, not what the
connector image does.

## What is reported

- Per run: tests run, passed, failed, ignored, skipped as go-ftw counts
  them; the pass rate with its denominator (all tests run; a test go-ftw
  could not run counts as failed in the worst case, rule 20).
- A1 status: passing only if engine-strict has 0 failed tests. Otherwise
  the count, never a rounded "about 100%".
- Every failed test of engine-strict by id, with: the rule file, what it
  expected, what the engine did (status, decision marker, logged ids),
  whether the reference fails it too, whether the CRS override list covers
  it, and exactly one class (rule 39): BUG (fixed test first, in this step
  if the fix is inside the request path the engine already has), DESIGN
  (the documented engine property it follows from, with the count measured
  here, rule 41), UNEXPLAINED (counted).
- Per-test differences, by test id (rule 32): engine-strict against the
  reference, worker, repeat, go-ftw 2.7.0 and DIAGNOSTIC stock.
- Engine events during the run by kind (framing, limit, timeout, overload,
  content-encoding): each one is a request the engine answered itself.
- After any fix: the suite again, and the Go and Python suites.

Durable files (rule 42) under docs/logs/runs/s25-ftw/<run>/: go-ftw's
output, the per-test result list, the engine's config proof and its events
file. The error logs quote the test payloads (the CRS project's own
samples); they are kept compressed with the run.

## Not in this plan

Response inspection in the engine (a feature, not a fix); the suite in
blocking mode; other CRS versions; the container images.
