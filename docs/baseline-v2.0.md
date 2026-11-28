# Baseline v2.0 (step-25, 2026-11-27)

Host and tools are those of baseline v1.9 (macOS 27.0 arm64, Apple M6,
go1.27.4, Python 3.15.2, pytest 9.2.0; no container image was used in this
step). New in this step: the CRS project's own regression suite, run for
the first time against the engine (acceptance A1), and five fixes the suite
led to. Every run below prints the engine's `/__kortex/config` output in
its log (rule 29) and names the engine binary.

Engine of this baseline: built from 497d585 with no change under engine/
after it; darwin/arm64 binary sha256 761ef5ad...702792fb. Coraza v3.8.1
with the step-23 patch, CRS 4.25.2 (engine/RULES.sha256 unchanged). No
limit, lane or budget changed. Two test-only switches were added, both off
by default (docs/baseline-config.md, step 25). kortex_eval is unchanged.
Raw outputs and deviations: reports/step-25.md.

## What changed in the engine

| id | change | test (failing first) |
|---|---|---|
| T1 | `KORTEX_ERROR_LOG`: one ModSecurity-form line per matched rule; `KORTEX_CRS_TEST_SETUP=on`: the suite's rules 900005, 900511 and marker rule 999999. Both off by default and shown on `/__kortex/config` | E49, E50 (guard E51) |
| T3 | the rules get the request target as it was sent and the request's own protocol, not a normalised target and the constant `1.1` | E52 |
| T3 | the rules see a Transfer-Encoding header (net/http removes it from the header map) | E53 |
| T3 | the rules see the Host line the request has: none when there is none, and the same in worker mode | E54 |
| T3 | CRS 942130 no longer gets the REQUEST_BODY target, which stopped it from matching a tautology in a form body: 165 target updates, were 166 | E55 |
| T3 | in-process the rules were given Content-Length twice; now once, as in worker mode | E56 |

The five T3 changes are BUG-class differences between the engine and stock
coraza found by the suite (E52 to E55) or while fixing them (E56). The
request that is forwarded to the backend is unchanged.

## A1: the CRS regression suite

CRS v4.25.2 tests (commit b9818c37, 320 files), go-ftw 2.1.0 (the version
the CRS workflow pins at this tag), albedo 0.3.0 as backend, the WAF in
DetectionOnly at paranoia level 4 with the suite's own setup, one request
at a time. Denominator: every test go-ftw lists, 4,987. A test that go-ftw
could not finish counts as failed.

| run | passed | failed | pass rate |
|---|---|---|---|
| engine, in-process (headline) | 4,862 | 125 | 4,862/4,987 = 97.49% |
| engine, with the CRS project's `coraza-overrides.yaml` | 4,863 | 124 | 97.51% |
| engine, worker mode | 4,862 | 125 | 97.49% |
| engine, repeat | 4,862 | 125 | 97.49% |
| DIAGNOSTIC: engine on stock coraza v3.8.1 | 4,862 | 125 | no baseline number (rule 34) |
| engine before the T3 fixes (c1bb0c5) | 4,857 | 130 | 97.39% |
| reference: stock coraza v3.8.1 as Go middleware, coraza's harness configuration plus rule 900511 | 4,970 | 17 | 99.66% |
| reference with the CRS overrides | 4,975 | 12 | 99.76% |
| reference, coraza's harness as written (no rule 900511) | 4,746 | 241 | 95.17% |

**A1 is failing: 125 tests fail, the pass condition is 0.**

- Per test id (rule 32): in-process against worker mode, against the
  repeat and against the DIAGNOSTIC stock-coraza build: 0 tests with a
  different result and 0 with a different logged rule-id set, of 4,987, in
  each comparison. The step-23 patch changes no test.
- The T3 fixes: 5 tests moved from failed to passed (920100-16, 920171-2,
  920171-3, 920280-1, 942130-7), none from passed to failed; 19 other tests
  keep their result with a different rule-id set (942130 in 15 of them).
  The E56 fix changed no test and no rule-id set.
- go-ftw 2.7.0 (first runs only): same results, except that it refuses to
  send 921140-1 (1 skipped).
- go-ftw stops a whole run when a `retry_once` test fails twice. That
  happens at 959100-1 and 959100-3 (response rules). They are counted as
  failed, excluded, and the run is restarted; every run in the table went
  the same way.

The 125 failed tests, each in exactly one group:

| group | tests | class | shown by |
|---|---|---|---|
| the test needs a response rule (files 950 to 956 and 959); the engine does not inspect responses | 78 | DESIGN | 950: 9, 951: 20, 952: 9, 953: 9, 954: 7, 955: 10, 956: 12, 959: 2; the reference, which inspects responses, passes all 78 |
| the test expects 920420 (content type not in the allow-list); the engine has no allow-list (rule 900220, decision 0002 C4) | 19 | DESIGN, PROVEN | DIAGNOSTIC without rule 900220: exactly these 19 more pass |
| the test says a rule must not match and it matches through the added REQUEST_BODY target | 15 | DESIGN, PROVEN | DIAGNOSTIC without the target updates: these 15 pass (and 942130-7, since fixed) |
| the gate refuses the request before the rules run | 3 | DESIGN | per-test probe: `framing 400` for 920181-1 (Transfer-Encoding with Content-Length), 920430-5 and 920430-8 (HTTP version); the reference fails the last two as well |
| the reference fails the test the same way | 10 | no difference to the reference | 6 expect the status 400 that Apache gives (920100-5, 920100-8, 920270-4, 920274-1, 920290-1, 920610-2), 920620-1, 922130-1, -2, -7 |

0 UNEXPLAINED. The 15 tests of the third group are requests the CRS
project wrote as benign for the rule under test: 932340-10 to -13,
942210-31, 942210-44, 942430-7, 942431-2, -3, -6, 942432-5, 942440-16, -21,
-22, -23. On the engine they are potential false positives of the
REQUEST_BODY targets. The reference fails 5 tests that the engine passes:
920100-4, 920280-3, 920290-4, 920430-3, 920430-9.

Logs: docs/logs/s25-ftw.txt (first runs, reference, DIAGNOSTIC runs),
docs/logs/s25-ftw-fixed.txt (final), docs/logs/step25-ftw-final-diffs.txt,
docs/logs/step25-failed-tests.txt, docs/logs/step25-failed-probe.txt,
docs/logs/runs/s25-ftw/, docs/logs/runs/s25-ftw-fixed/.

## Our own datasets on the step-25 engine

Every number of baseline v1.9 is unchanged. Against the step-24 runs, per
sample id, 20 runs, 10,080 pairs: 0 status differences and 0
worst-case-set differences. "attack" means "listed under this family in
the public source", not "verified exploitable" (rule 11). In-process and
worker mode give the same line in every cell.

| dataset | requests | distinct payloads / endpoints | PL | waf_block | error | best case | worst case |
|---|---|---|---|---|---|---|---|
| attacks-v0 (IN-SAMPLE for the REQUEST_BODY targets) | 1,054 | 527 payloads | 1 | 954 | 0 | recall 954/1,054 = 90.51% (headline) | 90.51% |
| attacks-v0 (IN-SAMPLE) | 1,054 | 527 payloads | 2 | 1,024 | 0 | recall 1,024/1,054 = 97.15% (headline) | 97.15% |
| attacks-ct-v0 (IN-SAMPLE) | 320 | 40 payloads | 1 | 292 | 0 | recall 292/320 = 91.25% (headline) | 91.25% |
| attacks-ct-v0 (IN-SAMPLE) | 320 | 40 payloads | 2 | 313 | 0 | recall 313/320 = 97.81% (headline) | 97.81% |
| encoding-diff-v0 | 192 | 16 payloads | 1 | 137 | 10 | counts only (rule 35) | |
| encoding-diff-v0 | 192 | 16 payloads | 2 | 147 | 10 | counts only (rule 35) | |
| benign-browse-v1 (natural) | 774 | 313 endpoints | 1 and 2 | 124 | 0 | 124/774 = 16.02% | 16.02% (headline) |
| benign-hard-v0 (hard) | 180 | 2 endpoints | 1 | 22 | 0 | 22/180 = 12.22% | 12.22% (headline) |
| benign-hard-v0 (hard) | 180 | 2 endpoints | 2 | 78 | 0 | 78/180 = 43.33% | 43.33% (headline) |

The two benign sets are never merged (rule 14); every block on them is a
potential false positive. attacks-v0 and attacks-ct-v0 are also IN-SAMPLE
for the 942130 change of this step in the sense of rule 45: their result
was seen before the change was kept. The change itself was chosen from the
CRS test 942130-7.

Rule-id sets differ from step 24 only by 942130, only at PL2, the same in
both modes: attacks-ct-v0 35 requests (942130 lost on 28, gained on 7),
encoding-diff-v0 12 requests (gained). No other id differs in any run.
Rule 18 / 24 lists are those of baseline v1.9 (911100 on 120 of the 124
benign-browse-v1 entries: CONFIG-MISMATCH).

Logs: docs/logs/step25-own-datasets.txt, step25-own-summary.txt,
step25-own-vs-step24.txt, docs/logs/runs/s25-own/.

## The wcp datasets on the step-25 engine

Unchanged from baseline v1.9 in status and outcome, sample by sample:
against the step-24 in-process runs 0 status and 0 outcome differences in
60,000 pairs. Rule-id sets differ on 4 requests, all at PL2 and all by
942130 alone (benign-wcp-v0: lost on 2, gained on 1; benign-wcp-v1: lost on
1). In-process against worker mode, 60,000 pairs: 0 status, 0
worst-case-set and 0 rule-id-set differences.

| dataset | PL | waf_block (403) | fail-closed 413 | fail-closed 415 | deny_status | inconsistent | error | best case | worst case (headline) |
|---|---|---|---|---|---|---|---|---|---|
| benign-wcp-v0 (IN-SAMPLE for the 921 exclusion) | 1 | 2,184 | 28 | 19 | 52 | 0 | 1 | 2,184/20,000 = 10.92% | 2,284/20,000 = 11.42% |
| benign-wcp-v0 (IN-SAMPLE for the 921 exclusion) | 2 | 8,866 | 28 | 19 | 52 | 1 | 1 | 8,866/20,000 = 44.33% | 8,967/20,000 = 44.84% |
| benign-wcp-v1 | 1 | 1,091 | 17 | 0 | 25 | 0 | 0 | 1,091/10,000 = 10.91% | 1,133/10,000 = 11.33% |
| benign-wcp-v1 | 2 | 4,438 | 17 | 0 | 25 | 0 | 0 | 4,438/10,000 = 44.38% | 4,480/10,000 = 44.80% |

Logs: docs/logs/step25-parity.txt, docs/logs/runs/s25-parity/.

## Not measured in this step

The suite against the Coraza connector and ModSecurity images; the suite
in blocking mode or at another paranoia level; whether any of the 11 other
chain-starting rules that keep the REQUEST_BODY target misses matches the
way 942130 did; any timing; a held-out attack set (step 26); what steps 27
and 28 cover.
