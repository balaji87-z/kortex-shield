# Baseline v1.9 (step-24, 2026-11-27)

Host, tools and datasets are those of baseline v1.8 (macOS 27.0 arm64, Apple
M6, go1.27.4, Python 3.15.2, pytest 9.2.0; no container image was used in
this step). What changed is the engine's gate. Every run below prints the
engine's `/__kortex/config` output in its log (rule 29) and names the engine
binary.

Engine of this baseline: built from 40c57ad or later with no change under
engine/ after it; darwin/arm64 binary sha256 3aef0168...96cc79. Coraza
v3.8.1 with the step-23 patch, CRS 4.25.2 (engine/RULES.sha256 unchanged).
No limit, lane, budget or rule setting changed (docs/baseline-config.md is
unchanged). kortex_eval is unchanged in this step. Raw outputs and
deviations: reports/step-24.md.

## What changed in the engine

| id | change | test (failing first) |
|---|---|---|
| T1 | a request head that Go's net/http would answer itself without running the handler (bare 400, 501, 505, 417, 431) is refused by the gate: `400 kortex-decision=framing`, one `framing` event, reason `parser:<class>` | E42 (33 cases), E43, E44, E45 |
| T2a | the framing checks also read the header lines the way Go's parser does, so a Content-Length or Transfer-Encoding line after a bare LF is seen | E46, E47 |
| T2b | keep-alive is off on the engine's server: a connection carries one request, so every request is judged by the gate | E48 |

T2a and T2b are holes of the framing gate that existed before this step and
were found while building T1. Both let a request the gate refuses reach the
backend (E46: 4 of 4 cases; E48: 6 of 6). The request was still inspected by
the rules and forwarded with the engine's own framing.

## Parser refusals (T1)

- The 61 cases of the step-23 parsing differential, same backends: 0 are
  refused without a kortex marker (step 23: 17). The 17 moved from a bare
  400 (12) or 501 (5) to `400 kortex-decision=framing` with an event
  (`parser:content-length` 8, `parser:transfer-encoding` 5,
  `parser:request-target` 3, `parser:header-name` 1). The other 44 cases
  are unchanged; the disagreement classes against the Python and the Go
  backend are unchanged in 61 of 61 cases; 29 framing answers, 29 framing
  events. docs/logs/step24-parsing-diff.txt,
  docs/logs/step24-parsing-diff-vs-step23.txt.
- The gate and net/http decide alike on 19,257 seeded damaged heads: 11,890
  refused by both, 7,367 passed by both, 0 decided differently (E45). With
  the gate's Expect check switched off the same test fails on 421 heads
  (DIAGNOSTIC), so it can see a missing check.
- Status change: what net/http answered 501, 505, 417 or 431 is now 400.
- Left as it was: `OPTIONS *` is answered 200 by net/http itself,
  uninspected, not forwarded, no event; a head the gate cannot read (no
  blank line in 30 s, or more than 65,536 bytes) is closed without an
  answer.

## Our own datasets with the step-24 engine (T4)

First engine runs of these datasets with Host `localhost` (step 21 sent
them to 127.0.0.1). Denominator: all requests. "attack" means "listed under
this family in the public source", not "verified exploitable" (rule 11).
In-process and worker mode give the same line in every cell.

Attack datasets. Recall best case counts only `waf_block` (headline, rule
21); worst case also counts errors. attacks-v0 and attacks-ct-v0 are
IN-SAMPLE for the REQUEST_BODY target choice of step 18 (rules 19, 45).

| dataset | requests | distinct payloads | PL | waf_block | error | pass | recall best case (headline) | worst case |
|---|---|---|---|---|---|---|---|---|
| attacks-v0 (IN-SAMPLE) | 1,054 | 527 | 1 | 954 | 0 | 100 | 954/1,054 = 90.51% | 90.51% |
| attacks-v0 (IN-SAMPLE) | 1,054 | 527 | 2 | 1,024 | 0 | 30 | 1,024/1,054 = 97.15% | 97.15% |
| attacks-ct-v0 (IN-SAMPLE) | 320 | 40 | 1 | 292 | 0 | 28 | 292/320 = 91.25% | 91.25% |
| attacks-ct-v0 (IN-SAMPLE) | 320 | 40 | 2 | 313 | 0 | 7 | 313/320 = 97.81% | 97.81% |
| encoding-diff-v0 | 192 | 16 | 1 | 137 | 10 | 45 | counts only (rule 35) | |
| encoding-diff-v0 | 192 | 16 | 2 | 147 | 10 | 35 | counts only (rule 35) | |

Per family, blocked of requests:

| dataset | PL | command-injection | path-traversal | sqli | xss |
|---|---|---|---|---|---|
| attacks-v0 | 1 | 224/300 | 298/300 | 132/154 | 300/300 |
| attacks-v0 | 2 | 276/300 | 300/300 | 148/154 | 300/300 |
| attacks-ct-v0 | 1 | 59/80 | 80/80 | 73/80 | 80/80 |
| attacks-ct-v0 | 2 | 73/80 | 80/80 | 80/80 | 80/80 |
| encoding-diff-v0 | 1 | 24/48 | 40/48 | 37/48 | 36/48 |
| encoding-diff-v0 | 2 | 34/48 | 40/48 | 37/48 | 36/48 |

- The 10 errors of encoding-diff-v0 are the 10 `encd-query-plain-*`
  requests whose query holds a raw space: the Python client refuses to
  build the URL (`InvalidURL`), so they were never sent. Same 10 as in
  step 21.
- No deny_status, inconsistent or fail-closed outcome and no framing event
  in any of the 20 runs.

Benign datasets, never merged (rule 14). Every block is a potential false
positive (rule 46); both are held-out for every engine setting.

| dataset | kind | requests | distinct endpoints | PL | waf_block | best case | worst case (headline) |
|---|---|---|---|---|---|---|---|
| benign-browse-v1 | natural | 774 | 313 | 1 | 124 | 124/774 = 16.02% | 124/774 = 16.02% |
| benign-browse-v1 | natural | 774 | 313 | 2 | 124 | 124/774 = 16.02% | 124/774 = 16.02% |
| benign-hard-v0 | hard | 180 | 2 | 1 | 22 | 22/180 = 12.22% | 22/180 = 12.22% |
| benign-hard-v0 | hard | 180 | 2 | 2 | 78 | 78/180 = 43.33% | 78/180 = 43.33% |

- Rule 18/24: on benign-browse-v1, 911100 (method not allowed) is in 120 of
  the 124 audit entries at both levels. The dataset has 90 PUT and 30 DELETE
  requests and the engine allows GET HEAD POST OPTIONS: CONFIG-MISMATCH,
  as in the earlier baselines. On the attack sets the common rules are the
  detection rules of the family (930120, 941100, 941120, 941160, 941390,
  942100, ...), listed with counts in docs/logs/step24-own-summary.txt.
- Parity per sample id (rule 32), 5,040 pairs each: in-process against
  worker, and patched against a DIAGNOSTIC build of the same commit on
  stock coraza v3.8.1: 0 status differences, 0 worst-case-set differences,
  0 rule-id-set differences in both comparisons.
- DIAGNOSTIC numeric Host, PL1: sent to 127.0.0.1, every audit entry
  carries 920350 (954, 292, 137, 124, 22 of the entries; 0 with Host
  localhost) and no status differs in the 2,520 requests. The statuses are
  also those of the step-21 runs (0 of 2,520 differ). PL2 with a numeric
  Host: NOT MEASURED.
- Logs: docs/logs/step24-own-datasets.txt,
  step24-own-datasets-DIAGNOSTIC-stock-coraza.txt,
  step24-own-datasets-DIAGNOSTIC-numeric-host.txt, step24-own-summary.txt,
  docs/logs/runs/s24-own/.

## The wcp datasets with the step-24 engine (T5)

Unchanged from baseline v1.8, sample by sample: against the step-23 runs, 0
status, 0 outcome and 0 rule-id-set differences in 60,000 pairs. The gate
refuses none of the 30,000 requests (0 framing events in all eight runs).

| dataset | PL | waf_block (403) | fail-closed 413 | fail-closed 415 | fail-closed 400 / 503 | deny_status | inconsistent | error | best case | worst case (headline) |
|---|---|---|---|---|---|---|---|---|---|---|
| benign-wcp-v0 (IN-SAMPLE for the 921 exclusion) | 1 | 2,184 | 28 | 19 | 0 | 52 | 0 | 1 | 2,184/20,000 = 10.92% | 2,284/20,000 = 11.42% |
| benign-wcp-v0 (IN-SAMPLE for the 921 exclusion) | 2 | 8,866 | 28 | 19 | 0 | 52 | 1 | 1 | 8,866/20,000 = 44.33% | 8,967/20,000 = 44.84% |
| benign-wcp-v1 | 1 | 1,091 | 17 | 0 | 0 | 25 | 0 | 0 | 1,091/10,000 = 10.91% | 1,133/10,000 = 11.33% |
| benign-wcp-v1 | 2 | 4,438 | 17 | 0 | 0 | 25 | 0 | 0 | 4,438/10,000 = 44.38% | 4,480/10,000 = 44.80% |

In-process against worker mode, 60,000 pairs: 0 status, 0 worst-case-set
and 0 rule-id-set differences. Logs: docs/logs/step24-parity.txt,
docs/logs/runs/s24-parity/.

## Not measured in this step

The connector and ModSecurity images; any timing; the parsing differential
at PL2, against other backends, and with the new shapes (bare LF, connection
reuse, Host, version, Expect), which are covered by the Go tests on the
engine only; raw requests the Python client cannot send (the 10 of
encoding-diff-v0); the CRS regression suite on the patched coraza.
