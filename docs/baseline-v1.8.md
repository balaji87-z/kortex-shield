# Baseline v1.8 (step-23, 2026-11-27)

Host, tools and datasets are those of baseline v1.7 (macOS 27.0 arm64, Apple
M6, go1.27.4, Python 3.15.2, pytest 9.2.0; no container image was used in
this step). What changed is the engine. Every run below prints the engine's
`/__kortex/config` output in its log (rule 29) and names the engine binary.

Engine of this baseline: built from 4d56170 or later with no change under
engine/ after cf79759; darwin/arm64 binary sha256 4bf1d57e...b42578.
CRS 4.25.2 (engine/RULES.sha256 unchanged). **The coraza library is no
longer stock v3.8.1**: engine/go.mod replaces it with
engine/third_party/coraza-v3.8.1-kortex, a copy of v3.8.1 with one patch
(below). Raw outputs and deviations: reports/step-23.md.

## What changed in the engine

| id | change | test (failing first) |
|---|---|---|
| T1 | every refusal of the framing gate writes a `framing` event (status 400, the gate's reason, the sample id); it wrote nothing before | E35, E36 |
| T2 | map-backed collections of coraza are walked in sorted key order (patch of +30 / -5 lines in 2 files plus 1 new file; 197 of the 200 vendored files are byte-identical to the module) | E37, E38, E39 |
| T3 | a body without Content-Encoding that starts with gzip (1f 8b 08) or zlib (78 01 / 5e / 9c / da) magic writes a log-only `would_reject` event; the decision is unchanged | E40, E41 |

No limit, lane, budget or rule setting changed (docs/baseline-config.md is
unchanged). kortex_eval is unchanged in this step.

## Rule matching is now repeatable (T2)

The same request, replayed, gets the same status and the same rule-id set.

| request | stock coraza v3.8.1 (b69492e) | patched (ed48b1e) |
|---|---|---|
| syn-chain, 2,000 replays, PL2 | 1,564 x 403, 436 x 200 | 2,000 x 403, rules 942130 + 949110 |
| syn-dup, 2,000 replays, PL2 | 2 rule-id sets: 1,701 with 941390, 299 without | 2,000 x one set of 8 rule ids |
| syn-chain / syn-chain-rev, 300 each | 228 x 403, 72 x 200 (first order) | 300 x 403 for each order |
| tautology under a key that sorts first, 300 | 230 x 200, 70 x 403 | 300 x 200 |

- The last row is the limit of the patch: repeatable is not the same as
  caught. CRS 942130's chained rule sees the captures of the last matching
  variable, which is now the one whose key sorts last, so a tautology
  followed (in key order) by a harmless `x=y` member is passed every time.
  ModSecurity 3.0.17 passes that shape too (baseline v1.7). Rule question,
  open.
- tools/flip_repro.py (two wcp samples), in-process, PL2, 5 x 500 rounds:
  0 flips per round in every repeat, on Host localhost and on 127.0.0.1
  (5,000 x 403 each, one rule-id set per sample). DIAGNOSTIC control on a
  coraza v3.7.0 scratch build (replace dropped): 741 and 573 of 2,500
  rounds with a flip.
- Cost: no difference seen at the resolution of these runs. Wall time of
  the four in-process wcp runs, stock (step-22 C2) against patched: 142 /
  141 s, 239 / 243 s, 68 / 67 s, 116 / 117 s; 2,000 replays of syn-chain
  2.35 / 2.39 s and of syn-dup 3.97 / 3.99 s. The host load differed
  between the stock and the patched runs (load 3 to 8); a controlled timing
  is NOT MEASURED.

## The wcp datasets with the step-23 engine

Benign-labelled natural traffic (rule 14: nothing merged; rule 46: every
block or refusal is a potential false positive). Denominator: all samples.
The one errored sample of v0 is flagged in the worst case only (rules 20,
21, 30). In-process and worker mode give the same line in every cell.

| dataset | PL | waf_block (403) | fail-closed 413 | fail-closed 415 | fail-closed 400 / 503 | deny_status | inconsistent | error | best case | worst case (headline) |
|---|---|---|---|---|---|---|---|---|---|---|
| benign-wcp-v0 | 1 | 2,184 | 28 | 19 | 0 | 52 | 0 | 1 | 2,184/20,000 = 10.92% | 2,284/20,000 = 11.42% |
| benign-wcp-v0 | 2 | 8,866 | 28 | 19 | 0 | 52 | 1 | 1 | 8,866/20,000 = 44.33% | 8,967/20,000 = 44.84% |
| benign-wcp-v1 | 1 | 1,091 | 17 | 0 | 0 | 25 | 0 | 0 | 1,091/10,000 = 10.91% | 1,133/10,000 = 11.33% |
| benign-wcp-v1 | 2 | 4,438 | 17 | 0 | 0 | 25 | 0 | 0 | 4,438/10,000 = 44.38% | 4,480/10,000 = 44.80% |

- These are the numbers of baseline v1.7's close-out table: the patch moved
  no status on these datasets (per sample against the stock-coraza runs: 0
  status differences and 0 outcome differences in 60,000 pairs; 1 rule-id
  set difference, wcp-7b0bdeda7bc7 at PL2, rule 942130 present in the stock
  replay only and blocked either way).
- In-process against worker mode, 60,000 pairs: 0 status differences, 0
  worst-case-set differences with the full fail-closed set (the first time
  this is measured: both modes now write `engine_decision`), and **0
  rule-id set differences** (step 22: 3 ids in each parity run).
- Rule 18/24, PL2, both sets and both modes: 931130, 942430, 942200,
  942370, 942340, 942330, 932200 each on 20% or more of the audit entries
  (949110 is the blocking evaluation rule); PL1 v0: 932370 on 466 of 2,236.
  Unchanged from v1.7; not re-examined.
- Logs: docs/logs/step23-parity.txt, docs/logs/runs/s23-parity/.

## Compressed-looking bodies without Content-Encoding (T3, log-only)

| dataset | samples | events (same in both modes and at both levels) | kind | what they are |
|---|---|---|---|---|
| benign-wcp-v0 | 20,000 | 14 | zlib, all `78 01` | POST, text/plain, 132 to 7,425 bytes |
| benign-wcp-v1 | 10,000 | 2 | zlib, both `78 01` | POST, text/plain, 294 and 1,190 bytes |

- No gzip magic in either dataset. All 16 samples are already blocked by
  rules at PL1 and at PL2 (waf_block 16 of 16), so the event marks nothing
  that passes today on these datasets.
- As replayed, none of the 16 bodies is a complete zlib stream. The
  manifests store bodies as text, so whether the original requests carried
  real zlib streams is UNVERIFIED.
- Logs: docs/logs/step23-magic-analysis.txt.

## 503 overload seen by the harness (T4, DIAGNOSTIC)

With the runner at `--workers 8` (every other run uses 1), 48 hand-written
100,000-byte benign POSTs, standard limits and no test hook: 46 of 48
(in-process) and 47 of 48 (worker mode) were answered
`503 kortex-decision=overload` and classified `waf_fail_closed_503_overload`;
the rest passed. Not a rate of anything; it shows the outcome exists on the
real engine. docs/logs/step23-overload-DIAGNOSTIC.txt.

## Strict parsing differential, first slice (T5)

61 hand-written raw requests (Content-Length 19, Transfer-Encoding 17,
invalid percent sequences 14, overlong UTF-8 11) sent to the engine and,
directly, to a local Python http.server and a local Go net/http backend.
Chosen cases: counts of cases, never a rate (rule 35).

| who decided in the engine | cases |
|---|---|
| forwarded | 14 |
| framing gate, 400 with event | 12 |
| rule block, 403 | 16 |
| body read error, 503 timeout with event | 2 |
| Go's HTTP parser inside the engine, 400 or 501, no marker, no event | 17 |

| backend | accepts directly | engine and backend disagree | of which: engine refuses, backend accepts | engine forwards, backend refuses | both accept, backend sees something else through the engine | canary reaches the backend |
|---|---|---|---|---|---|---|
| Python http.server | 61 of 61 | 50 | 47 | 0 | 3 | 0 |
| Go net/http | 37 of 61 | 23 | 23 | 0 | 0 | 0 |

- In every disagreement the engine is the stricter side or re-frames the
  request; no case was found where the engine lets through something a
  backend parses differently. The three "sees something else" cases are
  chunked bodies, which the engine reads and forwards with a
  Content-Length; the Python backend alone would read no body and leave
  the chunks on the connection.
- The two backends differ from each other on 31 of the 61 cases; the
  engine refuses 28 of those and re-frames the other 3.
- Finding: 17 refusals come from Go's HTTP parser, not from the engine's
  own code. They carry no kortex marker and no event, so the harness
  cannot tell them from a backend status (docs/block-discriminator.md).
- Finding: overlong UTF-8 in the PATH writes no log-only event (the checks
  cover the query and urlencoded bodies); one such case was forwarded
  silently (overlong NUL, `%C0%80`).
- The overlong canaries were blocked on the `alert(` call (941390), not on
  the tag: the engine does not turn an overlong `<` into `<`, and neither
  backend does. A backend that does was not in this slice (NOT MEASURED).
- Logs: docs/logs/step23-parsing-diff.txt,
  docs/logs/runs/s23-parsing-diff/results.jsonl.

## Suites

At 9754a0d (the last commit that changes code), run one after another:

| suite | passed | failed | skipped | time |
|---|---|---|---|---|
| Go, fixture not set | 55 | 0 | 5 (E16, E17, E19, E20, E21) | 62.676 s |
| Go, with the recorded wcp fixture, `-timeout 900s` | 60 | 0 | 0 | 336.432 s (E20 265.18 s) |
| pytest | 234 | 0 | 4 | 60.07 s |

Step 22 ended at Go 48 / 0 / 5 (53 / 0 / 0 with the fixture) and pytest
222 / 0 / 4. New Go tests: E35 to E41 (7). New Python tests: 12
(tests/test_step23_tools.py). coraza's own tests for 8 of its packages pass
on a full copy of the module with the committed patch applied
(docs/logs/step23-coraza-own-tests.txt). Logs:
docs/logs/step23-final-go-test.log, step23-final-go-test-with-fixture.log,
step23-final-pytest.log.

## Standing notes

- Replays go to `localhost`, never to a numeric address (v1.7).
- A parity or recall figure from this engine is now one replay that a
  second replay reproduces (shown on the 60,000 wcp pairs and on the two
  synthetic requests; the attack sets were not re-run in this step: NOT
  MEASURED).
- Rule-id parity against the stock connector image can no longer be exact
  for requests whose outcome depends on variable order: the connector
  still iterates at random and ModSecurity keeps arrival order.
