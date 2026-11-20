# Step-16 report

- Summary: Classified all 396 engine-vs-connector differing ids (rule 39):
  252 BUG (missing connector-image body-processor/parse-failure rules, PROVEN
  Coraza URLENCODED fallback), 141 DESIGN-C4, 2 DESIGN-FRONT cells, 1
  UNEXPLAINED-at-the-time. Fixed the BUG class test-first (E10-E15, rule 40);
  the re-run shows 146 remaining diffs, ALL documented DESIGN, zero BUG,
  zero UNEXPLAINED. Bounded body processing by the time budget (E16) and
  fixed the abandoned-call/tx.Close crash it exposed (E17); added real
  engine-audit-dialect samples (T4); docs updated (baseline-v1.1, decision
  0004 stays provisional).

## Task table

| task | status | evidence |
|---|---|---|
| Rules 39-40 appended to AGENTS.md | done | commit 2c363b0 |
| T1 classify all diffs BUG/DESIGN/UNEXPLAINED | done | docs/logs/step16-t1-classes.txt (396 ids), step16-t1-summary.txt, tools/analyze_step16_t1.py, commit 29fd635 |
| T2 fix BUGs test-first + full re-run + new diff table | done | failing E10-E15 5807afe (docs/logs/step16-t2-failing-tests.txt), fix 7d438fa, re-run tools/run_step16_t2.sh (docs/logs/step16-t2-runs.txt), table docs/logs/step16-t2-analysis.txt, confound docs/logs/step16-t2-confound.txt |
| T3 bound body processing by the budget, test-first | done | failing E16 bda1678, fix 6235777, follow-up E17 7d78963/39324c9 (docs/logs/step16-t3-e17-failing.txt), measurements docs/logs/step16-t3-runs.txt (+ first-pass kept) |
| T4 real engine-audit-dialect samples per case | done | docs/samples/kortex-audit-{attack,benign,limit,timeout}.txt, tests/test_crs_audit.py, commit 7668208 |
| T5 docs (baseline-v1.1, design/evidence/acceptance/decision 0004, README, this report) | done | docs/baseline-v1.1.md, docs/engine-design.md, docs/engine-evidence.md, docs/acceptance.md, docs/decisions/0004-engine-core.md, README.md |

## Key results (numbers in the body, rule 31)

### T1 classification (inputs: step-15 T6 engine runs vs connector reference)

396 differing ids: **252 BUG** (every one an application/json POST, verified
from the frozen manifests), **141 DESIGN-C4** (920420 content-type
allow-list: attacks-ct-v0 18+3, benign-browse-v1 60+60), **1
UNEXPLAINED-at-the-time** (attacks-v0 PL2 command-injection-036c522d-q),
**2 DESIGN-FRONT cells** (smoke trav-01, connector nginx 400 vs engine
930100/930110). Correction: the T1 summary file's "253 BUG" double-counts
the UNEXPLAINED id; the cells sum to 252.

BUG root cause PROVEN (three independent proofs):
1. Coraza v3.7.0 internal/corazawaf/transaction.go ProcessRequestBody: with
   ForceRequestBodyVariable (CRS 901340) and no processor selected it sets
   `rbp = "URLENCODED"` (source comment admits JSON/XML "must be forced
   with ctl:requestBodyProcessor").
2. The connector image ships the missing rules (/opt/coraza/config/
   coraza.conf lines 31-41): 200000 XML, 200001 JSON, 200007 &ARGS>=1000
   deny 400, 200002 REQBODY_ERROR deny 400, 200003 MULTIPART_STRICT_ERROR
   deny 400.
3. Engine-audit matched variables like `ARGS_NAMES:{"email":` (raw JSON as
   an argument name) — only the URLENCODED fallback produces that.

### T2 re-run after the fix (engine side re-run with the UA fix; ref side unchanged)

| dataset | PL | engine blocked | ref blocked | diff | class |
|---|---|---|---|---|---|
| smoke | 1/2 | 7/12 | 6/12 | 1+1 | DESIGN-FRONT |
| attacks-v0 | 1 | 954/1054 | 954/1054 | 0 | — |
| attacks-v0 | 2 | 1024/1054 | 1024/1054 | 0 | — |
| benign-browse-v1 | 1 | 124/774 | 184/774 | 60 | DESIGN-C4 |
| benign-browse-v1 | 2 | 124/774 | 184/774 | 60 | DESIGN-C4 |
| benign-hard-v0 | 1 | 22/180 | 22/180 | 0 | — |
| benign-hard-v0 | 2 | 78/180 | 78/180 | 0 | — |
| attacks-ct-v0 | 1 | 286/320 | 304/320 | 18 | DESIGN-C4 |
| attacks-ct-v0 | 2 | 310/320 | 316/320 | 6 | DESIGN-C4 |

**146 differing ids, all DESIGN (144 C4 + 2 front-proxy cells); zero BUG,
zero UNEXPLAINED.** 0 errors, 0 waf_deny_status, 0 inconsistent outcomes on
both sides in every cell. attacks-v0 and benign-hard-v0 are exact parity at
both PLs. The 3 attacks-ct PL2 C4 diffs T1 did not list are the BUG mask
lifting: CRS 920240's chain requires REQBODY_PROCESSOR == URLENCODED, so its
T6 engine blocks were fallback artifacts (PROVEN from the rule text).

Harness artifacts found, documented, and fixed (rules 18/24; both PROVEN by
raw-socket bisection + a Go tx probe):
- **Missing User-Agent on the engine side** (run scripts omitted
  --default-user-agent): CRS 920320 adds +2 (pl2) on every UA-less request.
  Engine audit totals were 5·n_crit + 3·n_warn + 2 vs the connector's
  5·n_crit + 3·n_warn. This alone explains the T1 "UNEXPLAINED" id and the
  T6 engine-only blocks on command-injection-036c522d-q/-login. The T1
  DIAGNOSTIC replay's contrary conclusion was itself the next artifact.
- **Numeric-IP Host in manual replays**: CRS 920350 (+3) — `Host:
  127.0.0.1:8082` blocks what `Host: localhost:8082` passes. Correction
  recorded in docs/logs/step16-t1-920230-replay.txt.

### T3 measurements (fixed binary; budget 2000 ms unless stated)

- Single replay of the 481,798-byte wcp body (inspection cap raised):
  **503 kortex-decision=timeout at 2.002-2.004 s** (budget+500 ms met).
- Unfettered cost (budget 60,000 ms): **403 at 42.41 s** — the work one
  abandoned goroutine performs in the background.
- Abandoned call (ownership fixed): finished at **elapsed_ms=43474-45114**
  with the real result (949110/403).
- Benign latency before the burst: **5.0 ms**. 20 concurrent copies:
  **20/20 answered 503 in 2.00-2.08 s** (none wedged, none crashed).
- Under the accumulated background load (20 × ~43 s CPU-bound goroutines,
  load average 15.41): benign latency 4.5 ms at +8 s, **59.5 ms at +59 s** —
  responsive but degraded; the goroutines were still running at script end.
- First-pass finding kept (rule 12): the handler's deferred tx.Close()
  killed the abandoned call (finish at budget+12 ms, stale 949110/403) and
  CRASHED the engine under concurrency (copy16 and the post-burst benign
  probe got status 000) — docs/logs/step16-t3-runs-firstpass-txclose.txt.

### Test suites

- `go test ./...` in engine/ (KORTEX_TEST_WCP_BODY set): **19/19 PASS**
  (E1-E9, E10 PL1/PL2, E11-E17), 0 FAIL.
- `pytest tests/ -q`: **110 passed** in 14.02 s.

## Raw evidence

- docs/logs/step16-t1-classes.txt (1208 lines, per-id), step16-t1-summary.txt,
  step16-t1-920230-replay.txt (with CORRECTION section).
- docs/logs/step16-t2-failing-tests.txt (8/8 FAIL), step16-t2-runs.txt
  (per-run effective-config lines, rule 29), step16-t2-analysis.txt (full
  per-id diff list with classes), step16-t2-confound.txt.
- docs/logs/step16-t3-e17-failing.txt, step16-t3-runs.txt,
  step16-t3-runs-firstpass-txclose.txt.
- docs/samples/kortex-audit-{attack,benign,limit,timeout}.txt.
- All runs used fresh containers per ref run (rule 13), --workers 1, and
  print the in-container effective config (rule 29). Counts, not rates
  (rule 35); errors/deny_status/inconsistent reported separately (rule 30):
  all zero in every cell of the re-run.

## Deviations from instructions

- The T2 engine-side re-run was needed twice: the first re-run inherited a
  harness bug (missing --default-user-agent on the engine side, inherited
  from the step-15 T6 script). Fixed in tools/run_step16_t2.sh (same UA on
  both sides) and re-run; the ref side was not re-run (it always had the
  UA). The connector-side s16-t2 outcomes are from the first re-run pass.
- E17 (abandoned-call ownership) was not in the task list; it was forced by
  evidence found during T3 (the first-pass crash + the 12 ms "finish").
  Treated as part of T3's fix under rule 40.
- The parity tests now send User-Agent and Host: localhost:8090 to match the
  runner contract on both sides; the tables were updated accordingly (the
  two formerly-excluded ids joined wantAttacksV0PL2).

## UNVERIFIED

- The claim "20 goroutines × ~43 s CPU-bound each" for the concurrency tail
  is arithmetic from the single-call measurement plus the observed load
  average; the individual conc abandoned-finished events were not captured
  (the goroutines were still running when the script ended and the engine
  was then stopped). The 20/20 answered-within-budget result is measured.
- The exact reason CRS 920320's message does not appear in the engine's
  audit `messages` (the +2 is proven by arithmetic and the tx probe, but the
  audit-message omission mechanism inside Coraza is not investigated).

## Questions for instructor

1. The engine deliberately does not implement two connector policies: the
   C4 content-type allow-list (decision 0002 addendum) and the method
   allow-list (crs-setup 900200; CRS 911100 never fires on the engine). Both
   are documented DESIGN differences with zero blocked-set impact on the
   current datasets. Should either be implemented for parity, or stay
   documented design differences?
2. The abandoned body-processing goroutine keeps ~43 s of CPU-bound work
   alive per over-budget request (no library cancellation exists). The
   engine stays responsive but degrades under accumulation (59.5 ms benign
   at +59 s with 20 pending). Acceptable as documented DoS behaviour, or
   should a future step add a hard cap on concurrent in-flight body
   processing (e.g., reject with 503 when N goroutines are already
   abandoned)?
3. The T1 summary file (committed in 29fd635) says "253 BUG" where the cells
   sum to 252 (the UNEXPLAINED id double-counted). Leave the file as-is with
   the correction noted here and in baseline-v1.1.md, or amend it?
