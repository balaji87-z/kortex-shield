# Baseline v1.1 (step-16, 2026-11-20)

Dated notes on top of v1.0 (docs/baseline-v1.0.md, kept unchanged). Corrections
are listed here, never applied to older text. Step-16 classified every
engine-vs-reference difference (rule 39), fixed the BUG class test-first
(rule 40), bounded body processing by the time budget, and added real
engine-audit-dialect fixtures. The T6/T2 comparisons remain DIAGNOSTIC
(rule 34): "connector" is the reference for rule faithfulness, not
"correct" (rule 4).

## Rules 39-40 (process, committed before the work)

- AGENTS.md rules 39 (every engine-vs-reference diff classified exactly
  BUG / DESIGN / UNEXPLAINED, nothing dropped) and 40 (a failing Go test is
  committed before every engine fix) appended in commit 2c363b0.

## T1: classification of all step-15 T6 differing ids

Inputs: out/s15-t6-engine-* (engine) vs the step-12/14 connector reference
runs; 396 differing ids across the five datasets at PL1/PL2. Full per-id
dump: docs/logs/step16-t1-classes.txt; summary:
docs/logs/step16-t1-summary.txt; analysis tool: tools/analyze_step16_t1.py.

| class | ids (cells) | meaning |
|---|---|---|
| BUG | 252 | missing connector-image body-processor selection (200000 XML, 200001 JSON) and body-parse-failure rules (200002 REQBODY_ERROR, 200003 MULTIPART_STRICT_ERROR, 200007 &ARGS>=1000, each deny 400) |
| DESIGN-C4 | 141 | the connector's 920420 content-type allow-list (attacks-ct-v0 18+3, benign-browse-v1 60+60); the engine deliberately inspects any content type (C4, decision 0002 addendum) |
| UNEXPLAINED (at T1 time) | 1 | attacks-v0 PL2 command-injection-036c522d-q; explained during T2, see below |
| DESIGN-FRONT | 2 cells, 1 id | smoke trav-01: the connector's nginx rejects the %-encoded traversal path with 400 (proxy_reject) before the engine; the engine has no nginx front and CRS blocks it 930100/930110 |

- Correction to the T1 summary file: it says "BUG: 253 ids" but its own cell
  list sums to 252 distinct ids (the UNEXPLAINED id was double-counted under
  attacks-v0 PL2 "15 + 1 UNEXPLAINED = 16"). 396 = 252 + 141 + 1 + 2 cells.
- PROVEN root cause of the BUG class: Coraza v3.7.0
  internal/corazawaf/transaction.go ProcessRequestBody - with
  ForceRequestBodyVariable (CRS 901340) and no processor selected it falls
  back to `rbp = "URLENCODED"`; the connector image selects XML/JSON
  processors via rules 200000/200001 (/opt/coraza/config/coraza.conf lines
  31-41) which the engine lacked. Engine-audit evidence of the mangled
  fallback parse: matched variable NAMES like `ARGS_NAMES:{"email":` (raw
  JSON as an argument name). Every BUG id is an application/json POST
  (verified from the frozen manifests).

## T2: BUG fix, harness-artifact discovery, re-run

Test-first (rule 40): failing parity tests E10-E15 committed (5807afe) with
data-driven id->connector-outcome tables built from the frozen T6 outcomes;
failing evidence docs/logs/step16-t2-failing-tests.txt (8/8 FAIL). Fix
committed 7d438fa: image rules 200000/200001/200002/200003/200007 added to
engine/config.go directives(); Proxy.block() honors it.Status (400 denies).

### Harness artifacts found on the way (rules 18/24, documented, then fixed)

1. Missing User-Agent on the engine side. tools/run_step15_t6.sh and the
   first tools/run_step16_t2.sh engine-side runner invocation omitted
   --default-user-agent, so the engine saw UA-less requests while the
   connector saw the Chrome UA. CRS 920320 "Missing User Agent Header"
   (NOTICE) sets tx.inbound_anomaly_score_pl2=+2 on every UA-less request:
   engine totals were 5*n_crit + 3*n_warn + 2 while the connector's were
   5*n_crit + 3*n_warn (audit-arithmetic comparison over the PL2 attack
   entries; connector side identical arithmetic without the +2). This flipped
   marginal warning-score detections: command-injection-036c522d-q/-login
   (920230 +3 alone = 3 < 5 pass; + 2 = 5 block). Mechanism proof: Go tx
   probe with the engine directives - without UA: 920320 + 920230 matched,
   403; with UA: only 920230, pass. The earlier "stale ref" hypothesis and
   the T1 DIAGNOSTIC replay conclusion ("current container blocks it") were
   BOTH wrong: the replay sent Host: 127.0.0.1:8082 (numeric IP), firing
   920350 (+3) - raw socket bisection and the correction are in
   docs/logs/step16-t1-920230-replay.txt (CORRECTION section).
2. Numeric-IP Host in manual replays (920350, +3): same mechanism, my probe
   error; the runner itself uses localhost on both sides.

### Re-run (engine side with the UA fix; ref side unchanged, it always had the UA)

tools/run_step16_t2.sh (ENGINE_ONLY=1 for the engine side), runs
docs/logs/step16-t2-runs.txt, analysis docs/logs/step16-t2-analysis.txt
(tools/analyze_step16_t2.py), confound check docs/logs/step16-t2-confound.txt.

| dataset | PL | engine blocked | ref blocked | diff |
|---|---|---|---|---|
| smoke | 1 | 7/12 | 6/12 | 1 (DESIGN-FRONT trav-01) |
| smoke | 2 | 7/12 | 6/12 | 1 (DESIGN-FRONT trav-01) |
| attacks-v0 | 1 | 954/1054 | 954/1054 | 0 |
| attacks-v0 | 2 | 1024/1054 | 1024/1054 | 0 |
| benign-browse-v1 | 1 | 124/774 | 184/774 | 60 (DESIGN-C4) |
| benign-browse-v1 | 2 | 124/774 | 184/774 | 60 (DESIGN-C4) |
| benign-hard-v0 | 1 | 22/180 | 22/180 | 0 |
| benign-hard-v0 | 2 | 78/180 | 78/180 | 0 |
| attacks-ct-v0 | 1 | 286/320 | 304/320 | 18 (DESIGN-C4) |
| attacks-ct-v0 | 2 | 310/320 | 316/320 | 6 (DESIGN-C4) |

- Total differing ids: 146, ALL classified DESIGN (144 C4 + 2 front-proxy
  cells). ZERO BUG, ZERO UNEXPLAINED remain. 0 errors, 0 waf_deny_status,
  0 inconsistent outcomes on both sides in every cell.
- The three "new" C4 diffs at attacks-ct-v0 PL2 (command-injection-f48aa068
  and -ecb32a80 x octet-stream/text-plain/unknown-CT) are the BUG mask
  lifting: at T6 the engine's URLENCODED fallback made CRS 920240 fire (its
  chain REQUIRES REQBODY_PROCESSOR == URLENCODED - proof the fallback was
  engaged); with the correct processor the engine passes and only the C4
  content-type policy difference remains.
- The tests were aligned with the runner contract (User-Agent and
  Host: localhost:8090 in engine/step16_test.go sendSample/postJSON) and the
  two formerly-excluded ids joined wantAttacksV0PL2 (16 ids). go test: 19/19
  PASS (E1-E9, E10 PL1/PL2, E11-E17).

## T3: time budget bounds body processing

Test-first (rule 40): failing E16 committed (bda1678) - the 481,798-byte wcp
body (fixture read from KORTEX_TEST_WCP_BODY, skip when unset, rule 25) with
the inspection cap raised answered 403 after 44.1 s pre-fix. Fix committed
6235777: ProcessRequestBody runs in a goroutine bounded by the remaining
budget; on expiry the request is answered 503 (kortex-decision=timeout) and
the call is abandoned; the finish is logged as DoS-risk evidence.

- Follow-up bug found by E17 (failing test 7d78963, fix 39324c9): the
  handler's deferred tx.Close() ran on the timeout path and killed the
  abandoned call (it "finished" at budget+12 ms with a stale 949110/403
  interruption while the unfettered call needs ~42 s - unfettered replay
  measured 403 at 42.41 s with a 60 s budget). The abandoned goroutine now
  owns and closes the transaction. First-pass log kept:
  docs/logs/step16-t3-runs-firstpass-txclose.txt; E17 failing evidence
  docs/logs/step16-t3-e17-failing.txt.
- Re-run measurements (docs/logs/step16-t3-runs.txt, fixed binary): single
  replay 503 at 2.002-2.004 s (budget 2000 ms); the abandoned call ran to
  completion at elapsed_ms=43474-45114 with the real result (949110/403);
  unfettered cost measured separately: 403 at 42.41 s with a 60 s budget.
  Benign latency 5.0 ms before the burst; 20 concurrent copies all answered
  503 in 2.00-2.08 s (none wedged, none crashed — the first pass crashed the
  engine via the Close bug); benign latency under the accumulated background
  load 4.5 ms at +8 s and 59.5 ms at +59 s (load average 15.41; the 20
  ~43 s CPU-bound goroutines were still running at script end).

## T4: real engine-audit-dialect samples

docs/samples/kortex-audit-{attack,benign,limit,timeout}.txt captured from
engine runs (attack entry from out/s16-t2-engine-attacks-v0-pl1, sample
sqli-01; the benign/limit/timeout captures prove the engine writes NO coraza
audit entry for them - 0-byte audit logs under SecAuditEngine RelevantOnly;
limit/timeout decisions appear as kortex-events rows). crs_audit parses both
dialects additively; tests in tests/test_crs_audit.py. pytest: 110 passed.

## Decision 0004 status

STAYS PROVISIONAL, with the T2 evidence strengthening it: after the BUG fix
the engine matches the connector's block decisions on every dataset except
the two documented DESIGN differences (C4 content-type policy; no nginx
front proxy). The C4 criterion held on attacks-ct-v0 (the engine blocks the
attack payloads in every carrier once the body processor is right).
Reversal triggers unchanged (docs/decisions/0004-engine-core.md).

## Still open after step-16

- DESIGN differences are accepted, not fixed: C4 (no content-type allow-list)
  and no nginx front proxy (path-level rejects like trav-01).
- The engine does not implement the connector's method allow-list (CRS
  911100 never fires there; tx.allowed_methods is unset). No blocked-set
  diff exists in these datasets because every 911100-ref-blocked sample was
  also blocked by the engine via other rules, but the policy difference is
  real and documented (docs/logs/step16-t2-confound.txt notes).
- A1, A3, A4, A5, A6, A7 acceptance bars: not started.
