# Baseline v1.0 (step-15, 2026-11-20)

Dated notes on top of v0.9 (docs/baseline-v0.9.md, kept unchanged). Corrections
are listed here, never applied to older text. Step-15 built the engine
skeleton (decision 0004) and measured it; nothing in this file is a parity
claim about a production engine — the T6 comparison is DIAGNOSTIC (rule 34).

## T1 loose ends closed (2026-11-20)

- Byte lengths of the 11 step-12 oversize samples: 1,401,149-2,829,426 bytes
  (all above the 1 MiB nginx default; confirms the v0.9 explanation).
- wcp-80a49c991b2d is 477,231 Python str characters but 481,798 UTF-8 bytes;
  earlier logs quoted both numbers. The wire size is 481,798 bytes.
- Plain-encoding stratum of encoding-diff-v0: 10 of 16 payloads are http_error
  malformed targets (marked in the dataset README; the stratum stays frozen).
- The overlong-utf8 stratum of encoding-diff-v0 is INVALID as built (the
  encoder emitted raw bytes without the `%` prefixes). Marked in the dataset
  README; the dataset was not edited (rule 10).
- Exact T3/T4 tables: docs/logs/step15-t1-exact-tables.txt.
- The one reproducible step-13 timeout (wcp-80a49c991b2d) re-replayed 3x with
  the exact runner bytes: docs/logs/step15-t1-probe-rerun.txt.

## T2: engine decision and criterion C4 (2026-11-20)

- docs/decisions/0004-engine-core.md: Coraza v3.7.0 + CRS 4.25.2 as inspection
  core, wrapped by our own proxy that owns (1) body limits before the engine,
  (2) a per-request time budget, (3) strict framing checks, (4)
  content-type-independent body inspection. Status: provisional pending T1
  and T4; reversal triggers documented.
- Criterion C4 added to docs/decisions/0002-engine-criteria.md (dated
  addendum): detection must not depend on the content-type allow-list.

## T3: ct-wide benign policy on the held-out WCP TEST split (2026-11-20)

Preregistered before the runs (docs/plan-ct-wide-benign.md, rule 22). Data:
out/wcp-heldout-test-manifest.jsonl, 10,047 benign WCP TEST hosts (split rule
sha256('wcp-heldout-v0|'+host)%2 fixed before any run; the policy was derived
on TRAIN, so TEST is out-of-sample for the derivation).

| cell | blocked | rate | Wilson 95% | worst case (rule 21) |
|---|---|---|---|---|
| coraza default PL1 | 1769/10047 | 17.61% | [16.87, 18.36] | 1808 (18.00%) |
| coraza ct-wide PL1 | 1018/10047 | 10.13% | [9.56, 10.74] | 1057 (10.52%) |

- 0 detection-rule blocks under ct-wide that were not blocked under default
  (the widening removes 920420 content-type blocks only).
- Symmetric diff 751 samples; every diff is a 920420-only block under default
  that passes under ct-wide (rules=['920420','949110']).
- 6 errors in each cell (5 shared, 1 differing). Errors included in the
  worst-case column (rule 20/21).
- Analysis: docs/logs/step15-t3-analysis.txt.

## T4: body-size scaling in-library + replay vs the skeleton (DIAGNOSTIC)

- 80 jobs = {pathology, benignjson} x 4 content-types x 5 sizes x 3 reps at
  PL1 and PL2 (docs/logs/step15-t4-scaling.txt, table
  docs/logs/step15-t4-analysis.txt). The pathology sample scales roughly
  linearly in body size and is PL-independent: text/plain medians 321 ms
  (16K) -> 27,915 ms (256K); benign JSON tops out near 2.1-2.7 s at 256K.
- Replay of the 481,798-byte pathology body against the engine skeleton
  (docs/logs/step15-t4-skeleton-replay.txt): with the default 131,072-byte
  inspection cap the engine answers 413 kortex-decision=limit in 1.1-2.9 ms
  (3/3); with the cap raised to 13,107,200 the body runs 41.8-43.5 s per rep
  and ends in a normal 403 block — the 2,000 ms time budget never fired.
  PROVEN: the budget does not interrupt a single-shot body-processing call
  (docs/engine-design.md has the corrected wording).

## T5: engine skeleton, acceptance tests E1-E9

Test-first (rule 37): failing tests committed (1de93ef), then the
implementation (1b7dcb9). `go test` in engine/: 9/9 PASS. Binary verification:
docs/logs/step15-t5-verify.txt. Block discriminator:
docs/block-discriminator.md (written before the skeleton ran).

## T6: engine skeleton vs Coraza connector, per-sample diff (DIAGNOSTIC)

Runs docs/logs/step15-t6-runs.txt, analysis
docs/logs/step15-t6-analysis.txt, confound check
docs/logs/step15-t6-confound.txt. Key counts (blocked sets, common ids;
difference-chosen counts, not rates, rule 35):

| dataset | PL | engine | connector | diff |
|---|---|---|---|---|
| smoke | 1/2 | 7/12 | 6/12 | 1 (engine-only trav-01) |
| attacks-v0 | 1 | 909/1054 | 954/1054 | 65 (55 ref-only, 10 engine-only) |
| attacks-v0 | 2 | 1040/1054 | 1024/1054 | 16 (all engine-only) |
| benign-browse-v1 | 1 | 124/774 | 184/774 | 60 (all ref-only) |
| benign-browse-v1 | 2 | 214/774 | 184/774 | 150 (90 engine-only, 60 ref-only) |
| benign-hard-v0 | 1 | 35/180 | 22/180 | 23 (18 engine-only, 5 ref-only) |
| benign-hard-v0 | 2 | 129/180 | 78/180 | 51 (all engine-only) |
| attacks-ct-v0 | 1 | 279/320 | 304/320 | 25 (all ref-only, non-urlencoded carriers) |
| attacks-ct-v0 | 2 | 312/320 | 316/320 | 4 (all ref-only) |

- 0 errors and 0 inconsistent outcomes in every engine run.
- The attacks-ct-v0 PL1 ref-only set is exactly the JSON / octet-stream /
  text-plain / unknown-CT carriers: the connector blocks attack bodies there,
  the engine passes them (PROVEN pattern from the id list; the rule-level
  cause is HYPOTHESIS until a rule diff is done).
- Harness notes: the first T6 pass used the default nginx block marker and
  scored every engine block blocked=false; re-run with the engine's
  kortex-decision=block marker (first-pass log kept:
  docs/logs/step15-t6-runs-firstpass-nginxmarker.txt). crs_audit learned the
  engine's audit dialect (lowercase/list headers, top-level messages,
  error_message rule brackets); container-dialect tests unchanged, pytest
  105 passed. Per-run audit copies are cumulative within each PL; the
  confound check filters by sample-id prefix.

## Still open after step-15

- The engine time budget does not bound single-shot body processing (PROVEN);
  fixing it is future work.
- Rule-level cause of the attacks-ct-v0 PL1 carrier differences (HYPOTHESIS).
- A1, A3, A4, A5, A6, A7 acceptance bars: not started.
