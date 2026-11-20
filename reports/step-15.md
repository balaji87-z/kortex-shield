# Step-15 report

- Summary: Built and measured the engine skeleton (decision 0004: Coraza
  v3.7.0 + CRS 4.25.2 behind our own proxy with framing gate, body limits,
  time budget, C4 no-allow-list); E1-E9 acceptance tests pass. Ran the
  preregistered ct-wide benign cells on the held-out WCP TEST split
  (10.13% vs 17.61% default, 0 new detection blocks). Ran the DIAGNOSTIC
  per-sample diff of the skeleton vs the Coraza connector on five datasets
  and proved one engine limitation (time budget does not bound single-shot
  body processing).

## Task table

| task | status | evidence |
|---|---|---|
| T1 loose ends (byte lengths, encoding-diff strata marks, exact tables, probe re-run) | done | docs/logs/step15-t1-exact-tables.txt, step15-t1-probe-rerun.txt; dataset README marks; commit 1965e25 |
| T2 engine decision + criterion C4 | done | docs/decisions/0004-engine-core.md (provisional), 0002 addendum; commit 2f2014a |
| T3 ct-wide benign on held-out TEST split | done | docs/plan-ct-wide-benign.md (preregistered), docs/logs/step15-t3-analysis.txt; commits ffbfaf3, 05ec43a, 90a2e30 |
| T4 body-size scaling + skeleton replay | done | docs/logs/step15-t4-scaling.txt, step15-t4-analysis.txt, step15-t4-skeleton-replay.txt; commit 3dd457a |
| T5 engine skeleton, E1-E9 test-first | done | engine/, docs/block-discriminator.md, docs/logs/step15-t5-verify.txt; commits 1de93ef, 1b7dcb9 |
| T6 skeleton vs connector per-sample diff (DIAGNOSTIC) | done | docs/logs/step15-t6-runs.txt, step15-t6-analysis.txt, step15-t6-confound.txt; commit 2a3d2ef |
| T7 docs + report | done | docs/baseline-v1.0.md, docs/engine-evidence.md (step-15 section), docs/engine-design.md, docs/acceptance.md, README.md, this report |

## Key results (rule 31: numbers in the body)

### T3 (preregistered, held-out TEST split, out-of-sample for the policy derivation)

| cell | blocked | rate | Wilson 95% | worst case |
|---|---|---|---|---|
| coraza default PL1 | 1769/10047 | 17.61% | [16.87, 18.36] | 1808 (18.00%) |
| coraza ct-wide PL1 | 1018/10047 | 10.13% | [9.56, 10.74] | 1057 (10.52%) |

0 detection-rule blocks under ct-wide that default did not block; symmetric
diff 751 samples, every one a 920420-only block under default; 6 errors per
cell (5 shared), included in the worst-case column.

### T4 (DIAGNOSTIC)

- Pathology body (wcp-80a49c991b2d bytes) scales ~linearly, PL-independent:
  text/plain medians 321 ms (16K) -> 27,915 ms (256K); benign JSON medians
  <= 2.7 s at 256K.
- Skeleton replay of the 481,798-byte body, 3 reps each:
  - default cap 131,072: 413 kortex-decision=limit in 1.9/1.9/2.9 ms;
  - cap 13,107,200: 403 block after 43.5/42.5/41.8 s — the 2,000 ms budget
    never fired. PROVEN: the budget does not interrupt a single-shot
    ProcessRequestBody call. The design text claiming it bounds the ~44 s
    pathology was corrected in docs/engine-design.md before commit.

### T5

`go test -buildvcs=false -count=1 ./...` in engine/ -> `ok kortexshield/engine
0.288s` (9/9, re-run 2026-11-20). CRS file set sha256 recorded in
engine/RULES.sha256. pytest: 105 passed.

### T6 (DIAGNOSTIC; counts on difference-chosen sets, not rates, rule 35)

| dataset | PL | engine blocked | connector blocked | diff (common ids) |
|---|---|---|---|---|
| smoke | 1 | 7/12 | 6/12 | 1 (engine-only trav-01) |
| smoke | 2 | 7/12 | 6/12 | 1 (engine-only trav-01) |
| attacks-v0 | 1 | 909/1054 | 954/1054 | 65 (55 ref-only, 10 engine-only) |
| attacks-v0 | 2 | 1040/1054 | 1024/1054 | 16 (all engine-only) |
| benign-browse-v1 | 1 | 124/774 | 184/774 | 60 (all ref-only) |
| benign-browse-v1 | 2 | 214/774 | 184/774 | 150 (90 engine-only, 60 ref-only) |
| benign-hard-v0 | 1 | 35/180 | 22/180 | 23 (18 engine-only, 5 ref-only) |
| benign-hard-v0 | 2 | 129/180 | 78/180 | 51 (all engine-only) |
| attacks-ct-v0 | 1 | 279/320 | 304/320 | 25 (all ref-only) |
| attacks-ct-v0 | 2 | 312/320 | 316/320 | 4 (all ref-only) |

- 0 errors and 0 inconsistent outcomes in every engine run (rule 30: nothing
  extra for the worst case).
- attacks-ct-v0 PL1 ref-only ids are exactly the JSON / octet-stream /
  text-plain / unknown-CT carriers: the connector blocks attack bodies in
  those carriers, the engine passes them (PROVEN pattern from the id list;
  rule-level cause HYPOTHESIS).
- Confound check (rule 18/24): 949110 in 100% of engine audit entries per
  dataset — that is the blocking-evaluation rule itself, expected. Detection
  rules >=20% of blocked entries: attacks-v0 PL1 930120 35%, 941390 34%;
  PL2 942430/942200 51%; benign-browse-v1 PL2 942340/942200/942430 56%;
  benign-hard-v0 PL2 942200 71%, 942430 67%. On the benign datasets these
  are CONFIG-MISMATCH signals (PL2 rules vs real browsing patterns),
  consistent with steps 13-14; they are the FP drivers, not a harness
  artifact.

## Raw evidence (commands and outputs; trimmed where noted)

- T3 runs: `bash tools/run_step15_t3.sh coraza-default-pl1`,
  `bash tools/run_step15_t3.sh coraza-wide-pl1` — rule-29 lines and 20/40
  rule-36 control counts in docs/logs/step15-t3-runs.txt; run dirs
  out/s15-t3-coraza-{default,ct-wide}-pl1 (run.json, responses, outcomes,
  audit logs); summary and intervals in docs/logs/step15-t3-analysis.txt.
- T4 replay (`bash tools/run_step15_t4_skeleton_replay.sh` -> docs/logs/
  step15-t4-skeleton-replay.txt, untrimmed):
  ```
  == config A: default max_inspected_bytes=131072
  status=413 time_total_s=0.001939 / 0.001887 / 0.002916
  413 kortex-decision=limit
  == config B: KORTEX_MAX_INSPECTED_BYTES=13107200
  status=403 time_total_s=43.469464 / 42.452131 / 41.845037
  403 kortex-decision=block rules=900000,900001,900110,900990,900220,901111,...
  load_avg_start: 4.83 5.49 7.05   load_avg_end: 8.25 6.69 7.24
  ```
- T5: `go test -buildvcs=false -count=1 -timeout 300s ./...` in engine/ ->
  `ok kortexshield/engine 0.288s`.
- T6 first engine run summary line (attacks-v0 pl1, untrimmed except this
  quote): `"total_samples": 1054, "responses_ok": 1054, "blocked": 909,
  "error_count": 0, "block_rule": {"block_status": 403, "block_marker":
  "kortex-decision=block"}}`.
- pytest: `105 passed in 13.93s`.

## Deviations from instructions

- First T6 pass used the runner's default nginx block marker; every engine
  block was scored blocked=false (status 403 correct, body marker wrong).
  Re-run with `--block-marker 'kortex-decision=block'`; the first-pass log is
  kept (docs/logs/step15-t6-runs-firstpass-nginxmarker.txt), nothing dropped
  silently (rule 12).
- kortex_eval/crs_audit.py was extended to attribute the engine's Coraza
  audit dialect (lowercase/list-valued headers, top-level messages,
  error_message rule brackets). Additive only; the container-dialect
  real-sample tests are unchanged and pass. Flagged under Questions.
- docs/engine-design.md's time-budget section was corrected BEFORE its first
  commit once the T4 replay proved the budget does not bound single-shot
  bodies (the pre-run text claimed it did).
- Per-run engine audit copies are cumulative within each PL (run script does
  not truncate between datasets); the confound check filters by sample-id
  prefix. Outcomes are unaffected (attribution by unique sample id).

## UNVERIFIED items

- Rule-level cause of the attacks-ct-v0 PL1 carrier differences (HYPOTHESIS;
  no rule-by-rule diff between connector and engine configs yet).
- The exact internal Coraza code path behind the ~42-43 s single-shot body
  processing (HYPOTHESIS; no CPU profile).
- Coraza Go module v3.7.0 vs the container's internal engine version string
  (UNVERIFIED in earlier steps; unchanged here).

## Questions for instructor

1. The crs_audit extension (engine audit dialect) changes a kortex_eval
   parser. It is additive and the container-dialect tests are unchanged, but
   per rule 5 we flag it: is this in scope, or should the engine emit a
   container-shaped audit log instead?
2. The time-budget gap (single-shot body processing unbounded, PROVEN) —
   fix now (e.g. goroutine + deadline around ProcessRequestBody) or defer to
   a later step?
3. T6 shows the engine MORE aggressive than the connector on benign-hard-v0
   PL2 (51 engine-only blocks) and LESS aggressive on attacks-v0 PL1 (55
   ref-only). Before any tuning: should the engine stay rule-faithful to the
   connector as the reference, or is the diff list itself the deliverable for
   step-16 triage?
