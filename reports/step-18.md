# Step-18 report

- Summary: Durable run evidence (rule 42) + host facts (rule 43). The 413
  connection reset is fixed test-first (E22: the engine drains the body
  before answering; the three step-17 reset ids now return 413 with a
  readable body). Raw-carrier body fidelity fixed test-first (E23-E25) via
  SecRuleUpdateTargetById adding REQUEST_BODY to 166 CRS rules; REQUEST-921
  excluded after it manufactured 126 PL1 false positives (E26). Pre/post
  re-runs of all five datasets: attacks-ct +6/+3 (exactly the split-broken
  ids), held-out benign sets 0/0, benign-wcp-v0 +61/+29 real gains
  (flip-corrected) with 0 real detection losses; the fix costs 6.2x on the
  worst-case abandoned call (62.7 s -> 389 s, PROVEN), which fails E20's
  120 s deadline. A NEW pre-existing engine non-determinism (occasional
  pass-through of a would-block request) was found, reproduced and counted
  (UNEXPLAINED). T2 connector comparison BLOCKED (no docker/sudo) —
  decision 0004 stays provisional.

## Host facts (rule 43)

- OS: Ubuntu 26.04.1 LTS, kernel 7.0.0-44-generic (same host as step-17;
  no host change, so rule 29 proofs carry over per run — printed in every
  run log).
- Go: go1.25.0 linux/amd64 ($HOME/go/bin/go). Python: 3.14.4 (.venv).
- Docker: ABSENT (no docker, no docker.sock, no podman/nerdctl, no
  passwordless sudo) — T2 blocked for the second step running.
- Image digests: no container images used this step (engine runs are
  native; CRS 4.25.2 files are pinned by RULES.sha256 in engine/crs).

## Task table

| task | status | evidence |
|---|---|---|
| T1 durable evidence + host facts | done | tools/preserve_run.sh (commit 518e5cc); 24 files under docs/logs/runs/; s17-t2 dirs back-filled (counts match); lost artifacts listed below |
| T2 WCP connector-side comparison | BLOCKED | no docker / no sudo on this host (verified in T1); per instructor fallback decision 0004 stays provisional, no aggregates promoted |
| T3 413 connection reset | done | failing E22 13e0b13, fix e198ead, replay docs/logs/step18-t3-replay.txt |
| T4 body parsing fidelity | done | failing E23-E25 1964793, fix 3f3f440, scope fix E26 02bac43, pre/post runs + analysis docs/logs/step18-t4-analysis.txt, flip evidence docs/logs/step18-t4-flip-replay.txt, cost A/B docs/logs/step18-t4-abandoned-cost.txt |
| T5 docs | done | docs/baseline-v1.3.md, engine-design.md (scope + UNEXPLAINED entry), engine-evidence.md, acceptance.md E22-E26, decisions/0004, README |
| go test + pytest reported; this report | done | below |

## Key results (numbers in the body, rule 31)

### T3 — 413 delivered instead of connection reset (PROVEN)

Replay of the three step-17 reset ids against the fixed engine
(tools/run_step18_t3_replay.sh): all three return status=413 with body
`413 kortex-decision=limit`, 0 errors. In the T4 v2 WCP runs the same ids
are status 413 / waf_pass, 0 errors. E22 (raw TCP client, 300 KB body,
1024-byte inspected limit) passed pre-fix? No — E22 FAILED before the fix
(read reset after 184 bytes) and passes after.

### T4 — fidelity fix and its measured cost

Pre/post blocked counts (pre = commit 1964793 = the engine WITHOUT the
REQUEST_BODY updates; post = final engine, 166 updates; same host, config,
UA; rule-29 config proof printed per run):

| dataset | PL1 pre -> post (gained/lost) | PL2 pre -> post (gained/lost) |
|---|---|---|
| attacks-ct-v0 (IN-SAMPLE, counts only, rule 35) | 286 -> 292 (+6/0) | 310 -> 313 (+3/0) |
| attacks-v0 (IN-SAMPLE, counts only) | 954 -> 954 (0/0) | 1024 -> 1024 (0/0) |
| benign-browse-v1 (HELD-OUT) | 124 -> 124 (0/0) | 124 -> 124 (0/0) |
| benign-hard-v0 (HELD-OUT) | 22 -> 22 (0/0) | 78 -> 78 (0/0) |
| benign-wcp-v0 (HELD-OUT, n=20000) | 2128 -> 2191 | 8845 -> 8871 |

- attacks-ct gains are exactly the split-broken payload x carrier ids the
  fix targets (sqli-6e47f23b, command-injection-dc2932d5, ecb32a80 under
  text-plain/octet-stream/unknown-ct); 0 lost. IN-SAMPLE: counts only.
- benign-wcp-v0 flip-corrected (see the non-determinism section): PL1
  +61 real gains / 0 real losses (3 apparent gains were pre-run flip
  artifacts, 1 apparent loss was a 503 timeout); PL2 +29 real gains /
  0 real losses (1 apparent gain was a pre-run flip; 3 apparent losses
  were 503 timeouts, 1 was a post-run flip). Worst case (errors flagged,
  rule 21): PL1 2190 -> 2250, PL2 8908 -> 8931.
- Real-gain rule distribution (excl. 949110): PL1 932370 x32, 933120 x10,
  932235 x10, 932125 x8, 932130 x5, 942550 x4, 933180 x2, 933210 x1;
  PL2 942430 x18, 942120 x11, 932240 x10, 942440 x3, 932200 x1. 921150
  contributes ZERO gains after the scope fix.
- Timeouts (fail-closed 503): pre 3 (PL1) / 0 (PL2); post 3 / 3 — the
  added targets push three near-budget samples over the 2 s budget at PL2
  (counts, rule 35; ids in the analysis file).
- Confound check (rule 18/24): v2 PL2 has 931130 in 65.5%, 942430 in
  55.9%, 942200 in 47.8% of audit entries (PL1: 932370 20.7%). The PRE
  runs show the same dominance (931130 57%, 942430 54%, 942200 47%) —
  a CONFIG-MISMATCH property of the WCP corpus under this config, not an
  artifact introduced by the change.
- The WCP gains are new blocks on benign-labelled raw telemetry bodies
  (rule 11: label meaning — "attack" would mean listed-in-source; these
  are detection-rule blocks on samples the corpus labels benign). They are
  reported as counts of an effect (rule 35), not as a rate.

**Cost of the fix (PROVEN, A/B, same host/body/budget, uncontended)**:
the abandoned body-processing call on the 481,798-byte text/plain fixture
(budget 200 ms; coraza has no cancellation, the call runs to completion)
takes 62,658 ms on PRE and 389,118 ms on POST — 6.2x
(docs/logs/step18-t4-abandoned-cost.txt; secondary contended readings
44.5 s / 306 s kept in the file). Each of the 166 rules now also runs its
operator against the full raw body. The in-flight cap (8) still bounds
concurrency; the per-call CPU cost rose ~6x.

### Engine non-determinism (UNEXPLAINED, counted; pre-existing — PROVEN)

A request that should be blocked is occasionally passed. Evidence:

- v2 PL2 WCP run: wcp-62cd1bd36bf7 (GET; query-based 942370+942430 match)
  passed (404 from the stub, no audit entry) where the pre run, the v1
  run and a 3/3 replay of the same binary block it.
- Tight alternating replay of two same-path samples: 7/20 rounds with >=1
  flip (v2 binary), 5/20 with tx.Close() disabled — the transaction pool
  is NOT the vector (DIAGNOSTIC); 3/20 with the PRE engine — the
  behaviour PREDATES step-18 (PROVEN by replay); no GC correlation
  (GODEBUG=gctrace=1, DIAGNOSTIC).
- Runner-based contamination measurement: of the 64 PL1 gained ids, 3 are
  pre-run flip artifacts (the PRE engine blocks them under the runner);
  of the 30 PL2 gained ids, 1. Flip frequency in real runs so far: 3 per
  2128 would-block (pre PL1), 1 per 8845 (pre PL2), 1 per 8871 (post PL2).
- Raw evidence: docs/logs/step18-t4-flip-replay.txt. Mechanism HYPOTHESIS
  (unproven): coraza-internal shared state; the transformation cache key
  uses a string pointer (unsafe.StringData, coraza v3.7.0
  rulegroup.go:290). Not fixed in this step (rule 1).

### T2 — connector-side comparison: BLOCKED

No docker, no docker.sock, no podman/nerdctl, no passwordless sudo on this
host (verified in T1). The per-id engine-vs-connector comparison on
benign-wcp-v0 is NOT computed; per the instructor's fallback, decision
0004 stays provisional and no aggregate is promoted to a parity claim.

## Raw evidence (exact commands; outputs trimmed where noted)

- Engine build: `(cd engine && go build -buildvcs=false -o /tmp/kortex-engine-v2 .)`;
  PRE engine built from a git worktree at 1964793 (md5 recorded in
  docs/logs/step18-t4-runs.txt).
- Runs: `bash tools/run_step18_t4_v2.sh` (post side, 921 excluded) and
  `bash tools/run_step18_t4_pre.sh` (pre side) — full log
  docs/logs/step18-t4-runs.txt including the per-run effective config
  lines and `curl /__kortex/config` output (rule 29):
  `request_body_target_updates=166` (pre: 0), `blocking_paranoia=1/2`,
  `detection_paranoia=1/2`, `max_body_bytes=13107200`,
  `max_inspected_bytes=131072`, `engine_time_budget_ms=2000`.
- Runner contract per run: `.venv/bin/python -m kortex_eval.runner
  --manifest data/<ds>/manifest.jsonl --base-url http://localhost:8090
  --out out/<dir> --timeout 30 --workers 1 --block-status 403
  --block-marker 'kortex-decision=block' --default-user-agent "$UA"`;
  then crs_audit, outcome --engine-mode blocking, tools/preserve_run.sh.
- Analysis: `.venv/bin/python tools/analyze_step18_t4.py >
  docs/logs/step18-t4-analysis.txt` (pre vs post per dataset/PL, gained/
  lost ids, rule distributions, confound check, flip corrections).
- Flip replays: the exact client and per-round statuses are quoted in
  docs/logs/step18-t4-flip-replay.txt (trimmed to the summary lines).
- Abandoned-call A/B: single POST of the 481,798-byte fixture at budget
  200 ms; the abandoned-body-processing-finished event lines are quoted
  verbatim in docs/logs/step18-t4-abandoned-cost.txt.
- Manifest integrity: the runner's run.json records
  manifest_sha256 = c8ce11f2... for benign-wcp-v0 (the frozen value; note
  the run log's `sha256sum data/$DS/MANIFEST.sha256` line hashes the
  checksum file itself, not the manifest — the frozen value inside the
  file is what matches).

## Test suites (exact commands and outputs)

- `cd engine && KORTEX_TEST_WCP_BODY=/tmp/kx-wcp-body.bin go test
  -buildvcs=false -count=1 -timeout 1200s -v .` (fixture = the recorded
  481,798-byte wcp-80a49c991b2d body, rebuilt from the frozen manifest):
  **28 PASS, 1 FAIL, 0 skip** — the FAIL is E20
  (`E20: abandoned call did not finish within 120s`, 176.37 s), the
  PROVEN cost consequence above. E16 passed in this run but is
  load-flaky on this desktop VM (one earlier run failed at 2.85 s vs the
  2.5 s bound while the desktop load average was ~6.8; it passes 2/3 in
  isolation).
- `cd engine && go test -buildvcs=false -count=1 .` (no fixture; E16-E21
  skip): **ok 1.979s**.
- `.venv/bin/python -m pytest tests/ -q`: **108 passed, 3 skipped**
  in 13.50 s (same counts as step-17; the 3 skips are lab-host run
  artifacts).

## Deviations from instructions

- The first E26 scenario (benign multi-line body with no '='/'&') was
  replaced after it turned out to be blocked even by the PRE engine via
  the URLENCODED split itself (ARGS_NAMES holds the raw body) — it did
  not isolate the added target. The committed E26 uses a body whose split
  fragments are newline-free. The wrong-scenario commit (c354928) is in
  history; the correction is documented in acceptance.md E26 and
  engine-design.md.
- The first-pass POST runs (v1, 173 updates incl. REQUEST-921) are kept
  under out/ as an audit trail; the reported numbers are the v2 runs
  (166 updates). The first pass's PRE runs were invalid (script bug: the
  PRE binary path did not exist) and were re-run by
  tools/run_step18_t4_pre.sh.

## Lost artifacts

- The step-09..16 runs' out/ directories (per-id connector outcomes
  needed for the T2 comparison) exist only on the unreachable lab host
  (/home/Kavinharish/kortexshield). Everything step-17/18 comparisons
  need from the engine side is under docs/logs/runs/ (rule 42).

## UNVERIFIED items

- The flip mechanism (HYPOTHESIS: coraza transformation-cache pointer
  key) — unproven; only its existence, pre-existence and rates are proven.
- Whether the 61/29 new WCP blocks are "false positives" depends on
  ground truth the corpus does not carry (rule 11); they are reported as
  new blocks by id/rule.
- E16's 2.5 s bound under load: one failure observed under desktop load;
  not systematically characterized (DIAGNOSTIC-only evidence).

## Questions for instructor

1. The fidelity fix costs 6.2x on the worst-case abandoned call
   (62.7 s -> 389 s on the 481,798-byte body) and therefore fails E20's
   120 s deadline. Options: (a) keep the fix and raise E20's deadline /
   make it measure the cap's bounding instead, (b) narrow the 166-rule
   scope (e.g. drop the most expensive operators), (c) revert. E20 was
   NOT weakened; the choice changes the engine's DoS posture and needs a
   decision.
2. The engine non-determinism (occasional pass-through of a would-block
   request, pre-existing, ~0.01-0.14% of would-block samples per run) is
   UNEXPLAINED. It undermines single-run reproducibility everywhere.
   Dedicate a step to it (reproduce harness + coraza interaction analysis)?
3. Should the 61/29 new WCP blocks be treated as acceptable (detection on
   raw bodies is the intended behaviour) or tuned? They are the direct
   product of the fidelity fix on held-out benign traffic.
4. May E16's budget+500ms bound be revisited for load-noise tolerance, or
   should the suite pin a quieter environment?

## Status

DONE within the step's scope: T1 done, T2 BLOCKED (host capability,
unchanged), T3 done, T4 done (with the cost and non-determinism findings
reported), T5 done, suites reported. Everything committed; one commit per
task where the task produced changes.
