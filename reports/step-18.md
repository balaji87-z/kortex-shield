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
| T2 WCP connector-side comparison | done (addendum) | docker became available; coraza connector vs engine per-id, PL1+PL2 — see "T2 results" below |
| T3 413 connection reset | done | failing E22 13e0b13, fix e198ead, replay docs/logs/step18-t3-replay.txt |
| T4 body parsing fidelity | done | failing E23-E25 1964793, fix 3f3f440, scope fix E26 02bac43, pre/post runs + analysis docs/logs/step18-t4-analysis.txt, flip evidence docs/logs/step18-t4-flip-replay.txt, cost A/B docs/logs/step18-t4-abandoned-cost.txt |
| T5 docs | done | docs/baseline-v1.3.md, engine-design.md (scope + UNEXPLAINED entry), engine-evidence.md, acceptance.md E22-E26, decisions/0004, README |
| go test + pytest reported; this report | done | below |
| Addendum R1 per-id artifact inventory | done | "Per-id artifact inventory" section below |
| Addendum R2 T2 missing-items statement | done | "T2 — exactly what is missing" section below |
| Addendum R3 cap latency, 3 repeats, medians, DIAGNOSTIC | done | tools/run_step18_cap_latency.sh, docs/logs/step18-cap-latency.txt, artifacts docs/logs/runs/s18-cap-latency-repeat-{1..6}/ |
| Addendum R4 every run preserves artifacts | done | preserve_run.sh on all runner scripts; cap test copies per-repeat artifacts incl. events |

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

### Cap latency test (addendum R3 — DIAGNOSTIC, this-host only)

tools/run_step18_cap_latency.sh: phase A (KORTEX_MAX_INFLIGHT_BODY=32) and
phase B (cap 8) back to back on the SAME host in one script, three repeats
each (repeats 1-3 = phase A, 4-6 = phase B). Per repeat: a wave of 20
concurrent 481,798-byte bodies, then 15 benign probes during the overload
window. Median benign latency per phase (n=15 probes per repeat, 45 per
phase):

| phase | repeat medians (ms) | OVERALL median |
|---|---|---|
| A — cap 32 | 576 / 478 / 616 | **583 ms** |
| B — cap 8 | 96 / 164 / 123 | **142 ms** |

Phase B's median benign latency is ~4x lower than phase A's: with cap 8,
12 of the 20 wave requests get an immediate 503 overload and only 8
CPU-bound abandoned calls run; with cap 32 all 20 run. This is the
cap's bounding benefit MEASURED on this host with the v2 engine (whose
abandoned calls are 6.2x more expensive — see the cost section), which
makes the difference larger than in the step-17 measurement. DIAGNOSTIC:
these numbers do not enter any baseline or parity claim; they are
this-host only. Artifacts per repeat under docs/logs/runs/s18-cap-latency-
repeat-{1..6}/ (rule 42, including the engine events files).

### T2 — connector-side comparison: DONE (addendum — docker became available)

Docker 29.1.3 + compose 2.40.3 became available on this host after the
main report was written. The comparison ran exactly as specified above:
pinned coraza-crs image (digest in deploy/compose.yml), stub-backend:3000
(in-container proof), rule-29 proof printed per run, artifacts preserved
to docs/logs/runs/coraza-benign-wcp-v0-pl{1,2}-default (rule 42).

Blocked-set comparison (quantity: waf_block outcome sets, per rule 32):

| PL | engine blocked | connector blocked | sym-diff | worst-case engine | worst-case connector | sym-diff |
|---|---|---|---|---|---|---|
| 1 | 2191 | 3824 | 1673 | 2250 | 3896 | 1686 |
| 2 | 8871 | 8951 | 114 | 8931 | 9018 | 121 |

Connector-only blocks, classified by the engine's answer in the run
(docs/logs/step18-t2-classification.json):

- PL1 (1653): 1637 = 920420 CT policy (DESIGN-C4 — the engine deliberately
  has no content-type allow-list); 14 = engine answered 413 (body-limit
  policy DESIGN); 2 = engine timed out 503 (budget DESIGN); **0 genuine
  detection misses**.
- PL2 (97): 78 = 920420 (DESIGN-C4); 15 = engine 413; 3 = engine 503
  timeout; **1 = wcp-62cd1bd36bf7, the known flip** (UNEXPLAINED; the
  connector blocked it with 942370+942430, engine replays 4/6 block,
  2/6 pass).

Engine-only blocks: PL1 20 (19 REQUEST_BODY fidelity gains + 1 where
942190 fired on ARGS_NAMES — the engine's raw-body-into-ARGS_NAMES
processor behaviour, DESIGN residual); PL2 17 (all fidelity gains). The
connector runs stock CRS and has none of the 166 REQUEST_BODY target
updates, so this asymmetry is the T4 fix measured against a reference
that lacks it.

Rule-ID-set differences on commonly blocked ids: PL1 1509/2171, PL2
3481/8854 — two systematic causes: the connector adds 920420-family
policy rules the engine lacks (C4), the engine adds REQUEST_BODY
detection hits the connector lacks (T4).

Connector-side extras (counted): PL1 61 deny_status + 11 errors + 5
proxy_reject; PL2 61 deny_status + 5 errors + 5 proxy_reject + 1
inconsistent.

**Conclusion**: after removing the documented DESIGN differences (CT
policy C4, body-limit policy, time budget) and the 1 flip, the engine's
blocked set equals the connector's blocked set on benign-wcp-v0 at both
paranoia levels. Decision 0004's provisional status is lifted for the
coraza-connector comparison (docs/decisions/0004-engine-core.md); the
modsec-connector comparison was not re-run this step (step-13 evidence
stands). Evidence: docs/logs/step18-t2-analysis.txt, sym-diff and
classification JSONs, both connector runs under docs/logs/runs/.

### Rule-25 finding during T2 (external-traffic secret)

GitHub push protection blocked the first T2 push: a **Mapbox publishable
access token** (`pk.eyJ1IjoiZG9vcmRhc2gi...` — pk. prefix = publishable,
not a server secret) appeared in recorded WCP traffic and was copied into
the preserved connector audit logs.

- Type and count: Mapbox publishable token of the doordash crawl;
  **6 samples** in data/benign-wcp-v0/manifest.jsonl (and 6 in its
  annotations.jsonl) carry it in a query string; 1 occurrence in each
  connector audit log (docs/logs/runs/coraza-benign-wcp-v0-pl{1,2}-default).
- Action taken: both preserved audit logs redacted
  (`pk.REDACTED-mapbox-pk-token`) BEFORE the push; the pushed tree
  contains no occurrence (verified with git grep on HEAD, exit 1). The
  un-pushed commit was amended.
- UNRESOLVED: the token is also inside the **frozen** benign-wcp-v0
  dataset files, which were committed in an earlier step. Rule 10 forbids
  changing a frozen dataset, so I did not touch it. The token is
  publishable-by-design (client-side map tokens), but the instructor
  should decide whether the frozen dataset may keep it, be re-frozen
  redacted as a new version, or be taken down.

### T2 — what was missing before docker (kept for the record)

No docker, no docker.sock, no podman/nerdctl, no passwordless sudo on this
host (verified in T1). To run the comparison I need, in order:

1. **A host with Docker** (docker compose v2; the compose project brings
   up `stub-backend` + `coraza-crs` on localhost:8082). Rootless docker or
   podman-with-compose would also work; passwordless sudo is NOT needed if
   the user is in the docker group.
2. **The pinned image digests** (already in deploy/compose.yml, no action
   needed beyond pulling on the new host):
   `owasp/modsecurity-crs:4.25.2-nginx-lts@sha256:6296ce68...` and
   `ghcr.io/coreruleset/coraza-crs:4.25.2-nginx-lts@sha256:bfbfe70b...`
   (full digests in deploy/compose.yml lines 38/88; re-pinning history in
   docs/baseline-config.md "Step-12: image digests re-pinned").
3. **The commands**: `tools/run_coraza_parity.sh` (and
   `tools/run_modsec_parity.sh`) — per run: docker compose down,
   force-recreate with MODSEC/CORAZA_RULE_ENGINE=On and PARANOIA/
   BLOCKING_PARANOIA/DETECTION_PARANOIA env, the in-container rule-29
   proof line, then the runner at --base-url http://localhost:8082,
   docker cp of the audit log, coraza_audit.py, kortex_eval.outcome.
   Rule 42 applies to the new runs automatically (preserve_run.sh is
   appended).

Nothing else is missing: the manifests are frozen and committed, the
runner/audit tooling is host-independent, and the engine side runs
natively. Until a Docker host exists, decision 0004 stays provisional and
no aggregate is promoted to a parity claim.

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

## Per-id artifact inventory (addendum R1)

Per-id outcome files that survive in the repo (outcomes.jsonl and/or
responses.jsonl with one row per sample):

- docs/logs/runs/ — 41 run dirs, each with per-id outcomes.jsonl +
  responses.jsonl (audit.jsonl where the capture produced one):
  s17-t1-engine-attacks-ct-v0-pl{1,2}, s17-t2-engine-{smoke,benign-browse-v1}-pl1,
  s17-t4-engine-benign-wcp-v0-pl{1,2}, s18-t3-reset-ids,
  s18-t4-engine-{attacks-ct-v0,attacks-v0,benign-browse-v1,benign-hard-v0}-
  {pre,post,v2}-pl{1,2} (24 dirs), s18-t4-engine-benign-wcp-v0-{post,v2}-pl{1,2}
  (4 dirs), s18-cap-latency-repeat-{1..6} (probe-level, DIAGNOSTIC).
- docs/logs/ per-id files from the lab-host era:
  step12-t6-replay-{coraza,modsec}.jsonl (45 WCP ids each, both engines),
  t5-probe-{coraza,modsec}-pl1.jsonl (30 probes each),
  step12-oversize-{coraza,modsec}-audit.jsonl (2 probe entries each),
  step12-sizeprobe-{coraza,modsec}-audit.jsonl (1 each),
  step12-t3-probes-{coraza,modsec}-audit.jsonl (6 each),
  t4-parity-wcp-fixed.txt (per-id sym-diff lists for the step-13 WCP
  parity re-run), wcp-decompose.txt (per-rule block attribution).

Step-09..17 runs with NO per-id artifacts anywhere (only aggregates or
analyses are committed; the out/ dirs lived on the unreachable lab host
or in wiped /tmp):

- step-09/10: the CRS baseline runs (crs-default v0/v1, benign-hard,
  aligned / aligned-v2 policy runs) — aggregate tables only.
- step-11: out/backup-step11-small, step11-parity-batch3,
  step11-old-harness-runs, the deny-status runs — side-by-side aggregates
  (step11-side-by-side.txt) only.
- step-12: step12-batch1, step12-restored-all, wcp-cookie-restored,
  wcp-cookie-restored-all, the wcp-heldout-* parity runs — only the
  probe-level jsonl files listed above survive.
- step-13: step13-policy-clear-wcp, step13-t5-coraza-wcp,
  step13-t5-parity, step13-smoke-rerun — per-id sym-diff LISTS survive
  (t4-parity-wcp-fixed.txt), not full per-id outcomes.
- step-14: step14-t1-coraza-pl2, the step14-t3/t4/t5 runs — analyses only.
- step-15: s15-t3-coraza-*, step15-t4-scaling, step15-t4-skeleton-replay,
  step15-t6 — analyses only.
- step-16: the s16-t2 engine and connector re-runs — analyses
  (step16-t2-analysis.txt) only.
- step-17: NOW covered — s17-t1/t2/t4 per-id artifacts were back-filled
  into docs/logs/runs/ this step (rule 42); before step-18 they existed
  only under out/ on this host.

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
