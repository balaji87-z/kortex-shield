# Step-20 report

- **Summary**: T1 — no duplicate-argument bypass on the 8 preregistered shapes
  on any of the three engines (identical counts); the step-19 flip defect is
  fixed by the coraza v3.7.0→v3.8.1 bump (E30 48/2000→0/2000 flips,
  flip_repro PL2 0/2500). T2 — size-class body lanes shipped test-first;
  the large-lane attack now serves 269/269 benign POSTs (step-19: 0/131);
  the small-lane residual exposure is measured (6/276). T3 — cost matrix:
  pathology content costs 5–12× same-size benign prose; 942100's raw-body
  target contributes 0 blocks on 40k benign requests and 2/23 on a directed
  SQLi canary; no change shipped. T4 — canary proves body inspection
  (engine 98/100, connector 99/100) and exposes the
  application/json+protobuf REQUEST_BODY gap; the 42 new benign-wcp-v1
  blocks audited 0/42 attack-looking (false positives); token count
  corrected 6→8. T5 — baseline-v1.5, design/evidence/acceptance/decision
  0004 (now ACCEPTED), README updated.

| task | status | evidence |
|---|---|---|
| T1 dup-args measurement (3 engines × PL1/PL2) | done | docs/plan-dup-args.md, docs/logs/step20-t1-summary.txt, docs/logs/runs/s20-t1-dupargs/ |
| T1 E30 failing test + fix (v3.8.1) | done | commit 83fbebd (failing), docs/logs/runs/s20-t1-e30/, docs/baseline-v1.5.md T1 |
| T2 lanes design + deterministic E29 + runs | done | docs/engine-design.md (commit 0140b35), commits 9f252d7/71d3aec, docs/logs/step20-t2-*.txt |
| T2 DIAGNOSTIC subprocess-kill spike | done (DIAGNOSTIC, not shipped) | docs/logs/step20-t2-spike.txt, commit 6e1ea69 |
| T3 cost matrix + 942100 attribution + options | done | docs/logs/step20-t3-cost-analysis.txt, docs/logs/step20-t3-cost.txt, docs/logs/runs/s20-t3-* |
| T4 A3 canary (engine + connector) | done | docs/logs/step20-t4-canary-audit.txt, docs/logs/runs/s20-t4a-* |
| T4 audit of 42 new blocks (rule 26) | done | docs/logs/step20-t4b-audit.txt |
| T4 token count reconciliation | done | docs/logs/wcp-v0-token-ids.txt, reports/step-19.md correction |
| T5 docs (baseline-v1.5, design, evidence, acceptance, decision 0004, README) | done | docs/baseline-v1.5.md, commits 179cdfb/18b0521/55e45d1/ce8729e |
| go test + pytest | done (32/33; E20 known-fail) | docs/logs/step20-gotest.txt |

## Key numbers (rule 31)

**T1** (40 payloads attacks-v0 seed 0, 8 shapes Q1–Q4/B1–B4, 20 repeats,
fresh transaction; errors counted separately — 0 errors in all valid runs):

| engine | PL1 query | PL1 body | PL2 all shapes |
|---|---|---|---|
| engine v3.7.0 | 40/800 pass (2/40 variants) | 220/800 (11/40) | 0/800 |
| coraza connector | 40/800 | 220/800 | 0/800 |
| ModSecurity control | 40/800 | 220/800 | 0/800 |

No bypass on the preregistered shapes: the three engines are identical and
shape-invariant; passing payloads never block (they also pass at PL2).
Rule 44 answer: the connector shows the same flip ONLY in the captured
7-param context (wcp-62cd1bd36bf7; connector flip_repro PL2 median 0.26
flips/round, step-20 T1 summary) — nothing extra on the preregistered shapes.

Fix: E30 (2000 replays of wcp-62cd1bd36bf7 at PL2, runtime.GC() between
rounds, zero flips required) failed on v3.7.0 with 48/2000; after the
**coraza v3.8.1** bump: **0/2000**; flip_repro 5×500 PL2: **0/2500**
(v3.7.0 median 114/500). PL1 flip_repro 500/500 on BOTH versions — those
samples never block at PL1 (baseline behaviour, not flips). dup-args
measurement on v3.8.1 identical to v3.7.0. Candidate 2 (vendored patch)
not needed.

**T2** (stub backend returns 200; 300 s attacks; 8 attackers; 1 benign
POST/s + 1 GET/s):

- Large-lane attack (131,071 B attackers, PL1): benign POSTs **269/269
  served** (step-19: 0/131); recovery 0.1 s; engine events overload=12478,
  timeout=2, abandoned_finished=0.
- Small-lane attack (32,768 B attackers, PL2): benign POSTs **6/276
  served** — the documented residual exposure is real.
- E29 rewritten deterministically (KORTEX_TEST_HOLD_BODY_MS +
  X-Kortex-Test-Hold: 1): failing by design pre-lanes (commit 9f252d7),
  passing after lanes (commit 71d3aec).
- DIAGNOSTIC spike (scratch only): subprocess kill caps post-deadline CPU
  at ≤500 ms per 2 s budget (vs 74–80 s in-process); respawn 1.3–2.7 s
  paid by the next request. Not proposed for shipping.
- abandoned_finished=0 investigated (rule 33): a single abandoned call
  takes 74.2 s (~77 s CPU) on v3.8.1 and 79.6 s (~86 s CPU) on v3.7.0 —
  not a v3.8.1 regression; the host changed at the VM reboot (rule 43).

**T3** (3 bodies × 4 sizes × pre/post × PL1/PL2 × 3 reps; medians, s;
confound declared: pre/post also differ in coraza version and lanes):

| cell | pre | post |
|---|---|---|
| PL1 pathology 131,072 B | 27.0 (403) | **83.4** (403) |
| PL1 prose 131,072 B | 4.8 (200) | 6.5 (200) |
| PL1 adversarial 131,072 B | 4.0 (403) | 7.4 (403) |
| PL2 pathology 131,072 B | 34.6 (403) | **30.3–120** (403/503, bimodal UNEXPLAINED) |
| PL2 prose 131,072 B | 9.4 (200) | 16.9 (200) |

Pathology content costs 5–12× same-size prose; keyword-dense adversarial
blocks early and cheap. 942100 raw-body attribution: **0** audit entries on
benign-wcp-v1 (40,000 requests); directed canary (23 SQLi raw bodies):
full engine 8/23 vs no-942100 6/23 → **2/23 at PL1, 0/23 at PL2**.
Options measured: (a) raw-body cap N=64 KB still leaves 22 s, N=16 KB
leaves 3.1 s but gives up large-body inspection; (b) windowed inspection
needs coraza changes; (c) status quo — **no change shipped**.

**T4**: canary on the 100 A3 ids (connector-only 920420, benign-wcp-v0)
with a payload appended to the body. Attempt 1 INVALID (rule 18): the `\n`
separator itself fired 921150 on 54/71 — redone with a space separator.
SQLi canary: 18/100 (942100 is context-sensitive). XSS canary
(`"><script>alert(1)</script>`): **engine 98/100** (941 family),
**connector 99/100** (920420 CT rejection + 941). Passes: wcp-dedb89ec3d3d
(application/json+protobuf — JSON processor does not populate REQUEST_BODY:
a real inspection gap on BOTH engines) and wcp-483cfc44d381 (text/plain
100 KB, no match, cause UNVERIFIED). Conclusion: body inspection PROVEN
for this class; A3's 0/100 now reads "inspected, no match" for text/plain
ids; the JSON+protobuf CT is NOT raw-body inspected.

Audit of the 42 new benign-wcp-v1 blocks (28 PL1 + 14 PL2, one id in both;
rule 26): all 42 read as benign browser telemetry / e-commerce beacons
(Datadog RUM, GA4, Adobe Analytics, Shopify monorail, perf beacons, cart
forms); matched rules are the 932 RCE family on substrings inside
telemetry bodies. **0/42 look like attacks** → classified false positives
(rule 46: new blocks, never "gains"). Audit of 42 by one reader, not a proof.

Token count: benign-wcp-v0 contains **8** publishable token shapes
(docs/logs/wcp-v0-token-ids.txt), not 6 — reports/step-19.md corrected
in place. Values not reproduced (rule 25); frozen manifest untouched (rule 10).

**go test ./...** (engine/, KORTEX_TEST_WCP_BODY set, -timeout 1800s,
fresh host after the second VM reboot): **32/33 test functions pass**
(33 total; raw output docs/logs/step20-gotest.txt). The only failure is
E20 (known: "abandoned call did not finish within 120s" — the cost
cross-trade-off documented in step-19; wall 180.52 s in-suite). E29
(rewritten) and E30 (amended) pass; E19/E21/E23, which failed in earlier
contaminated runs, pass here. pytest: no Python test suite changed this
step; kortex_eval modules used as tools (crs_audit) behaviour unchanged.

Suite-run history this step (documented per rule 48):
1. Run 1 hit the default 10 m timeout (E30 still running at 6m2s under
   E20's leftover CPU burn).
2. Run 2 (timeout 1800s) ran while a stray engine binary (left over from
   the T2 spike / T3 / T4a cleanups) burned ~35% CPU: E19, E23 and E30
   failed, all with 503 kortex-decision=timeout outcomes. E30's failure
   ("8/2000 rounds passed") was NOT flips — the test counted any non-403
   as a flip, including load-induced 503 timeouts. Fixed per rule 48:
   E30 now classifies 403=blocked, 200=flip, 503=timeout (timeouts must
   stay <= N/10 or the run is declared too noisy to prove the fix);
   commit 5f049d6. On a quiet host E30 gives blocked=2000 flips=0
   timeouts=0 of 2000 (58.6 s).
3. Run 3 (final, fresh host after the second reboot): 32/33 as above.

Host changes this step (rule 43): the VM rebooted TWICE. T1/T2/T3/T4
measurements were taken on the first post-reboot host (2611 MHz, no
boost); the final go test suite ran on the second fresh boot. All /tmp
artifacts (binaries, bodies, scripts) were lost at each reboot; every
number cited above is reproduced from the committed docs/logs/ copies.

## Raw evidence (exact commands, trimmed where noted)

- T1: `.venv/bin/python tools/run_step20_t1_dupargs.py ...` per engine/PL —
  outputs in docs/logs/runs/s20-t1-dupargs/t1-{engine,coraza,modsec}-pl{1,2}.json;
  summary docs/logs/step20-t1-summary.txt. E30: `go test -run TestE30`
  pre (48/2000, commit 83fbebd) and post (0/2000) — logs in
  docs/logs/runs/s20-t1-e30/.
- T2: `tools/run_step20_t2_lanes.sh large|small` — outputs
  docs/logs/step20-t2-*.txt; run dirs docs/logs/runs/s20-t2-*.
- T3: `tools/run_step20_t3_cost.sh` (+ REDO/REDO2 re-runs after the agent
  accidentally killed the rep2/rep3 engine during T4a cleanup — the 000
  cells are re-measured; per-cell load recorded; cells with load>8
  excluded) — docs/logs/step20-t3-cost.txt.
- T4 canary: replay script /tmp/t4a_engine.py (contract: manifest headers
  case-exact, no setdefault; Host/Content-Length/Cookie omitted); engine
  leg on 127.0.0.1:8099 (rule-29 effective config printed in engine.log),
  connector leg on 127.0.0.1:8082 after `CORAZA_BACKEND=stub-backend:3000
  docker compose --profile coraza up -d --force-recreate --no-deps
  coraza-crs`; audits parsed with kortex_eval.crs_audit. Artifacts:
  docs/logs/runs/s20-t4a-canary-{engine,connector}/.
- Connector startup finding (rule 4): with the pinned image bfbfe70b
  (nginx 1.30.6), `CORAZA_BACKEND` WITH a scheme
  (`http://stub-backend:3000`) now fails: the image's
  /templates/nginx.conf renders `server ${BACKEND};` inside `upstream`,
  and nginx rejects the scheme ("invalid host in upstream"). Starting with
  `CORAZA_BACKEND=stub-backend:3000` (no scheme) works (ready=200). The
  step-20 T1 connector runs used the WITH-scheme export and succeeded
  pre-reboot; the difference is UNVERIFIED (possibly a container that
  inherited an older generated config). tools/run_step20_t1_flip_connector.sh
  documents the with-scheme export — flagged for correction.

## Deviations from instructions

- The T3 pre/post comparison carries a declared confound (pre = commit
  1964793 with coraza v3.7.0, post = HEAD with v3.8.1 + lanes); isolating
  the raw-body targets alone would need a v3.8.1 build WITHOUT the target
  updates — not run (the task's pre/post definition was followed as
  written).
- Two T3 re-runs (REDO/REDO2) were needed because the agent's own cleanup
  kills (for T4a) terminated the running T3 engine mid-run; the affected
  cells were re-measured and the incident is recorded here (rule 4).
- The full go test suite hit the default 10 m timeout on the first run
  (E30 still running at 6m2s under E20's leftover CPU burn); re-run with
  -timeout 1800s.

## UNVERIFIED

- Why wcp-483cfc44d381 (text/plain, 100,254 B) passed the engine canary
  (no audit match): cause not determined.
- Why the post PL2 pathology-131 KB cell is bimodal (30.3 s vs 99–120 s
  across runs, same binary): UNEXPLAINED (rule 39), reported as a range.
- Why the connector started fine pre-reboot with a scheme-ful
  CORAZA_BACKEND but not post-reboot: UNVERIFIED (see raw evidence).
- The 42-sample audit is one reader's judgement on manifest previews
  (truncated bodies), not a proof (rule 26 wording kept).

## Questions for instructor

1. T3 options: cap the raw-body targets at N bytes (measured: N=64 KB
   leaves 22 s worst case, N=16 KB leaves 3.1 s), windowed inspection
   (needs coraza changes), or status quo (kept this step)? Any change
   needs its own test-first + held-out cycle.
2. The application/json+protobuf inspection gap (JSON processor does not
   populate REQUEST_BODY, both engines): accept as DESIGN (documented) or
   fix (e.g. also target ARGS_JSON-adjacent raw scanning)? Measured: 1/100
   canary pass on both engines.
3. The 42 audited false positives (932 family on telemetry bodies): accept
   as the known cost of raw-body fidelity, or open a scoped exclusion
   cycle (rule 17 constraints apply)?
4. The small-lane residual exposure (6/276 served when attackers fit the
   small lane): acceptable, or does T3's cost data justify a smaller
   KORTEX_BODY_LANE_THRESHOLD default (e.g. 16,384 B) in a follow-up step?
5. E20 remains a known failure (abandoned call >120 s on the post-reboot
   host, both coraza versions). Keep as documented trade-off or re-scope
   the test's deadline?

## Step-21 addendum (corrections, rule 4/44)

- The T4 canary pass on wcp-483cfc44d381 does NOT reproduce: the same
  body+canary blocks at every offset/truncation, in the exact step-20
  replay conditions, and in the full 100-id batch (99/100 blocked; the
  only pass is the known application/json+protobuf gap). The step-20
  pass is UNEXPLAINED (1 occurrence, 2 failed reproduction attempts),
  suspected state-dependent pass-through — not a property of the body.
  Evidence: docs/logs/step21-t1b-483cfc.txt.
- The T1 "fixed" wording for the coraza bump: per rule 49 this stays
  "fixed empirically" until the changed upstream code is identified.

## Step-21 addendum 2 (correction, PROVEN — supersedes addendum 1 partly)

- Both step-20 canary "passes" were classification artifacts of the canary
  script (`blocked = status==403`): wcp-dedb89ec3d3d was REJECTED with 400
  (canary made the JSON invalid → JSON-processor rejection, E11 class) and
  wcp-483cfc44d381 was a 503 kortex-decision=timeout (pathology-class body
  ~6–24 s vs the canary run's 2000 ms budget). Both fail-closed. There was
  NO pass-through and NO application/json+protobuf inspection gap. The T1c
  matrix (step-21) shows JSON-CT payloads in values/keys ARE detected
  (403) on both processors' variables.
- Consequence: the "known inspection gap" paragraph added to
  docs/engine-design.md in step-20 is corrected in place (step-21 note).

## Step-21 addendum 3 (corrections to T1 wording, PROVEN)

- "The passing payloads are ones that never block (they also pass at
  PL2)" is WRONG: the committed PL2 data (t1-engine-pl2.json) shows
  passes=0 for every id and shape at PL2 (0/800). The correct statement:
  the PL1 body-shape passes (11/40) are a DOUBLE-ENCODING artifact of the
  harness's B-shape construction (`quote()` applied to an
  already-percent-encoded manifest query); they all block at PL2 with
  920230 "Multiple URL Encoding Detected" (a PL2-by-design CRS rule).
- The 11/40 (B shapes, double-encoded) vs 2/40 (Q shapes, single-encoded)
  vs 4/40 (attacks-ct, single-encoded carriers) numbers measure different
  encodings and are not directly comparable; see
  docs/logs/step21-t1d-explain.txt for the exact request bytes and the
  discriminating probes.
