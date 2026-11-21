# Baseline v1.4 (step-19, 2026-11-21)

Dated notes on top of v1.3 (docs/baseline-v1.3.md, kept unchanged). Step-19
PROVED the flip root cause with a discriminating experiment, measured the
cost of the shipping configuration, measured availability under sustained
slow requests (DIAGNOSTIC), evaluated the final scope on UNSEEN data
(benign-wcp-v1, preregistered), and re-ran the connector comparison on the
held-out set. Host facts (rule 43): Ubuntu 26.04.1 LTS, go1.25.0
linux/amd64, Python 3.14.4 (.venv), **docker 29.1.3 + compose 2.40.3
available** (user installed it mid-step-18), 8 cpus, noisy desktop VM
(load 1.3–6.6 during the runs).

## T1: pass-through flips — PROVEN (rule 44)

- Reproducer committed first (tools/flip_repro.py): 2 samples with TWO
  same-named `filter` args each (wcp-62cd1bd36bf7, wcp-b6f2246ef4b8),
  500 rounds, PL2. Flip rounds/500 across 5 fresh processes: 114/111/
  122/117/113 (median 114).
- Discriminating experiments (5×500 each, same binary): GOGC=off
  110/111/94/107/107; GOGC=1 122/108/115/122/108; GOMAXPROCS=1
  121/111/122/126/113; `-race` build 56/300 rounds with ZERO race
  reports → GC and data-race hypotheses REJECTED.
- Divergence capture (DIAGNOSTIC, coraza debug logger E28): same sample,
  same tx input — rule 942370 MATCH in the block tx, NO MATCH in the pass
  tx on IDENTICAL argument values. Divergence is inside operator
  evaluation.
- **Root cause PROVEN in coraza v3.7.0 source**: `rule.go transformArg()`
  keys the per-tx transformation cache by
  `transformationKey{argKey: unsafe.StringData(arg.Key()), argIndex: i}`
  where `argIndex` is the position in `tx.GetField()` → `FindAll()`,
  which iterates `c.collection.data` — a Go MAP with randomized order
  (internal/collections/named.go:155). With two same-named args the
  randomized index is the only key component that differs → rules
  cache/read the WRONG argument's transformation → intermittent misses.
- **Discriminating experiment**: scratch coraza copy with the cache
  bypassed in transformArg → 5×500 rounds = **0/0/0/0/0 flips (0/2500)**
  vs median 114/500 with cache (docs/logs/step19-t1-nocache.txt).
  PROVEN per rule 44.
- NOT fixable in the shipped build (the cache is internal to coraza; no
  config disables it) → exposure documented, no mitigation shipped:
  498/20,000 benign-wcp-v0 samples have ≥2 same-named args
  (docs/logs/step19-t1-exposure.txt). Version bump = instructor decision
  (upstream issue #1815 acknowledges the FindAll map-order
  nondeterminism; v3.8.1 release notes do not list the cache-key fix).
- E27 (test-first): every request now logs a block/pass event with
  matched rule ids in kortex-events.jsonl. E28: optional coraza debug
  logger (KORTEX_CORAZA_DEBUG_LEVEL/FILE).

## T2: cost at the shipping configuration

- PRE (1964793) vs POST, 3 reps, PL1+PL2, budget 120 s so the call
  finishes (docs/logs/step19-t2-cost.txt). text/plain 131,071 B:
  pre 6.00/6.25 s vs **post 17.64/20.10 s (median PL1/PL2)**. JSON at the
  same sizes: ≤1.5 s (the JSON processor does not populate REQUEST_BODY).
- Smallest body ≤ the 131,072 cap that exceeds the 2 s budget under POST:
  **32,768 B text/plain at PL2 (median 2.04 s)**; at PL1 the smallest is
  65,536 B (4.57 s). At the cap: 17.6–20.1 s ≈ 10× the budget.
- >1 s WCP samples (post-fix runs): 3 PL1 + 3 PL2 (the PL2 three are new
  from the fix), all budget timeouts; dominant rules captured via a
  120 s-budget replay (docs/logs/runs/s19-t2-slow-replay/).
- Rule-level cost (DIAGNOSTIC bisect, scratch engine, env-gated subset
  filter of the 166 updates; config proof per run): on the 131,071 B
  body at PL2, **rule 942100 ALONE reproduces the entire added cost**
  (17.7–19.9 s solo ≈ 19–21 s all-166; every other family solo = 6.2–7.2 s
  = baseline). 942100 is the libinjection SQLi rule; its chain runs over
  the full raw body.

## T3: availability under sustained slow requests (DIAGNOSTIC)

- 8 workers re-sending the 131,071 B text/plain body for 5 min, cap 8,
  budget 2 s, PL1 (tools/run_step19_t3_availability.sh).
- **Benign body-bearing POST success rate: 0/131** (129×503 overload).
  Benign GET: median 521 ms, p90 3,218 ms, max 6,262 ms (never starved).
- CPU: engine consumed 2,154 CPU-seconds over ~306 s (~7 of 8 cores);
  load 1.27 → 10.39. Abandoned calls: 102 finished, median hold 23.7 s,
  max 33.0 s.
- Recovery: response path resumes on the first probe after the attack
  stops; CPU drain continues up to ~33 s (max slot hold).
- E29 (FAILING BY DESIGN, test-first): documents the starvation; no fix
  proposed (instructor decides).

## T4: final scope on UNSEEN data (benign-wcp-v1, HELD-OUT)

- Preregistered (docs/plan-benign-wcp-v1.md, committed BEFORE build):
  seed 1, 10,000 samples, 2% site cap, v0 global indices excluded →
  ids disjoint (intersection 0, verified). 2 publishable-token shapes
  REDACTED by the A1 scrub; 0 pk.eyJ/sk.eyJ in the built manifest
  (verified). Rebuild hash VERIFIED identical (049b7dea…).
- Runs (8): PRE/POST × PL1/PL2 × 2, workers 1, fresh engine per run,
  rule-29 config proof per run (166 updates post, 0 pre), artifacts
  preserved (rule 42).
- **New blocks (post−pre): PL1 = 28, PL2 = 14** — identical in both post
  runs at PL1 (0 disagreement); PL2 post run-to-run disagreement = 3 ids
  (the PROVEN coraza flip). 0 timeouts, 0 errors in all 8 runs.
- In-sample reference (benign-wcp-v0, step-18): 61/29 → held-out v1 is
  LOWER (28/14): no overfitting signal.
- New-block composition: PL1 = 949110×28 (the block phase of the
  libinjection SQLi chain, 942100), 932370×16, 932235×6, 932125×5
  (RCE family), 942550×3, 933120×3; content: text/plain ×17,
  urlencoded ×10, csp-report ×1. PL2 = 949110×14, 942430×11, 942440×2,
  942120×2, 932240×5. These are NEW BLOCKS on benign traffic (rule 46) —
  potential false positives of the fidelity fix, counts only (rule 35).

## A2: connector comparison on the held-out set

- Connector (coraza-crs pinned digest, crs_setup_version=4252, limits
  13107200/131072 proven in-container): PL1 blocked 1,868, PL2 4,480.
- Engine POST: PL1 1,092, PL2 4,436. Per-id (rule 32):
  PL1 common 1,080, connector-only 788 (754 = engine passed → stub 501,
  26 = 404, 8 = engine 413; connector rules on them: 920420×784 = the CT
  allowlist policy, DESIGN-C4), engine-only 12 (fidelity additions).
  PL2 common 4,426, connector-only 54 (920420×49 DESIGN; 14×404, 9×413,
  29×501, 2×503), engine-only 10.

## T5: stability

- E16 ×10: 10/10 ok, test wall 2.97–4.38 s, load average recorded per
  rep (docs/logs/step19-e16x10.txt).
- benign-wcp-v1 = HELD-OUT for the scope choice; benign-wcp-v0 = IN-SAMPLE
  for the REQUEST-921 exclusion and the 166-rule target list (rule 45,
  corrected in engine-design.md).
