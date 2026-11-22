# Baseline v1.6 (step-21, 2026-11-22)

Host: Ubuntu 26.04.1 LTS, kernel 7.0.0-44-generic, go1.25.0, 8 cpus
(i5-13420H). Engine: coraza **v3.8.1** + CRS 4.25.2, size-class lanes
(SMALL cap 8 / LARGE cap 2) — unchanged from v1.5. New in this baseline:
killable worker subprocesses for body inspection (opt-in), per-client
fairness, and the /__kortex/stats endpoint. In-process mode remains the
DEFAULT; worker mode is enabled with KORTEX_WORKER_MODE=on.

## T1: inspection-evasion questions closed (docs/logs/step21-t1*.txt)

- T1a padding canary matrix: 864/864 cells blocked (engine+connector,
  PL1/PL2, XSS+SQLi, k=0..100 KB padding before/after, 3 CTs, 3 reps).
  Zero evasion cells.
- T1b wcp-483cfc44d381 "JSON+protobuf gap" RETIRED: the step-20 passes
  were a canary-script classification artifact (blocked = status==403).
  The sample was answering 400 (JSON validity, fail-closed) and 503
  (timeout); with a 120 s budget it blocks 403. PROVEN by re-run.
- T1c content-type matrix: 9 CTs x 4 body cases x engine+connector at
  PL1 = 72 requests; engine and connector identical (28x403 + 8x400 on
  non-parseable bodies, rule 200002). Zero attacker-chosen-CT evasion.
- T1d dup-args numbers explained (PROVEN): the step-20 "11/40 pass at
  PL1" is a harness double-encoding artifact in
  tools/run_step20_t1_dupargs.py (quote() applied to already-encoded
  queries). Single-encoded bytes block at PL1 (932235/932125/932250);
  the same double-encoded body blocks at PL2 via 920230 (Multiple URL
  Encoding, PL2-by-design). The step-20 claim "they also pass at PL2"
  was FALSE (committed PL2 data: 0/800). Step-20 report amended
  (addenda 2-3); no engine or CRS change.

## T2: /__kortex/stats and the large-lane anomaly

- E31 (test-first, rule 40): GET /__kortex/stats (loopback-only, like
  /__kortex/config) exposes inflight_small, inflight_large,
  abandoned_running, kills, overloads, penalised_clients and
  workers{pool,busy,spares,loading,recycled}.
- Slot-leak question: NO LEAK — PROVEN. Isolated watch with 2
  concurrent abandoned 131,071-B text/plain calls: slots released at
  112.5 s (elapsed_ms 112456/112579, interrupted=true,
  abandoned-body-processing-finished events logged, stats return to
  zero and stay zero). Single isolated call: 503 at exactly 120.0 s.
- Abandoned-call cost is >=112 s and variable (112 s -> >250 s across
  runs of the same body). Variance UNEXPLAINED; the worker design (T3)
  makes it irrelevant (the worker is killed, not waited for).
- One 300 s re-run was INVALID and is documented, not silently
  discarded (rule 12): its 4 abandoned calls report elapsed 2.6-3.0 s
  with completed_no_interruption=true, audit log empty (0 bytes despite
  540 pass events), load_end=11.09. Excluded from all conclusions.

## T3: killable worker subprocesses (design BEFORE code: docs/engine-design.md)

- Body inspection moves to worker subprocesses (--kortex-worker-child,
  JSON-line protocol over fd 3/4, readiness handshake). At the budget
  the worker is SIGKILLed: kills counter, client penalty, immediate
  slot release. Bounded CPU is the property bought.
- Pool: KORTEX_WORKER_POOL (default 3) + KORTEX_WORKER_SPARES (default
  1) + KORTEX_WORKER_RECYCLE_AFTER (default 1000). Measured: rule-load
  ~1.5-2 s/worker, RSS ~51 MB/worker (parent+3 = 213 MB), startup
  6.9 s; spares hide rule-load from the hot path.
- Fairness: client = peer address (trusted-proxy XFF derivation only
  with KORTEX_TRUSTED_PROXIES, default empty). Per-client in-flight cap
  (KORTEX_CLIENT_MAX_INFLIGHT, default 4) and penalty after kill
  (KORTEX_CLIENT_PENALTY_MS, default 10000, map capped 4096
  oldest-evict). State observable at /__kortex/stats (rule 50).
- Tests T3a-T3g committed FAILING-BY-DESIGN (a699174) before the
  implementation (5795c34); all pass. Acceptance (f) zero-diff parity
  on 5 datasets (2520 samples) engine-vs-worker, both PLs, plus
  flip_repro worker PL2 2500 rounds 0 flips (1c823ca).
- Fairness attack re-runs (docs/logs/runs/s21-t3-fairness/): 8
  attackers from ONE address -> 2 kills + 6 overloads, all from the
  lane cap; per-client cap never acted (cap 4 > lane cap 2);
  penalised_clients=1. From 8 addresses -> 4 kills over 2 clients,
  pool=1 (global cap), 12 overloads. Worker overhead on benign smoke:
  +0.2-0.4 ms median, p99 equal/better, >100 ms counts identical.
- E20 (unbounded in-process CPU after a budget timeout, step-16) is
  RETIRED and replaced by the stricter bounded-CPU property (T3g,
  committed failing-first): after a kill the engine process CPU stops
  growing. The E20 test itself is kept passing (in-process mode still
  exists) but no longer carries the availability claim.

## T4: large-body cost and the 41 new benign-wcp-v1 blocks

- Replay of every frozen body >16 KB (402 samples, benign-wcp-v0+v1)
  at PL1 and PL2, worker mode, 120 s budget, load 1.4-2.3
  (docs/logs/runs/s21-t4-bigbodies/): PL1 0/402 exceed 2 s (would have
  been 503 at the 2 s default budget); PL2 4/402 (elapsed 2051-2133 ms,
  all 403 blocks, sizes 77-98 KB). Elapsed PL1 p50 212.9 ms / p99
  1132.1 ms; PL2 p50 410.4 ms / p99 1992.2 ms. The 49 bodies >=128 KB
  return 413 at both PLs (inspection limit). Counts only, per the
  preregistered plan.
- Full-body re-audit of the 41 distinct new benign-wcp-v1 blocks
  (docs/logs/step21-t4b-reaudit.txt): 41/41 read; 39 ordinary benign
  (analytics beacons, CSP reports, checkout forms, reCAPTCHA/Facebook
  tokens), 2 cannot-tell-by-content (opaque obfuscated telemetry
  blobs), 0 plausibly malicious. All matches are on REQUEST_BODY/ARGS
  content (932/942/933/931/920230), never on control parameters.
  Reconciliation: 42 in step-20 = 28 (PL1) + 14 (PL2) with one id
  blocked at both levels -> 41 distinct. No exclusions applied
  (instructor decision). PII found in 1 sample (email/name/phone/
  address; type and count only, rule 25).

## Standing notes carried from v1.5

- Small-lane starvation residual 6/276 (measured, not tuned).
- modsec-connector comparison not re-run since step-13.
- Step-20 addenda 2-3 amend the T1b canary classification and the
  dup-args reading (see v1.5 T1 and docs/logs/step21-t1d-explain.txt).
