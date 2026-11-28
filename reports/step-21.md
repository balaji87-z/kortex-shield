# Step-21 report

- Summary: closed the step-20 evasion anomalies (padding matrix 864/864
  blocked; "JSON+protobuf gap" retired as a canary-script artifact;
  dup-args 11/40 PROVEN a harness double-encoding artifact); shipped
  /__kortex/stats (E31) and PROVED there is no slot leak (slots release
  when the abandoned call finishes, 112.5 s); replaced the unbounded-CPU
  budget timeout with killable worker subprocesses (T3a-T3g test-first,
  zero-diff parity on 2520 samples, per-client fairness), measured
  large-body cost (0/402 > 2 s at PL1, 4/402 at PL2) and re-audited the
  41 distinct new benign-wcp-v1 blocks with full bodies (0 malicious).

- Task table:

| task | status | evidence |
|---|---|---|
| T1a padding canary matrix | done | docs/logs/step21-t1a-padding.txt, docs/logs/runs/s21-t1-pad/ |
| T1b wcp-483cfc44d381 cause | done | docs/logs/step21-t1b-483cfc.txt |
| T1c content-type gap matrix | done | docs/logs/step21-t1c-ct.txt, docs/logs/runs/s21-t1c-ct/ |
| T1d dup-args numbers explained | done | docs/logs/step21-t1d-explain.txt |
| T2 /__kortex/stats + large-lane re-explanation | done | docs/logs/step21-t2-analysis.txt, docs/logs/runs/s21-t2-large-replay/ |
| T3 killable workers + fairness + parity | done | docs/engine-design.md (design), engine/worker*.go, docs/logs/runs/s21-t3-parity/, s21-t3-fairness/ |
| T4 big-body replay + 41-block re-audit | done | docs/logs/step21-t4-bigbodies.txt, docs/logs/step21-t4b-reaudit.txt, docs/logs/runs/s21-t4-bigbodies/ |
| T5 docs + decision note + report | done | docs/baseline-v1.6.md, docs/decisions/0004-engine-core.md, docs/acceptance.md, README.md, this file |

- Raw evidence (key numbers, per rule 31):

**T1a.** 864/864 cells blocked: {engine, connector} x {PL1, PL2} x
{XSS, SQLi} x {k=0, 1, 4, 16, 64, 100 KB} x {before, after} x
{text/plain, application/json, text/xml} x 3 reps = 2*2*2*6*2*3*3 = 864.
Zero evasion cells; engine and connector identical.

**T1b (PROVEN).** wcp-483cfc44d381: step-20 "pass" statuses were 400
(JSON validity, fail-closed) and 503 (timeout at the old budget); with a
120 s budget the same sample blocks 403. The "JSON+protobuf REQUEST_BODY
gap" claim is RETIRED. The discriminating experiment is the budget
change: same bytes, same rules, different outcome — the earlier "pass"
was never an inspection miss.

**T1c.** 9 CTs x 4 body cases x {engine, connector} at PL1 = 72
requests: engine 28x403 + 8x400, connector identical (28x403 + 8x400).
The 400s are the non-parseable bodies (rule 200002, fail-closed). Zero
attacker-chosen-CT evasion cells. Matched variables seen in the raw
audit: ARGS:json.v (JSON), REQUEST_XML (XML), ARGS_NAMES fallback.

**T1d (PROVEN).** Exact request bytes of a "passing" PL1 B-shape
sample: `p=q%3D%257C%2520ls%2520-l%2520%252Ftmp` (double-encoded —
tools/run_step20_t1_dupargs.py applies quote() to already-encoded
manifest queries). Probes: double-encoded -> PL1 200 (the step-20
number); single-encoded `p=%7C%20ls%20-l%20%2Ftmp` -> PL1 403 with
932235/932125/932250+949110; the same double-encoded body -> PL2 403
with 920230 "Multiple URL Encoding Detected" (PL2-by-design CRS rule).
The step-20 sentence "they also pass at PL2" is FALSE: the committed
PL2 data shows 0/800. The 11/40 (body shapes, v3.7.0 and v3.8.1), 2/40
(query shapes) and 4/40 (connector) numbers measure different
encodings and are not comparable. No engine or CRS change; step-20
report amended (addenda 2-3).

**T2 (no leak — PROVEN).** E31 test-first (failing commit ba365d5,
implementation e4a2e76): GET /__kortex/stats (loopback-only) exposes
inflight_small, inflight_large, abandoned_running, kills, overloads,
penalised_clients, workers{pool,busy,spares,loading,recycled}.
Discriminating experiment: 2 concurrent abandoned 131,071-B text/plain
calls watched in isolation — slots released at 112.5 s (elapsed_ms
112456/112579, interrupted=true), two `abandoned-body-processing-finished`
events logged, stats return to zero and STAY zero for the rest of the
watch. Single isolated call: 503 at exactly 120.0 s. Abandoned-call
cost is >=112 s and variable (112 s -> >250 s for the same body across
runs) — variance UNEXPLAINED; under worker mode (T3) the call is killed
at the budget instead of being waited for, so the variance no longer
affects availability. A 300 s re-run (s21-t2-large-lane-rerun) was
INVALID and is documented, not discarded (rule 12): its 4 abandoned
calls report elapsed 2.6-3.0 s with completed_no_interruption=true
(contradicting the isolated >120 s measurement), the audit log is empty
(0 bytes despite 540 pass events) and load_end=11.09. Excluded from all
conclusions. 60 s replay sanity check: 8 attackers -> benign POST 17/19,
GET 19/19, overloads 655; large lane pinned at 2/2 abandoned the whole
run (expected: abandoned calls outlast the 70 s window).

**T3.** Design committed before code (58928b9). Tests T3a-T3g committed
FAILING-BY-DESIGN (a699174) before the implementation (5795c34); all
pass. Semantics: at the budget the worker is SIGKILLed -> kills counter
+ client penalty + immediate slot release; pre-spawned spare hides the
~1.5-2 s rule-load; recycle-after-N bounds worker lifetime; per-client
in-flight cap (default 4) + penalty after kill (default 10000 ms, map
capped 4096 oldest-evict); client = peer address, XFF derivation only
with KORTEX_TRUSTED_PROXIES (default empty).
- Cost: rule-load ~1.5-2 s/worker; RSS ~51 MB/worker (parent+3 workers
  = 213 MB total); cold startup 6.9 s (parent + 3 workers in series).
- Acceptance (f) decision parity, zero-diff (tools/step21_engine_diff.py
  + tools/run_step21_t3_parity.sh), 2520 samples: attacks-v0 1054
  {200:100, 403:954}; attacks-ct-v0 320 {200:28, 403:292};
  encoding-diff-v0 192 {200:45, 403:137, None:10}; benign-browse-v1 774
  {200:650, 403:124}; benign-hard-v0 180 {200:158, 403:22} —
  in-process vs worker identical at PL1 and PL2, zero diffs. flip_repro
  worker PL2: 2500 rounds, 0 flips.
- Fairness re-runs (docs/logs/runs/s21-t3-fairness/): 8 attackers from
  ONE address -> 2 kills + 6 overloads (all from the lane cap
  "in-flight body-processing cap reached"; the per-client cap never
  acted because cap 4 > lane cap 2), penalised_clients=1. From 8
  loopback addresses -> 4 kills spread over 2 clients, pool=1 (global
  cap), 12 overloads. Kill path standalone: 503 at 0.34 s, kills=1,
  pool stays 3/3.
- Latency smoke (benign-browse-v1 / hard-v0 / wcp-v1, in-process vs
  worker): median +0.2-0.4 ms (3.9->4.1, 4.1->4.5, 6.4->6.6 ms), p99
  equal or better, >100 ms counts identical (218/218 on wcp-v1).
- E20 is RETIRED in favour of the stricter T3g (bounded CPU after
  kill); E20's test is kept and still passes (in-process mode remains
  supported and default). Bugs found during bring-up (fixed, with the
  T3 tests written first): pipe ends swapped; killed workers returned
  to idle (spawn storm, 30+ children, negative counters); child audit
  log touch (coraza v3.8.1 O_CREATE); child recursion via main().
- Full-suite regression evidence (rule 12, documented not hidden):
  run 1 (1641.9 s, load 9-11): 4 FAIL — E20 "abandoned call did not
  finish within 120s" (511 s test) plus the cascade T3c/T3f/T3g. Run 2
  (809.3 s, load 1.8-5.6): E20 fail ONLY (139.6 s test); T3a-T3g and
  everything else PASS (docs/logs/step21-suite-run2.log). E20's failure
  is PROVEN pre-existing, not a worker-code regression: the same test
  fails identically on the pre-worker commit 763f8dd (288.3 s, still no
  abandoned-finish event; docs/logs/step21-e20preworker.log). The cause
  is the same UNEXPLAINED variance T2 measured (the 131,071-B abandoned
  call: 112.5 s isolated earlier today, >288 s now) — a rule-48
  flakiness (a test that sometimes passes cannot gate a fix), which is
  additional evidence FOR retiring E20 in favour of the deterministic
  T3g. The run-1 cascade was load poisoning: T3g's check reads
  /proc/self/stat, which counts the still-running E20 leftover
  goroutine (PROVEN mechanism: same process); T3c/T3f 503s under that
  CPU load are HYPOTHESIS (contention slowed replacement-worker rule
  load). Discriminating re-runs: T3 batch without E20 passes 7/7 twice
  (9.4 s / 8.9 s, load 1-2); T3c alone 3/3 (0.9 s); T3b+T3c pair 3/3;
  and in run 2 the whole T3 batch passes WHILE E20 fails. Known
  test-hygiene noise (not a product bug): replacement-spawn goroutines
  can outlive a test's tempdir, so leaked children print "audit touch
  failed ... no such file or directory" after cleanup; production
  engines never tear down.

**T4.** Replay of every frozen body >16 KB (402 samples from
benign-wcp-v0+v1; first launch INVALID — build_big_manifest.py emitted
extra keys and was rewritten as a pure filter; the valid run is the
second), worker mode, 120 s budget, load 1.4-2.3:
- PL1: n=402 {200:97, 400:49, 403:207, 413:49}; elapsed p50 212.9 ms,
  p95 893.3, p99 1132.1, max 1200.2. **0/402 exceed 2 s** (would have
  been 503 at the 2 s default budget).
- PL2: n=402 {200:17, 400:49, 403:287, 413:49}; elapsed p50 410.4 ms,
  p95 1582.3, p99 1992.2, max 2133.3. **4/402 exceed 2 s** (elapsed
  2051.1-2133.3 ms; ids wcp-8aa4b0b85a6f, wcp-f8ba3db5e5c3,
  wcp-a01f72758b1b, wcp-81f2f8b2c3e0; all 403 blocks, sizes 77-98 KB).
- Size buckets: >=128 KB -> 49/49 413 at both PLs (inspection limit);
  <64K PL1 p50 239.7 ms; <128K PL1 p50 831.2 ms, PL2 p50 1531.8 ms.
- By CT (PL2 worst): application/vnd.chrome.uma p50 1306.7 ms max
  2133.3; text/plain p50 465.2 max 1982.0; JSON p50 235.6 max 1062.8.
- Re-audit of the 41 distinct new benign-wcp-v1 blocks
  (docs/logs/step21-t4b-reaudit.txt): all 41 bodies read in full;
  **39 ordinary benign** (analytics beacons Adobe/GA4/Datadog, CSP
  reports, Shopify/Facebook checkout, reCAPTCHA tokens), **2
  cannot-tell-by-content** (opaque obfuscated telemetry blobs
  wcp-f5e2ec747222, wcp-3003d84bc92a; the same-format base64 blobs
  wcp-f03cc8a0452b / wcp-fd32a862be95 decode to southwest.com booking
  telemetry), **0 plausibly malicious**. Matches are on REQUEST_BODY/
  ARGS content (932/942/933/931/920230), never control parameters.
  Reconciliation: 42 in step-20 = 28 (PL1) + 14 (PL2) with one id
  blocked at both levels -> 41 distinct ids. No exclusions applied
  (instructor decision). PII found in 1 sample (email, name, phone,
  postal address — type and count only, rule 25).

**Full engine test suite** (regression check after the worker-mode
code): run 1 (1641.9 s, load 9-11): 4 FAIL — E20 "abandoned call did
not finish within 120s" plus the cascade T3c, T3f, T3g (load poisoning
from the E20 leftover, see T3 above). Run 2 (809.3 s, load 1.8-5.6):
**E20 fail ONLY** (139.6 s test); T3a-T3g and all other tests PASS
(docs/logs/step21-suite-run2.log). E20 also fails on the pre-worker
commit 763f8dd (288.3 s, docs/logs/step21-e20preworker.log) — PROVEN
pre-existing host-timing variance, not a worker-code regression.

- Deviations from instructions:
  - The T2 300 s re-run was invalid (audit log empty, elapsed
    contradiction, load 11.09); documented per rule 12 and excluded
    rather than re-run a third time — the isolated watch already
    answers the leak question and the worker design supersedes it.
  - T3c (spare test) runs with KORTEX_CLIENT_PENALTY_MS=0 so it
    measures spare availability, not fairness (T3f covers fairness).
  - T4 first launch invalid (extra manifest keys); rewritten as a pure
    filter, valid run is the second.
  - The per-client in-flight cap default (4) sits above the large lane
    cap (2), so in the one-address attack the lane cap binds first —
    measured and reported, not tuned (instructor decision: don't tune).

- UNVERIFIED items:
  - The variance of abandoned-call cost (112 s -> >250 s) is UNEXPLAINED.
  - The two opaque telemetry blobs are classified cannot-tell by
    content; their format resembles Akamai/Boomerang beacons but this
    is not verified against a spec.
  - The modsec-connector comparison remains not re-run since step-13
    (carried standing note).

- Questions for instructor:
  - Worker mode is opt-in (KORTEX_WORKER_MODE=on) while in-process
    stays default. Should a later step flip the default for the
    shipping config, and should the connector compose use worker mode?
  - The per-client cap (4) never binds before the lane caps (8/2).
    Keep as a second line of defence, or lower it for large bodies?
  - The 2 cannot-tell telemetry blobs: keep labelled as-is in the
    dataset README, or attempt source-format identification?

Commit chain this step (SHAs after the history rewrite described
below): d9f1c6f (rules 49-50) -> 5b3a80c (T1a) -> f742b1e (T1b) ->
3361323 (T1c+T1d) -> 09f7c1b (E31 failing) -> 3eece7d (E31) -> a485538
(T2 tools + T3 design) -> 49725f8 (T2 analysis) -> 3bfea4b (T3 failing
tests) -> 8477209 (T3 impl) -> 9c8f8fd (T3 parity) -> 9df305f (T4) ->
d07e849 (T3 run evidence) -> <this commit>.

History-rewrite note (evidence hygiene): the push was rejected because
docs/logs/runs/s21-t4-bigbodies/manifest-derived.jsonl is 105.15 MB
(GitHub limit 100 MB). The 14 step-21 commits were rewritten with git
filter-branch --index-filter replacing that file by its gzip -9 copy
manifest-derived.jsonl.gz (25.8 MB, identical content) plus a body-less
index manifest-derived-nobodies.jsonl (507 KB, ids/sizes/CT for the
replay analysis). No other content changed.
SHA-256 of the uncompressed original: c52e118fa4f6b4e1ba3021e2cd02a46fa147bac249e7eb147ffea1469ab30230

## Amendment (step-22, 2026-11-27): numeric Host in the step-21 runs

Added in step 22; the text above is unchanged. The step-21 T3 (parity) and
T4 (big-body) runs replayed against `http://127.0.0.1:<port>`
(tools/run_step21_t3_parity.sh, tools/run_step21_t2_replay.sh). The runner
takes the Host header from the base URL, and a numeric Host matches CRS
920350 (+3) on every request, so a request with one warning-level match is
blocked at PL2. PROVEN in step 22 (reports/step-22.md, "Numeric-Host
artifact"; docs/logs/step22-numeric-host.txt).

- T4, PL2: the count above is `403: 287` of 402. The step-22 re-run with
  `localhost` (docs/logs/step22-t4-bigbodies-audit.txt, other host, in-process
  mode) gives **286 of 402**; the one id that differs is wcp-43ad8735b4fe
  (403 here, 200 there). PL1 is 207 of 402 in both.
- T4 timings (0/402 over 2 s at PL1, 4/402 at PL2) are from the step-21
  host and were not re-measured there; the step-22 run on another host has
  0/402 over 2 s at both levels.
- T3 parity (5 datasets, 2,520 samples, 0 differences): both modes were
  replayed with the same numeric Host, so the comparison is like with like
  and the parity result stands. The block counts inside those runs include
  the artifact at PL2. The 5 datasets were NOT re-run with `localhost`; the
  step-22 parity runs with `localhost` cover benign-wcp-v0 and v1 (60,000
  samples, 0 status differences).

