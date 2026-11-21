# Baseline v1.5 (step-20, 2026-11-21)

Host: Ubuntu 26.04.1 LTS, kernel 7.0.0-44-generic, go1.25.0, 8 cpus
(i5-13420H, post-reboot: 2611 MHz, no boost — rule 43; step-19 numbers were
pre-reboot and are NOT directly comparable to step-20 timings).
Engine: coraza **v3.8.1** (bumped from v3.7.0 in T1 this step) + CRS 4.25.2,
lanes (T2). Connector images: coraza-crs 4.25.2-nginx
sha256:bfbfe70b…, modsec 6296ce68… (both proven in-container in T1).

## T1: duplicate-argument bypass (preregistered: docs/plan-dup-args.md)

Measurement (40 payloads from attacks-v0, seed 0, 10 per family; 8 shapes
Q1-Q4/B1-B4; 20 repeats each; fresh transaction per request; 3 engines,
PL1 and PL2; errors counted separately from passes):

| engine | PL1 query shapes | PL1 body shapes | PL2 (all shapes) |
|---|---|---|---|
| engine (v3.7.0) | 40/800 (2/40 variants) | 220/800 (11/40) | 0/800 |
| coraza connector | 40/800 | 220/800 | 0/800 |
| ModSecurity control | 40/800 | 220/800 | 0/800 |

**No duplicate-argument bypass on the preregistered shapes**: all three
engines produce identical, shape-invariant counts; the passing payloads are
ones that never block (they also pass at PL2 with zero dup-arg effect).
Rule 44 (connector shares the defect?): the PROVEN flip needs the richer
7-param duplicate-`filter` context (wcp-62cd1bd36bf7); on the preregistered
shapes the connector behaves identically to the engine — nothing to share.

Fix (rule 40, test-first): **E30** (commit 83fbebd, failing first:
48/2000 flips on v3.7.0) — 2000 replays of wcp-62cd1bd36bf7 at PL2 with
runtime.GC() between rounds, zero flips required. Fix = candidate 1:
coraza v3.7.0 → **v3.8.1** (go.mod). After the bump: E30 0/2000
(~40.6 s); flip_repro 5×500 at PL2: **0/2500** (was median 114/500);
at PL1 flip_repro counts 500/500 "flips" on BOTH versions — not a
regression: those samples never block at PL1 in any version. The
dup-args measurement re-run on v3.8.1 is identical to v3.7.0
(PL1 40/220, PL2 0/800; request_body_target_updates=166).
Candidate 2 (vendored patch) NOT needed.

## T2: availability (design documented BEFORE running: docs/engine-design.md)

Size-class lanes: SMALL lane (declared Content-Length ≤
KORTEX_BODY_LANE_THRESHOLD, default 65536) cap 8 (KORTEX_MAX_INFLIGHT_BODY);
LARGE lane (> threshold, or unknown framing / no Content-Length —
conservative) cap 2 (KORTEX_MAX_INFLIGHT_BODY_LARGE, new). Residual
exposure documented up front: attacker bodies that fit the SMALL lane can
still starve small benign POSTs inside that lane.

Deterministic test hook (rule 48): KORTEX_TEST_HOLD_BODY_MS +
`X-Kortex-Test-Hold: 1` sleeps inside the slot.

E29 rewritten as a probe-gate test (failing by design pre-lanes, commit
9f252d7; passing after lanes, commit 71d3aec): 8 attackers hold slots
(100,000 B bodies), a probe must observe 503 (lane full), then a benign
SMALL POST must be served (non-503 + backend hit).

Runs (tools/run_step20_t2_lanes.sh; stub backend returns 200):

- Large lane (131,071 B attackers, PL1): benign POSTs **269/269 served**
  (step-19: 0/131); recovery 0.1 s; engine events overload=12478,
  timeout=2, abandoned_finished=0.
- Small lane (32,768 B attackers, PL2): benign POSTs **6/276 served** —
  the documented residual exposure is real (attackers fit the small lane);
  slot holds median 9.2 s, max 86.7 s.

`abandoned_finished=0` investigated (rule 33): a single abandoned call now
takes 74.2 s (~77 s CPU) on v3.8.1 AND 79.6 s (~86 s CPU) on v3.7.0 — not
a v3.8.1 regression; the host changed at the VM reboot (rule 43).

DIAGNOSTIC subprocess-kill spike (scratch only, never shipped, commit
6e1ea69): body inspection in a killable child process caps CPU burned
after the deadline to ≤500 ms per 2 s budget (vs 74-80 s in-process), but
respawn costs 1.3-2.7 s paid by the next request. Not proposed for
shipping (docs/logs/step20-t2-spike.txt).

## T3: inspection cost vs body size (docs/logs/step20-t3-cost-analysis.txt)

3 bodies (pathology = real WCP prefix, benign prose, keyword-dense
adversarial) × 4 sizes × pre/post engine × PL1/PL2 × 3 reps. Key medians:

- PL1 pathology 131,072 B: pre 27.0 s → post **83.4 s** (403).
- PL1 prose 131,072 B: 4.8 → 6.5 s (200 — cost is paid even when passing).
- PL1 adversarial 131,072 B: 4.0 → 7.4 s (403, cheap — early match).
- PL2 pathology 131,072 B: pre 34.6 s → post **30.3-120 s (bimodal,
  UNEXPLAINED, rule 39)**; some reps hit the 120 s budget (503).
- Confound declared: pre/post differ also in coraza version (v3.7.0 vs
  v3.8.1) and lanes; the comparison does not isolate the raw-body targets.

Blocks existing only because of the 942100 raw-body target:

- benign-wcp-v1 (40,000 requests): **0** audit entries mention 942100 —
  no v1 block is attributable to it; its only measurable effect is cost.
- Directed canary (23 SQLi payloads as raw text/plain bodies): full engine
  8/23 vs engine without 942100 6/23 → 942100 uniquely contributes **2/23
  at PL1** (`admin" or "1"="1"#` and a JSON carrier), **0/23 at PL2**.

Measured options (no change shipped this step):
(a) cap raw-body targets at size N — N=64 KB still leaves 22 s; N=16 KB
leaves 3.1 s but gives up large-body inspection;
(b) windowed inspection — needs coraza changes, out of scope;
(c) status quo — kept.

## T4: canary + audit (docs/logs/step20-t4-canary-audit.txt, step20-t4b-audit.txt)

A3 canary (rule 47) on the 100 A3 ids (benign-wcp-v0, connector-only
920420 at PL1): same requests with a known payload appended to the body.

- Attempt 1 INVALID (rule 18, harness artifact): the `\n` separator itself
  triggered 921150 (CR/LF) on 54/71 — redone with a space separator.
- SQLi canary (` admin" or "1"="1"#`): engine 18/100 blocked, all by
  942100 — libinjection's whole-body fingerprint is context-sensitive;
  not a universal canary.
- XSS canary (`"><script>alert(1)</script>`, substring-deterministic):
  **engine 98/100 blocked** (941100/941110/941160/941390 + 949110);
  **connector 99/100 blocked** (920420 CT rejection on all 100 + 941 on
  98). The 2 engine passes: wcp-dedb89ec3d3d (application/json+protobuf —
  the JSON processor does not populate REQUEST_BODY: a REAL inspection
  gap, also the connector's only pass) and wcp-483cfc44d381 (text/plain
  100 KB, no match, UNVERIFIED cause).
- Conclusion: body inspection is PROVEN for this request class; A3's
  0/100 920420 matches now reads "inspected, no match" for text/plain
  ids; the JSON+protobuf CT is NOT inspected (gap, both engines).

Audit of the 42 new blocks on benign-wcp-v1 (rule 26; 28 PL1 + 14 PL2,
one id in both): all 42 read as benign browser telemetry / e-commerce
beacons (Datadog RUM, GA4, Adobe Analytics, Shopify monorail, perf
/ingest.php, cart/checkout forms). Matched rules are the 932 RCE family
firing on substrings inside telemetry bodies. **0/42 look like attacks**
→ the new blocks are classified false positives (rule 46: new blocks,
never "gains"). Audit of 42 by one reader, not a proof.

Token count reconciliation: benign-wcp-v0 contains **8** publishable
token shapes (docs/logs/wcp-v0-token-ids.txt), not 6 as stated in
reports/step-19.md — corrected in place (step-19 report, question 4).
Values not reproduced (rule 25); frozen manifest untouched (rule 10).

## Test suite state

`go test ./...` in engine/ with KORTEX_TEST_WCP_BODY set: 30 passing +
E29 (rewritten, passing) + E30 (passing); E20 remains a known failure
(abandoned-call duration — cost trade-off documented in step-19, not a
lane regression); E19 passes in isolation, flaky only under parallel
load (as in step-19). Exact counts in reports/step-20.md.
