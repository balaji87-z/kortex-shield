# kortex-waf

Building a WAF to an independently checkable standard. The first deliverable is
not the WAF; it is the measuring stick, so every later claim comes with counts,
provenance and a baseline.

## What exists today

| Part | State |
|---|---|
| `kortex_eval/` manifest, leak-proof split, metrics with 95% intervals, report | Written, 105 unit tests pass |
| `kortex_eval/runner.py` verbatim request runner (stdlib http.client, sample-id header, block discriminator, manifest sha256 + labels in run.json) | Written, smoke-tested and used for the corpus runs |
| `kortex_eval/crs_audit.py` CRS audit-log parser, sample correlation via `X-Kortex-Sample-Id`, dual score readings (949110 total vs severity sum) | Written, tested on real audit samples |
| `kortex_eval/outcome.py` per-sample outcome classifier (error / waf_block / waf_would_block / waf_pass / proxy_reject / inconsistent) | Written, tested on synthetic + real data |
| `deploy/compose.yml` baseline testbed (target + OWASP CRS) | Running and verified: Juice Shop v20.4.0 behind owasp/modsecurity-crs 4.25.2-nginx-lts; ports/engine/paranoia are env vars with defaults |
| `docs/block-discriminator.md` WAF-block vs target-error discrimination rule | Written from captured evidence |
| `tools/build_attacks.py` + `data/attacks-v0/` first frozen ATTACK corpus (1054 samples, 527 distinct payloads × 2 injection points, 4 families) | Frozen (MANIFEST.sha256) |
| `tools/record_benign.py` + `data/benign-browse-v0/` frozen NATURAL benign browsing corpus (214 unique requests from 20 real UI sessions via Playwright) | Frozen (MANIFEST.sha256) |
| `tools/build_benign_hard.py` + `data/benign-hard-v0/` frozen HARD benign corpus (180 samples, 90 hand-written attack-adjacent values — overstates natural FP rate, never merge rates) | Frozen (MANIFEST.sha256) |
| `kortex_eval/endpoints.py` endpoint templating (numeric/hex/UUID segments → `{id}`) | Written, 10 tests |
| `tools/attack_breakdown.py`, `tools/benign_breakdown.py` stratified breakdowns with 95% Wilson intervals | Written, used for docs/baseline-v0.md |
| `docs/baseline-v0.md` / `v0.1` / … / `v0.9` / `v1.0` CRS false-positive baseline (crs-default: 34/214 natural v0, 184/774 natural v1, 22/180 hard; crs-policy-aligned in-sample 2/214, out-of-sample 34/774 on v1; crs-policy-aligned-v2: 2/214 v0, 4/774 v1 at PL1; UA confound removed in v0.2; v0.4: external WCP benign-wcp-v0 out-of-sample — default 19.12% PL1 / 44.76% PL2, aligned-v2 32.80% PL1 / 50.93% PL2; v0.5: WCP FPs decomposed (920420 = 76.7% of PL1 blocks, detection-involved bound 3.79% PL1), held-out-host policy widening made rates WORSE (31.66% vs 17.61% PL1 TEST), cookie restoration doubled the rate (48.05% vs 21.50% PL1), Coraza parity: blocked sets identical on all 4 datasets; v0.6: stub-drain fix, parity re-proven; v0.7 (step-12): images digest-pinned after upstream drift, small-dataset parity 0 diff in all 8 cells on both engines, Coraza body-limit pin proven ineffective (effective 524,288 — explains all 11 413 divergences), 17 status-400 samples classified (10 gzip replay artifacts / 2 malformed / 5 over-1000-argument JSON), 7 of 8 Coraza timeouts transient + 1 engine-specific (477KB text/plain: ModSecurity 23 ms vs Coraza ~46 s), 20 matched-shape probes 0 block disagreements, cookie restore was incomplete (case-sensitive bug, 7,511 of 13,261) — fixed and re-run: restored-cookie stratum 40.43% PL1 / 81.51% PL2 vs 20.22% / 46.08% with the placeholder; v0.8 (step-13): body-limit claim corrected — the 11 413s were nginx client_max_body_size 1 MiB, not Coraza, and Coraza v3.7.0 enforces no NoFilesLimit at all; proxy aligned (client_max_body_size 0) and WCP parity re-run at full scale: PL1 blocked 3,823 vs 3,824 (sym-diff 13), PL2 8,949 vs 8,951 (sym-diff 14), worst-case 5/11, policy-clear body-less sym-diff 0 at both PLs (410/4,130), body-bearing 8/9; audit-capture reload race fixed, smoke re-run PL1 sym-diff 0 (6=6); content-type swap test PROVEN (modsec records body rules on 6/100 policy-rejected-CT samples vs coraza 97/100, 97/100 after CT rewrite); Coraza latency pathology PROVEN engine-internal, not a CRS rule (477 KB text/plain ~44 s vs modsec 7–92 ms at PL1 and PL2; SecRequestBodyAccess Off → 3–5 ms; multipart 2.8 MB fast); v0.9 (step-14): the 11 oversize divergences fully explained (nginx 1 MiB; after alignment 10/11 multipart samples 200 on both engines at both PLs), step-13 timeouts transient except wcp-80a49c991b2d, T6 variable classes corrected (REQUEST_BODY 0 matches both engines), attacks-ct-v0 frozen (320 samples, 8 cells: default totals identical 304/316 per PL; ct-wide modsec 224/236 vs coraza 292/312 — modsec has no body processor for text/plain+octet-stream), encoding-diff-v0 frozen (192 samples, 0 engine disagreements), coraza-as-library probe: 44 s pathology reproduces in-library (PROVEN engine-internal), NoFilesLimit non-enforcement confirmed in-library; v1.0 (step-15): ct-wide policy on the held-out WCP TEST split 1,018/10,047 = 10.13% vs default 1,769 = 17.61% (worst case 10.52% vs 18.00%), 0 new detection blocks, sym-diff 751 all 920420-only; engine skeleton built (decision 0004, Coraza v3.7.0 + CRS 4.25.2, E1-E9 passing), T6 DIAGNOSTIC per-sample diff vs the connector (attacks-ct PL1: the 25 ref-only blocks are exactly the non-urlencoded carriers), time budget PROVEN not to bound single-shot body processing (481,798-byte body 41.8-43.5 s, then 403); v1.1 (step-16): all 396 T6 diffs classified (rule 39) — 252 BUG (missing connector-image body-processor/parse-failure rules, PROVEN Coraza URLENCODED fallback), 141 DESIGN-C4, 1 UNEXPLAINED (later explained as a harness artifact), 2 DESIGN-FRONT cells; BUG fixed test-first (E10-E15), re-run shows 146 diffs ALL DESIGN (zero BUG/UNEXPLAINED; attacks-v0 and benign-hard exact parity at both PLs); harness artifacts documented (missing User-Agent 920320 +2 on the engine side, numeric-IP Host 920350 +3 in manual replays); time budget now bounds body processing (E16) and the abandoned call owns the tx (E17); v1.2 (step-17): C4 MEASURED on the engine and HOLDS (attacks-ct per carrier: 36/36/36/36 structured, 34/34/34 raw-body, 40=34+6 no-ct at PL1; 39x4, 38x3, 40=39+1 at PL2 — every block except no-ct's 920640 cells is a detection rule; replayed identically on the current host), method allow-list implemented (911100 via tx.allowed_methods, E18; re-run 124/774 unchanged), in-flight body-processing cap (default 8, E19-E21; Phase B: 12x503 overload in 47-282 ms + 8x503 timeout, all 8 abandoned-finish events captured), WCP through the engine PL1 2,128 blocked / 58 deny_status / 4 errors, PL2 8,845 / 58 / 4 / 1 inconsistent, 3 timeouts (max 2,043.5 ms) and 32 limits per PL, 0 overload; per-id connector comparison NOT COMPUTED (lab host unreachable, no docker here); v1.3 (step-18): 413 delivery fixed test-first (body drained before the response, E22; the 3 step-17 reset ids now 413 with a readable body, 0 errors), raw-carrier body fidelity via SecRuleUpdateTargetById REQUEST_BODY on 166 CRS rules (E23-E25; REQUEST-921 excluded after 921150 manufactured 126 PL1 false positives on multi-line raw bodies, E26), pre/post re-runs of all five datasets: attacks-ct-v0 +6/+3 (exactly the split-broken payload x carrier ids), held-out benign sets 0/0, benign-wcp-v0 +61/+29 real gains (flip-corrected) with 0 real detection losses (3 PL2 timeouts, fail-closed), a NEW pre-existing engine non-determinism found and counted (occasional pass-through of a would-block request; UNEXPLAINED), durable run evidence under docs/logs/runs/ (rule 42), T2 connector comparison still BLOCKED (no docker/sudo); v1.4 (step-19): flip root cause PROVEN (coraza v3.7.0 transformation-cache collision on same-named args via map-order; scratch no-cache build 0/2500 flips vs median 114/500; unfixable in shipped build, exposure 498/20,000 samples; E27/E28 events+debug), cost at shipping config measured (text/plain 131,071 B: pre 6.0 s vs post 17.6-20.1 s; >2 s budget from 32,768 B at PL2; rule 942100 ALONE accounts for the entire added cost — DIAGNOSTIC bisect), availability DIAGNOSTIC (0/131 benign POSTs starved during 5-min slow-body attack, 2,154 CPU-s, E29 failing-by-design), final scope on UNSEEN benign-wcp-v1 (preregistered, ids disjoint, 2 tokens redacted, rebuild hash verified): new blocks PL1 28 / PL2 14, stable across runs (3 flips PL2 = the PROVEN defect), 0 timeouts; connector on v1: 1,868/4,480 vs engine 1,092/4,436, connector-only dominated by 920420 CT policy (DESIGN); docker available → decision 0004 coraza condition MET on held-out data; v1.5 (step-20): dup-arg bypass ruled out on 8 preregistered shapes on all 3 engines (identical counts), flip defect FIXED by coraza v3.7.0→v3.8.1 (E30 48/2000→0/2000, flip_repro PL2 0/2500), size-class body lanes (SMALL cap 8 / LARGE cap 2) end large-body starvation (269/269 benign POSTs served vs 0/131 in step-19; small-lane residual 6/276 documented), cost matrix (pathology 128 KB PL1 83.4 s vs prose 6.5 s; 942100 raw-body target = 0 blocks on 40k benign, 2/23 on directed SQLi canary), canary proves body inspection (98/100 engine, 99/100 connector) and exposes the application/json+protobuf REQUEST_BODY gap, 42 new benign-wcp-v1 blocks audited 0/42 attack-looking (FPs), token count corrected 6→8; v1.6 (step-21): evasion closed (padding matrix 864/864 blocked, CT matrix 0 evasion cells, JSON+protobuf gap RETIRED as canary-script artifact, dup-args 11/40 PROVEN harness double-encoding artifact), /__kortex/stats (E31) + no slot leak PROVEN (slots release at 112.5 s when the abandoned call finishes), killable worker subprocesses (T3a-T3g test-first, E20 retired for stricter bounded-CPU T3g, zero-diff parity 2520 samples + flip_repro 0/2500, fairness cap+penalty, worker overhead +0.2-0.4 ms median), big-body replay 402 samples: 0/402 >2 s at PL1, 4/402 at PL2, 49/402 413 (>=128 KB), 41 distinct new benign-wcp-v1 blocks re-audited with full bodies (39 benign, 2 cannot-tell, 0 malicious) | Written from real runs |
| `engine/` step-15 engine skeleton, step-16 fixes, step-17 policy: Go proxy wrapping Coraza v3.7.0 + CRS 4.25.2 (files verbatim from the pinned image, RULES.sha256), framing gate, body limits, budget-bounded body processing, C4 no-allow-list + connector-image body-processor rules (200000/200001/200002/200003/200007), method allow-list (900200 -> tx.allowed_methods, 911100; KORTEX_ALLOWED_METHODS), in-flight body-processing cap (KORTEX_MAX_INFLIGHT_BODY, default 8, 503 kortex-decision=overload), /__kortex/config proof, events log | Written test-first, E1-E21 passing (23/23 `go test ./...` in engine/ with the recorded wcp fixture); T1 classification + T2 re-run diff in docs/engine-evidence.md and docs/logs/step16-t2-analysis.txt; step-17 evidence in docs/logs/step17-*.txt; step-18: bounded body drain on the limit/overload/timeout paths, bodytargets.go REQUEST_BODY target updates (166 rules, printed at /__kortex/config), E22-E26; step-20: coraza v3.8.1, size-class lanes (KORTEX_BODY_LANE_THRESHOLD default 65536, KORTEX_MAX_INFLIGHT_BODY_LARGE default 2), deterministic test hook KORTEX_TEST_HOLD_BODY_MS + X-Kortex-Test-Hold, E29 rewritten/E30 added |
| `docs/acceptance.md` industry bars turned into tests | Written; no numeric targets until baseline is measured |
| `docs/decisions/0001-build-on-coraza.md` | Proposed |
| Dataset-scale expansion (1,600 attacks / 1,400 legitimate), engine | In progress — current: 1,054 attacks / 1,168 Juice Shop benign (214 v0 natural + 180 hard + 774 v1) + 19,994 external WCP benign (benign-wcp-v0, out-of-sample, replayed against a stub backend — not one app's traffic; built 20,000, 1 quarantined) + attacks-ct-v0 (320 carrier-expanded attack samples, frozen) + encoding-diff-v0 (192 encoding-variant attack samples, frozen) |

## Run the tests

    python -m pip install pytest
    python -m pytest -q

## Request convention

In a Sample, `path`, `query` and `body` are the raw request content exactly as
it goes on the wire: `query` is the raw query string with no leading "?",
already percent-encoded exactly as intended; `body` is the raw body as sent;
`path` is the raw path. The runner (`kortex_eval/runner.py`) sends them
unmodified and never re-encodes the request line. Every request carries the
header `X-Kortex-Sample-Id: <sample id>`; ids must match
`[A-Za-z0-9._:-]{1,64}` and are never rewritten.

## Replaying samples and reading the audit log

    python -m kortex_eval.runner --manifest data/smoke/manifest.jsonl \
        --base-url http://localhost:8081 --out out/<run-name>/
    docker logs <baseline-container> > out/<run-name>/docker-logs.txt
    python -m kortex_eval.crs_audit --logs out/<run-name>/docker-logs.txt \
        --out out/<run-name>/audit.jsonl
    python -m kortex_eval.report --manifest data/smoke/manifest.jsonl \
        --predictions out/<run-name>/predictions.jsonl --name "CRS PL1"

## Evaluate a system

    python -m kortex_eval.report --manifest data/test.jsonl \
        --predictions out/crs-pl1.jsonl --name "CRS PL1"

`manifest` is JSONL, one request per line (`id`, `label`, `family`, `source`,
`method`, `path`, ...). A sample with no `source` is rejected. `predictions` is
JSONL of `{"id": ..., "flagged": true|false}`; a sample with no prediction is an
error, never skipped.

## Rules this repo follows

1. Every sample records where it came from.
2. Test attack families are never in training.
3. Every rate is reported with its count and a 95% interval.
4. Every comparison includes the ModSecurity + CRS baseline.
5. A number is only quoted if one command regenerates it.

## Next steps, in order

1. ~~Check the VERIFY items in `deploy/compose.yml` and run the testbed on a machine with Docker.~~ Done in step-01.
2. ~~Write traffic generators: attack tools through the baseline, and a recorded benign browsing script.~~ Done (step-03 attacks, step-04 benign browsing + hard benign).
3. Build the dataset manifest; split with `kortex_eval.split`.
4. Measure CRS at paranoia levels 1 and 2. Set the numeric targets in `docs/acceptance.md` from those results.
5. Only then start the engine work (ADR 0001).
