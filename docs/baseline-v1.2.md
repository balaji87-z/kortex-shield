# Baseline v1.2 (step-17, 2026-11-20)

Dated notes on top of v1.1 (docs/baseline-v1.1.md, kept unchanged). Step-17
measured C4 on the engine (rule 41: a DESIGN classification is not a result
until its criterion is measured), closed the method allow-list gap, bounded
abandoned body-processing work with a hard in-flight cap, and ran
benign-wcp-v0 through the engine. ENVIRONMENT NOTE: the lab host used for
steps 09-16 (paths /home/Kavinharish/kortexshield) was no longer reachable
during step-17; the engine-side work was re-done on the current host
(go 1.25.0 linux/amd64, no docker, no sudo). Connector reference RUNS could
not be reproduced here; committed lab logs are used as the reference where
per-id files are gone.

## Rule 41 (process, appended to AGENTS.md)

"A DESIGN classification needs the criterion it relies on shown as measured."
Appended this step; it is what forced the T1 re-measurement below.

## T1: C4 measured on the engine — HOLDS (with a measured caveat)

Inputs: the committed s16-t2 engine runs (lab host) for the original
analysis (docs/logs/step17-t1-c4.txt, commit 460eed7), then a full replay of
attacks-ct-v0 through the engine on the current host
(tools/run_step17_t1_engine.sh, docs/logs/step17-t1-engine-runs.txt,
analysis docs/logs/step17-t1-c4-replay.txt). The replay reproduces the
committed per-carrier table EXACTLY:

| carrier | PL1 engine blocked/40 (detection / policy-only) | PL2 engine blocked/40 (detection / policy-only) |
|---|---|---|
| query | 36 (36/0) | 39 (39/0) |
| urlencoded | 36 (36/0) | 39 (39/0) |
| json | 36 (36/0) | 39 (39/0) |
| multipart | 36 (36/0) | 39 (39/0) |
| text-plain | 34 (34/0) | 38 (38/0) |
| octet-stream | 34 (34/0) | 38 (38/0) |
| unknown-ct | 34 (34/0) | 38 (38/0) |
| no-ct | 40 (34/6) | 40 (39/1) |

- Every block on every carrier except no-ct's 920640 cells is a DETECTION
  rule block; the engine has no content-type allow-list to depend on
  (config 900220 sets the allowed list to the request's own type — measured
  in the rule-29 config proof and engine/config.go).
- Payloads detected under a structured carrier but missed under a raw-body
  carrier (the URLENCODED-fallback split caveat, PROVEN from diag audit
  entries in step17-t1-c4.txt): PL1 command-injection-dc2932d5 (932125,
  932380) and sqli-6e47f23b (942100); PL2 command-injection-ecb32a80
  (932240). Same lists in the replay.
- PROVEN (step17-t1-c4.txt, raw engine audit entries per carrier): the
  engine transaction receives and parses the body for text/plain,
  octet-stream and unknown-ct (REQBODY_PROCESSOR=URLENCODED via CRS 901340
  + the Coraza fallback; ARGS_POST populated; the missed payloads are missed
  because the '&'/'=' split destroys them, not because detection depends on
  an allow-list).

**Conclusion: C4 HOLDS on the engine, measured at both PLs** — detection
blocks happen on carriers the connector refuses at phase 1 (34/40 and 38/40
detection blocks on text-plain, octet-stream, unknown-ct). The 920420
difference stays DESIGN under rule 41, now with the criterion measured.

## T2: method allow-list — implemented, outcome sets unchanged

- Failing tests E18 committed first (460eed7), implementation 559d9b6:
  config 900200 sets tx.allowed_methods from KORTEX_ALLOWED_METHODS
  (default "GET HEAD POST OPTIONS", mirroring the connector's crs-setup
  900200); CRS 911100 rejects methods outside the list; the value is
  printed at /__kortex/config (measured:
  `"allowed_methods":"GET HEAD POST OPTIONS","max_inflight_body":8`).
- CORRECTION to the step-16 note "911100 never fires on the engine": it
  DOES fire and scores identically (+3 warning + 2 notice = 5); what
  differs is that the engine's audit entries carry only phase-2 messages,
  so 911100 never appears in the engine's audit MESSAGES (measured on both
  engines; s17-t2 analysis, committed).
- Re-run on the current host (docs/logs/step17-t2-runs.txt): smoke PL1
  7/12 blocked, benign-browse-v1 PL1 124/774 blocked, 0 errors — the same
  counts and (for the lab re-run, proven per-id) the same id sets as
  s16-t2. The method gap is CLOSED as a policy difference; outcome parity
  was already exact in step-16 and is unchanged.

## T3: in-flight body-processing cap — measured on the current host

E19-E21 written failing first (460eed7), implementation 559d9b6:
KORTEX_MAX_INFLIGHT_BODY (default 8) caps concurrent body-processing calls
including abandoned ones; over the cap a body-bearing request gets
503 kortex-decision=overload immediately and an `overload` event.

Measurement (docs/logs/step17-t3-runs.txt; the lab run was twice killed by
platform restarts — its partial log is kept as step17-t3-runs-lab.txt and
-firstpass-lab.txt):

- Phase A (cap=32, 20 concurrent 481,798-byte bodies): all 20 answered 503
  timeout at ~2.0-2.3 s; process CPU 0.98+1.88 s at start, 8.17+6.75 s at
  the 2 s deadline, 278.72+65.69 s at +60 s; benign latency 144 ms before,
  447 ms at deadline, 859 ms at +8 s, 468 ms at +59 s (this VM is slower
  and noisier than the lab: load average 9-21 through the phase).
- Phase A2 (cap=32, 4 copies): 4/4 abandoned-body-processing-finished
  events captured, elapsed_ms 136815-137351 (this host: a single call costs
  ~137 s wall under 4-way contention vs ~43 s on the lab).
- Phase B (cap=8 default, 20 copies): **12 x 503 kortex-decision=overload
  answered in 47-282 ms, 8 x 503 timeout at ~2.0-2.1 s; 12 overload + 8
  timeout events; all 8 abandoned-finish events captured
  (elapsed_ms 341132-346544)**; benign during the overload window 183 ms,
  after recovery 502 ms (load still ~12).
- Does the cap remove the step-16 degradation (59.5 ms benign at +59 s with
  20 pending)? The background work is now bounded to at most 8 concurrent
  abandoned calls instead of 20 (Phase A CPU at +60 s: ~345 CPU-s for 20
  in-flight; Phase B bounds that to 8/20 of the wave). On THIS host the
  benign probes stay at hundreds of ms under the burst either way, so the
  cap's benefit shows as bounded background work (8 finish events, not 20)
  and fast overload answers, not as a sub-10 ms benign tail — the step-16
  59.5 ms figure is not reproduced here because the host is ~10x slower
  per abandoned call (~137 s vs ~45 s). HYPOTHESIS (not PROVEN on this
  host): with the cap, sustained overload degrades benign latency less
  because at most 8 CPU-bound goroutines accumulate.

## T4: benign-wcp-v0 through the engine (DIAGNOSTIC, counts of effects)

Engine runs on the current host (tools/run_step17_t4.sh,
docs/logs/step17-t4-runs.txt; frozen manifest sha c8ce11f2... proven
in-run; stub backend; same UA contract; rule-29 config proof printed):

| | PL1 | PL2 |
|---|---|---|
| samples | 20,000 | 20,000 |
| blocked (waf_block) | 2,128 | 8,845 |
| waf_deny_status | 58 | 58 |
| inconsistent | 0 | 1 (wcp-67cb71cd0c38, status 403) |
| error | 4 | 4 |
| worst-case set | 2,190 | 8,908 |
| timeouts | 3 (wcp-8aa4b0b85a6f 2043.5 ms, wcp-b6414928592d 2010.1 ms, wcp-ce387745a393 2011.9 ms — all within budget+500 ms) | 0 |
| limit (413) | 32 | 32 (same ids) |
| overload | 0 | 0 |

- The 4 errors: 3 x ConnectionResetError (wcp-1140885081e1, f83f7556fc66,
  908ef72be103 — all three are also 413-limit ids: the engine answers 413
  and closes while the runner is still streaming the large body) and
  wcp-6b0bf5e43122 (known non-latin-1 header sample, documented step-13).
- Policy-clear subset (tools/policy_clear.py, 17,022 samples): body-less
  n=14,279 blocked 411 (PL1) / 4,131 (PL2); body-bearing n=2,743 blocked
  432 (PL1) / 1,838 (PL2). Against the committed step-13 connector
  aggregates (410/4,130 body-less; 441/1,848 body-bearing): engine +1/-9/+1/-10.
- **Per-id rule-32 comparison and rule-39 classes: NOT COMPUTED.** The
  step-13 connector per-id outcome files live in gitignored out/ on the
  unreachable lab host and docker is unavailable here. Only aggregate
  comparison is possible. Zero UNEXPLAINED is therefore UNPROVEN, not
  shown.
- Harness fix found by T4 (rule 40, failing test first): crs_audit's
  str.splitlines() split valid audit lines on raw U+0085/U+2028/U+2029
  inside JSON body strings (191/203 lines) and refused the capture; fixed
  to newline-only splitting (regression test in tests/test_crs_audit.py).

## Decision 0004 status

STAYS PROVISIONAL. Two of the three step-17 conditions are now met (C4
measured and holds; method allow-list gap closed), but the third ("T4 has
zero UNEXPLAINED") is UNPROVEN — the per-id comparison could not be run on
this host. See docs/decisions/0004-engine-core.md.

## Test suites (current host)

- `go test -buildvcs=false -count=1 ./...` in engine/ with
  KORTEX_TEST_WCP_BODY set (rebuilt from the frozen manifest, 481,798
  bytes): **23/23 PASS, 0 skip, 0 fail** (E1-E9, E10 PL1/PL2, E11-E15,
  E16-E21), ok 54.3 s.
- `pytest tests/ -q`: **108 passed, 3 skipped** in 13.9 s (the 3 skips are
  run-artifact fixtures present only on the lab host; step-16 had 110
  passed there).

## Still open after step-17

- T4 per-id engine-vs-connector comparison (needs the lab host or docker).
- DESIGN difference: no nginx front proxy (smoke trav-01 cells).
- The engine's audit entries carry only phase-2 rule messages (911100,
  920350, 901160 never appear as audit messages) — measured DESIGN
  difference, documented in the T2 analysis.
- A1, A3, A4, A5, A6, A7 acceptance bars: not started.
