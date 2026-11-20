# Step-17 report

- Summary: C4 measured on the engine and it HOLDS (per-carrier table
  reproduced exactly on the current host; rule 41 satisfied). Method
  allow-list closed (911100 via tx.allowed_methods, outcome sets unchanged
  124/774). In-flight body-processing cap measured: Phase B 12x503
  overload in 47-282 ms + 8x503 timeout, all 8 abandoned-finish events
  captured. WCP through the engine: PL1 2,128 blocked / PL2 8,845, 0
  overload, per-id connector comparison NOT COMPUTED (lab host gone, no
  docker here) — decision 0004 stays provisional. Harness bug fixed
  test-first (crs_audit splitlines). ENVIRONMENT: the step-09..16 lab host
  (/home/Kavinharish/kortexshield) was unreachable; all engine-side work
  re-done on the current host (go 1.25.0, no docker, no sudo).

## Task table

| task | status | evidence |
|---|---|---|
| Rule 41 appended to AGENTS.md | done | commit fd33e81 |
| T1 C4 on the engine (analysis of existing runs, then replays) | done | committed analysis docs/logs/step17-t1-c4.txt (460eed7, lab runs); replay on this host tools/run_step17_t1_engine.sh + tools/analyze_step17_t1.py -> docs/logs/step17-t1-engine-runs.txt, step17-t1-c4-replay.txt (commit fd33e81) |
| T2 method allow-list | done | failing E18 460eed7, impl 559d9b6, lab re-run step17-t2-runs-lab.txt + analysis (360dff9), this-host re-run docs/logs/step17-t2-runs.txt (769a9d6) |
| T3 bound abandoned work | done | failing E19-E21 460eed7, impl 559d9b6, docs BEFORE the run (360dff9), measurement completed on this host docs/logs/step17-t3-runs.txt (32239ec; lab partials kept as -lab.txt) |
| T4 WCP through the engine | partial | engine runs + analysis done (4a2064c); per-id rule-32/39 comparison NOT COMPUTED — reference outcomes on the unreachable lab host, docker unavailable here |
| T5 docs | done | docs/baseline-v1.2.md, engine-design.md, engine-evidence.md, acceptance.md, decisions/0004 (stays provisional), README (3e19d59) |
| go test + pytest reported; this report | done | below; commits fd33e81..final |

## Key results (numbers in the body, rule 31)

### T1 — C4 on the engine: HOLDS (measured, rule 41)

Per-carrier blocked/40 on the engine, default config (replay on this host;
identical to the committed lab analysis):

| carrier | PL1 blocked (detection/policy-only) | PL2 blocked (detection/policy-only) |
|---|---|---|
| query | 36 (36/0) | 39 (39/0) |
| urlencoded | 36 (36/0) | 39 (39/0) |
| json | 36 (36/0) | 39 (39/0) |
| multipart | 36 (36/0) | 39 (39/0) |
| text-plain | 34 (34/0) | 38 (38/0) |
| octet-stream | 34 (34/0) | 38 (38/0) |
| unknown-ct | 34 (34/0) | 38 (38/0) |
| no-ct | 40 (34/6) | 40 (39/1) |

- Every blocked cell except no-ct's 6+1 920640-only blocks has a detection
  rule. The engine has NO content-type allow-list (900220 sets the allowed
  list to the request's own type — proven from engine/config.go and the
  rule-29 config lines), so detection blocks on the raw carriers cannot
  depend on an allow-list: **C4 holds on the engine** (criterion measured,
  both PLs). No carrier fails.
- Payloads detected under one carrier and not another (engine, with both
  sides' rule IDs): PL1 command-injection-dc2932d5 (932125+932380 on
  query/urlencoded/json/multipart; no rules, waf_pass on
  text-plain/octet-stream/unknown-ct) and sqli-6e47f23b (942100 vs none);
  PL2 command-injection-ecb32a80 (932240 vs none). The 18 PL1 / 6 PL2
  connector-blocked engine-passed attacks-ct samples are the connector's
  920420 policy blocks (engine outcome waf_pass, no engine rules on any).
- PROVEN (raw engine audit entries, one per carrier, step17-t1-c4.txt +
  step17-t1-audit-passed.txt): the engine's transaction receives and
  parses the body for text/plain, octet-stream and unknown-ct;
  REQBODY_PROCESSOR=URLENCODED (CRS 901340 force + Coraza fallback);
  ARGS_POST/ARGS_NAMES populated by the '&'-split; REQUEST_BODY carries
  the raw body. The 2/1 missed payloads are missed BECAUSE of that split
  (e.g. sqli-6e47f23b's body splits into name 'admin" or "1"' + value
  '"1"#'; 942100 scans single variables) — a parsing-fidelity caveat, not
  allow-list dependence.

### T2 — method allow-list

- E18 (failing first): PUT/DELETE/PATCH -> 403 kortex-decision=block with
  911100 under the default policy; pass with KORTEX_ALLOWED_METHODS
  widened. Implementation: config 900200 sets tx.allowed_methods;
  printable at /__kortex/config (measured this host:
  `"allowed_methods":"GET HEAD POST OPTIONS","max_inflight_body":8`).
- Re-run on this host (docs/logs/step17-t2-runs.txt): smoke PL1 7/12
  blocked; benign-browse-v1 PL1 124/774 blocked, 0 errors — same counts as
  the lab re-run, which proved per-id equality with s16-t2 (124=124, same
  ids; connector ref 184, the 60 connector-only ids are the known
  DESIGN-C4 text/plain POSTs).
- CORRECTION (PROVEN, live probes + audits on both engines): 911100 DOES
  fire on the engine and scores 5 exactly like the connector; the engine's
  audit entries only ever carry phase-2 messages, so 911100 (phase 1)
  never appears among the engine's audit MESSAGES. The step-16 "911100
  never fires on the engine" note is wrong; the audit-message-emission
  difference is the real (documented) DESIGN difference.

### T3 — abandoned work bounded by the in-flight cap

E19-E21 failing first, then implemented: KORTEX_MAX_INFLIGHT_BODY
(default 8); over the cap a body-bearing request gets
503 kortex-decision=overload immediately + an `overload` event; body-less
requests need no slot. Docs written BEFORE the measurement run
(docs/engine-design.md, docs/block-discriminator.md, commit 360dff9).

Measurement on this host (docs/logs/step17-t3-runs.txt; the lab run was
twice killed by platform restarts — partials kept as -lab.txt):

- Phase A (cap=32, 20 concurrent 481,798-byte bodies): 20/20 answered 503
  timeout at 2.04-2.31 s. Process CPU (utime+stime): 2.86 s at start,
  14.92 s at the 2 s deadline, 344.41 s at +60 s. Benign latency: 144 ms
  before, 447 ms at deadline, 859 ms at +8 s, 468 ms at +59 s (load
  average 9-21; this VM is much slower/noisier than the lab).
- Phase A2 (cap=32, 4 copies): 4/4 abandoned-body-processing-finished
  events, elapsed_ms 136,815-137,351 (lab single-call cost was ~43-45 s;
  this host ~137 s under 4-way contention).
- Phase B (cap=8 default, 20 copies): **12 x 503 kortex-decision=overload
  in 0.047-0.282 s; 8 x 503 timeout at 2.02-2.11 s; 12 overload + 8
  timeout events; all 8 abandoned-finish events captured (elapsed_ms
  341,132-346,544, rule_id 949110 status 403)**; benign 18 ms before,
  183 ms during the overload window, 502 ms after recovery (load ~12).
- Does the cap remove the step-16 degradation (59.5 ms benign at +59 s
  with 20 pending)? What is PROVEN: the cap bounds concurrent background
  work to 8 (12 of 20 rejected in 47-282 ms instead of queueing into
  2 s timeouts, and only 8 finish events ever appear). What is NOT
  reproduced here: the lab's sub-60 ms benign tail — this host's benign
  probes stay at 180-500 ms under the burst in both Phase A (20
  goroutines) and Phase B (8 goroutines), so a same-host A-vs-B benign
  comparison cannot isolate the cap's latency benefit. HYPOTHESIS: with
  the cap, sustained overload accumulates at most 8 CPU-bound abandoned
  calls (bounded background CPU), which limits the degradation seen in
  step 16; PROVEN on this host only for the bounding itself, not for the
  latency tail.

### T4 — WCP through the engine (DIAGNOSTIC, counts of effects)

Engine runs on this host (frozen manifest sha c8ce11f2... proven in-run;
stub backend; same UA contract; rule-29 config proof per run):

| | PL1 | PL2 |
|---|---|---|
| samples | 20,000 | 20,000 |
| blocked (waf_block) | 2,128 | 8,845 |
| waf_deny_status | 58 | 58 |
| inconsistent | 0 | 1 (wcp-67cb71cd0c38, 403) |
| error | 4 | 4 |
| worst-case set | 2,190 | 8,908 |
| timeout decisions | 3 (wcp-8aa4b0b85a6f 2,043.5 ms; wcp-b6414928592d 2,010.1 ms; wcp-ce387745a393 2,011.9 ms) | 0 |
| limit decisions (413) | 32 | 32 (same ids) |
| overload decisions | 0 | 0 |

- No WCP request took longer than budget+500 ms (max response 2,043.5 ms).
- The 4 errors (same ids both PLs): 3 x ConnectionResetError
  (wcp-1140885081e1, wcp-f83f7556fc66, wcp-908ef72be103 — all three are
  also 413-limit ids: the engine answers 413 and closes the connection
  while the runner is still streaming the body) and wcp-6b0bf5e43122
  (known non-latin-1 header sample, documented step-13).
- Policy-clear subset (tools/policy_clear.py; 17,022 of 20,000): body-less
  n=14,279 -> engine blocked 411 (PL1) / 4,131 (PL2); body-bearing
  n=2,743 -> engine blocked 432 (PL1) / 1,838 (PL2). Committed step-13
  connector aggregates: 410 / 4,130 and 441 / 1,848 (docs/logs/
  step13-t5-parity.txt). Deltas: +1 / +1 / -9 / -10.
- **Blocked set, worst-case set and per-id rule-39 classes vs the
  connector: NOT COMPUTED.** The step-13 per-id outcome files
  (out/coraza-benign-wcp-v0-pl{1,2}-default) live in gitignored out/ on
  the unreachable lab host and docker cannot be installed here (no sudo).
  Only the aggregate comparison above exists. "Zero UNEXPLAINED" is
  therefore UNPROVEN for T4, not demonstrated.
- Confound check (rule 18): 949110 appears in 2,128/2,186 (PL1) and
  8,846/8,904 (PL2) audit entries — expected, the audit is RelevantOnly
  so the denominator is non-pass outcomes and 949110 is the block marker.
  931130 fires in 5,104/8,904 blocked entries at PL2 — a dataset property
  (WCP bodies contain SQLi-like strings at PL2), consistent with the
  step-13 PL2 behaviour, not a harness artifact.

### Harness fix found by T4 (rule 40)

crs_audit refused the engine audit captures: 191 (PL1) / 203 (PL2) lines
"unparseable". Root cause PROVEN: str.splitlines() also splits on
U+0085/U+2028/U+2029, which occur RAW inside JSON string values (recorded
WCP bodies); every such line parses fine when split on \n only (0 bad
lines). Failing regression test committed first
(tests/test_crs_audit.py::test_unicode_line_separator_inside_json_string_is_not_a_line_break),
then the fix (newline-only splitting). This is a harness bug, not an
engine bug; it would have falsely branded every engine capture corrupt.

### Test suites (current host, final state)

- `go test -buildvcs=false -count=1 -timeout 900s ./...` in engine/ with
  KORTEX_TEST_WCP_BODY set (fixture rebuilt from the frozen manifest,
  481,798 bytes, sha-verified build): **ok kortexshield/engine 54.300s,
  23/23 PASS, 0 FAIL, 0 SKIP** (E1-E9, E10 PL1/PL2, E11-E15, E16-E21).
- `.venv/bin/python -m pytest tests/ -q`: **108 passed, 3 skipped**
  in 13.94 s (skips: run-artifact fixtures that exist only on the lab
  host; step-16 reported 110 passed there).

## Raw evidence

- docs/logs/step17-t1-c4.txt + step17-t1-audit-{passed,per-carrier}.txt
  (lab analysis, committed 460eed7); step17-t1-engine-runs.txt +
  step17-t1-c4-replay.txt (this-host replay, fd33e81).
- docs/logs/step17-t2-runs-lab.txt (lab re-run + analysis) and
  step17-t2-runs.txt (this-host re-run, 769a9d6).
- docs/logs/step17-t3-runs-firstpass-lab.txt, step17-t3-runs-lab.txt
  (interrupted lab attempts), step17-t3-runs.txt (completed measurement,
  32239ec).
- docs/logs/step17-t4-runs.txt (engine runs, config proofs, manifest sha)
  and step17-t4-analysis.txt (4a2064c). Per-run artifacts under
  out/s17-t1-engine-*, out/s17-t4-engine-* (gitignored, paths stated here
  per rule 23).
- Frozen-dataset integrity: data/external/legitimate.zip sha256
  58faee18... (matches the fetch script); manifest rebuilt with the
  step-09 builder (git 5032ba7) reproduces MANIFEST.sha256 c8ce11f2...
  bit-exact. The CURRENT builder (post step-13 cookie canonicalization)
  produces a different manifest (8c6c20ed...) — that is a new version by
  rule 10 and was NOT used for any run reported here.

## Deviations from instructions

- The lab host (/home/Kavinharish/kortexshield) from the earlier step-17
  commits is gone. All runs were re-executed on the current host; the run
  scripts were made path-portable (repo-relative cd, $HOME/go/bin on
  PATH). The connector reference side could not be run anywhere (no
  docker, no sudo) — T4's per-id comparison is the only task item lost to
  this, and it is marked as such everywhere.
- The committed lab evidence files step17-t2-runs.txt and
  step17-t3-runs*.txt were renamed to -lab.txt (git mv) rather than
  overwritten, so the lab measurements stay in history alongside the
  this-host repeats.
- T3/T1/T2 evidence therefore mixes hosts: lab numbers (T1 original
  analysis, T2 per-id proof, step-16 references) and this-host replays
  are always labelled. Every this-host engine total matches its lab
  counterpart exactly (286/310 attacks-ct; 7/12 smoke; 124/774 browse-v1).
- The T3 script's `grep -c ... || echo 0` progress lines emit a cosmetic
  bash warning and printed "captured: 4" in Phase B while 8 event rows
  follow; the events themselves are the evidence (8 rows listed).
- tools/analyze_step17_t4.py was extended to print engine-side counts and
  an explicit REFERENCE MISSING notice instead of crashing when the
  step-13 reference files are absent.

## UNVERIFIED

- The HYPOTHESIS that the cap limits benign-latency degradation under
  sustained overload on a like-for-like host (see T3).
- Whether any of the 2,128/8,845 engine WCP blocks would differ per-id
  from the connector (T4 comparison not computed).
- The claim "the engine answers 413 and closes while the runner is still
  streaming" for the 3 ConnectionResetError ids is inferred from those ids
  also being limit ids, not from a packet capture.

## Questions for instructor

1. T4's per-id comparison needs either the lab host's out/ artifacts or a
   docker-capable host. Should step-18 re-provision the lab (the scripts
   are committed and path-portable), or is the aggregate comparison
   acceptable for decision 0004?
2. crs_audit's newline-only fix changes kortex_eval (rule 5). It is a
   strict bug fix with a regression test, but please confirm it is
   acceptable; the alternative was refusing every engine capture of
   bodies containing U+0085/U+2028/U+2029.
3. The 3 ConnectionResetError ids: should the engine keep the connection
   open long enough to deliver the 413 response body before closing
   (a small engine change, test-first), or is the early close acceptable
   documented behaviour?
4. The rebuilt-from-source benign-wcp-v0 manifest reproduces the frozen
   sha only with the step-09 builder; the current builder (with the
   step-13 cookie canonicalization) yields a different manifest. Confirm
   that "frozen v0 = step-09 builder output" is the intended reading of
   rule 10.
