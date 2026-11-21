# Baseline v1.3 (step-18, 2026-11-21)

Dated notes on top of v1.2 (docs/baseline-v1.2.md, kept unchanged, including
its unproven WCP per-id agreement and the latency HYPOTHESIS). Step-18 made
the run evidence durable (rule 42), fixed the 413 connection-reset behaviour
test-first, closed the raw-carrier body-parsing fidelity gap test-first with
a REQUEST_BODY target update, re-ran all datasets pre/post, and found and
counted a new engine non-determinism. Host facts (rule 43): Ubuntu 26.04.1
LTS, kernel 7.0.0-44-generic, go1.25.0 linux/amd64, Python 3.14.4 (.venv),
**no docker and no passwordless sudo** — the connector reference runs
(T2) stay BLOCKED on this host.

## T1: durable evidence (rule 42)

- tools/preserve_run.sh copies outcomes.jsonl, audit.jsonl, responses.jsonl
  and run.json of a run into docs/logs/runs/<run-name>/ (gzip when >5 MB);
  appended to every runner script (step-17 T1/T2/T4, both parity scripts,
  step-18 T3/T4 scripts).
- Back-filled 6 step-17 run dirs; 24 files under docs/logs/runs/ at the
  end of T1. The s17-t2 run dirs were missing audit.jsonl/outcomes.jsonl;
  they were regenerated from the preserved raw engine-audit logs and the
  counts match the committed analysis (124/774 browse, 7/12 smoke).
- Lost artifacts: the step-09..16 runs' out/ directories live only on the
  unreachable lab host (/home/Kavinharish/kortexshield); everything the
  comparisons below need from step-17 is now under docs/logs/runs/.

## T2: connector-side comparison — BLOCKED

No docker, no docker.sock, no podman/nerdctl, no passwordless sudo on this
host (verified in T1). Per the instructor's fallback decision the
connector per-id comparison is NOT computed and decision 0004 stays
provisional (see below). Nothing was faked: no aggregate was promoted to a
parity claim.

## T3: 413 no longer resets the connection (rule 40: E22 failing first)

- E22 (engine/step18_test.go, commit 13e0b13): a raw TCP client streaming a
  300 KB body against the 131,072-byte inspected limit got a connection
  reset after 184 bytes — the 413 response was unreadable and the runner
  recorded ConnectionResetError instead of 413.
- Fix (commit e198ead): the engine now DRAINS the request body (bounded by
  MaxBodyBytes, 5 s drain timeout) before writing the 413/503 response on
  the limit/overload/timeout paths, and flushes it. All 11 call sites
  updated.
- Replay of the three step-17 reset ids (wcp-1140885081e1,
  wcp-f83f7556fc66, wcp-908ef72be103): all now status=413 with body
  `413 kortex-decision=limit`, 0 errors (tools/run_step18_t3_replay.sh,
  docs/logs/step18-t3-replay.txt). In the T4 v2 WCP runs the same three ids
  are 413 / waf_pass, 0 errors.

## T4: raw-carrier body fidelity — REQUEST_BODY target update

- E23/E24 written failing first (commit 1964793): the step-17 split-broken
  payloads (sqli-6e47f23b `admin" or "1"="1"#`, command-injection-dc2932d5
  `& dir C:\Documents and Settings\*`, command-injection-ecb32a80
  `; type %SYSTEMROOT%\repair\SAM`) are NOT detected when carried in
  text/plain / octet-stream / unknown-ct bodies, because the URLENCODED
  fallback's '&'/'=' split destroys them. E25 guards the urlencoded
  behaviour (unchanged).
- Fix (commit 3f3f440): engine/bodytargets.go generates
  `SecRuleUpdateTargetById <id> "REQUEST_BODY"` for CRS rules whose target
  list has an ARGS-family variable, does not already have REQUEST_BODY, is
  not counted/size-based, is not phase:1 and is not chain-inner. Targets
  are only ADDED — no CRS file is edited, no rule excluded (rules 5/17).
  REQUEST_BODY is populated only by the URLENCODED and RAW processors, so
  JSON/XML/multipart carriers are unchanged by construction. The update
  list is appended AFTER the CRS Include; the count is printed at startup
  and at /__kortex/config (rule 29 proof per run).
- Scope fix after the first re-run (commit 02bac43, E26 failing first):
  REQUEST-921 was removed from the update list (173 -> 166 rules). 921150
  (CR/LF in argument NAMES) matched REQUEST_BODY on 126 of the 176 first-
  pass PL1 gained ids because raw bodies legitimately contain newlines
  (ND-JSON telemetry). Rationale documented in docs/engine-design.md
  BEFORE the v2 re-runs (rules 39/41).
- Anomaly-doubling risk was documented before the runs; no flip was
  observed (single-rule detections unchanged; CRS threshold 5 = CRITICAL).

### Results (v2 runs, 921 excluded; pre = commit 1964793, same host/config/UA)

Pre/post per dataset (blocked counts; worst-case adds errors to the
denominator, rule 20/21):

| dataset | PL1 pre -> post | PL2 pre -> post |
|---|---|---|
| attacks-ct-v0 (IN-SAMPLE, counts only, rule 35) | 286 -> 292 (+6/0) | 310 -> 313 (+3/0) |
| attacks-v0 (IN-SAMPLE, counts only) | 954 -> 954 (0/0) | 1024 -> 1024 (0/0) |
| benign-browse-v1 (HELD-OUT) | 124 -> 124 (0/0) | 124 -> 124 (0/0) |
| benign-hard-v0 (HELD-OUT) | 22 -> 22 (0/0) | 78 -> 78 (0/0) |
| benign-wcp-v0 (HELD-OUT, n=20000) | 2128 -> 2191 | 8845 -> 8871 |

- attacks-ct gains are exactly the split-broken payload x carrier ids
  (E23/E24 payloads): +6 at PL1, +3 at PL2, 0 lost.
- benign-wcp-v0 flip-corrected: PL1 +61 real gains (3 apparent gains were
  pre-run flip artifacts, see below), 0 real losses (1 apparent loss was a
  503 timeout); PL2 +29 real gains (1 apparent gain was a pre-run flip),
  real losses 0 (3 apparent losses were 503 timeouts, 1 was a post-run
  flip). Worst-case (errors flagged): PL1 2190 -> 2250, PL2 8908 -> 8931.
- Real-gain rule distribution (excl. 949110): PL1 932370 x32, 933120 x10,
  932235 x10, 932125 x8, 932130 x5, 942550 x4, 933180 x2, 933210 x1;
  PL2 942430 x18, 942120 x11, 932240 x10, 942440 x3, 932200 x1.
  921150 contributes ZERO gains after the scope fix.
- Timeouts: pre 3 (PL1) / 0 (PL2); post 3 / 3 — the added body targets
  push three near-budget samples over the 2 s budget at PL2 (fail-closed,
  503). Reported as counts (rule 35; the affected ids are listed in
  docs/logs/step18-t4-analysis.txt).
- COST of the fix, PROVEN by A/B (docs/logs/step18-t4-abandoned-cost.txt):
  the worst-case abandoned body-processing call on the 481,798-byte
  text/plain fixture (budget 200 ms, uncontended, same host) takes
  62,658 ms on the PRE engine and 389,118 ms on the POST engine — 6.2x.
  Each of the 166 rules now also runs its operator against the full raw
  body. The in-flight cap still bounds concurrency (8), but the per-call
  CPU cost rose ~6x, and the E20 acceptance test (120 s deadline for the
  abandoned call to finish) passes on PRE and FAILS on POST — the failure
  is the measured consequence of the fidelity fix, reported here instead
  of weakening the test (the trade-off is a question for the instructor).
- Rule-18/24 confound check: v2 PL2 has 931130 in 65.5%, 942430 in 55.9%,
  942200 in 47.8% of audit entries (PL1: 932370 20.7%). The PRE runs show
  the same dominance (931130 57%, 942430 54%...), so this is a property of
  the WCP corpus under this config (CONFIG-MISMATCH signal, rule 24), not
  an artifact introduced by the change.
- The WCP gains are detections on raw benign telemetry bodies (label
  meaning per rule 11: "attack" would mean listed-in-source; these are
  benign-labelled samples now blocked). Whether they are false positives
  depends on ground truth we do not have; they are reported as new blocks
  by id and rule, not as a rate (rule 35: the set was chosen because of an
  observed difference).

### Engine non-determinism found by T4 (UNEXPLAINED, counted)

A request that should be blocked is occasionally passed: in the v2 PL2 WCP
run wcp-62cd1bd36bf7 (GET, query-based 942370+942430 match) passed where
the pre run, the v1 run and a 3/3 replay of the same binary block it. A
tight alternating replay reproduces it at 7/20 rounds (v2 binary); a
variant with tx.Close() disabled still flips (5/20) — the transaction pool
is not the vector; the PRE engine flips too (3/20) — the behaviour
PREDATES step-18 (PROVEN by replay); no GC correlation. Raw evidence:
docs/logs/step18-t4-flip-replay.txt. Real-run frequency so far: 3 pre-run
flips / 2128 would-block (PL1), 1 / 8845 (PL2), 1 post-run flip / 8871.
Mechanism HYPOTHESIS (unproven): coraza-internal shared state; the
transformation cache key uses a string pointer (unsafe.StringData,
coraza v3.7.0 rulegroup.go:290). Not fixed in this step (rule 1); raised
as a question for the instructor.

## Decision 0004 status

STAYS PROVISIONAL. The T2 condition (per-id engine-vs-connector
comparison) remains unproven — BLOCKED on host capability, unchanged from
step-17. The engine-side evidence strengthened (413 fix, body fidelity,
durable evidence), but the reversal-trigger review needs the per-id
comparison.

## Test suites (current host)

- go test and pytest results: see reports/step-18.md for the exact
  commands and outputs (E20 fails with the fixture for the PROVEN cost
  reason above; E16 is load-flaky on this desktop VM).

## Still open after step-18

- T2 per-id connector comparison (needs docker or the lab host).
- The engine non-determinism (UNEXPLAINED) — root cause inside coraza
  interaction, needs a dedicated step.
- DESIGN difference: no nginx front proxy (smoke trav-01 cells).
- The engine's audit entries carry only phase-2 rule messages (step-17
  DESIGN note, unchanged).
- A1, A3, A4, A5, A6, A7 acceptance bars: not started.
