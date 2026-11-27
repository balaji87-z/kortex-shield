# Baseline v1.7 (step-22, 2026-11-27)

Host change (rule 43). Steps 12-21 ran on Ubuntu 26.04.1 (i5-13420H, go1.25.0).
The step-22 runs below ran on:

- macOS 27.0 (26A425), Darwin 27.0.0 arm64, Apple M6, 12 cores
- go1.27.4 darwin/arm64, Python 3.15.2 (pytest 9.2.0)
- Docker: none on the host until this step; added as Colima 0.10.3 + Lima
  2.3.0 (VM type vz, 8 cpus, 8 GB, Ubuntu 24.04.4, kernel 6.8.0-117,
  linux/arm64), Docker client 29.10.1 / server 29.5.2, Compose 5.8.1
- Images used: `python:3.12-alpine@sha256:c5ba3deef00c7758561a0f03c26f44f10589263d40e732b8748e0d1f38f6dd89`
  (T2 container), `ghcr.io/coreruleset/coraza-crs:4.25.2-nginx-lts@sha256:bfbfe70b4445c1ef1dc389c2de12cfdb194c9616746c33dc8a7131461c28f4a6`
  (connector; same index digest as before, now its linux/arm64 variant)
- Engine: coraza v3.8.1 + CRS 4.25.2 (engine/RULES.sha256 unchanged), built
  from 50e21a3; darwin/arm64 binary sha256 3739a11b...adb9, linux/arm64
  binary sha256 185014ed...f75c. Engine code is unchanged by this baseline.

Rule 29 was re-proven on this host: every run's `/__kortex/config` output is
in its log (docs/logs/step22-*.txt), and the connector runs print the levels
and the ruleset version from inside the container.

## Harness finding that changes how earlier numbers are read

**A numeric-IP Host header adds 3 points to every request (PROVEN).** The
runner takes the Host header from its base URL. The step-21 and first
step-22 run scripts replayed against `http://127.0.0.1:PORT`, so CRS 920350
("Host header is a numeric IP address", warning, +3) matched every request,
and any request with one more warning-level match crossed the threshold of 5.
Experiment (docs/logs/step22-numeric-host.txt, tools/step22_numeric_host_diff.py):
same engine binary, same manifests, only the base URL changed to
`http://localhost:PORT`:

| dataset, PL2, in-process | numeric Host | localhost | earlier step (localhost) |
|---|---|---|---|
| benign-wcp-v1, n=10,000 | 4,590 blocked | 4,438 | 4,436 (step 19) |
| benign-wcp-v0, n=20,000 | 9,160 blocked | 8,875 | 8,871 (step 18) |

The 152 and 285 ids blocked only with the numeric Host log a single rule:
942430 (136 and 249) or 920230 (16 and 36). No id is blocked only in the
clean run. At PL1 the block counts are the same with either Host (2,193 and
1,091). Consequences:

- Every step-22 number below comes from the `localhost` runs.
- Step-21 T3 (parity) and T4 (big bodies) used the numeric Host. Their
  parity conclusions compare like with like and stand; the T4 PL2 block
  count 287/402 carries one artifact block (wcp-43ad8735b4fe: 403 then,
  200 now); PL1 207/402 is unaffected.
- The other suggested cause, the coraza v3.7.0 -> v3.8.1 bump, was tested
  and ruled out: a scratch build with only go.mod changed to v3.7.0 gives
  the identical block set to v3.8.1 on benign-wcp-v1 PL2 (4,438 each, 0 ids
  differ; DIAGNOSTIC, docs/logs/step22-t3-DIAGNOSTIC.txt).
- The 2 (v1) and 4 (v0) ids blocked now but not in the earlier steps: 5 were
  503 timeouts on the slower host and are 403 here; 1 is wcp-62cd1bd36bf7,
  the duplicate-name sample of the step-19 flip defect (404 pass then, 403
  now). Cause of these 6: HYPOTHESIS (faster host; flip fix), not tested.

## T3: in-process vs worker parity on the wcp datasets

docs/logs/step22-t3-parity.txt, docs/logs/runs/s22-t3-parity/ (8 runs; one
engine process per run, runner --workers 1, budget 2 s). Worker mode proven
active per run (`worker_mode: true`, pool 4) and inactive in the others.

| dataset | PL | status diffs | worst-case set diffs | rule-id set diffs |
|---|---|---|---|---|
| benign-wcp-v0 (20,000) | 1 | 0 | 0 | 0 |
| benign-wcp-v0 (20,000) | 2 | 0 | 0 | 2 ids |
| benign-wcp-v1 (10,000) | 1 | 0 | 0 | 0 |
| benign-wcp-v1 (10,000) | 2 | 0 | 0 | 1 id |

Quantities compared (rule 32): status per id; the worst-case set (blocked +
deny_status + inconsistent + error), now with deny_status and inconsistent
MEASURED because every run has an outcomes.jsonl; and the logged rule-id set
per id. The 3 rule-id-set differences (wcp-7b0477d1157b, wcp-f754e70f73bd,
wcp-bc05c8d4eb28; rule 942130 on one side only, same 403 status) are
classified UNEXPLAINED-as-to-mechanism but shown NOT to be a mode
difference: replaying two such ids 200 times per mode gives 6 distinct
rule-id sets for one id and 2 for the other inside EACH mode (DIAGNOSTIC,
docs/logs/step22-t3-DIAGNOSTIC.txt), always with the same status. The rules
that come and go are 941340, 942120, 942210 and 942130.

False-positive rates on benign-labelled external traffic (rule 21 headline =
worst case; both modes identical; every block is a potential false positive):

| dataset | PL | blocked | deny_status | inconsistent | error | best case | worst case |
|---|---|---|---|---|---|---|---|
| benign-wcp-v0 | 1 | 2,193 | 58 | 0 | 1 | 2,193/20,000 = 10.96% | 2,252/20,000 = 11.26% |
| benign-wcp-v0 | 2 | 8,875 | 58 | 1 | 1 | 8,875/20,000 = 44.38% | 8,935/20,000 = 44.67% |
| benign-wcp-v1 | 1 | 1,091 | 25 | 0 | 0 | 1,091/10,000 = 10.91% | 1,116/10,000 = 11.16% |
| benign-wcp-v1 | 2 | 4,438 | 25 | 0 | 0 | 4,438/10,000 = 44.38% | 4,463/10,000 = 44.63% |

Best case = errors, deny_status and inconsistent not flagged; worst case =
all flagged; the denominator is every sample. The error is wcp-6b0bf5e43122
(no status in either mode); the inconsistent id is wcp-67cb71cd0c38. The
engine scope and settings were chosen in earlier steps using benign-wcp-v0,
so v0 is in-sample for those choices; v1 was unseen for them (rule 45).

Rule 18/24 list (rule ids in 20% or more of a run's audit entries): PL1 v0
932370 (466 of 2,251); PL1 v1 none; PL2 931130, 942430, 942200, 942370,
942340, 942330, 932200 (v0: 5,854 / 4,994 / 4,275 / 3,245 / 3,091 / 1,919 /
1,836 of 8,934). These are PL2 detection rules matching third-party page
and telemetry content, as in v1.3; none is a harness artifact now that
920350 is gone.

## T4: big-body audited re-run (402 benign wcp samples over 16 KB)

docs/logs/step22-t4-bigbodies-audit.txt, docs/logs/runs/s22-t4-bigbodies-audit/
(in-process, budget 120 s, load 1.2-1.9). The set was selected by body size,
so these are counts, not traffic rates.

| | PL1 | PL2 |
|---|---|---|
| status 403 / 400 / 413 / 200 | 207 / 49 / 49 / 97 | 286 / 49 / 49 / 18 |
| best case (blocked) | 207/402 | 286/402 |
| worst case (blocked + deny_status) | 256/402 | 335/402 |
| elapsed p50 / p95 / p99 / max (ms) | 111.5 / 491.5 / 597.5 / 695.4 | 217.1 / 911.5 / 1,109.5 / 1,240.3 |
| over 2,000 ms | 0/402 | 0/402 |

- The 49 status-400 answers are now attributed by rule id: 200007 (1,000 or
  more arguments after JSON flattening) on 47, 200002 (body not parseable)
  on 2. This replaces the earlier "valid JSON, other cause: 42" class.
- The 49 status-413 answers are the 42 bodies in the 128K-and-over band plus
  7 listed in the 64K-128K band: the index records body size in characters,
  and those 7 are 143,067 to 166,130 bytes as UTF-8, over the 131,072-byte
  inspection limit.
- Size bands, PL1: under 64K 183/318 blocked (top rules 921150, 942100,
  920270, 932130, 941100); 64K-128K 24/42. PL2: 260/318 (942430, 942200,
  942370, 942330, 932200) and 26/42.
- Per-id status against the step-21 run (worker mode, other host): PL1 0 of
  402 differ, PL2 1 of 402 (the numeric-Host artifact above).
- Timing differs from step 21 (PL2 p99 1,992 ms and 4/402 over 2 s there):
  this host is faster. No timing claim carries across hosts.
- A first run of this task was INVALID for timing (a Go build ran during
  it); its statuses and rule ids were identical per id and it is not used.

## T5: padding matrix extension and encoding probes

Engine: docs/logs/step22-t5.txt, docs/logs/runs/s22-t5/.
Connector: docs/logs/step22-t5-connector.txt, docs/logs/runs/s22-t5-connector/.

Padding matrix extension, k = 8, 32 and 120,000 bytes of benign padding,
XSS and SQLi canary before/after the padding, 3 content types, 3 reps = 108
requests per level and side:

| side | PL1 | PL2 |
|---|---|---|
| engine | 108/108 status 403 | 107/108 status 403, 1 x 503 timeout |
| connector | 108/108 status 403 | 108/108 status 403 |

- Zero status-200 cells on either side: no padding evasion.
- Engine: every 403 logs a 941 or 942 rule, so the canary itself was seen
  (rule 47). Connector: the same for the json and urlencoded cells and the
  XSS text/plain cells; its 18 SQLi text/plain cells at PL1 are blocked by
  the content-type policy rule 920420 alone (DESIGN C4, as in v1.6), and at
  PL2 they log 920420 plus 942 rules.
- The one engine 503 is t5a-pl2-k120000-xss-after-plain-r2: 2,005 ms, the
  2 s budget, fail-closed. The 120,000-byte text/plain cells take 1,362 to
  2,005 ms at PL2 (median 1,564) and 661 to 891 ms at PL1 on this host;
  the run started at host load 6.4 (other users' jobs on a shared machine).
  Two earlier runs of the same matrix on a quieter host gave 108/108.

Encoding probes, PL1, 36 requests per side: gzip + header (A), deflate +
header (B), gzip without header (C), raw control (D), chunked with the
payload split across a chunk boundary at two offsets (E).

| cell | engine | connector |
|---|---|---|
| A, B (12) | 8 x 403, 4 x 400 (json) | 8 x 403, 4 x 400 (json) |
| C (6) | 4 x 403, 2 x 400 (json) | 4 x 403, 2 x 400 (json) |
| D control (6) | 6 x 403 on 941/942 | 6 x 403 (5 on 941/942, SQLi text/plain on 920420 only) |
| E chunked (12) | 12 x 403 on 941/942 | 12 x 403 (10 on 941/942, 2 SQLi text/plain on 920420 only) |

- Zero status-200 cells: no evasion candidate in the preregistered cells.
- Chunked bodies are reassembled and the split payload is detected.
- **Neither side decodes Content-Encoding.** In A-C no 941/942 rule ever
  matches; the blocks come from 920270 (NUL byte in the compressed bytes),
  921150, the JSON validity rule (400) and, on the connector, 920420/920450.
  The engine's audit records a body whose size is that of the compressed
  bytes, not of the raw control.
- DIAGNOSTIC cells (rule 34): a benign body sent uncompressed but WITH a
  `Content-Encoding: gzip` header is blocked 403 on both sides (cell I), and
  passes on the engine without the header (cell J; the connector blocks J on
  920420, its text/plain policy). The engine's block page lists 920450
  (restricted header). So a request carrying Content-Encoding is refused by
  header policy at PL1 whatever its bytes are — PROVEN for the header-only
  case by I vs J on the engine.
- NOT MEASURED: a compressed canary whose bytes contain no NUL, CR or LF
  (cell G). No such zlib stream was found for these two canaries, so the
  claim "a compressed attack body is always blocked" rests on cell I
  (header policy), not on a direct test. If 920450 were ever relaxed for
  Content-Encoding, compressed bodies would be forwarded uninspected.
- Audit-logging difference, UNEXPLAINED (rule 39), decisions unaffected:
  the connector's audit log carries a 920450 message on all 15 cells with a
  Content-Encoding header; the engine's audit log carries none, although
  its block page lists 920450 as matched. The same holds for 920350 in the
  numeric-Host runs. Engine block attributions built from audit messages
  therefore under-report these two rules ("no rule message" blocks).

## T2: worker-mode attack cells, re-run after the per-lane clamp

First recording (2026-11-22, Ubuntu host, before the clamp):
docs/logs/runs/s22-t2-cells/. Re-run (this host, Linux container, after the
clamp 5dfdd19): docs/logs/runs/s22-t2-cells-v2/, logs
docs/logs/step22-t2-cells-v2-all.txt and -rest.txt, summary of both in
docs/logs/step22-t2-cells-summary.txt. One engine process per cell, worker
mode, pool 3 + 1 spare, budget 2 s, KORTEX_CLIENT_MAX_INFLIGHT=2 (effective
per-client caps from /__kortex/config: small 2, large 1), penalty 10 s,
300 s attack with the deterministic hold hook, 1 benign POST and 1 benign
GET per second from a separate address.

**The first recording's benign counts at PL2 were a harness artifact
(PROVEN, docs/logs/step22-t2-benign-shape-DIAGNOSTIC.txt).** Its benign
probe (numeric-IP Host, no User-Agent) gets 200 at PL1 but 403 at PL2 from
an idle engine with no attack (920350 + 920320); the corrected probe (Host
localhost, browser User-Agent) gets 200 at both levels. The "0/301" and
"0/300" of the two PL2 small cells and their "recovery=None" therefore say
nothing about starvation. Every re-run cell sends the probe once before
the attack (200/200 in all six) and records the benign statuses.

| cell (re-run) | benign POST 200 | benign GET 200 | kills | overloads | min pool | CPU s | recovery |
|---|---|---|---|---|---|---|---|
| large-one, PL1 | 301/301 | 301/301 | 24 | 276 | 3 | 2.7 | 8.2 s |
| large-eight, PL1 | 301/301 | 301/301 | 172 | 2,228 | 2 | 4.9 | 8.2 s |
| small-one, PL2 | 300/300 | 300/300 | 24 | 276 | 3 | 3.2 | 4.1 s |
| small-eight, PL2 | 291/300 (9 x 503) | 300/300 | 192 | 2,217 | 0 | 5.4 | 5.1 s |
| mixed-one, PL1 | 301/301 | 301/301 | 75 | 2,298,728 | 1 | 576.2 | 1.0 s |
| mixed-eight, PL1 | 294/301 (7 x 503) | 301/301 | 200 | 1,761,481 | 0 | 561.6 | 2.5 s |
| kill storm, 120 s | (no benign traffic) | | 80 (0.67/s) | 794,983 | 0 | 214.8 | |

- One attacker address never starves benign traffic: 0 benign refusals in
  large-one, small-one and mixed-one.
- Eight attacker addresses cost 9/300 (small) and 7/301 (mixed) benign POSTs,
  each a 503 after about 2,000 ms (benign POST p99 2,002.6 and 2,002.1 ms):
  the pool reached 0 and the benign request waited out its own budget.
  Benign GETs (no body) were never refused. Counts of an effect on a
  directed attack, not a traffic rate (rule 35).
- The mixed cells and the kill storm burn CPU on refusals: the unpaced
  attackers received 2.3 million and 1.8 million 503s in 300 s (576 and 562
  CPU-seconds on 8 cpus), the storm 795,236 in 120 s. Refusing is cheap per
  request but not rate-limited.
- Against the first recording: mixed-one went from 105/301 to 301/301 and
  mixed-eight from 275/300 to 294/301. The first mixed-one cell recorded
  30,092 attacker connection errors next to its 503s and benign POSTs
  failing in 0.2 ms; its cause was not recorded. Whether the improvement
  comes from the clamp, the host or the probe is NOT separated (the clamp,
  the host and the probe all changed between the two recordings).
- Shared-address penalty (design risk (b)) demonstrated in the container
  (docs/logs/runs/s22-t2-penalty-demo/demo.txt): innocent POST 200 before;
  after one budget kill from 127.0.0.2 an innocent POST from the same
  address gets 503, from 127.0.0.5 gets 200, and from 127.0.0.2 again after
  the 3 s penalty gets 200.
- Host caveat: the Mac is shared with other users' jobs. In-VM load was 0.0
  at the start of the first four cells and 4.5 to 9.1 during the mixed cells
  (the attack itself). Host-side load was not controlled.

## T1 and T6: hygiene and documentation

- Rules 51-52 added; pre-push scan (tools/prepush_scan.sh, 43 tests) gates
  staged content on credential shapes, request-body dumps and a 5 MB size
  limit. The six wcp request-body files were removed from the tree and
  replaced by body-less indexes. From this step on, raw engine audit logs
  and parsed audit.jsonl of wcp runs stay under gitignored out/; the durable
  copy of a run is responses.jsonl, outcomes.jsonl, run.json and a body-less
  audit index (ids, sizes, content types, status, rule ids).
- History still holds the removed files and 23 files with credential shapes
  (docs/logs/step22-history-cleanup-list.txt, 27 paths). Not rewritten:
  instructor decision pending.
- docs/logs/wcp-baseline-breakdown.json (7.4 MB) is over the 5 MB limit and
  its gzip fails the scan (email=72, jwt=4 shapes). Left as is: instructor
  decision pending.

## Standing notes carried from v1.6

- In-process mode remains the default; worker mode is opt-in.
- modsec-connector comparison not re-run since step-13.
- docs/logs/step22-t4-fp-decomposition.txt (FP decomposition from the
  step-18/19 runs) still says "connector v0/v1 PL2: NOT MEASURED".
