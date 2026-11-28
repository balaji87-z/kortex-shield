# Engine design (step-15, updated step-16)

## What the engine is

A Go reverse proxy (engine/) wrapping Coraza v3.7.0 with CRS 4.25.2 as the
inspection core (decision 0004). The engine owns everything the connector
stack did not enforce deterministically in steps 12-14: request framing,
body size limits, and a per-request time budget.

## Components

- `listener.go` — the framing gate. Runs on the raw connection before any
  HTTP parser: rejects duplicate or conflicting Content-Length,
  Transfer-Encoding with Content-Length, and raw NUL in the request line
  with `400 kortex-decision=framing`. The engine answers `Connection: close`
  so every request is the first on its connection and is always gated.
- `proxy.go` — the request pipeline: Coraza phases 1-2, body size limits,
  time budget, forwarding to the backend, decision markers, would_reject
  encoding checks (log-only).
- `config.go` — environment-only configuration; renders the SecLang config:
  engine settings, the CRS setup SecActions mirroring the pinned container's
  activated crs-setup.conf (ids 900000, 900001, 900110, 900990), the C4
  no-allow-list rule (id 900220), the connector-image body-processor
  selection and body-parse-failure rules (ids 200000 XML, 200001 JSON,
  200002 REQBODY_ERROR, 200003 MULTIPART_STRICT_ERROR, 200007 &ARGS>=1000,
  each deny 400 — step-16 T2 BUG fix, mirror of the pinned container's
  /opt/coraza/config/coraza.conf lines 31-41), audit directives, and the
  rule Include.
- `events.go` — kortex-events.jsonl writer (limit, framing, timeout,
  would_reject).
- `admin.go` — /__kortex/config, loopback-only, prints the effective config
  as JSON (in-container proof, rule 29 analogue for the engine).
- `main.go` — env parsing, startup line with the effective config, serve.

## Rules

- Rule files are copied verbatim from the pinned Coraza image
  (ghcr.io/coreruleset/coraza-crs, digest bfbfe70b…, CRS 4.25.2) into
  engine/crs/owasp-crs; the set hash is recorded in engine/RULES.sha256.
  The rules are not edited. The only CRS customization is the standard
  crs-setup variable set, emitted as SecActions before the Include.

## Body size limits (the instructor acceptance criterion)

Both limits are explicit engine configuration, enforced by the engine before
the body reaches the library, and provable from inside the running process
(startup line + /__kortex/config):

- max total body bytes (default 13,107,200) — hard ceiling;
- max inspected body bytes (default 131,072) — bodies above it are rejected
  413 (kortex-decision=limit) and are NOT passed to the engine.

This closes the step-14 finding that Coraza does not enforce
SecRequestBodyNoFilesLimit (docs/baseline-v0.9.md): the limit is ours, not
the library's.

## Time budget

KORTEX_ENGINE_TIME_BUDGET_MS (default 2000). Enforced at phase boundaries
(after headers, during chunked body writes, after body processing). Expiry
returns 503 kortex-decision=timeout and logs an event.

Step-15 PROVEN limitation (docs/logs/step15-t4-skeleton-replay.txt): the
budget cannot interrupt a single-shot ProcessRequestBody call. Step-16 fix:
proxy.go runs ProcessRequestBody in a goroutine bounded by the REMAINING
budget (select against a timer). On expiry the request is answered 503 and
the call is abandoned — coraza has no per-call cancellation, so the
goroutine keeps running to completion (measured ~42 s of CPU-bound work for
the 481,798-byte wcp body; unfettered replay 403 at 42.41 s) and then logs
an `abandoned-body-processing-finished` event and closes its transaction.
The abandoned goroutine OWNS the transaction: the handler's deferred Close
is skipped on the timeout path (E17 — closing the tx mid-call made the
in-flight call return within milliseconds with a stale interruption). The
DoS-risk statement is therefore: a body that overruns the budget costs the
engine the FULL processing time in the background regardless of the client
seeing a fast 503; concurrent over-budget bodies accumulate background CPU
work (20 concurrent copies measured in docs/logs/step16-t3-runs.txt).

## In-flight body-processing cap (step-17 T3, documented BEFORE the
## measurement run)

KORTEX_MAX_INFLIGHT_BODY (default 8) caps the number of body-processing
calls running concurrently, counting abandoned calls (they run to
completion, see above). A BODY-BEARING request (Body != nil and
ContentLength != 0) arriving when the cap is reached is answered
503 kortex-decision=overload immediately, before its body is read, and an
`overload` event is logged. Body-less requests need no slot (their
ProcessRequestBody call is instantaneous) and are answered promptly even on
a cap-reached engine (E21). A slot is released when the processing CALL
returns - for an abandoned call that is long after the handler returned
(E17), so the decrement lives in the processing goroutine. Recovery:
overload answers stop and new body-bearing requests are processed again
once the abandoned calls finish (E20). Outcome semantics: overload is a
capacity decision, NOT a WAF decision - it is reported separately from
block/limit/framing/timeout in every rate table (rule 30 style), and
`kortex-decision=overload` is distinguishable from `kortex-decision=timeout`
by its marker. DoS-risk statement after the cap: at most
KORTEX_MAX_INFLIGHT_BODY over-budget bodies accumulate background CPU work;
additional body-bearing requests get a fast 503 instead of queueing.

## Step-20 T2: size-class lanes for body inspection (documented BEFORE the run)

Problem (step-19 T3, PROVEN): a single shared in-flight cap lets slow LARGE
bodies starve small benign bodies. 8 workers re-sending the 131,071-byte
text/plain body held all 8 slots with abandoned calls (~18-24 s each); 0/131
benign body-bearing POSTs were served (docs/logs/step19-t3-availability.txt).

Fix: split the in-flight body-processing cap into two SIZE-CLASS LANES with
independent caps. A body-bearing request is classified by its declared
Content-Length and acquires a slot in its lane only; an overloaded LARGE lane
therefore cannot consume the SMALL lane's capacity, so small bodies keep
being served while large bodies are saturated.

Configuration (env-only, defaults documented here BEFORE any run):

| env | default | meaning |
|-----|---------|---------|
| KORTEX_SMALL_BODY_BYTES | 65536 | Content-Length <= this -> small lane; > this -> large lane |
| KORTEX_MAX_INFLIGHT_BODY | 8 | LARGE lane cap (existing env name preserved) |
| KORTEX_MAX_INFLIGHT_BODY_SMALL | 4 | SMALL lane cap |

- 65536 is chosen so the step-19 T2 smallest over-budget text/plain body at
  PL1 (65,536 B, 4.57 s > 2 s budget) fits the SMALL lane (<=). This lets the
  T2 second attack run (8 workers re-sending that body) exercise small-lane
  saturation honestly. At PL2 the smallest over-budget body is 32,768 B, also
  <= 65536.
- Classification uses Content-Length when > 0. Chunked / unknown length
  (Content-Length <= 0 with a body) is classified LARGE (conservative). The
  slot is acquired BEFORE the body is read, so the overload answer stays fast
  (E19's <= 50 ms bound is preserved). KNOWN LIMITATION: a client that
  under-declares Content-Length could enter the small lane while streaming
  more bytes; the bounded read still caps inspected bytes at
  MaxInspectedBytes (413 above it) and the framing gate rejects duplicate or
  conflicting Content-Length, so the inspected cost is bounded, but lane
  isolation is by declared size, not actual streamed size.
- Overload outcome UNCHANGED: a body-bearing request whose lane is full is
  answered 503 kortex-decision=overload immediately and an `overload` event
  is logged (now per lane). Body-less requests still need no slot (E21).
- DoS-risk trade-off (documented): worst-case concurrent abandoned
  body-processing calls rises from 8 to 8 + 4 = 12 (large + small caps). On
  this 8-core host that is more background CPU contention under a mixed
  attack; the availability gain for small bodies is the intended trade.
- A slot is still released when the processing CALL returns (abandoned calls
  hold their lane's slot until they finish, E17/E20 semantics unchanged).

Residual starvation path (NOT hidden, measured in T2): an attacker who sends
bodies that fit the SMALL lane (<= 65536 B) but still overrun the budget can
saturate the SMALL lane and starve small benign POSTs again. Lanes isolate
size classes; they do not make over-budget processing free. The T2 second
attack run measures this explicitly.

## Content-type policy (C4)

The engine implements NO content-type allow-list. CRS customization point
900220 sets tx.allowed_request_content_type per-request to the request's own
content type, so 920420 never blocks on content type while body processors
still act per content type. Detection therefore cannot depend on the
allow-list (decision 0002 addendum, criterion C4).

## Encoding checks

Invalid percent sequences and overlong UTF-8 in the query or urlencoded body
write `would_reject` events (kortex-events.jsonl) and never block — log-only
by design in this step.

## Content-Encoding on request bodies (step-22 follow-up, documented BEFORE the code and the run)

Measured in step 22 (T5 cells A-C, F-K): neither the engine nor the Coraza
connector decodes a request body sent with Content-Encoding, and the rules
do not see an attack inside the compressed bytes (cell K: the compressed
canary without the header passes at PL1). The only barrier was CRS 920450,
which refuses the header itself; in DetectionOnly mode, or with that rule
removed, a compressed attack body would be forwarded uninspected.

Design: the engine refuses such a request on its own. A request that has a
body and a Content-Encoding header with any coding other than `identity`
(case-insensitive, any element of a comma list, any repeat of the header) is
answered `415 kortex-decision=content-encoding`, is not inspected, takes no
body lane slot and never reaches the backend. An event row
(decision `content-encoding`, status 415) is written. The check does not
depend on the rule engine mode or the paranoia level. A request without a
body is left to the rules. The engine does not decode: decoding needs its
own size and time limits (decompression bombs) and is not attempted here.

Difference from the reference (rule 39, DESIGN): on these requests the
connector answers 403 through CRS 920450 and the engine answers 415. The
criterion (rule 41) is "an encoded body never reaches the backend, in either
rule-engine mode"; tests E33 and E34, and the T5 encoding cells re-run after
the change.

## Testing

Test-first per rule 37/40: E1-E9 in engine/engine_test.go were committed
failing before the implementation (docs/acceptance.md has the ids and
statuses); E10-E17 in engine/step16_test.go were committed failing before
the step-16 fixes. The parity tests (E10/E14/E15) replay real manifest
samples with the same User-Agent and Host the kortex_eval.runner sends on
both sides of the comparison — a missing User-Agent (CRS 920320, +2) or a
numeric-IP Host (CRS 920350, +3) flips marginal detections and is a harness
artifact, not engine behaviour (step-16 T2 finding).

## Step-17 additions (2026-11-20)

- C4 (no content-type allow-list) is no longer only a design statement: the
  criterion is MEASURED on the engine (rule 41). The engine blocks 34/40
  (PL1) and 38/40 (PL2) attacks-ct payloads by detection rules on
  text/plain, octet-stream AND unknown-ct carriers — carriers the connector
  refuses at phase 1 — and the 2/1 missed payloads are a measured
  URLENCODED-fallback split artifact, not allow-list dependence
  (docs/logs/step17-t1-c4.txt, reproduced on the current host in
  docs/logs/step17-t1-c4-replay.txt).
- Method allow-list (T2): the engine now sets tx.allowed_methods from
  KORTEX_ALLOWED_METHODS (default GET HEAD POST OPTIONS, mirroring the
  connector's crs-setup 900200) and CRS 911100 enforces it. Measured
  DESIGN difference that remains: the engine's audit entries carry only
  phase-2 rule messages, so phase-1 matches (911100, 920350, 901160) never
  appear as audit MESSAGES although they score and block; the connector's
  audit writer emits phase-1 messages.
- In-flight body-processing cap (T3): see "In-flight body-processing cap"
  above (documented before the measurement run, as required).

## Step-18 additions (2026-11-20)

### Body parsing fidelity: REQUEST_BODY as an added target (T4, documented BEFORE the re-runs)

Gap (PROVEN, step-17 T1 raw audit entries): the URLENCODED body processor
splits the raw body on '&' and the first '=' (coraza v3.7.0
bodyprocessors/urlencoded.go), so a payload spanning the split boundary is
scanned only as separate name/value fragments; CRS scans single variables.
This affects every carrier whose body the URLENCODED processor parses: real
urlencoded bodies and the text/plain / octet-stream / unknown-ct carriers
that fall back to it (CRS 901340 forces the body variable; coraza falls back
to URLENCODED when no processor was selected).

Fix: every inbound CRS rule that inspects parsed argument values now ALSO
inspects REQUEST_BODY (the full raw body, set by the URLENCODED processor
itself), via the CRS-documented tuning directive SecRuleUpdateTargetById
(coraza v3.7.0 internal/seclang/directives.go; targets are only ADDED — no
CRS file is edited, no rule is excluded or removed, rules 5/17 respected).
The id list is derived at engine startup from the shipped CRS files
(engine/bodytargets.go) and its size is printed at startup and served on
/__kortex/config (request_body_target_updates=N) so it is provable per run
(rule 29). On the pinned CRS 4.25.2 set the list is 173 rules.

Scope (criterion, measured by the count above and by the re-runs): rules in
REQUEST-930..REQUEST-944 whose target list contains an ARGS-family variable,
does not already contain REQUEST_BODY, is not counted (&ARGS) or size-based
(ARGS_COMBINED_SIZE), is not phase:1, and is not a chain-inner rule (chain
members have no id; SecRuleUpdateTargetById cannot reach them — known
residual limitation, listed here before the run). REQUEST-920 and
REQUEST-921 rules are deliberately out of scope: their ARGS checks are
size/count/encoding-structure checks (920) and CR/LF-in-argument-name checks
(921, 921150 targets ARGS_NAMES only) where the raw body is not a decoded
argument value. For 921 the exclusion is evidence-based from the FIRST
re-run pass on **benign-wcp-v0, which is therefore IN-SAMPLE for this
scope choice (rule 45)**: 921150 matched REQUEST_BODY on 126 of
the 176 PL1 gained ids (72%) because raw bodies legitimately contain
newlines (ND-JSON telemetry bodies; "Matched Data: \n found within
REQUEST_BODY", wcp-01dadd4f53bc) — the added target manufactured false
positives, so the family was removed from the update list (E26, rule 40
test first). The first-pass count was 173 rules; after the 921 exclusion it
is 166. The HELD-OUT evaluation of the final scope (166 rules, 921
excluded) is **benign-wcp-v1** (step-19 T4, preregistered in
docs/plan-benign-wcp-v1.md) and benign-browse-v1; benign-wcp-v0 must be
labelled IN-SAMPLE wherever the 921 exclusion or the target list is
reported. CR/LF reaching ARGS_NAMES through the URLENCODED split itself (a
body with no '=' or '&') is a PRE-EXISTING split behaviour (step-17 T1
parse-fidelity caveat) and is NOT changed by this fix.

Expected consequences, classified BEFORE the re-runs (rule 39):
- ENGINE-ONLY BLOCKS vs the connector on the URLENCODED-parsed carriers
  (urlencoded, text/plain, octet-stream, unknown-ct, no-ct): DESIGN. The
  connector has the same split gap; the engine deliberately closes it. The
  criterion is measured: request_body_target_updates=173 in the run log and
  the per-id diffs in the step-18 report.
- JSON, XML and multipart carriers are UNCHANGED: their processors never
  populate REQUEST_BODY (coraza bodyprocessors: only urlencoded and raw do),
  so the added target matches nothing there.
- Possible anomaly-score doubling when a rule matches both ARGS and
  REQUEST_BODY on the same request (coraza runs match actions per match and
  only de-duplicates multiphase chain matches): with the CRS inbound
  threshold of 5 and CRITICAL rules scoring 5 this does not change
  block/pass for single-rule detections, but it is a measured risk and any
  outcome flip it causes will be reported per id, not assumed away.

### Step-18: unexplained engine non-determinism (UNEXPLAINED, counted)

During the T4 v2 re-runs one benign-wcp-v0 sample (wcp-62cd1bd36bf7, a GET
whose block comes from the query string) passed in the v2 PL2 run where the
pre run, the v1 run, and a 3/3 replay of the same binary all block it. A
tight alternating replay of two same-path samples reproduces the flip at a
much higher rate (7/20 rounds with the v2 binary). Raw evidence and the
diagnostic matrix are in docs/logs/step18-t4-flip-replay.txt:

- the transaction pool is NOT the vector (a variant with tx.Close()
  disabled still flips, 5/20 rounds) — DIAGNOSTIC;
- the behaviour PREDATES step-18 (the pre-fix engine at 1964793 flips too,
  3/20 rounds) — PROVEN by replay;
- no GC correlation (GODEBUG=gctrace=1) — DIAGNOSTIC;
- real-run frequency is low: 1 flip / 8845 would-block samples (v2 PL2
  WCP), 0 / 2128 (v2 PL1 WCP), 0 in the v1 20k runs.

Classification per the standing rules: UNEXPLAINED, counted. Mechanism
HYPOTHESIS (unproven): coraza v3.7.0-internal shared state; the
transformation cache key uses a string pointer (unsafe.StringData,
internal/corazawaf/rulegroup.go:290) as a map key, which is fragile under
memory reuse. Not fixed in this step (rule 1); raised in the step-18
report as a question for the instructor.

### Step-22: the non-determinism has two mechanisms, both PROVEN

DIAGNOSTIC C (tools/run_step22_variance_diag.sh,
docs/logs/step22-variance-engine-DIAGNOSTIC.txt, reports/step-22.md F1)
replaces the HYPOTHESIS above. coraza v3.8.1 iterates its map-backed
collections (ARGS, headers, cookies) in Go's random map order on every call
(internal/collections/map.go). Two things depend on that order:

- H1, capture order: a rule with `capture` whose chained rule reads TX:1 /
  TX:2 (CRS 942130) gets the captures of the variable evaluated last. A
  request with two members that both match the regex, one a tautology and
  one not, is blocked in some of its replays and passed in the rest
  (131 / 69 of 200 at PL2; 69 / 131 with the two members swapped). Not fixed in coraza main as of 4cc95a33a6a2.
- H2, transformation cache: the cache key holds the position of the value
  in the iteration (internal/corazawaf/rule.go, transformArg), so with a
  repeated key a rule can be given the cached transformation of the other
  value. One body gets 8 different anomaly scores in 200 replays. The
  v3.7.0 -> v3.8.1 bump of step 20 removed the status flip of the E30
  sample, not this mechanism. Fixed on coraza main by PR #1682 (issue
  #1681), not in a release yet.

With ordered iteration (a scratch patch of coraza) both effects are gone:
every request of the diagnostic gets one status, one rule set and one
score. The engine cannot order the iteration from outside coraza, so the
engine at this commit still has both. Status: BUG in the dependency, open.

## Size-class body lanes (step-20 T2, documented BEFORE any run)

Motivation: step-19 T3 showed 8 abandoned large-body calls (131,071 B
text/plain, ~24 s runtime each) starve ALL body-bearing traffic: benign
POSTs 0/131 served for 5 minutes. The slot cap is global, so 8 slow
large bodies block small benign requests that cost <1 s.

Design: two in-flight caps (lanes), selected by declared body size.

- SMALL lane: declared Content-Length <= KORTEX_BODY_LANE_THRESHOLD.
  Cap = KORTEX_MAX_INFLIGHT_BODY (existing var, default 8, unchanged).
- LARGE lane: declared Content-Length > threshold, or no Content-Length
  at all (chunked/unknown framing). Unknown framing cannot escape the
  large lane (conservative: an attacker cannot shrug the large lane off
  by omitting Content-Length). Cap = KORTEX_MAX_INFLIGHT_BODY_LARGE
  (new, default 2).

Defaults, chosen from the measured step-19 T2 cost curve (median
inspection time, text/plain, pre-engine):

  <= 16,384 B : 0.66-0.81 s   (under the 2 s budget)
     32,768 B : 1.90-2.04 s   (at the budget edge)
     65,536 B : 4.57-4.89 s   (over budget)
    131,071 B : 6.00-20.10 s  (far over)

- KORTEX_BODY_LANE_THRESHOLD default = 65536 (64 KiB): everything the
  small lane admits is at worst ~4.9 s of inspection (65,536 B), and the
  bodies that dominate benign corpora (WCP: mostly < 10 KB) are all in
  the small lane.
- Large-lane cap default = 2: bounds the worst-case abandoned-call CPU
  burn to ~2 x 24 s per window instead of 8 x 24 s, while still serving
  two concurrent large uploads.

Known residual exposure (documented, not hidden): an attacker whose
bodies fit the SMALL lane can still occupy all 8 small slots and starve
small benign POSTs within that lane. Lanes only isolate attacker-large
from benign-small. Measured in the step-20 small-lane run.

Test hook (deterministic, rule 48): KORTEX_TEST_HOLD_BODY_MS=<ms> plus
request header `X-Kortex-Test-Hold: 1` makes the body-processing call
sleep <ms> while HOLDING its slot. Unset by default: no production
effect. Used by E29 so held slots are deterministic instead of
timing-dependent.

## Step-20 additions (2026-11-21)

- Engine core version: coraza v3.7.0 -> v3.8.1 (T1 fix, E30 test-first).
  The duplicate-arg flip defect (step-19, PROVEN) is fixed upstream in
  v3.8.1: E30 0/2000 flips (was 48/2000), flip_repro PL2 0/2500 (was
  median 114/500). No behaviour change observed at PL1 or on the
  preregistered dup-arg shapes (identical counts on both versions).
- Lane threshold vs measured cost (T3): the SMALL-lane default (65536 B)
  was chosen from the step-19 cost curve (<= ~4.9 s at 65,536 B on the
  pre-engine). The step-20 T3 matrix shows the POST-engine cost at
  65,536 B is up to 22.3 s for pathology content (PL1) — the default
  still holds for availability purposes (a slot is bounded by the 2 s
  budget at PL1 default config for typical content), but the worst-case
  content (real WCP pathology) occupies a small-lane slot far longer.
  Residual exposure unchanged and documented in the T2 section above.
- Body-processor variable population (step-19 T2, restated step-21): the
  JSON processor does not populate REQUEST_BODY; detection for JSON-CT
  bodies runs through ARGS_JSON/ARGS instead, and a payload that breaks
  JSON validity is rejected 400 (E11 class). Step-20 briefly documented a
  "JSON+protobuf inspection gap"; that was a canary-script classification
  artifact (400/503 counted as passes) and is withdrawn — see
  docs/logs/step21-t1b-483cfc.txt and the step-21 T1c matrix
  (docs/logs/runs/s21-t1c-ct/): no attacker-chosen content type avoided
  detection of a text/plain-detected payload in the 36-cell matrix.

## Step-21 T3 design: killable worker subprocesses (committed BEFORE code)

Status: DESIGN (this section committed before any worker code lands).

### Problem

Body inspection runs in-process (goroutine per request). A pathological
body keeps a goroutine CPU-bound for ~74-112 s (step-20/21 measurements)
with no way to cancel it (coraza has no per-call cancellation). The
request itself is answered 503 at the budget (2 s), but the engine
process keeps burning CPU on the abandoned call, and the lane slot is
held until the call completes.

### Design

The engine gains a worker mode. The main engine process keeps the HTTP
proxy, framing gate, lanes and accounting. Body inspection moves into
worker subprocesses:

- `engine --worker`: runs ONE worker that reads a request-job framing
  (method, path, headers, body bytes) from its stdin pipe and writes the
  inspection result (status, matched rule ids, interruption, elapsed) as
  one JSON line to stdout. The worker loads the same CRS ruleset from
  KORTEX_RULES_DIR.
- The engine (parent) spawns a pool of workers: default size = the LARGE
  lane cap (KORTEX_MAX_INFLIGHT_BODY_LARGE, default 2) plus one
  pre-spawned spare. Configurable: KORTEX_WORKER_POOL (pool size),
  KORTEX_WORKER_SPARES (pre-spawned spares, default 1),
  KORTEX_WORKER_RECYCLE_AFTER (recycle a worker after N jobs, default
  0 = never).
- Job dispatch: a body-bearing request checks out a worker from the pool
  (blocking wait bounded by the remaining request budget), writes the job
  framing, waits for the result line with a deadline = the remaining
  engine time budget. On deadline expiry the parent SIGKILLs the worker,
  increments the `kills` counter, starts the pre-spawned spare (and a
  replacement spare), answers 503 timeout, and marks the client for the
  fairness penalty (below). The killed worker's slot is released
  immediately: bounded CPU is the property this design buys.
- Rule-load cost is paid once per worker at spawn (measured: T3
  acceptance (f)); the spare is pre-spawned at startup so a kill does
  not pay rule-load on the hot path.
- Worker protocol framing: a single JSON line with base64 body (jobs
  are <= KORTEX_MAX_BODY_BYTES). Pipe transport (os.Pipe via
  exec.Cmd stdin/stdout) — no unix socket needed for one host.
- In-process mode stays the default (`engine` without --worker) so all
  existing tests and parity baselines are unchanged. The T5 tests run
  the parity comparison between in-process and worker modes.

### Per-client fairness

- Client identity = peer address. A trusted-proxy list
  (KORTEX_TRUSTED_PROXIES, comma-separated CIDRs, default EMPTY) may
  re-derive the client as the FIRST untrusted X-Forwarded-For hop. With
  the default (no trusted proxies) XFF is ignored entirely.
- In-flight limit per client, per lane: a client may hold at most
  floor(lane_cap/2) (at least 1) body-processing jobs in each lane at
  once. With the default lane caps (small 8, large 2) that is 4 small
  and 1 large. KORTEX_CLIENT_MAX_INFLIGHT (default 0 = not set) can
  lower the cap on both lanes; a value above half a lane is clamped to
  half that lane, so an override can never let one client fill a lane
  (T3i, T3j). The one exception is a lane whose cap is 1: its
  per-client cap is also 1 ("at least 1"), so one client fills it. Jobs
  are counted per lane, so a small job in flight does not block the
  client's large job (T3l). Excess body requests are answered 503
  kortex-decision=overload with reason "per-client in-flight cap". The
  caps in force are shown on /__kortex/config as
  client_max_inflight_small and client_max_inflight_large, next to the
  configured client_max_inflight and worker_mode (T3m); they act only
  in worker mode.
- Penalty state: after a budget kill, the client's address is put in a
  penalty map for KORTEX_CLIENT_PENALTY_MS (default 10000); while
  penalised, the client's body-bearing requests are answered 503
  kortex-decision=overload with reason "client penalty after kill"
  without checking out a worker. The penalty map is capped
  (KORTEX_CLIENT_PENALTY_MAX_ENTRIES, default 4096, evict oldest) so the
  map itself cannot be exhausted by address spoofing.
- Fairness state is observable at /__kortex/stats (rule 50):
  per-lane in-flight, abandoned_running, workers {pool, busy, spares,
  loading}, kills, overloads, penalised_clients, and the per-client
  in-flight jobs summed over all clients per lane (client_inflight_small,
  client_inflight_large).

### Refusing a penalised client before inspection (step-22 follow-up, documented BEFORE the code and the run)

Measured in the step-22 T2 cells: the engine tree spent 576.2 CPU-seconds
in the 300 s mixed-one cell (2,298,728 overloads) and 561.6 in mixed-eight
(1,761,481). A penalised client's body request was refused only in
workerServe, after the parent had created a transaction, evaluated the
phase-1 rules, taken a lane slot, read the whole body and written it into
the transaction. None of that work can change the answer.

Design: in worker mode, a body-bearing request from a client in penalty
state is refused at the top of the handler, before the transaction exists:
same answer (503 kortex-decision=overload, reason "client penalty after
kill"), same event row, same overloads counter, plus the new counter
refused_before_inspection on /__kortex/stats. The request body is drained
with the existing bound before the answer, as on every refusal. Body-less
requests are not affected. The later check in workerServe stays, for a
client that is penalised while its request is already in the handler.

This is not a rate limit: an attacker that keeps opening connections still
costs an accept, a header parse and a 503. What it removes is the rule
evaluation and body handling per refused request. Visible difference: a
penalised client's body request that the rules would have blocked gets 503
instead of 403. Test T3p; effect measured by re-running the mixed cells and
the kill storm (CPU-seconds, same container, same script).

### Design risk (b): single peer address, no trusted proxies (step-22 T2)

With the default KORTEX_TRUSTED_PROXIES empty, client identity is the
peer address, so ALL users behind one address share a single penalty
bucket and per-client in-flight cap. One client's budget kill penalises
every user on that address: after the kill, that address enters penalty
state (KORTEX_CLIENT_PENALTY_MS, default 10000 ms) and its body-bearing
requests are answered 503 kortex-decision=overload "client penalty after
kill" until the penalty expires, even for innocent clients sharing the
address. Measured in the step-22 T2 cells: under an 8-address PL2
small-body attack, penalised_clients reached 8 and the pool dropped to 0
during the attack. Correction (step-22, PROVEN by
docs/logs/step22-t2-benign-shape-DIAGNOSTIC.txt): the earlier wording
"the pool never re-stocked within the recovery watch (small-eight
recovery=None)" was wrong. The recorded recovery samples show pool 4,
penalised_clients 0 and no in-flight work 7.6 s after the attack ended;
recovery stayed None only because the cell's benign probe (numeric-IP
Host, no User-Agent) is itself blocked 403 at PL2 on an idle engine, so
its "status 200" condition could never be met. For the same reason the
0/301 and 0/300 benign counts of the two PL2 small cells do not measure
starvation.

Configuration guidance: if the engine sits behind a trusted proxy, set
KORTEX_TRUSTED_PROXIES to the proxy's CIDR(s) so the client is derived
as the FIRST untrusted X-Forwarded-For hop instead of the peer address;
this isolates innocent users sharing one egress address. With no trusted
proxies (the default), the shared-peer penalty is inherent and must be
accepted or mitigated by shortening KORTEX_CLIENT_PENALTY_MS. The
per-client cap is at most floor(lane_cap/2) per lane, at least 1
(design risk (a), T3h-T3j), so one client cannot hold a whole lane
of cap 2 or more, with or without a KORTEX_CLIENT_MAX_INFLIGHT override.

### What this replaces

E20 (step-16: CPU after a budget timeout is unbounded in-process) is
RETIRED as of step-21: the worker design demonstrates the stricter
bounded-CPU property with a committed failing-first replacement test
(T3g, committed failing in a699174, passing in 5795c34 — after a kill
the engine process CPU stops growing). The E20 test is kept and still
passes (in-process mode remains supported and default), but the
availability/CPU property the system relies on is now T3g. Worker-mode
decision parity is proven zero-diff on 5 datasets (2520 samples) and
flip_repro worker PL2 0/2500 (docs/logs/runs/s21-t3-parity/).

## Step-23 additions (2026-11-27)

### Framing refusals are logged (T1)

The framing gate (engine/listener.go) refuses on the raw connection before
any HTTP parser runs. Until step 23 it wrote the 400 and nothing else, while
engine/events.go and docs/block-discriminator.md said framing decisions are
always logged (found in step 22, C6). Now every refusal writes one event to
kortex-events.jsonl before the answer is sent: decision `framing`, status
400, reason = the gate's reason (`conflicting-content-length`,
`duplicate-content-length`, `transfer-encoding-with-content-length`,
`nul-in-target`, `no-request-line`), sample id read from the raw head
(`X-Kortex-Sample-Id`, empty when absent). A connection whose head cannot be
read (timeout, more than 65,536 bytes) is closed without an answer and
without an event, as before: no decision was made on a request. Tests E35
(failing first) and E36.

### Deterministic rule matching: patched coraza (T2, documented BEFORE the patch is built and run)

Problem (step-22 F1, PROVEN there): coraza v3.8.1 iterates its map-backed
collections (ARGS, ARGS_NAMES, request headers, cookies, ...) in Go's random
map order, on every call. Two consequences for one unchanged request:
(H1) a rule with `capture` and a chained rule that reads the captures (CRS
942130) sees the captures of whichever variable came last, so the request
is blocked or passed at random; (H2) the transformation cache is keyed by
position in the iteration, so the set of matched rules and the score vary
when a key repeats.

Decision (instructor, step 23): carry a minimal patch. The engine builds
against a vendored copy of coraza v3.8.1 through a `replace` in
engine/go.mod:

    replace github.com/corazawaf/coraza/v3 => ./third_party/coraza-v3.8.1-kortex

The patch, in full, is engine/third_party/coraza-v3.8.1-kortex.patch:

- new file `internal/collections/kortex_sorted.go`: `sortedKeys(m)`
  returns the keys of a collection's map in ascending byte order;
- `internal/collections/map.go`: `Map.FindRegex` and `Map.FindAll` walk
  the keys in that order instead of ranging over the map;
- `internal/collections/named.go`: `NamedCollectionNames.FindRegex`,
  `FindAll` and `String` do the same.

Values under one key keep their insertion order (they are a slice and were
never the problem). Nothing else in coraza is changed. It is the `sorted`
build of step-22 F1 (200 replays there: syn-chain 403 x 200, syn-dup one
rule-id set), now made the engine's dependency.

What is vendored: the non-test `.go` files of the coraza packages the
engine imports (25 packages), plus go.mod, go.sum and LICENSE (Apache-2.0).
Tests, docs, examples and the `testing` and `http` packages are not copied.
`tools/step23_coraza_vendor_check.sh` proves the copy from the Go module
cache: every vendored file is byte-identical to coraza v3.8.1 except the
two patched files and the one new file, and the diff of those equals the
committed patch.

What the patch gives and what it does not (rule 41):

- It gives repeatability: the same request, the same order, the same
  decision. Tests E37 (2,000 replays each of syn-chain and syn-dup, one
  status and one rule-id set), E38 (member order in a JSON body does not
  change the decision), E39.
- It does not make CRS 942130 catch every tautology. The chained rule still
  sees the captures of the LAST matching variable, which is now the one
  whose key sorts last. A tautology under a key that sorts before a
  harmless `x=y` member is passed, every time (E39 logs the outcome). That
  is a property of the rule (ModSecurity 3.0.17 passes it too, step-22
  F2b), not of the engine.
- Order is by key, not by arrival. ModSecurity keeps arrival order; a rule
  whose outcome depends on the order of variables can therefore still
  differ between this engine and ModSecurity or the stock connector.
- H2 is removed as a source of variation because the position of a value
  in the iteration is now fixed. The cache key itself is not changed
  (upstream PR #1682 changes it; not in a release).
- Cost: one sort of the key list per FindAll / FindRegex call. Measured in
  the step-23 report, not assumed.

Consequences recorded: the engine is no longer "stock coraza v3.8.1"; the
effective-config log line and /__kortex/config keep saying which rules
directory is used, and the build's coraza is named in docs/baseline-v1.8.md.
Rule-id parity against the stock connector image cannot be exact for
requests of the H1/H2 kind (the connector still varies). Scratch builds
that swap the coraza version (tools/run_step22_flip.sh FLIP_CONTROL,
tools/run_step22_variance_diag.sh) must drop the replace first.

Removal: when a coraza release has ordered iteration, delete the replace
line and the third_party directory; E37 to E39 then test the release.

### Compressed-looking body without Content-Encoding: log-only event (T3, documented BEFORE the code and the run)

Step-22 F3 (cell K): compressed bytes sent WITHOUT a Content-Encoding header
are not refused by E33 (there is no header to refuse) and pass the rules at
PL1, because neither the engine nor CRS inflates them. A backend that
sniffs the body and inflates it would then see what the engine did not.
Whether to refuse such bodies is undecided; step 23 only measures how often
they occur.

The engine looks at the first bytes of every request body it reads (after
the E33 header check, so only bodies without a Content-Encoding other than
identity get here):

| kind | first bytes | basis |
|---|---|---|
| gzip | `1f 8b 08` | RFC 1952: ID1, ID2, CM = 8 (deflate, the only method defined) |
| zlib | `78 01`, `78 5e`, `78 9c`, `78 da` | RFC 1950: CMF 0x78 (deflate, 32K window) with the four FLG values a stream without a preset dictionary can have, one per compression level class |

A match writes one event to kortex-events.jsonl: decision `would_reject`,
status 0, reason `compressed-body-without-content-encoding:gzip` or
`...:zlib`. Nothing else happens: the body is inspected, decided and
forwarded exactly as before (LOG-ONLY, like the encoding checks; tests E40
and E41). The event is written when the body has been read, whatever the
later decision, in in-process and in worker mode.

Known limits, on purpose for a first measurement: zlib streams with a
smaller window (CMF 0x08 to 0x68) or a preset dictionary are not flagged;
the pairs for those collide with ordinary text (for example `80`, `(4`,
`x ` are valid zlib headers) and would make the count meaningless. `x^`
(78 5e) is the one listed pair that is printable text. Raw deflate has no
magic and cannot be recognised this way. A body the engine does not read
(Content-Length above the total limit, refused 413) is not checked. The
check says "starts like", not "is": nothing is inflated.

### What was measured for the patched coraza (T2, after the runs)

- Repeatability: E37 2,000 replays each, one outcome (stock: syn-chain
  1,564 x 403 and 436 x 200; syn-dup two rule-id sets). In-process against
  worker mode on the four wcp runs: 0 rule-id set differences in 60,000
  pairs (step 22: 3 ids per parity run).
- The limit stated above is real: E39's request is passed in 300 of 300
  replays (stock: 230 passed, 70 blocked).
- Effect on real traffic: against the stock-coraza runs of the wcp
  datasets, 0 status differences in 60,000 pairs and 1 rule-id set
  difference (942130 on wcp-7b0bdeda7bc7, blocked either way).
- Cost: not visible at the resolution of these runs (wcp run wall times
  within 4 s of the stock runs; 2,000 replays 2.35 against 2.39 s and 3.97
  against 3.99 s). A controlled timing is NOT MEASURED.

### Who answers a request, in order (found while building the T5 differential)

A request can be refused at four places, and only three of them are the
engine's own code:

1. The framing gate (engine/listener.go), on the raw bytes: 400
   `kortex-decision=framing`, event since step 23 (E35).
2. **Go's net/http parser**, after the gate and before the handler: a
   Content-Length it cannot parse (`+5`, `0x5`, `-1`, empty, `5, 5`, a
   space before the colon), an unsupported or repeated Transfer-Encoding,
   an invalid percent escape in the path. It answers `400 Bad Request` or
   `501 Unsupported transfer encoding` itself. The engine's handler never
   runs, so there is no kortex-decision line, no event, no audit entry and
   no rule evaluation. 17 of the 61 T5 cases end here. This is fail-closed
   behaviour that the engine does not announce; kortex_eval sees a bare
   status. Not changed in step 23 (see the report's questions).
   **Changed in step 24:** the gate at (1) now refuses these heads itself
   (reason `parser:<class>`), so nothing is left for net/http to refuse
   here; see "Step-24 additions" below.
3. The handler's own checks (engine/proxy.go): 415 content-encoding, 413
   limit, 503 overload, 503 timeout (which also covers a body the engine
   cannot read, for example a malformed chunk: reason `body-read-error`).
4. The rules: 403 block, or the deny status of a body-parser rule.

A request that passes all four is forwarded with the engine's own framing:
Transfer-Encoding and Content-Length are dropped and a Content-Length for
the bytes the engine read is set, and the connection to the client is
closed after the answer. So a backend behind the engine never receives an
ambiguous length, and bytes a client sends after the declared body never
reach it (T5: `cl-short-body`, the three chunked cases).

The log-only encoding checks (invalid percent sequence, overlong UTF-8)
look at the query and at urlencoded bodies, not at the path. An invalid
percent escape in the path is refused at (2); overlong UTF-8 in the path
reaches the rules unremarked (T5: `ovl-path-nul-pct` forwarded, no event).

## Step-24 additions (2026-11-27)

### Refusals of Go's HTTP parser are made by the gate (T1, documented BEFORE the code)

Classification (rule 39): BUG. Step 23 (T5) found that 17 of 61 hand-written
requests were answered `400 Bad Request` or `501 Unsupported transfer
encoding` by Go's net/http inside the engine: no kortex-decision line, no
event, no audit entry. The request is not forwarded, so this is fail-closed,
but the evaluation reads a bare 400 or 501 as `waf_pass` and the events file
says nothing happened.

The fix keeps kortex_eval unchanged (rule 5) and moves the refusal into the
engine's own gate:

- After the framing checks, the gate (engine/listener.go) gives the request
  head it already holds to Go's own request parser (`http.ReadRequest`), then
  repeats the checks that net/http's server makes after parsing and before it
  calls a handler (protocol version, Host header present / single / well
  formed, header names and values, more than 500 header lines, an `Expect`
  value other than `100-continue`).
- A head that fails any of them is answered by the gate exactly like every
  other gate refusal: `400` with the body `400 kortex-decision=framing`, one
  `framing` event (status 400, sample id from the raw head) written before
  the answer, connection closed. kortex_eval already classifies this answer
  as `waf_fail_closed_400`.
- The event reason is `parser:<class>` where the class is one of a fixed list
  of words: `content-length`, `transfer-encoding`, `request-target`,
  `request-line`, `method`, `http-version`, `host-missing`, `host-duplicate`,
  `host-malformed`, `header-line`, `header-name`, `header-value`,
  `header-count`, `expect`, `other`. Go's error text quotes the offending
  value, so it is never written to the events file.
- The status changes for these requests: 501 (unsupported Transfer-Encoding),
  505 (HTTP version), 417 (Expect) and 431 (more than 500 header lines)
  become 400, the one status the gate uses. A request the gate refuses this
  way was already refused before; nothing that used to reach the handler is
  refused now (test E43 is the guard, E44 the canary that such requests are
  still inspected).

What this does not cover, and is left as it was:

- A head the gate cannot read (no blank line within 30 s, or more than
  65,536 bytes) is closed without an answer and without an event.
- Errors found while the body is read (a malformed chunk) are the handler's:
  503 timeout with reason `body-read-error`, as in step 23.
- `OPTIONS * HTTP/1.1` is answered 200 by net/http itself with an empty
  body; the handler does not run, nothing is inspected and nothing is
  forwarded. This is an answer, not a refusal; see the step-24 report.
- The checks made after parsing are a copy of what net/http does in
  go1.27.4. Test E42 proves, case by case on a bare net/http server, that
  each listed shape is answered by Go without running a handler; a shape
  that is not in the test is UNVERIFIED.

### Every request is judged by the framing gate (T2, documented BEFORE the code)

Classification (rule 39): BUG, two of them, both found while building T1 and
both PROVEN by failing tests (docs/logs/step24-e46-e48-failing.log).

1. Bare LF. The framing checks split the head on CRLF. Go's parser also ends
   a line at a bare LF. A `Content-Length` or `Transfer-Encoding` line that
   follows a bare LF was therefore part of the previous line for the gate
   and a header of its own for net/http. Test E46: four requests the gate
   refuses when written with CRLF (Transfer-Encoding with Content-Length,
   duplicate Content-Length) were forwarded to the backend when one line
   ending, or all of them, was a bare LF.

   Fix: the framing checks are made twice, on the raw CRLF lines as before
   and on the header block as Go's MIME reader returns it (the reader
   net/http itself uses). More than one Content-Length value, or
   Transfer-Encoding together with Content-Length, in either view is refused
   with the same reasons as before. A bare-LF request without a framing
   problem is treated as before (guard E47); bare LF itself is not refused.

2. Connection reuse. The gate judges the first request of a connection and
   relies on every answer closing it. Three answers did not: `OPTIONS *`,
   which net/http answers itself, and `/__kortex/config` and
   `/__kortex/stats`. A second request on such a connection was read by
   net/http directly. Test E48: the request the gate refuses on its own was
   forwarded to the backend when it followed any of the three.

   Fix: HTTP keep-alive is switched off on the engine's server
   (`SetKeepAlivesEnabled(false)`), so the connection is closed after the
   first answer whoever wrote it, and bytes after the first request are
   never read. main() and the tests build the server through one function,
   `newEngineServer`, so the tests run the setting production runs.

Neither change touches what the engine does with the first request of a
connection that has no framing problem.

## Step-25 additions (2026-11-27)

### What the CRS regression suite needs: error log and suite setup (T1, tests first)

Two switches, off by default (docs/baseline-config.md, step 25):

- `KORTEX_ERROR_LOG=<path>`: one line per matched rule that has the `log`
  action, in the ModSecurity error-log form (`MatchedRule.ErrorLog()`).
  The parent and each worker append to the same file, one write per line.
  The audit log is unchanged; it still records only requests that end in
  4xx / 5xx, so in DetectionOnly mode the error log is the only record of a
  match on a forwarded request (E49).
- `KORTEX_CRS_TEST_SETUP=on`: TEST ONLY. Renders rules 900005, 900511 and
  the marker rule 999999 of the CRS regression suite. With it on, any
  client can switch every rule off with an `X-CRS-Test` header. Only the
  exact value `on` enables it (E50, guard E51), and `/__kortex/config`
  shows `crs_test_setup`.

### The rules see the request head as it was sent (T3; tests E52 to E54 first, this note after the fix)

Go's net/http changes three things before a handler sees a request, and the
engine handed the changed form to the rules:

| what | before | now | found by |
|---|---|---|---|
| request target | `r.URL.RequestURI()`: an absolute-form target lost its scheme and host | `r.RequestURI`, the target as sent | CRS test 920100-16 |
| protocol | the constant `1.1` (REQUEST_PROTOCOL and REQUEST_LINE carried `1.1`, also for HTTP/1.0) | `r.Proto`, e.g. `HTTP/1.0`, as coraza's own middleware passes it | E52 |
| Transfer-Encoding | absent: net/http removes it from the header map | handed back from `r.TransferEncoding` | CRS tests 920171-2, -3 |
| Host | always added, empty when the request had no Host line; in worker mode the worker added none, so a body-bearing request without Host got 920290 from the parent and 920280 from the worker | the Host line as the gate read it from the raw head: its value when there is one, no header when there is none | CRS test 920280-1, E54 |

`engine/requestview.go` builds this view once (`viewOf`) and feeds it to
the transaction in the handler and, through the job, in the worker, so the
two cannot drift apart again. The gate keeps the Host lines of the head it
let through on the connection (`gatedConn.hostLines`), and the server's
`ConnContext` hands them to the handler. net/http itself cannot tell "no
Host line" from "empty Host line", and for an absolute-form target it
replaces the Host value with the target's host.

Not changed: what is forwarded to the backend (`r.URL.RequestURI()` and
`r.Host`, as before).

Found while writing the view (test E56 first): in-process the handler added
a `Content-Length` header of its own although net/http keeps the one that
was sent, so the rules were given the header twice; the worker was given it
once. The handler no longer adds it. No CRS test and no sample of our
datasets changed its result or its rule-id set with this fix
(docs/logs/step25-ftw-final-diffs.txt, last section).

### CRS 942130 gets no REQUEST_BODY target (T3; test E55 first, this note after the fix)

Step 18 added REQUEST_BODY as a target to every inbound 93x / 94x rule that
inspects parsed arguments, saying "targets are only added". For a rule that
starts a chain this is not true: the chained rule reads the captures of the
last variable that matched, and the added target is evaluated last. CRS
942130 (SQL tautology) captures two words around `=` or `like` and its
chained rule requires them to be equal. In a form body `a=42 like 42` the
argument gives (42, 42), then the raw body gives (a, 42), its first match
being the name=value pair, and the chain fails. Since step 18 the rule
could not match a tautology in any body parsed as a form (PROVEN: E55, and
the DIAGNOSTIC run without the target updates, where CRS test 942130-7
passes).

Fix: 942130 is left out of the target updates (`bodyTargetSkip`), 165
updates instead of 166. What this gives up: a tautology that the form split
destroys (for example a raw text body `x' or 1=1`, where the split puts the
two sides into name and value) was matched by 942130 through the raw body;
it no longer is by this rule. Measured on our datasets at PL2: attacks-ct-v0
942130 lost on 28 requests and gained on 7, encoding-diff-v0 gained on 12,
no status changed (docs/logs/step25-own-vs-step24.txt).

The other 11 chain-starting rules among the updates (931130, 932200,
932240, 933150, 941310, 942131, 942200, 942440, 942521, 943110, 943120)
keep the target: E24 needs it on 932240, and no CRS test shows a missed
match for them. Whether one of them loses matches the same way on other
inputs is not tested.

### Properties the CRS suite measures against (stated in the plan before the run)

- The engine does not inspect responses: `SecResponseBodyAccess Off`, and
  engine/proxy.go calls no response phase. Every CRS rule in the
  RESPONSE-95x files is inactive. Measured: 78 of the suite's tests.
- No content-type allow-list (rule 900220, decision 0002 addendum C4).
  Measured: 19 tests that expect 920420.
- REQUEST_BODY as an added target (step 18) scans the raw body, names and
  separators included. Measured: 15 tests in which the CRS project asserts
  that a rule must not match (`initials=DF` for 932340, one special
  character for 942432, ...) do match on the engine: potential false
  positives.
- The gate answers before the rules (steps 15 and 24). Measured: 3 tests
  that expect a rule id for a request the gate refuses.
