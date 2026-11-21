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
- Known inspection gap (T4 canary): requests with content type
  application/json+protobuf (and any CT routed to the JSON processor)
  do NOT get raw-body inspection — the JSON processor does not populate
  REQUEST_BODY, so the 166 REQUEST_BODY target updates are inert for
  them. Proven by canary: the only engine pass (wcp-dedb89ec3d3d) and
  the only connector pass are both this CT. Detection for these requests
  relies on the JSON processor's ARGS_JSON targets only.
