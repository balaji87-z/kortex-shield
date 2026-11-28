# Block discriminator (step-15 T5) — written BEFORE the skeleton was run

The engine skeleton (engine/, Coraza v3.7.0 + CRS 4.25.2 as the inspection
core) distinguishes four outcome classes. Every non-2xx answer carries a
kortex-decision marker in the response body, so a run's outcomes.jsonl can be
classified without guessing:

| decision | status | body marker | meaning |
|----------|--------|-------------|---------|
| block    | 403    | `403 kortex-decision=block rules=<ids>` | CRS matched a disruptive rule in blocking mode |
| limit    | 413    | `413 kortex-decision=limit` | body above max inspected (131,072) or max total (13,107,200) bytes; rejected before the engine |
| framing  | 400    | `400 kortex-decision=framing` | duplicate/conflicting Content-Length, Transfer-Encoding with Content-Length, or a raw NUL in the request line; rejected before the engine |
| timeout  | 503    | `503 kortex-decision=timeout` | per-request engine time budget (2,000 ms) exceeded |
| overload | 503 | `503 kortex-decision=overload` | concurrent in-flight body-processing cap reached IN THE REQUEST'S SIZE-CLASS LANE (step-20 T2): small lane (Content-Length <= KORTEX_SMALL_BODY_BYTES, default 65536; cap KORTEX_MAX_INFLIGHT_BODY_SMALL, default 4) or large lane (cap KORTEX_MAX_INFLIGHT_BODY, default 8). A saturated large lane does not consume small-lane capacity. Capacity decision, not a WAF decision (step-17 T3) |
| pass     | backend status | — | request inspected and forwarded |

Outcome classes in kortex_eval (step-22 close-out). The runner records the
decision of an engine answer in `engine_decision` (the whole response body
must be the marker line, with the response's own status in front).
`kortex_eval.outcome` then classifies the engine's own refusals as
fail-closed outcomes, in blocking and in detection mode:

| engine answer | outcome |
|---|---|
| `400 kortex-decision=framing` | `waf_fail_closed_400` |
| `413 kortex-decision=limit` | `waf_fail_closed_413` |
| `415 kortex-decision=content-encoding` (step-22 E33) | `waf_fail_closed_415` |
| `503 kortex-decision=timeout` | `waf_fail_closed_503_timeout` |
| `503 kortex-decision=overload` | `waf_fail_closed_503_overload` |

All five are refusals by the WAF without a rule decision, so they are part
of the worst case of a rate (rules 20, 21) and are counted apart from
`waf_block` (403) and from each other. Overload stays a capacity decision
(step-17 T3): its own outcome keeps it separable in every table. A 400 with
decision `block` is a rule deny and stays `waf_deny_status`. The same status
without the marker is the backend's status and stays `waf_pass`; so does
every row of a responses.jsonl written before the field existed.

Notes

- limit and framing decisions never reach the engine and never reach the
  backend; a timeout may have consumed engine time but is never forwarded.
- The time budget is enforced at phase boundaries (after headers, during
  chunked body writes, after body processing). KORTEX_ENGINE_TIME_BUDGET_MS=0
  means "expire immediately" (used by test E6).
- Encoding checks (invalid percent sequences, overlong UTF-8 in query or
  urlencoded body) are LOG-ONLY: they write `would_reject` events to
  kortex-events.jsonl and never block.
- The framing gate runs on the raw connection before any HTTP parser; the
  engine answers `Connection: close` so every request is the first on its
  connection and is always gated.
- Detection blocks must not depend on the content-type allow-list (criterion
  C4, decision 0002 addendum): the engine does not implement a content-type
  allow-list at all; CRS rules decide.
- Events: kortex-events.jsonl lines are
  `{"ts","sample_id","decision","status","elapsed_ms","reason"}` for limit,
  framing, timeout and overload decisions (and would_reject for log-only
  encoding checks). Blocks and passes are visible in the Coraza JSON audit log and in
  the response statuses.
- The effective configuration is printed at startup and served as JSON on
  /__kortex/config (loopback only), so it is provable in-container.
