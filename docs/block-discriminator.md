# Block discriminator (step-15 T5) — written BEFORE the skeleton was run

The engine skeleton (engine/, Coraza v3.7.0 + CRS 4.25.2 as the inspection
core) distinguishes four outcome classes. Every non-2xx answer carries a
kortex-decision marker in the response body, so a run's outcomes.jsonl can be
classified without guessing:

| decision | status | body marker | meaning |
|----------|--------|-------------|---------|
| block    | 403    | `403 kortex-decision=block rules=<ids>` | CRS matched a disruptive rule in blocking mode |
| limit    | 413    | `413 kortex-decision=limit` | body above max inspected (131,072) or max total (13,107,200) bytes; rejected before the engine |
| framing  | 400    | `400 kortex-decision=framing` | duplicate/conflicting Content-Length, Transfer-Encoding with Content-Length, or a raw NUL in the request line; since step 24 also every request head that Go's HTTP parser would refuse (event reason `parser:<class>`: unparsable Content-Length, unsupported or repeated Transfer-Encoding, invalid request target, request line, method, HTTP version, missing / duplicate / malformed Host, malformed header line, name or value, more than 500 header lines, an Expect other than 100-continue); rejected before the engine |
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
- The framing gate runs on the raw connection before any HTTP parser.
  Keep-alive is off on the engine's server (step 24, E48), so the connection
  is closed after every answer, every request is the first on its
  connection and is always gated. Before step 24 this relied on the
  handler's `Connection: close`, which `OPTIONS *` and the `/__kortex/`
  admin paths did not send.
- Since step 24 the gate reads header lines the way Go's parser does as
  well as by CRLF, so a framing header after a bare LF is seen (E46), and
  it refuses with the framing marker what net/http would otherwise answer
  itself with a bare 400, 501, 505, 417 or 431 (E42). `OPTIONS *` is still
  answered 200 by net/http itself, uninspected and not forwarded.
- Since step 27 (E57 to E62, E65) the gate also answers
  `400 kortex-decision=framing`, each with one `framing` event, for:
  `OPTIONS *` (reason `parser:options-asterisk`; the sentence above no
  longer holds), a head over 65,536 bytes (`head-too-large`), a head that
  does not end within `KORTEX_HEAD_TIMEOUT_MS`, default 30 s
  (`head-timeout`), and a request target the engine cannot forward byte
  for byte (`target-not-forwardable`). A connection that arrives while
  `KORTEX_MAX_PENDING_HEADS` (default 256) connections are still sending
  their head gets `503 kortex-decision=overload` with an `overload` event,
  reason `pending-heads`. The event of a head whose
  `X-Kortex-Sample-Id` line the engine cannot read has an empty
  `sample_id`.
- Detection blocks must not depend on the content-type allow-list (criterion
  C4, decision 0002 addendum): the engine does not implement a content-type
  allow-list at all; CRS rules decide.
- Events: kortex-events.jsonl lines are
  `{"ts","sample_id","decision","status","elapsed_ms","reason"}` for limit,
  framing, timeout and overload decisions (and would_reject for log-only
  encoding checks). Blocks and passes are visible in the Coraza JSON audit log and in
  the response statuses. Since step 23 the framing gate really does write its
  event (E35; it did not before), and `would_reject` also covers a body
  without Content-Encoding that starts with gzip or zlib magic bytes (E40,
  reason `compressed-body-without-content-encoding:gzip|zlib`, log-only).
- NOT covered by any marker or event (found in step 23, T5): a request that
  Go's HTTP parser inside the engine refuses after the gate and before the
  engine's handler (a Content-Length it cannot parse, an unsupported
  Transfer-Encoding, an invalid percent escape in the path). The client gets
  Go's plain `400 Bad Request` or `501 Unsupported transfer encoding`, with
  no kortex-decision line and no event; kortex_eval classifies such an
  answer by status only.
- The effective configuration is printed at startup and served as JSON on
  /__kortex/config (loopback only), so it is provable in-container.
