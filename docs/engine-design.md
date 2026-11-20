# Engine design (step-15)

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
  no-allow-list rule (id 900220), audit directives, and the rule Include.
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

PROVEN limitation (step-15 T4 replay, docs/logs/step15-t4-skeleton-replay.txt):
the budget does NOT interrupt a single-shot body processing call. A
481,798-byte text/plain body with max_inspected_bytes=13,107,200 ran
41.8-43.5 s per rep (3/3) inside Coraza phase 2 and then returned a normal
403 block — the 2,000 ms budget never fired, because one
ProcessRequestBody call is a single phase with no boundary inside it.
The budget only bounds requests that hit a phase boundary while over budget
(chunked writes, per-phase checks). Mitigation in this step: the default
max_inspected_bytes=131072 rejects such bodies with 413 in ~1-3 ms before
the engine (config A of the same replay). Closing the gap for
full-inspection configurations is future work, not done in step-15.

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

Test-first per rule 37: E1-E9 in engine/engine_test.go were committed
failing before the implementation (docs/acceptance.md has the ids and
statuses). The tests run the real CRS rule set and a stub backend.
