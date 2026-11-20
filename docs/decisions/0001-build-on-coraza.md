# ADR 0001: Build on Coraza and OWASP CRS; do not write a rule engine

Status: proposed

## Context

Facts from the CRS project's engine-integration page:

- Coraza (Go, open source) passes 100% of the CRS v4 test suite.
- ModSecurity v3 fails 2-4% of the CRS unit tests and, as of that page, performs
  worse than ModSecurity v2 on Nginx. ModSecurity v2 is the reference implementation.
- Trustwave and OWASP agreed in January 2024 to transfer ModSecurity to OWASP,
  which remains free to use and modify.
- Most cloud WAFs implement only a subset of CRS or translate it into their own language.

Facts from research on how WAFs fail:

- WAFFLED (arXiv 2503.10846) found 1,207 bypasses across five WAFs, including
  ModSecurity on Nginx, caused by differences in how request bodies are parsed,
  not by the attack payload.

## Decision

Use Coraza with CRS as the rule engine. Spend engineering effort on the layers
where the evidence shows a gap: strict request normalisation, evaluation,
logging, and rollout safety. Any machine-learning component is additive and
must beat the CRS baseline on held-out attack families at an equal or lower
false positive rate before it ships.

## Consequences

- We inherit CRS behaviour and its tuning model (paranoia levels, anomaly scores).
- We are a Go codebase at the engine layer. Evaluation tooling stays in Python.
- The baseline in `deploy/compose.yml` uses the ModSecurity CRS container because
  it is quick to stand up. It is a measuring stick, not our engine.

## What would change this decision

- Coraza failing the CRS suite in our build.
- Evidence from our own tests that its performance cannot meet the latency target set after baseline.
- A parsing layer we cannot make strict enough without forking the engine.

## Not verified

We have not benchmarked Coraza's performance ourselves. Nothing here claims it
is fast enough; that is test A6.

## Evidence-status addendum (step-14, 2026-11-20)

This decision predates our own measurements. Status of its assumptions after
steps 9-14 (details in docs/engine-evidence.md and docs/baseline-v0.9.md):

- "We inherit CRS behaviour": measured on benign-wcp-v0 and attacks-ct-v0;
  blocked-set parity holds on the benign set (worst-case sym-diffs of 5-14
  per 20,000) but NOT on the attack side once the content-type policy is
  widened: ModSecurity has no body processor for text/plain and
  application/octet-stream, Coraza inspects those bodies (34-38/40 detection
  blocks vs 0). Any parity claim must now name the config (crs-default vs
  crs-ct-wide).
- "Coraza failing the CRS suite in our build" (what would change this
  decision): we have not run the CRS suite; not covered.
- Latency: coraza v3.7.0 has a PROVEN engine-internal body-processing
  pathology (44 s on a 477 KB text/plain body, reproduced in-library with no
  connector). This is direct evidence relevant to "evidence that its
  performance cannot meet the latency target" — it is one pathological shape,
  not a benchmark; test A6 remains undone.
- SecRequestBodyNoFilesLimit is not enforced by coraza v3.7.0 (proven
  in-container and in-library). Accepted as a documented engine difference
  (instructor answer 2026-11-20); it becomes an acceptance criterion for our
  own engine: our limits must be explicit, enforced, and provable from inside
  the running container.
