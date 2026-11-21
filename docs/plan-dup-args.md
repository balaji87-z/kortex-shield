# Plan: duplicate-argument bypass measurement (preregistered before build or run — rule 22)

Written 2026-11-21, step-20 T1. Nothing below has been run yet.

## Question

Does the duplicate-argument shape (the same parameter name appearing more
than once in the query string or in a urlencoded body) let an attack payload
pass engines that block the same payload in a single-argument shape? The
step-19 T1 flip root cause (coraza v3.7.0 transformation cache keyed by
arg pointer + map-order index) predicts intermittent passes on duplicate
names for the engine; the connector (same coraza version inside the
container) should show the same defect if the cache is active there;
ModSecurity has no such cache and is the control.

## Payloads

- Source: `data/attacks-v0/manifest.jsonl` (frozen). Families: sqli, xss,
  path-traversal, command-injection.
- Selection: `random.Random(0).sample` of 10 sample ids per family among
  the samples that have a non-empty `query` (all four families have ≥77
  such samples) → **40 payloads**. The chosen ids are fixed in
  `tools/run_step20_t1_dupargs.py` output and committed with the results.

## Shapes (8 per payload)

Let `Q` be the sample's original query string (verbatim, URL-encoded as
recorded) and `E` be `urlencode(Q)` (the whole query string encoded as one
parameter value).

Query shapes (GET, sample's own path):
- Q1 `?Q`
- Q2 `?Q&Q`  (every parameter name duplicated)
- Q3 `?q=benign&Q`
- Q4 `?Q&q=benign`

Urlencoded body shapes (POST, sample's own path,
`Content-Type: application/x-www-form-urlencoded`):
- B1 `p=E`
- B2 `p=E&p=E`
- B3 `p=benign&p=E`
- B4 `p=E&p=benign`

## Protocol

- Each of the 40×8 = 320 variants is sent **20 times** (fresh transaction
  each; sequential, workers 1) against each engine at PL1 and PL2.
- Outcome per repeat: blocked (engine's block status + marker) or passed.
- Reported number: **passes out of 20** per variant, aggregated per shape
  class (Q1..Q4, B1..B4) per engine per PL. Counts only (rule 35). The
  single-arg shapes (Q1, B1) are the baseline: a payload that never blocks
  there cannot show a duplicate-shape bypass; the bypass signal is passes
  in Q2/B2 (and Q3/Q4/B3/B4) where Q1/B1 blocks.
- UA contract as always; stub backend for the engine; in-compose
  stub-backend for the containers.

## Engines

1. **engine** — the kortex engine (current build) on 127.0.0.1:8090.
2. **coraza connector** — `deploy/compose.yml` `coraza-crs`, pinned digest
   `sha256:bfbfe70b…`, port 8082, rule-29 config proof per run.
3. **modsec control** — `baseline-crs`, pinned digest
   `sha256:6296ce68…`, port 8081, rule-29 config proof per run.

## Fix protocol (after the measurement)

- **Candidate fix 1**: bump coraza to the newest release available on the
  host (go.mod), rebuild, run `tools/flip_repro.py` 5×500 at PL1 and PL2
  and re-run this measurement. Zero flips required.
- **Candidate fix 2 (only if flips persist)**: vendored patch via go.mod
  replace that keys the transformation cache by content or bypasses it;
  commit the diff, document in engine-design.md, measure the latency cost
  on the benign datasets (counts and medians).
- **Failing Go test FIRST (rule 40)**: ≥2000 replays of a duplicate-name
  request with `runtime.GC()` between rounds, zero flips required
  (E30). The test must fail against the current build before the fix.
- After the fix: re-run flip_repro (5×500, PL1 and PL2) and this
  measurement on the fixed build.
- The connector's own bypass (same measurement on the container) states
  whether the reference shares the defect (rule 44: PROVEN needs the
  duplicate-arg measurement on the connector).
