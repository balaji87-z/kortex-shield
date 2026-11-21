# Plan: benign-wcp-v1 (preregistered before build or run — rule 22)

Written 2026-11-21, step-19 T4. Nothing below has been run yet. After this
plan is committed, the dataset is built exactly as specified; deviations get
recorded in reports/step-19.md, never silently.

## Purpose

Test the step-18 T4 final scope (REQUEST-930..944 REQUEST_BODY targets, 166
rules, REQUEST-921 excluded) on UNSEEN benign traffic — unseen for that
choice (rule 45). benign-wcp-v0 is IN-SAMPLE for the scope choice (its
first-pass run motivated the REQUEST-921 exclusion); benign-wcp-v1 is
held-out for it.

## Source

- Same zip as v0: openappsec WCP `legitimate.zip`, SHA-256
  `58faee18c54229759287a574f6f8cb1e3b951fa135e403ea9a679d2b18efd778`
  (verified before build; recorded in docs/corpus-sources.md). Apache 2.0.
- Streamed; never extracted to disk.

## Sample definition (deterministic, seed 1)

1. Same global ordering and content-tuple dedupe as v0 (builder
   tools/build_benign_wcp.py at the step-19 commit; the step-13 T2 fixes
   and the step-19 A1 publishable-token scrub apply — they are part of the
   current builder).
2. Stratified sample of **10,000 distinct requests, seed 1**, strata = the
   692 site files, allocation proportional with minimum 1 per non-empty
   stratum, capped at **2% of 10,000 = 200** requests per site (freed
   capacity redistributed as in v0).
3. **Disjointness from v0**: the global indices chosen by v0
   (data/benign-wcp-v0/sample-plan.json) are EXCLUDED from the v1 sampling
   frame before `random.Random(1).sample`; ids are content hashes, so id
   disjointness follows from index disjointness.
4. No sample is selected, removed, or edited based on any WAF result,
   before or after freezing.

## Credential and personal-data handling (rule 25)

- As v0: `Authorization`, `Proxy-Authorization`, `Cookie` header values
  replaced with `[DROPPED]`; dropped-cookie markers canonicalized to
  lowercase (step-13 T2); Content-Encoding headers dropped when the stored
  body is decoded (step-13 T2); email-like strings COUNTED (reported), not
  modified; API-key-like query parameters COUNTED (reported), not modified.
- NEW (step-19 A1): publishable-token shapes (pk./sk. JWT-like, e.g. the
  Mapbox tokens found in v0) are REDACTED in query/body/header values; the
  count is reported in the dataset README.

## Commit policy (push protection)

- COMMITTED: this plan, `data/benign-wcp-v1/sample-plan.json` (global
  indices only, no content), `data/benign-wcp-v1/MANIFEST.sha256`, the
  builder, the dataset README.
- NOT COMMITTED: `manifest.jsonl` and `annotations.jsonl` (WCP external
  traffic contains personal data / token shapes; rule 25 and the step-18
  push-protection incident). They exist locally for the runs; the
  MANIFEST.sha256 + sample-plan allow exact reconstruction.

## Freeze

The dataset is frozen when the SHA-256 of manifest.jsonl is written to
`data/benign-wcp-v1/MANIFEST.sha256` (and quoted in reports/step-19.md).
After that no sample may be added, removed or edited (rule 10).

## Runs (after freeze)

- PRE engine (worktree 1964793) and POST engine (step-18 final, 166
  updates), each at PL1 and PL2, **TWICE each** (run-to-run disagreement
  measurement) = 8 runs, workers 1, one log capture per run, rule-29
  config proof per run, artifacts preserved under docs/logs/runs/ (rule 42).
- Connector (coraza-crs container, pinned digest) at PL1 and PL2 — 2 more
  runs (step-19 addendum A2).
- UA contract unchanged; same runner contract as step-18.

## Analysis (pre-registered)

- New blocks = POST-blocked minus PRE-blocked ids, per PL, with rule IDs.
- How many new blocks appear in BOTH post runs (stable) vs one run only
  (flip-suspect, given the PROVEN coraza cache defect).
- Run-to-run disagreement of the SAME binary: ids blocked in run 1 but not
  run 2 and vice versa.
- Timeouts (fail-closed 503) counted.
- Classification of new blocks by rule family and by content type.
- Comparison with v0's new-block counts (side by side, counts only,
  rule 35; no rates of traffic; the word "gain" is forbidden — rule 46:
  these are NEW BLOCKS, potential false positives).
- No tuning: no config, scope or target change may result from these runs.
