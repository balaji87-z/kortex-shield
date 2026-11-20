# Plan: encoding differential (step-14 T4) — PREREGISTERED before any run

Status: written and committed BEFORE building the manifest or running any
request (AGENTS.md rule 22). Nothing in this file may be changed after
results are seen; corrections go in docs/baseline-v0.9.md as dated notes.

## Question

Do ModSecurity and Coraza decode the same encodings the same way, and does a
difference change what CRS detects? We measure blocked/not-blocked only; no
verdict on which engine is "right".

## Dataset: encoding-diff-v0 (frozen manifest, rule 10)

- Base payloads: the first 4 payloads (alphabetical by id) of each family's
  10 already-frozen T2 selections in docs/plan-attacks-ct-v0.md (families:
  sqli, xss, path-traversal, command-injection). No new randomness.
  NOTE (work-order discrepancy, recorded before the build): the work order
  says "12 base payloads (4 per family, seeded)", but 4 families x 4 = 16.
  We follow the more specific "4 per family" and build 16 base payloads;
  the discrepancy is flagged in reports/step-14.md. 16 payloads x 6
  encodings x 2 carriers = 192 samples.
- 6 encodings of the raw payload text (UTF-8 bytes of the payload):
  1. `plain` — payload bytes verbatim, no encoding.
  2. `single-pct` — every byte percent-encoded, uppercase hex.
  3. `double-pct` — the `single-pct` form with every `%` replaced by `%25`
     (i.e. percent-encoding applied twice).
  4. `pct-u` — every UTF-16 code unit of the payload as `%uXXXX`
     (uppercase hex; BMP only; this is the IIS-style `%u` encoding).
  5. `mixed-case-hex` — every byte percent-encoded with hex digits
     alternating lower/upper case by position (first byte lowercase,
     second uppercase, ...).
  6. `overlong-utf8` — every ASCII byte b encoded as the 2-byte overlong
     sequence `%C0%XX`-style: byte1 = 0xC0 | (b >> 6), byte2 = 0x80 | (b & 0x3F).
- 2 carriers:
  - `query` — GET, raw form `/?q=<encoded>` (for `plain` the payload is
    inserted verbatim; `&`, `#`, spaces etc. are left raw on purpose — that
    IS the encoding being tested).
  - `urlencoded` — POST, body `q=<encoded>`, Content-Type
    `application/x-www-form-urlencoded`.
- 16 payloads x 6 encodings x 2 carriers = 192 samples.
- Sample id scheme: `encd-<carrier>-<encoding>-<base payload id>` where base
  payload id is the T2 base (e.g. `encd-query-overlong-utf8-sqli-6e47f23b`).
- Labels: `attack` (all samples are attack payloads by construction; rule 11
  note: "attack" means listed in the source family, not verified exploitable).
- Stub backend as target (local testbed only, rule 6).
- Freeze: `tools/build_encoding_diff.py` writes
  `data/encoding-diff-v0/manifest.jsonl` and `MANIFEST.sha256`; both are
  committed before the first run. After results are seen the manifest is
  never edited (rule 10).

## Runs

- Engines: ModSecurity (port 8081, image digest as in step-13) and Coraza
  (port 8082, digest bfbfe70b...). Config: crs-default only (no ct-wide
  interaction here).
- Paranoia: PL1 and PL2 (blocking=detection=PL per run).
- 4 cells x 192 samples = 768 requests.
- Rule 13: fresh container per run (compose down + up --force-recreate,
  runner --workers 1).
- Rule 29: rule-29 line printed from inside each container into the run log.
- Rule 36: 20 control requests (`/?audit-ctl=%27%20OR%201%3D1--`, matches
  942100) before and 20 after each run; audit entry counts printed in the
  run log.
- Raw logs committed under docs/logs/step14-t4-*.txt.

## Analysis (stated before the runs)

- Per cell: blocked count out of 192, and blocked counts per encoding and
  per carrier (counts, not rates across carriers — rule 35 note applies:
  this set is chosen to probe encodings, not sampled traffic).
- Disagreement cells: samples where the engines' blocked outcomes differ,
  listed per sample id with each engine's outcome.
- "Which side decodes" attribution: stated only where PROVEN (from engine
  documentation or an in-container experiment); otherwise HYPOTHESIS.
- No rates across encodings, no engine verdict.
