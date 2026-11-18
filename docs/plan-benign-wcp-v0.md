# Plan: benign-wcp-v0 (preregistered before build or run — rule 22)

Written 2026-11-18, step-09 T4. Nothing below has been run yet. After this
plan is committed, the dataset is built exactly as specified; deviations get
recorded in reports/step-09.md, never silently.

## Source

- openappsec WAF Comparison Project legitimate set
  (`legitimate.zip`, SHA-256 `58faee18c54229759287a574f6f8cb1e3b951fa135e403ea9a679d2b18efd778`,
  recorded in docs/corpus-sources.md). Apache 2.0.
- The malicious set from the same project is NOT used in this step.

## Sample definition (deterministic, seed 0)

1. Read the 692 `Legitimate/browsing_*.json` members from the zip in sorted
   filename order; within each file keep array order. Give every request a
   global sequential index `0..1040241` in that order.
2. Deduplicate on the content tuple `(method, path, query, content_type,
   body)` — the same tuple kortex_eval uses for `content_hash`. The FIRST
   occurrence in the global order is kept; later duplicates are dropped and
   counted (rule 12: the count goes in the dataset README). All later steps
   operate on the deduplicated list.
3. Stratified sample of **20,000 distinct requests, seed 0**:
   - strata = the 692 site files;
   - allocation = proportional to each file's deduplicated request count,
     rounded, minimum 1 per non-empty stratum, then capped so no site
     contributes more than 2% of 20,000 (= 400 requests); freed capacity is
     redistributed proportionally to uncapped strata (repeat until stable);
   - within each stratum, requests are chosen with `random.Random(0).sample`
     over that stratum's global indices in ascending order;
   - the sampled ids are written to `data/benign-wcp-v0/sample-plan.json`
     (stratum → list of global indices) so the sample is reproducible.
4. No sample is selected, removed, or edited based on any WAF result, before
   or after freezing.

## Credential and personal-data handling (rule 25)

- Default: header VALUES of `Authorization`, `Proxy-Authorization`, and
  `Cookie` are replaced with `[DROPPED]` in the built manifest; header NAMES
  are kept. This is recorded here before the fact and again in the dataset
  README.
- On the built sample (not the full 1.04M set), a value-level scan counts
  (type and count only, nothing committed): email-like strings in URL,
  header values, and body; API-key-like query parameters
  (`(api[_-]?key|token|secret|password|apikey|access[_-]?token)=`).
- Counts go into the dataset README and reports/step-09.md.

## Label audit (rule 26)

- Before any WAF run: seeded random sample of 100 requests from the built
  manifest (`random.Random(0).sample` over sorted ids), each manually read;
  count how many look mislabelled (i.e. look like attacks or look
  machine-generated garbage rather than real browsing) and list the ids.
- Reported as "an audit of 100", not a proof.

## Reach check (rule 13)

- One run, DetectionOnly PL1, against the neutral stub backend
  (`BACKEND=http://stub-backend:3000`), container force-recreated before the
  run, runner `--workers 1`.
- Filtering: only `proxy_reject`, `inconsistent`, `error` outcomes are
  counted as reach failures. DetectionOnly cannot block, so nothing else
  disqualifies. Samples failing reach are quarantined (named file + count),
  never silently dropped.

## Baseline runs

- Backend: the stub (T5). Engine: CRS 4.25.2-nginx-lts as pinned in
  deploy/compose.yml.
- Four runs, blocking mode: {crs-default, crs-policy-aligned-v2} × {PL1, PL2},
  each with `BLOCKING_PARANOIA` and `DETECTION_PARANOIA` pinned explicitly
  (step-05 finding), container force-recreated per run, `--workers 1`.
- User agent: the requests carry recorded UA headers; the runner's
  `--default-user-agent` is used ONLY for requests lacking a UA header
  (never overrides a recorded one).
- Logs land in `out/benign-wcp-v0-*` with docker-logs captured per run
  (rule 23); crs_audit over each log.

## Reporting (rules 14, 15, 18, 19, 20, 21, 24)

- Rates per request, per endpoint, per host, per endpoint-class, with
  denominators stated; errors reported best case (not flagged) and worst
  case (flagged); headline = conservative (rule 21).
- Every blocked-rule combination with counts; share of policy-only vs
  detection blocks per docs/rule-classes.md; top 10 detection rules by
  blocked-request count.
- Rule 18 confound check per run: any rule ID in ≥20% of audit entries is
  listed and, if it fires because the corpus exercises something the config
  forbids, labelled CONFIG-MISMATCH (rule 24).
- Rule 19: crs-policy-aligned-v2 methods/content-types were derived from
  Juice Shop traffic, so on WCP data the aligned config is OUT-OF-SAMPLE.
- Endpoint-class definition (fixed here): `static` if the path's last
  segment contains a `.` suffix of 1–5 chars from a fixed asset list
  (js css png jpg jpeg gif svg woff woff2 ttf ico json xml map webp mp4);
  `api` if the path starts with `/api/` or `/rest/` or contains `/v1/`,
  `/v2/`, `/graphql`; else `page`. Third-party hosts (host not reachable as
  a "site" here) are still replayed as-is; per-host counts are reported so
  host mix is visible.

## Freeze

- After reach check passes: `MANIFEST.sha256` (SHA-256 of manifest.jsonl),
  README.md (counts, exclusions, credential handling, scan counts), and
  `annotations.jsonl` (id → endpoint, host, endpoint-class). Only then are
  baseline runs reported against the frozen SHA.
