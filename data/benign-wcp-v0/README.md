# benign-wcp-v0

20,000 legitimate HTTP requests sampled from the openappsec WAF Comparison
Project legitimate dataset, for out-of-sample WAF false-positive measurement
against a neutral stub backend. Built per docs/plan-benign-wcp-v0.md
(preregistered before build; seed 0).

## Provenance and licence

- Source: `legitimate.zip` from
  https://downloads.openappsec.io/waf-comparison-project/legitimate.zip
  (repo commit `8ec8263eebba76816601f7c7052f8ffb83e31312`, Apache 2.0).
  Fetch script: `tools/fetch/fetch_wcp_legitimate.sh`; zip SHA-256
  `58faee18c54229759287a574f6f8cb1e3b951fa135e403ea9a679d2b18efd778`.
  The zip itself is NOT committed (1.2 GB); only this derived sample is.
- Label meaning (rule 11): "benign" here means "present in the vendor's
  legitimate dataset", i.e. recorded by scripted browsing of real websites
  (vendor-asserted). It does NOT mean each request was independently verified
  as non-attack traffic. Rule 26 audit below is an audit of 100, not a proof.

## Build numbers (docs/logs/build_wcp.log)

- Scanned: 1,040,242 requests across 692 site files (matches the vendor's
  published total; the repo README says "185 sites / 12 categories" — the zip
  has 692 files and requests carry 10,455 distinct host values; we use the
  692 files as strata).
- Distinct content tuples `(method, path, query, content_type, body)`:
  765,231. Dropped as duplicates of an earlier tuple: **275,011** (rule 12:
  counted here, never silently dropped; the dropped duplicates are not
  materialised anywhere — they are the non-first occurrences in the global
  order defined in the plan).
- Sampled: 20,000 (proportional allocation across 690 non-empty strata,
  min 1 per stratum, cap 400 = 2%; largest stratum contribution 258).
  Selection: `random.Random(0).sample` per stratum over dedup-list positions;
  `sample-plan.json` records every chosen global index.

## Sample composition

- Distinct hosts: 3,038. Top: www.google.com 440, www.facebook.com 367,
  www.google-analytics.com 327, www.forever21.com 303,
  googleads.g.doubleclick.net 231.
- Endpoint classes (plan definition): page 11,670; static 5,807; api 2,523.
- Methods: see manifest; bodies present where the source had them.

## Credential and personal-data handling (rule 25)

- Header VALUES of `Authorization`, `Proxy-Authorization`, `Cookie` were
  replaced with `[DROPPED]` before writing the manifest; header names kept.
  Counts: cookie values dropped 13,266; authorization values dropped 528.
- Value-level scan of the sample (type and count only, nothing committed):
  email-like strings in URL query 0; in a header value 6; in body 162;
  API-key-like query parameters 372. These remain in the sample because they
  are part of the recorded traffic shape; none are committed anywhere except
  inside this gitignored-source-derived sample, and no credentials were
  committed (auth/cookie values are dropped).

## Label audit (rule 26) — an audit of 100, not a proof

- Seeded sample of 100 ids (`random.Random(0).sample` over sorted ids),
  manually read before any WAF run.
- Result: 0 of 100 look mislabelled (none resemble attack payloads).
- Characterisation notes (not mislabels): a large share is third-party
  tracker/analytics/ad traffic; two bodies are binary/compressed
  (wcp-38 connatix, wcp-45 quantummetric zlib); one host is a raw UUID edge
  node (wcp-96).

## Freeze

- `MANIFEST.sha256`: SHA-256 of `manifest.jsonl` =
  `c8ce11f26406df96d55e5a1cc6186bcbf648cb29bd628081dd834c6ccf1329d1`.
- Frozen 2026-11-18. After this, no sample may be added, removed or edited
  (rule 10); changes create a new version folder.

## Why manifest.jsonl and annotations.jsonl are NOT committed

The raw third-party-derived request data contains credential-like values that
GitHub push protection blocks (it flagged an "Amazon AWS Secret Access Key"
pattern in a reCAPTCHA site-key URL at annotations.jsonl:2793; the corpus
also carries 16 AWS-access-key-shaped strings, 234 Google-API-key-shaped
strings and 121 JWT-shaped strings in URLs/bodies — counts only, rule 25).
Per rule 25 the committed artefacts are instead: this README, the fetch
script (tools/fetch/fetch_wcp_legitimate.sh), the deterministic builder
(tools/build_benign_wcp.py), the exact sample selection
(sample-plan.json: seed, allocation, and every chosen global index), the
frozen manifest SHA-256 (MANIFEST.sha256), and the census/build logs. The
dataset is exactly reproducible: fetch the zip (SHA-256 checked), run the
builder — it reads sample-plan.json and reproduces the identical manifest
byte-for-byte.
