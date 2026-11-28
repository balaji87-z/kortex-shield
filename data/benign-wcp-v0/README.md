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

Correction (step-22, 2026-11-27; the dataset itself is unchanged): the
sentence above holds for the builder as it was when this dataset was frozen,
not for tools/build_benign_wcp.py at HEAD, which changed in steps 13 and 19.
Checked on 2026-11-27 with the zip of the recorded SHA-256:

- builder from commit 71cb753 (`git show 71cb753:tools/build_benign_wcp.py`):
  manifest SHA-256 c8ce11f26406df96d55e5a1cc6186bcbf648cb29bd628081dd834c6ccf1329d1,
  equal to MANIFEST.sha256;
- builder at HEAD (6e2b666): 39830d0a819467f301f2ae0e261626f5f9982a53b4fb61aa232dab588a05fdb7,
  not equal.

To rebuild this version, use the builder from 71cb753.

## replay-defects.jsonl (added step-13, additive annotation only)

One line per (id, defect): `{"id": ..., "defect": ...}` — no request values.
The frozen manifest is NOT modified; this file only annotates replay-relevant
defects of v0 samples, derived from the manifest itself:

- gzip_header_mismatch (19): a Content-Encoding header is recorded but the
  stored body is the DECODED text; replay sends header+decoded body and the
  engine's decoder fails (the 10 step-12 "replay_artifact" status-400 samples
  are all in this class).
- recorded_cl_mismatch (653): recorded Content-Length differs from the encoded
  byte length the runner actually sends. Metadata-only (the runner sends
  len(encoded bytes) and drops the recorded CL); 10 of the 17 step-10
  status-400 samples are among these, but the mismatch does not cause the 400s
  (step-11 T3 recheck).
- non_latin1 (1): a header name, header value or request-line not latin-1
  encodable; http.client cannot send it (wcp-6b0bf5e43122, the runner-side
  encoding error).
- body_over_131072 (32): encoded body larger than ModSecurity's effective
  SecRequestBodyNoFilesLimit 131,072.
- json_members_over_1000 (42): JSON body with more than 1,000 members
  (recursive count, same measure as tools/forensic_status400.py); the 5
  step-12 "unknown" status-400 samples (200007) are in this class.
- uri_too_long (5): path+query > 8,190 bytes; nginx rejects 414 at the reach
  check (the 5 quarantined ids).

700 of 20,000 samples carry at least one defect. Label meaning (rule 11):
"defect" means "this recorded property differs from what a replay sends or
from what the engine limits allow", NOT "the sample is unusable" — rates
computed with and without defect samples are reported separately in the
step-13 report (rule 14/20 hygiene).
