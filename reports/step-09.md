# Step 09 report

- Summary: Reconciled the review-PUT block attribution (932236+949110, not
  950100) with a dated correction in baseline-v0.3; annotated
  benign-browse-v1 with replay-status.jsonl (363/774 stateful failures) and
  reported v1 rates with and without them; verified the openappsec WCP
  legitimate set (Apache 2.0, headers+bodies present → replayable), built and
  froze benign-wcp-v0 (20,000 requests, seed 0, rule-26 audit 0/100), ran the
  reach check and 4 blocking baselines against a new neutral stub backend,
  and wrote baseline-v0.4 with a numbers-only comparison to wafplanet.
- pytest: **86 passed** (`.venv/bin/python -m pytest -q`, incl. 5 new
  tests/test_stub_backend.py).

## Task table

| task | status | evidence |
|---|---|---|
| rules 25–26 appended | done | AGENTS.md commit "step-09: rules 25-26" |
| T1 review-PUT attribution | done | audit entries below; dated correction in docs/baseline-v0.3.md |
| T2 replay-status.jsonl | done | data/benign-browse-v1/replay-status.jsonl; rates below |
| T3 WCP verification | done | docs/corpus-sources.md; census docs/logs/wcp-census.json |
| T4 preregistration | done | docs/plan-benign-wcp-v0.md (committed before build/run) |
| T5 stub backend | done | tools/stub_backend.py, deploy/compose.yml BACKEND wiring, 5 tests; in-container check below |
| T6 build/audit/reach/freeze/baseline | done | data/benign-wcp-v0 (SHA c8ce11f2…), 4 runs in out/benign-wcp-v0-* |
| T7 docs | done | docs/baseline-v0.4.md, README.md, docs/acceptance.md |

## T1 — review-PUT attribution (raw evidence)

Blocked review-PUT samples, identical in both runs
(`out/benign-browse-v1-pl2-aligned-ua` and
`out/benign-browse-v1-pl2-aligned-v2-ua`), from each run's audit.jsonl:

- `browse-b2ab9d80fd8a`, `browse-55bd9916b08b`, `browse-589725d2df33`
  — all `PUT /rest/products/1/reviews`, status 403:
  - rule **932236** "Remote Command Execution: Unix Command Injection
    (command without evasion)" (REQUEST-932-...RCE.conf line 1679, severity
    CRITICAL, tag paranoia-level/2; matched `ARGS:json.message`, matched data
    `time and well ` within "Good value for the money, arrived on time and
    well packed." — from the raw docker-logs entry, which carries the match
    data that audit.jsonl omits)
  - rule **949110** "Inbound Anomaly Score Exceeded (Total Score: 5)"

Verdict: the step-07 report's "950100 + 949110" attribution was **wrong**
(950100 is the phase-3 500-status rule and appears nowhere in these
entries); the step-08 aligned-v2 table (932236 + 949110) is correct. Both
runs agree, so both are right about the rules; only step-07's attribution
was wrong. Dated correction added to docs/baseline-v0.3.md, old text kept.

## T2 — replay-status.jsonl (raw evidence)

Built from `out/benign-browse-v1-pl1-aligned-v2-ua/outcomes.jsonl`;
`stateful_failure = (400 ≤ replay_status < 600) and not blocked`. Manifest
and MANIFEST.sha256 untouched (additive file only).

Stateful failures per endpoint (only non-zero rows, distinct endpoints):

| endpoint | failures/total |
|---|---|
| GET /socket.io | 103/286 |
| POST /socket.io | 60/60 |
| GET /api/BasketItems/{id} | 60/60 |
| PUT /api/BasketItems/{id} | 60/60 |
| POST /api/Users | 30/30 |
| DELETE /api/BasketItems/{id} | 30/30 |
| POST /api/BasketItems | 20/30 |
| **total** | **363/774** |

v1 FP rates, crs-policy-aligned-v2 (denominator 774; errors: none of the
flagged samples were runner errors, so best=worst for errors):

| PL | all samples | excluding stateful_failure samples (n=411) |
|---|---|---|
| PL1 | 4/774 = 0.52% (0.20–1.32) | 4/411 = 0.97% (0.38–2.48) |
| PL2 | 7/774 = 0.90% (0.44–1.85) | 7/411 = 1.70% (0.83–3.47) |

The rate excluding stateful failures is HIGHER because every stateful
failure replayed as waf_pass; no sample is removed from the headline
denominator (rule 21) — the second column is a secondary lens only.

## T3 — WCP verification (raw evidence)

- Repo clone: `data/external/waf-comparison-project`, HEAD
  `8ec8263eebba76816601f7c7052f8ffb83e31312` (2026-02-11), Apache 2.0
  LICENSE. Recorded in docs/corpus-sources.md.
- Dataset: `legitimate.zip`, 1,203,983,791 bytes, SHA-256
  `58faee18c54229759287a574f6f8cb1e3b951fa135e403ea9a679d2b18efd778`.
  First download truncated at 792,576,000 bytes (no zip central directory);
  resumed via byte-range and verified. Fetch script committed:
  tools/fetch/fetch_wcp_legitimate.sh (zip itself not committed).
- Format (measured, streaming): 692 JSON files, 1,040,242 requests, every
  request has exactly `method`, `url`, `headers`, `data`; all have headers,
  240,554 have bodies (1,661,808,469 bytes). Methods: GET 741,100,
  POST 295,304, PUT 2,014, HEAD 1,311, DELETE 457, PATCH 56.
- Distinct hosts: 10,455 (top: www.facebook.com 21,183; www.google.com
  18,195). Full census: docs/logs/wcp-census.json.
- Credential census (full set, header names): Authorization/Proxy-Authorization
  in 35,738 requests; Cookie in 715,322. Value-level scan done on the built
  sample only (counts below, rule 25).
- STOP condition check: headers AND bodies present; Apache 2.0 permits
  replay/redistribution with attribution → **T4–T6 NOT blocked**.

## T4 — preregistration

docs/plan-benign-wcp-v0.md committed BEFORE any build or run (commit
"step-09: T4 preregistration for benign-wcp-v0"). Contains: seed 0, 20,000
requests, stratified by the 692 site files with ≤2% (400) per site;
credential handling (values dropped, names kept, recorded); distinct
endpoint/host counts to be reported; rule 26 audit; neutral backend (T5);
no sample selected/removed based on any WAF result; malicious set not used.

## T5 — stub backend (raw evidence)

- tools/stub_backend.py: stdlib ThreadingHTTPServer, 200 + fixed HTML for
  GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS, any path.
- deploy/compose.yml: `BACKEND` now overridable (default unchanged:
  `http://target:3000`); new `stub-backend` service, image
  `python:3.12-alpine` (digest
  `sha256:c5ba3deef00c7758561a0f03c26f44f10589263d40e732b8748e0d1f38f6dd89`).
- Tests: 5 new in tests/test_stub_backend.py, no Docker.
- In-container verification (through the baseline, after `docker compose up`
  with BACKEND=http://stub-backend:3000):
  `GET/POST/PUT/DELETE http://localhost:8081/any/path?q=1` → `200 200 200 200`;
  body fetched via curl shows the stub HTML; stub container log empty (no
  errors).

## T6 — build, audit, reach check, freeze, baseline (raw evidence)

Build (docs/logs/build_wcp.log):

```
scanned 1040242; distinct 765231; duplicate tuples dropped 275011
allocation done; max per site 258 (cap 400); sites used 690
sampled 20000 global indices
manifest sha256: c8ce11f26406df96d55e5a1cc6186bcbf648cb29bd628081dd834c6ccf1329d1
credential scan: {'cookie header value dropped': 13266, 'authorization header value dropped': 528, 'email-like string in body': 162, 'API-key-like query parameter': 372, 'email-like string in a header value': 6}
distinct hosts in sample: 3038
endpoint classes: {'static': 5807, 'api': 2523, 'page': 11670}
BUILD OK
```

Rule 26 label audit (before any WAF run): seeded 100 ids
(`random.Random(0).sample` over sorted ids), each manually read. **0/100
look mislabelled.** Characterization: large tracker/analytics share; two
binary/compressed bodies (wcp-38 connatix, wcp-45 quantummetric); one raw
UUID edge host (wcp-96). An audit of 100, not a proof.

Reach check (rule 13: one run, container force-recreated, --workers 1;
DetectionOnly PL1 vs stub):

```
crs_audit: 3887 audit entr(ies) -> out/benign-wcp-v0-reach/audit.jsonl
proxy_reject: 5
waf_pass: 19994
waf_would_block: 3840
```

Runner summary: total_samples 19999 (one sample pre-quarantined, see
deviations), responses_ok 19999, error_count 0. Reach failures =
5 × proxy_reject, all status 414 (URI too long, nginx error page):
wcp-0a215302467a, wcp-ea0a05ccb67e, wcp-5f05329756d9, wcp-9f8b37ae80d7,
wcp-005b0edbf82b. Quarantined to
out/benign-wcp-v0-reach-quarantine.jsonl (rule 12); baseline denominator
19,994. NOTE: out/ is gitignored; the quarantine list is reproduced in this
report and the counts are committed here — the five ids above ARE the file
contents.

Baseline runs (each with fresh container, verified in-container:
`B=$BLOCKING_PARANOIA D=$DETECTION_PARANOIA P=$PARANOIA E=$MODSEC_RULE_ENGINE`
printed per run in docs/logs/wcp_baselines.log; e.g. "B=2 D=2 P=2 E=On"):

| run | blocked/total | FP rate (Wilson 95%) | errors |
|---|---|---|---|
| default PL1 | 3,823/19,994 | 19.12% (18.58–19.67) | 0 |
| default PL2 | 8,949/19,994 | 44.76% (44.07–45.45) | 0 |
| aligned-v2 PL1 | 6,558/19,994 | 32.80% (32.15–33.45) | 0 |
| aligned-v2 PL2 | 10,183/19,994 | 50.93% (50.24–51.62) | 0 |

Errors = 0 in all runs → best case = worst case (rule 20/21); the
conservative headline number is the rate itself.

Rule 18 confound check (≥20% of all audit entries per run):

- aligned PL1 & PL2: 920420 in 6,075/19,994 = **30.4%** → CONFIG-MISMATCH
  (rule 24): the corpus exercises content types the Juice Shop-derived
  allow-list forbids.
- default PL2: 931130 in 4,502/19,994 = **22.5%** (detection rule; fires on
  URLs embedding full URLs, common in tracker query strings). Not a config
  mismatch; reported as confound.
- default PL1: none ≥20%.

Blocked-rule composition (non-threshold rules per blocked request;
threshold rules 949110/959100/950100 excluded; classes per
docs/rule-classes.md):

| run | policy-only | detection-only | both | neither |
|---|---|---|---|---|
| default PL1 | 3,045 | 661 | 97 | 20 |
| default PL2 | 2,326 | 4,409 | 2,214 | 0 |
| aligned PL1 | 5,800 | 325 | 433 | 0 |
| aligned PL2 | 3,495 | 2,828 | 3,860 | 0 |

Top blocked-rule combinations (counts): default PL1 — (policy) 2,933,
(detection) 489; default PL2 — (detection) 2,419, (policy) 2,229,
(detection+policy) 813; aligned PL1 — (policy) 5,654, (detection+policy)
299, (detection) 271; aligned PL2 — (policy) 3,375, (detection) 1,706,
(detection+policy) 1,538.

Top 10 detection rules by blocked-request count:

- default PL1: 943110 (157), 932370 (121), 942290 (112), 932235 (96),
  942100 (75), 942550 (67), 932130 (49), 931120 (45), 930120 (36),
  933135 (24)
- default PL2: 931130 (4,502), 942430 (2,289), 942200 (1,859), 942340 (981),
  942370 (908), 942120 (654), 932271 (516), 932200 (493), 932236 (368),
  942330 (347)
- aligned PL1: same top-10 as default PL1 (identical counts — the aligned
  config changes only policy rules).
- aligned PL2: 931130 (4,502), 942430 (2,354), 942200 (1,859), 942340 (981),
  942370 (908), 942120 (654), 932271 (516), 932200 (493), 932236 (368),
  942330 (347)

Top policy rule: 920420 (2,931 default PL1; 6,075 aligned runs) — verified
in-image as paranoia-level/1, severity CRITICAL (one hit blocks). The
aligned content-type list is narrower than the image default, which is why
aligned blocks MORE than default on this corpus.

Per-endpoint / per-host / per-class tables: committed full JSON at
docs/logs/wcp-baseline-breakdown.json; summary in docs/baseline-v0.4.md
(16,735 distinct endpoints; per-class and top-host tables there).

## T7 — docs

- docs/baseline-v0.4.md written (numbers-only comparison with wafplanet
  29.7% PL1 CRS nightly; every setup difference listed; no numeric targets).
- README.md and docs/acceptance.md counts updated only.

## Deviations from instructions

1. The zip download was truncated on the first attempt (792,576,000 bytes);
   resumed with byte-range and verified against the server's content-length.
2. The full 7.3 GB extraction does not fit on this machine's 25 GB volume
   (it hit 100% mid-extraction; the partial extraction was deleted). The
   dataset is streamed from the zip instead; nothing else about the build
   changed. The volume was also full of unrelated caches; ~5.2 GB was freed
   (npm cache, .hermes, .udocker, .strix) at the user's direction.
3. Audit-log capture: `docker logs` captures were repeatedly corrupt
   (interleaved writes of large-bodied audit entries and nginx error lines
   containing raw multi-line bodies → unparseable `{"transaction"` lines, on
   which crs_audit correctly exits non-zero per rule 13). Changed the
   capture to an in-container audit file (`SecAuditLog`) copied with
   `docker cp`, documented in docs/baseline-config.md BEFORE use (rule 17).
   No CRS rules or levels changed. A bind-mount implementation failed
   because this machine's volume is read-only inside containers; the
   in-container `sed` + `nginx -s reload` mechanism is documented instead.
4. One sample (wcp-6b0bf5e43122) has a header value that is not latin-1
   encodable, which crashes the runner (http.client). It was quarantined
   (named file + reason) rather than changing kortex_eval behaviour (see
   Questions). Reach run 1 (before this quarantine) crashed with
   UnicodeEncodeError and was rerun after the pre-scan.
5. The 5 proxy_reject reach failures (414 URI-too-long) are quarantined per
   the plan; the quarantine file lives in gitignored out/, so its contents
   (5 ids) are reproduced verbatim in this report.
6. GitHub push protection blocked the push: the third-party-derived dataset
   contains credential-shaped strings (it flagged an "Amazon AWS Secret
   Access Key" pattern in a reCAPTCHA site-key URL; the sample also carries
   16 AWS-access-key-shaped, 234 Google-API-key-shaped and 121 JWT-shaped
   strings — counts only, rule 25). Resolution: manifest.jsonl and
   annotations.jsonl are NOT committed (gitignored); the committed artefacts
   are the fetch script, the deterministic builder, sample-plan.json (every
   chosen global index), MANIFEST.sha256, README and the build/census logs.
   Reproducibility verified by rebuilding from the committed plan: the
   rebuild produced manifest SHA-256 c8ce11f2... identical to the frozen
   dataset (byte-for-byte). The WAF runs were executed against the identical
   local dataset, so all numbers stand. docs/logs/wcp-baseline-breakdown.json
   was regenerated with endpoint keys stripped of query strings for the same
   reason (full endpoints reproducible from the dataset).

## UNVERIFIED items

- The vendor's claim that all WCP legitimate requests are genuine benign
  browsing (vendor-asserted; our check is the 100-request audit, rule 26).
- wafplanet setup details (engine version, sampling) — from our step-08
  notes, not re-verified against the source this step.
- Whether the 275,011 dropped duplicate tuples are "true duplicates" in any
  semantic sense beyond identical content tuples — they are identical by
  construction of the dedupe key.

## Questions for instructor

1. kortex_eval.runner crashes (UnicodeEncodeError, latin-1) on samples whose
   header names/values or request lines contain non-latin-1 characters. May
   a future step harden the runner to record a per-sample error row instead
   of aborting the run?
2. 920420 (content-type policy, PL1, CRITICAL) is the dominant blocker on
   WCP data, and the Juice Shop-derived aligned allow-list makes things
   WORSE out-of-sample (32.80% vs 19.12% PL1). Should a future step consider
   per-backend content-type policy, or is the aligned config frozen as-is
   for comparisons?
3. The WCP sample retains 372 API-key-like query parameters and 168
   email-like strings (counts only, values unmodified except dropped
   auth/cookie values). Keep as-is (traffic shape) or scrub in a v1 of this
   dataset?
4. 931130 fires on 22.5% of default-PL2 audit entries (URLs embedding full
   URLs in tracker query strings). Any instruction on how to treat
   detection-rule confounds beyond reporting them?
