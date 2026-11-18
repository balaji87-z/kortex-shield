# Baseline v0.4 — WCP legitimate sample (step-09)

New benign dataset: `data/benign-wcp-v0` (20,000 requests sampled from the
openappsec WAF Comparison Project legitimate set; plan preregistered in
docs/plan-benign-wcp-v0.md; frozen at manifest SHA-256
`c8ce11f26406df96d55e5a1cc6186bcbf648cb29bd628081dd834c6ccf1329d1`).

This is the first OUT-OF-SAMPLE benign corpus for both configs: the requests
come from 692 real-world websites, not Juice Shop, and were not used to tune
anything. Backend: neutral stub (tools/stub_backend.py) returning 200 for
everything, so every block is attributable to the WAF alone. Errors: 0 in all
four runs, so best case = worst case for every rate below (rule 20/21).
Denominator: 19,994 samples (20,000 minus 1 quarantined non-latin-1 sample
and 5 quarantined proxy_reject reach failures — both named in
out/benign-wcp-v0-reach-quarantine.jsonl; nothing silently dropped, rule 12).

## False-positive rates (blocking mode, per request)

| config | PL1 | PL2 |
|---|---|---|
| crs-default | 3,823/19,994 = **19.12%** (Wilson 18.58–19.67) | 8,949/19,994 = **44.76%** (44.07–45.45) |
| crs-policy-aligned-v2 | 6,558/19,994 = **32.80%** (32.15–33.45) | 10,183/19,994 = **50.93%** (50.24–51.62) |

Per endpoint class (default / aligned, PL1):

| class | crs-default | crs-policy-aligned-v2 |
|---|---|---|
| page | 2,808/11,664 = 24.07% | 4,544/11,664 = 38.96% |
| static | 141/5,807 = 2.43% | 167/5,807 = 2.88% |
| api | 874/2,523 = 34.64% | 1,847/2,523 = 73.21% |

Per-host and per-endpoint tables: docs/logs/wcp-baseline-breakdown.json
(16,735 distinct endpoints; e.g. default PL1: 76 endpoints fully blocked
with ≥5 requests; aligned PL1: 148).

## Blocked-rule composition (non-threshold rules per blocked request)

| run | policy-only | detection-only | both | neither |
|---|---|---|---|---|
| default PL1 | 3,045 | 661 | 97 | 20 |
| default PL2 | 2,326 | 4,409 | 2,214 | 0 |
| aligned PL1 | 5,800 | 325 | 433 | 0 |
| aligned PL2 | 3,495 | 2,828 | 3,860 | 0 |

Top blocked-rule combinations and top 10 detection rules per run are in
reports/step-09.md. Top policy rule overall: 920420 "Request content type is
not allowed by policy" (paranoia-level/1, CRITICAL — one hit blocks):
2,931 blocked requests carry it in default PL1 and 6,075 in aligned runs
(the aligned Juice Shop content-type list is narrower than the image default,
so it blocks MORE on this corpus). Top detection rules: 931130 (PL2), 942430,
942200, 942340, 942370.

## Rule 18 confound check (≥20% of all audit entries)

- aligned PL1 and PL2: **920420 in 30.4%** of all entries — the corpus
  exercises content types the aligned config forbids → **CONFIG-MISMATCH**
  (rule 24): the allow-list was derived from Juice Shop traffic and does not
  describe WCP traffic.
- default PL2: **931130 in 22.5%** of all entries (detection rule, RCE/RFI
  family; fires on URLs embedding full URLs, common in tracker/analytics
  query strings). Not a config mismatch; reported as a confound.
- default PL1: no rule ≥20%.

## Rule 19 (in-sample / out-of-sample labelling)

- crs-default: no component was derived from any benign dataset → this
  result is out-of-sample by construction.
- crs-policy-aligned-v2: methods and content types were derived from Juice
  Shop traffic (v0/v1) → on WCP data this config is **OUT-OF-SAMPLE**, and
  the result shows it generalizes badly (32.80% vs 0.52% on benign-browse-v1).

## Numbers-only comparison with a published result (no interpretation)

| | this project (v0.4) | wafplanet 2026 (docs/published-crs-results.md) |
|---|---|---|
| benign FPR, PL1, CRS | 19.12% (crs-default, n=19,994) | 29.7% |
| CRS version | 4.25.2-nginx-lts (pinned) | CRS nightly (2026) |
| Engine | ModSecurity v3.0.17 / nginx connector | per their setup (not stated in our notes) |
| Benign traffic | 20,000 requests sampled from openappsec WCP legitimate set (692 real sites, seeded, stratified) | ~4,500 "real browsing" requests from WCP + 95 CVE payloads in the benign stream |
| Label source | vendor-asserted legitimate (rule 11 meaning) | their harness definition (per our notes; UNVERIFIED details) |
| Backend | neutral stub, always 200 | their target applications (not stated in our notes) |
| Sampling | seeded 1-in-38 of the deduplicated set; no site >2% | not stated in our notes |
| Paranoia | PL1 = PL2 = 1 pinned explicitly | not stated in our notes |

Setup differences are listed, not adjusted for. No numeric targets are set
anywhere in this document.

## Relation to earlier baselines

- benign-browse-v0/v1 and benign-hard-v0 numbers (v0–v0.3) are unchanged and
  remain in their documents. This document adds a new, external, out-of-sample
  benign corpus; it does not revise them.
- The step-07/08 open question "does the aligned config generalize?" is now
  answered numerically: no (32.80% PL1 out-of-sample vs 0.52% in-sample on
  benign-browse-v1).
