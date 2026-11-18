# CRS baseline v0 — first full false-positive baseline

> see v0.1: docs/baseline-v0.1.md (paranoia verified, policy/detection split,
> policy-aligned config; the numbers below are unchanged and still valid for
> the crs-default config at effective blocking PL1).

Engine **On** (blocking), OWASP CRS 4.25.2-nginx-lts (`owasp/modsecurity-crs:4.25.2-nginx-lts`),
Juice Shop v20.4.0 target. Rule 13 hygiene on every run: container force-recreated,
runner `--workers 1`, one run per log capture. Frozen dataset SHA-256s recorded in
each run's `run.json` (`manifest_sha256`).

## Datasets (frozen, never edited after blocking results)

| dataset | samples | SHA-256 (manifest.jsonl) |
|---|---|---|
| `data/benign-browse-v0` (natural browsing, Playwright) | 214 | `20fe88df3152c43dd8312fe16e835a6de432e01f14dd5e191f0933ca1d4de8b1` |
| `data/benign-hard-v0` (hand-authored hard benign) | 180 | `65bdfc69022c5b026815acacd033d1e005fadc9c2e7000745614bd903a01d78b` |

## ⚠️ Rule 14: the two rates below are NEVER merged or averaged

`benign-browse-v0` is natural traffic; `benign-hard-v0` deliberately overstates the
FP rate. They answer different questions and are reported separately everywhere.

## Results — natural browsing (benign-browse-v0)

Per-request FP rate (unstratified, PL1 and PL2 gave identical blocking):

| blocked (FP) | 34/214 | 15.89% | 95% Wilson 11.60% – 21.38% |

Per-endpoint FP rate (only endpoints with ≥1 block; 64 of 68 distinct endpoints had zero blocks):

| endpoint | blocked/samples | FP rate | 95% Wilson |
|---|---|---|---|
| POST /socket.io | 20/20 | 100.00% | 83.89% – 100.00% |
| PUT /rest/products/{id}/reviews | 10/10 | 100.00% | 72.25% – 100.00% |
| GET /rest/user/whoami | 2/2 | 100.00% | 34.24% – 100.00% |
| PUT /api/BasketItems/{id} | 2/2 | 100.00% | 34.24% – 100.00% |

Blocked endpoints with firing rule IDs:

- `GET /rest/user/whoami`: 932260, 949110
- `POST /socket.io`: 920420, 949110
- `PUT /api/BasketItems/{id}`: 911100, 949110
- `PUT /rest/products/{id}/reviews`: 911100, 949110

### Interpretation (natural browsing)

1. **911100 "Method is not allowed by policy"** — the baseline container's method
   policy does not allow PUT, so every legit PUT (edit review, change basket item
   quantity) is blocked. This is policy, not CRS rule logic; it would need an
   allowed-methods exclusion in a real deployment.
2. **920420 "Request content type is not allowed by policy"** — socket.io engine.io
   polling POSTs use `text/plain`; blocked by the content-type policy.
3. **932260** on `GET /rest/user/whoami` — the false positive already identified in
   step 02 (CRS rule matching a legit JWT-ish response pattern in the request path).

## Results — hard benign (benign-hard-v0) — UPPER BOUND, overstated by design

Per-request FP rate (PL1 and PL2 identical):

| blocked (FP) | 22/180 | 12.22% | 95% Wilson 8.21% – 17.81% |

Per-endpoint (both endpoints affected):

| endpoint | blocked/samples | FP rate | 95% Wilson |
|---|---|---|---|
| GET /rest/products/search | 11/90 | 12.22% | 6.96% – 20.57% |
| POST /rest/user/login | 11/90 | 12.22% | 6.96% – 20.57% |

Rule IDs on blocked samples: 930120, 932140, 932160, 932235, 932250, 932260, 932380,
934110, 942100, 949110 (PL1; PL2 adds no new blocking on this set).

## Distinct counts (rule 15)

- benign-browse-v0: 214 distinct requests = 214 distinct (method, path, query, body)
  triples; 34 distinct blocked triples.
- benign-hard-v0: 180 distinct requests = 180 distinct triples; 22 distinct blocked
  triples.
- attacks-v0 (for contrast): 1054 samples, 527 distinct payloads × 2 injection points.

## PL1 vs PL2

Blocking on both benign sets was identical at PL1 and PL2 (34/214 and 22/180). The
extra PL2 rules did not flip any benign sample.

## Limitations

1. **UI search is client-side** in Juice Shop v20.4.0: the browser sends one
   `GET /rest/products/search?q=` (empty) when the search page loads; per-term search
   requests never hit the wire, so the natural corpus contains no per-term search
   traffic. Verified via Playwright request-event logging.
2. All 20 browse sessions ran in one browser context, so browser caching collapsed
   repeated identical requests into single samples (1374 captured → 214 unique).
3. The natural corpus is asset-heavy (static files, socket.io polling); per-endpoint
   counts are small — treat per-endpoint rates as indicative.
4. The hard set overstates the natural FP rate by design (rule 14); it is an upper
   bound and a tuning-stress set, not an estimate of real traffic FP.
5. The recorder/runner duplicate-Content-Type bug (CRS 920620 on every recorded POST)
   was found and fixed during this step; the numbers above are from the fixed runner
   (`runner=content-type-fixed` label). The first (buggy) browse run blocked 81/214 —
   kept in `out/` history but superseded.
6. Sample size: 214 natural requests give a wide interval (±~5–9 pp); v1 should
   record more sessions.
