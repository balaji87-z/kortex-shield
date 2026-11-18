# CRS baseline v0.3 — benign-browse-v1 (60 sessions), out-of-sample check

Supplements `docs/baseline-v0.2.md` (whose numbers stand). New here: the
per-family denominator correction (see the dated correction in v0.2), the
benign sample-level diff, and `benign-browse-v1` — 60 Playwright sessions
(indices 1000–1059, preregistered in `docs/plan-benign-v1.md`) with the v1
flows (review edit, basket quantity change, basket item removal, log
out/in). Theme switch is not drivable (no UI control); language switch was
dropped before recording (menu never renders under Playwright — deviation
recorded in the plan and in `reports/step-07.md`).

## Dataset

- `data/benign-browse-v1`: 774 unique samples, 68 distinct endpoints,
  60 sessions; manifest SHA-256
  `950a683bf776ef637691514f1dab809fddd2de757bacdff3dc9cb1f30af3b085`.
- `sessions.jsonl` maps every sample id to all session indices that
  produced it, so dedupe no longer erases the session dimension.
- Reach check (DetectionOnly PL1, fresh container, rule 13): 774/774
  reachable; 0 proxy_reject / inconsistent / error; nothing excluded.
  184 samples would-block under DetectionOnly (kept; reported below).

## Benign sample-level diff, step-05 (no UA) vs step-06 (UA fixed)

For all four dataset/PL/config comparisons the inbound-blocked sets are
identical: **+0/−0 everywhere** (benign-browse-v0 and benign-hard-v0, PL1
and PL2, crs-default and crs-policy-aligned). The only change is
classification: the 18 benign-hard PL2 rows that step-05 reported as
`error` are now `waf_block_outbound` (they count only in the worst case,
rule 21).

## v1 through the baseline (UA fixed, rule 13, container parity verified per run)

Denominator = 774 (full manifest). No errors, no outbound cuts in any run,
so best case = worst case (rule 20). 95% Wilson intervals.

| PL | config | blocked | rate |
|---|---|---|---|
| 1 | crs-default | 184/774 | 23.77% (20.91–26.90) |
| 1 | crs-policy-aligned **(OUT-OF-SAMPLE)** | 34/774 | 4.39% (3.16–6.08) |
| 2 | crs-default | 184/774 | 23.77% (20.91–26.90) |
| 2 | crs-policy-aligned **(OUT-OF-SAMPLE)** | 37/774 | 4.78% (3.49–6.52) |

**The aligned config does not fully generalize.** On v0 (in-sample) it
scored 0.93% PL1; on v1 (out-of-sample) 4.39% PL1 / 4.78% PL2.

### Rule 18 check (rule IDs in ≥20% of audit entries)

- PL1/PL2 crs-default: 949110 (53–54%), 911100 (35–36%). 911100 is a
  harness artifact of the v1 flows: the corpus now intentionally exercises
  PUT and DELETE, which the default method policy blocks wholesale.
- PL1 aligned: none. PL2 aligned: 950100 (28%) — the outbound-threshold
  rule firing on 3 review-edit PUTs (see below).

### Blocked endpoints with rule IDs (all runs)

| endpoint | PL1/PL2 default | aligned PL1 | aligned PL2 |
|---|---|---|---|
| POST /socket.io (60 req) | 920420 + 949110 | – | – |
| PUT /api/BasketItems/{id} (60 req) | 911100 + 949110 | – | – |
| PUT /rest/products/{id}/reviews (30 req) | 911100 + 949110 | – | 950100 + 949110 (3/30) |
| DELETE /api/BasketItems/{id} (30 req) | 911100 + 949110 | 911100 + 949110 (30/30) | 911100 + 949110 (30/30) |
| GET /rest/user/whoami (4 req) | 932260 + 949110 | 932260 + 949110 (4/4) | 932260 + 949110 (4/4) |

Per endpoint class (PL1): default — api 124/360, socket.io 60/346, static
0/66, other 0/2; aligned — api 34/360, others 0.

### Per-session rates (via sessions.jsonl)

Every session (60/60) contains at least one blocked request in all four
runs: default because PUT/DELETE/socket.io fire everywhere; aligned because
the DELETE and whoami blocks are spread across sessions (30 DELETE samples
in the 30 registered sessions; the 4 whoami samples span the anonymous
sessions). Rate: 60/60 = 100.00% (93.98–100.00) for every run.

### Endpoints new in v1 vs v0

- `DELETE /api/BasketItems/{id}` — new (the removal flow).
- v0 had `POST /api/SecurityAnswers`, v1 does not (registration flow
  difference observed in the recordings; not investigated further).

## Saturation measurement (T5)

Cumulative distinct samples / distinct endpoints after k v1 sessions, in
recording order (v0 cannot be computed: its recording erased the session
dimension — the gap v1's `sessions.jsonl` fixes):

| sessions | distinct requests | distinct endpoints |
|---|---|---|
| 5 | 134 | 68 |
| 10 | 208 (+74) | 68 |
| 20 | 321 (+113) | 68 |
| 30 | 435 (+114) | 68 |
| 40 | 545 (+110) | 68 |
| 50 | 659 (+114) | 68 |
| 60 | 774 (+115) | 68 |

**Endpoint diversity saturates immediately** (all 68 endpoints within the
first 5 sessions). **Request-level diversity does not flatten**: each
additional 10 sessions adds ~110–115 new distinct requests (query strings,
product ids, review texts, basket item ids). Implication for the
1,400-distinct-legitimate-requests bar of `docs/acceptance.md` A2: scripted
sessions of this shape reach it by quantity (~110 more sessions), not by
saturation — the marginal value of each session is roughly constant, so
scaling is mechanical but the corpus keeps growing in surface variety only
slowly (new endpoints stopped after session 5).

## In-sample / out-of-sample statement (rule 19)

- crs-policy-aligned results on **v0** remain **in-sample** (derived from
  v0 traffic).
- crs-policy-aligned results on **v1** are **OUT-OF-SAMPLE** and are the
  first honest estimate of the config's generalization: 4.39% PL1 /
  4.78% PL2 vs 0.93% in-sample. The residual FPs are DELETE (method still
  not in the aligned allow-list — adding it would be a new config change
  requiring rule 17 documentation) and the whoami 932260 path match.
- The attack corpus still exercises no PUT/DELETE or text/plain, so
  unchanged attack recall under aligned config remains by construction.

## Limitations

1. The final recording's raw captured-request count was lost with the
   recorder log (post-dedupe counts are exact; the first attempt's
   7970 → 879 is recorded in the step-07 report as evidence of scale).
2. Log out / log in again could not be verified from the deduped data (a
   second identical login POST collapses into the first sample within the
   same session; the recorder's per-session step reports were lost with
   the log). UNVERIFIED.
3. v0 saturation curves are not computable (no session attribution).
4. No numeric targets are set anywhere in this document.
