# Step 08 report — recorder logging, crs-policy-aligned-v2, research notes

Date: 2026-11-18. Rules 23–24 appended to AGENTS.md first. No dataset
edits, no rule exclusions, no models, no engine code.

## Summary

- Recorder now writes its per-session step report and raw captured count
  to a committed path (`--log`, default `docs/logs/`); rule 23.
- Third config `crs-policy-aligned-v2` (adds DELETE to allowed methods)
  documented before running; v1 FP drops 34/774 → 4/774 (0.52%) at PL1.
- 911100 relabelled CONFIG-MISMATCH (rule 24); 950100 corrected to the
  500-status rule and its frequency explained as a stateful-replay
  artifact.
- Research notes written: published CRS numbers (10 sources) and external
  benign dataset candidates (6 candidates).

## Task table

| task | status | evidence |
|---|---|---|
| T1 recorder --log | done | §T1; tests/test_record_benign.py (7 tests) |
| T2 aligned-v2 | done | §T2; docs/baseline-config.md (rationale committed before runs) |
| T3 relabels | done | §T3; dated notes in docs/baseline-v0.3.md |
| T4 published CRS numbers | done | docs/published-crs-results.md |
| T5 external benign datasets | done | docs/external-benign-candidates.md |
| T6 README/acceptance | done | counts/statuses only |

## T1 — recorder logging (rule 23)

`tools/record_benign.py` gained `--log PATH` (default
`docs/logs/record_benign.log`): appends a run header (base_url, sessions,
start_index, extra_flows), the per-session step report (including FAILED
steps) and the raw captured-request count. Additive; nothing re-recorded.
Tests: `test_write_run_log_appends_session_report_and_raw_count`,
`test_default_log_path_is_committed_dir_not_tmp`. `docs/logs/README.md`
placeholder committed. Full suite: 81 passed.

## T2 — crs-policy-aligned-v2

Rationale committed to docs/baseline-config.md BEFORE any run: identical
to crs-policy-aligned plus `DELETE` in `ALLOWED_METHODS`
(`GET HEAD POST OPTIONS PUT DELETE`), because v1 shows the real UI issues
`DELETE /api/BasketItems/{id}` when a user removes a basket item
(30/30 blocked under aligned, rule 911100 + 949110). Nothing else changed.
Compose passes the two variables; container verified per run
(`AM=GET HEAD POST OPTIONS PUT DELETE` printed).

Results (UA fixed, rule 13; denominators = full manifest; no errors, no
outbound cuts → best = worst, rule 20):

| dataset | PL | blocked | rate (95% Wilson) | label (rule 19) |
|---|---|---|---|---|
| benign-browse-v0 | 1 | 2/214 | 0.93% (0.26–3.34) | IN-SAMPLE-ADJACENT (v0 has no DELETE; tests only that the addition does not regress v0) |
| benign-browse-v0 | 2 | 3/214 | 1.40% (0.48–4.04) | IN-SAMPLE-ADJACENT |
| benign-browse-v1 | 1 | 4/774 | 0.52% (0.20–1.32) | IN-SAMPLE (DELETE derived from v1) |
| benign-browse-v1 | 2 | 7/774 | 0.90% (0.44–1.85) | IN-SAMPLE (DELETE derived from v1) |

Per distinct endpoint, remaining blocks with rule IDs:

- v0 PL1: `GET /rest/user/whoami` 2 samples ← 932260 + 949110 (1 of 68
  endpoints).
- v0 PL2: whoami 2 ← 932236+932239+932260+949110; `PUT
  /rest/products/{id}/reviews` 1 ← 932236+949110 (2 of 68).
- v1 PL1: whoami 4 ← 932260+949110 (1 of 68).
- v1 PL2: whoami 4 ← 932236+932239+932260+949110; review PUT 3 ←
  932236+949110 (2 of 68).

Rule 18 (with rule-24 labels): v0 runs — none over 20%. v1 PL2 — 950100
at 30% of audit entries: verified in the image
(`RESPONSE-950-DATA-LEAKAGES.conf` line 152) that 950100 = "The
Application Returned a 500-Level Status Code" (phase 3, PL2+). Its
frequency is a **stateful-replay artifact**: 84 v1 basket requests (56
`PUT /api/BasketItems/{id}`, 28 `POST /api/BasketItems`) get 5xx from
Juice Shop because the recorded basket-item ids/auth tokens do not exist
in the freshly created container; all are `waf_pass`, so no FP rate is
affected. It is neither a config mismatch nor a detection change.

**No out-of-sample estimate exists for this config yet** — both datasets
contributed to its derivation (v0: method/content-type alignment; v1:
DELETE). A future recording (v2) the config has never seen is required.

## T3 — relabels in docs/baseline-v0.3.md

Dated note (2026-11-18, step-08 T3) appended, old text kept:

1. 911100 relabelled CONFIG-MISMATCH (rule 24): the corpus legitimately
   exercises PUT/DELETE; crs-default forbids them.
2. 950100 corrected: it is the 500-status rule (not "the outbound
   threshold rule firing on 3 review-edit PUTs" as step-07 wrote); its
   28–30% frequency is the stateful-replay artifact described above; no
   FP rate affected.
3. 60/60 sessions with ≥1 blocked request reflects shared app-generated
   background traffic (whoami polling, socket.io), not user-level
   failure; read alongside the per-endpoint table.

## T4 — published CRS numbers (docs/published-crs-results.md)

Ten sources recorded with URL, date, CRS version, PL, dataset, numbers,
and attack/benign definitions; nothing averaged. Highlights (all read
directly in the source text seen):

- Bill-Benson MSc dissertation (CRS 3.3.8, PL1 vs PL2, 700 requests):
  TPR 97.0% at both PLs, FPR 1.0% → 2.0%; "threshold-not-rules" effect.
- j-ptiik journal 2026 (ModSecurity+CRS on Juice Shop): DR 98.82% (PL1) →
  99.99% (PL4); FPR 25.93% (PL1) → 57.43% (PL2) → 66.96% (PL3) → 100%
  (PL4). Benign definition UNVERIFIED (abstract).
- wafplanet blog 2026 (CRS nightly, PL1, 4,500 real browsing requests
  from openappsec WCP + 95 CVE payloads): baseline TPR 55.8%, FPR 29.7%.
- Anuvarshini et al., Computers & Security 2025: precision 60.54% →
  97.46% with 146 custom rules (abstract; details UNVERIFIED).
- AutoEx, Electronics 2026: FP 100% → 32–46% residual (simple datasets)
  or <2% (representative datasets); detection 100% (abstract).
- CRS GitHub issue #1016 (2018): CRS 2.2.9 on CSIC 2010 — precision 0.5,
  recall 0.343, FPR 23.93%; ECML/PKDD — precision 0.7, recall 0.93, FPR
  57.21%.
- CRS project docs (read directly, qualitative): PL1 "ideally zero" FPs;
  PL2 "expect to encounter false positives"; no aggregate benchmark found
  in the project documentation (UNVERIFIED whether one exists elsewhere).
- Abstract-only, numbers UNVERIFIED: Reyes Narváez Eng.Proc. 2025 (FP
  framework PL1–PL4), Curipallo Martínez Eng.Proc. 2025 (Coraza + CRS
  4.15.0, PL2–PL4 — relevant to the future engine decision),
  ModSec-Learn, ModSec-AdvLearn, Riverol 2024.

Comparability: only wafplanet's benign half (real browsing sessions) and
Bill-Benson's engine setup are partially comparable; the j-ptiik Juice
Shop target makes its FP numbers suggestive but its benign definition is
unknown. All judgements are in the doc, per source.

## T5 — external benign candidates (docs/external-benign-candidates.md)

Six candidates recorded (URL, licence as stated, size, generation,
criticisms, suitability):

- **CSIC 2010**: 36k+36k normal + 25k anomalous, machine-generated forms
  traffic for a Spanish e-commerce app; licence not visible (UNVERIFIED);
  criticized for labelling misspelled-parameter requests as anomalous
  (CRS issue #1016) and unknown attack/normal distribution. Usable as an
  additional benign stress set, not a replacement.
- **ECML/PKDD 2007**: 35,006 normal + 15,110 attacks; real traffic with
  all parameter names/values randomized — not usable for WAF FP replay.
- **openappsec/waf-comparison-project**: 1,040,242 legitimate requests
  from 692 real websites + 73,924 malicious; Apache 2.0. Strongest
  candidate; vendor-originated (openappsec), no independent critique
  found (UNVERIFIED).
- **Biblio-US17**: 47.9M real requests, 6 months, semi-automatic labels —
  but method+URI+status only, no headers/bodies → not replayable.
- **pralab/http-traffic-dataset**: only seen via the ModSec-Learn
  abstract — UNVERIFIED, follow-up candidate.
- **WebRequests (redata.uy)**: URI-only TF-IDF aggregation, CC BY 4.0 —
  not usable for replay.

Nothing downloaded or ingested.

## Deviations

- None material. The v1 PL2 aligned-v2 run's rule-18 hit (950100) was
  investigated and explained (stateful-replay artifact) rather than
  relabelled mechanically.

## UNVERIFIED items

- Licence status of CSIC 2010 and Biblio-US17; existence of a CRS-project
  aggregate benchmark; full-paper numbers for the five abstract-only
  sources; pralab/http-traffic-dataset contents and licence.

## Questions for instructor

1. For the engine decision: is a hands-on Coraza comparison (CRS 4.15.0
   numbers exist in Curipallo Martínez et al., but UNVERIFIED at abstract
   level) wanted as a future step, or should the decision rest on our own
   recorded evidence plus the published notes?
2. Should a future step preregister use of the openappsec WCP legitimate
   set as an out-of-sample benign corpus (rule 22 plan first)? It is the
   only large, licensed, real-browsing candidate found.
3. The stateful-replay artifact (basket 5xx/404 on fresh containers) is
   now documented. Should a future recording version avoid stateful
   requests (basket ids, auth tokens) in the frozen manifest, or keep
   them and accept replay artifacts?

## Test status

`.venv/bin/python -m pytest -q` → **81 passed**.
