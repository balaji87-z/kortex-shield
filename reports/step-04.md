# Step 04 report — benign corpora, endpoint templating, first full CRS baseline

Date: 2026-11-18. Branch `main`. All commands run from the repo root with
`.venv/bin/python`; testbed via `deploy/compose.yml`.

## New standing rules recorded (13–15)

- **13** capture hygiene: one run per log capture, container force-recreated before
  each run, runner `--workers 1`; `crs_audit` exits non-zero on unparseable
  `{"transaction"` lines and prints the count.
- **14** never merge natural and hard benign rates.
- **15** report distinct requests AND distinct payloads/endpoints.

## T1 — v0 follow-ups

- `crs_audit` rule 13: `parse_logs` collects unparseable `{"transaction"` lines and
  raises `AuditError` with count + line numbers; CLI exits non-zero. Tests:
  truncated-line parse abort + CLI exit code. Evidence: `tests/test_crs_audit.py`,
  50 tests passing at commit time.
- `data/attacks-v0/annotations.jsonl`: 1054 rows; injection point from id suffix
  (`-q` → query, else login; 527/527); payload URL-decoded; fragment = fewer than 2
  runs of `[A-Za-z0-9]+` (True 96 / False 958). **Bug found and fixed**: the first
  version stored the still-encoded query remainder for `-q` samples; regenerated
  with `urllib.parse.unquote`, then q/login payload pairs matched with 0 mismatches.
  Frozen manifest untouched.
- attacks-v0 README notes the stratification rule was defined AFTER seeing v0
  results, so stratified numbers appear alongside, never instead of, unstratified.
- `tools/attack_breakdown.py`: unstratified per-family recall first, then family ×
  injection_point and family × fragment/complete with 95% Wilson intervals and
  distinct-payload counts; XSS diversity (distinct tag names, event handlers).
- Re-runs (rule 13, engine On): `out/attacks-v0-pl1-on` (1007 audit entries),
  `out/attacks-v0-pl2-on` (1054). **Recall identical at PL1 and PL2**:
  command-injection 224/300 (74.67%), path-traversal 298/300 (99.33%),
  sqli 132/154 (85.71%), xss 300/300 (100%). Distinct payloads blocked: cmdinj 150,
  trav 150, sqli 77, xss 150 (2 injection points per payload). Fragment view (PL1):
  cmdinj complete 206/256 (80.47%) vs fragment 18/44 (40.91%); sqli complete
  92/102 (90.20%) vs fragment 40/52 (76.92%); traversal 298/300 complete; xss all
  complete. XSS diversity: 90 distinct tag names, 42 distinct event-handler names.

## T2 — endpoint templating

`kortex_eval/endpoints.py`: `endpoint(sample)` = METHOD + path with pure-numeric,
8+-hex, and UUID segments replaced by `{id}`; query excluded. 10 tests
(`tests/test_endpoints.py`), including the boundary `deadbeef` (8 hex → `{id}`)
vs `deadbee` (7 chars → kept). 60 tests passing at commit time.

## T3 — recorded natural benign traffic

- Playwright installed; Chromium launch initially failed on missing system libs
  (`playwright install-deps`/`apt-get` unavailable — no sudo). Working setup:
  pre-existing libs at `~/.opencode/pwlibs/usr/lib/x86_64-linux-gnu` with
  `LD_LIBRARY_PATH=$HOME/.opencode/pwlibs/usr/lib/x86_64-linux-gnu:$HOME/.opencode/pwlibs/usr/lib/x86_64-linux-gnu/gbm`.
  Verified the browser loads the real Juice Shop UI (title "OWASP Juice Shop").
- Runner extended to send `Sample.headers`, skipping `Host`, `Content-Length`,
  `X-Kortex-Sample-Id` (ours overrides recorded). Test
  `test_recorded_headers_sent_and_sample_id_wins`.
- Selectors discovered against the real DOM (v20.4.0): product tiles `.product`
  with `.name`, welcome banner dismissed via `Close Welcome Banner`, login ids
  `#email`/`#password`/`#loginButton`, reviews are a `mat-expansion-panel` inside
  the product dialog, add-to-basket via `button[aria-label='Add to Basket']`.
- `tools/record_benign.py`: 20 sessions (10 anonymous: home, 5 product dialogs,
  10 catalog-derived searches; 10 registered: deterministic register/login, 2
  basket adds, basket, profile, 1 review from a 20-sentence hand-written list with
  apostrophes/commas). Recorded through the target directly (no WAF).
- Result: 20/20 sessions completed with zero failed steps; **1374 requests
  captured → 214 unique samples** after content-hash dedupe →
  `data/benign-browse-v0/candidates.jsonl`.
- **Environment finding**: UI search is client-side in v20.4.0 — the SPA sends only
  one `GET /rest/products/search?q=` (empty q) when the search page loads; per-term
  search requests never hit the wire. Verified twice via Playwright request-event
  logging (typed searches and direct `#/search?q=` navigation). Documented in the
  dataset README and baseline doc.

## T4 — hard benign inputs

`tools/build_benign_hard.py`: 90 hand-written legitimate values (SQL/shell/HTML
words in natural-language searches, apostrophes/unicode names, special-char
passwords, URLs/emails in text, long review sentences, code-like text) → 180
samples over the same two injection points (search `q=`, login `email`/`password`
alternating). Source `hand-authored-hard-benign@<commit>`. README carries the
overstatement warning and the never-merge rule.

## T5 — reach checks and freeze

- First hard-set reach run violated rule 13 (container not recreated between the
  browse and hard runs → 230 audit entries, 114 unattributed). **Redone** with a
  fresh container: 116 entries, clean attribution. Recorded here as a deviation.
- benign-browse-v0: 214/214 reachable, 0 probes, 0 quarantine, 0 excluded.
- benign-hard-v0: 180/180 reachable, 0 probes, 0 quarantine, 0 excluded.
- Frozen: `manifest.jsonl` + `MANIFEST.sha256` + `annotations.jsonl` (endpoint per
  sample from `kortex_eval.endpoints`) + README, for both datasets.
  - browse: SHA-256 `20fe88df3152c43dd8312fe16e835a6de432e01f14dd5e191f0933ca1d4de8b1`
  - hard: SHA-256 `65bdfc69022c5b026815acacd033d1e005fadc9c2e7000745614bd903a01d78b`

## T6 — first full CRS baseline v0

Engine On; PL1 and PL2; rule 13 hygiene; frozen hashes recorded in each `run.json`.

### Bug found during the first baseline run

The first browse run blocked **81/214 (37.85%)** with CRS **920620 "Multiple
Content-Type Request Headers"** on every recorded POST — a runner bug: recorded
lowercase `content-type` was copied into the header dict and then
`headers["Content-Type"]` was set again, sending the header twice. Fixed
(case-insensitive duplicate guard) with a new test
(`test_recorded_content_type_not_duplicated`); 62 tests passing. All baseline
numbers below are from the fixed runner (`runner=content-type-fixed` label in
run.json). The buggy run is superseded.

### Results (identical at PL1 and PL2)

Natural browsing (benign-browse-v0): **34/214 blocked = 15.89% FP** (Wilson
11.60–21.38%). Endpoints with blocks:

| endpoint | blocked/samples | rules |
|---|---|---|
| POST /socket.io | 20/20 | 920420 (content-type policy), 949110 |
| PUT /rest/products/{id}/reviews | 10/10 | 911100 (method not allowed by policy), 949110 |
| GET /rest/user/whoami | 2/2 | 932260, 949110 |
| PUT /api/BasketItems/{id} | 2/2 | 911100, 949110 |

64 of 68 distinct endpoints had zero blocks. Interpretation: 911100 = method
policy (PUT not allowed by the baseline container config), 920420 = content-type
policy (socket.io text/plain), 932260 = the whoami FP already identified in step 02.

Hard benign (benign-hard-v0): **22/180 blocked = 12.22% FP** (Wilson 8.21–17.81%),
11/90 on each endpoint; rules 930120, 932140, 932160, 932235, 932250, 932260,
932380, 934110, 942100, 949110. Upper bound by design (rule 14); reported
separately from the natural rate.

Distinct counts (rule 15): browse 214 distinct requests = 214 distinct
(method, path, query, body) triples, 34 distinct blocked triples; hard 180 = 180,
22 blocked. Full tables: `docs/baseline-v0.md`; regeneration via
`tools/benign_breakdown.py`.

## T7 — README and acceptance updates

- README component table now lists both benign corpora, endpoints, breakdown
  tools, baseline doc; roadmap step 2 marked done; scale line updated
  (1,054 attacks / 394 benign).
- `docs/acceptance.md` A2: distinct-count comparison against the bar —
  attacks 1,054 vs 1,600 (**546 short**), legitimate 214+180=394 vs 1,400
  (**1,006 short**); rates reported separately, no numeric targets set.
  A8 updated: reproducible chain proven at dataset scale.

## Deviations

1. Hard-set reach run first executed without recreating the container (rule 13
   violation, caught via unattributed audit entries); redone cleanly.
2. The first browse baseline run used the buggy runner (duplicate Content-Type);
   superseded by the fixed-runner runs quoted above.
3. UI search is client-side in Juice Shop v20.4.0, so per-term searches produce no
   server-side samples; recorded traffic kept as-is and documented (no synthetic
   search requests were invented to fill the gap).

## Test status

`.venv/bin/python -m pytest -q` → **62 passed**.

## Commits (in order)

1. `step-04: rules 13-15 ...` (AGENTS.md)
2. `step-04: T1 crs_audit rule-13 ...`
3. `step-04: T1 annotations + attack_breakdown + PL1/PL2 re-runs`
4. `step-04: T2 endpoints.py ...`
5. `step-04: T3 runner sends recorded headers ...`
6. `step-04: T3 playwright benign recorder, 20 sessions, 214 unique samples`
7. `step-04: T4 hard benign builder (76 values, 152 samples)` — note: the builder
   actually emits 90 values → 180 samples; the commit message understates it
   (written before the final value list was expanded). Recorded here as a
   deviation; the dataset files are correct.
8. `step-04: T5 freeze benign-browse-v0 (214) and benign-hard-v0 (180) ...`
9. `step-04: fix duplicate Content-Type ...; benign_breakdown tool`
10. `step-04: T6 full CRS baseline v0 ...`
11. `step-04: T7 README and acceptance A2/A8 ...`
