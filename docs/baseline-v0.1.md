# CRS baseline v0.1 — paranoia verified, policy/detection split, policy-aligned config

Supersedes the *interpretation* (not the numbers) of `docs/baseline-v0.md`.
All runs in this document follow rule 13 (container force-recreated, one run
per log capture, `--workers 1`) and record `config` labels in `run.json`.
No frozen dataset was edited. No rule-specific exclusions were used.

> **NOTE (step-06):** all PL2 columns/rows in this document are **confounded
> by 920320** (missing-User-Agent artifact; corrected analysis in the
> correction note below) — see **docs/baseline-v0.2.md** for the UA-fixed
> re-run. Numbers below are unchanged.

## 1. Paranoia level verified (T1)

Raw evidence from the running container (`docker exec deploy-baseline-crs-1`):

- `printenv PARANOIA` → `1` / `2` as configured.
- Config lines (file `/etc/modsecurity.d/owasp-crs/crs-setup.conf`):
  - PARANOIA=1: line 192 `setvar:tx.blocking_paranoia_level=1`, line 220
    `setvar:tx.detection_paranoia_level=1`
  - PARANOIA=2 (before the fix): line 192 `=1`, line 220 `=2`
  - PARANOIA=2 (after the fix): line 192 `=2`, line 220 `=2`

**Image quirk found (rule 16 case):** the image
`owasp/modsecurity-crs:4.25.2-nginx-lts` bakes `BLOCKING_PARANOIA=1` into its
Dockerfile ENV. Its `95-configure-rules.sh` first sets both levels from
`PARANOIA`, then `BLOCKING_PARANOIA` (always present, =1) overwrites
`blocking_paranoia_level` back to 1. Container log (raw):

    Configuring 900000 for PARANOIA with blocking_paranoia_level=2
    Configuring 900001 for PARANOIA with detection_paranoia_level=2
    Configuring 900000 for BLOCKING_PARANOIA with blocking_paranoia_level=1

So in every step-03/step-04 run, `PARANOIA` effectively controlled only
`detection_paranoia_level`; blocking stayed at PL1. The two levels CAN differ
(the image supports separate `BLOCKING_PARANOIA` / `DETECTION_PARANOIA` env
vars). `deploy/compose.yml` now pins both to `PARANOIA` unless overridden.

**PL2-tagged rule proof.** Rule `932300` ("Remote Command Execution: SMTP
Command Execution", tag `paranoia-level/2`,
`REQUEST-932-APPLICATION-ATTACK-RCE.conf` line 1548) was probed with a request
crafted from its own pattern (`?q=%0d%0aVRFY%20admin%40example.com`):

- PL1: `grep -c 932300` in the captured log → **0** (no audit entry at all).
- PL2: → **1**, with `"ruleId":"932300"`, tags including
  `"paranoia-level/2"`, matched data `\x0d\x0aVRFY admin@example.com`
  within `ARGS:q`.

**Rule IDs seen per dataset per PL (image-default config, step-04/05 runs):**
PL2-only IDs (i.e., PL2-tagged rules that executed and logged):

- attacks-v0: 40 IDs only at PL2 (920230, 920271, 920320, 931130, 932200,
  932220, 932236, 932240, 933151, 933152, 934101, 934180, 941150, 941181,
  941320, 941330, 941340, 941380, 942120, 942130, 942131, 942150, 942180,
  942200, 942210, 942300, 942330, 942340, 942370, 942390, 942400, 942410,
  942430, 942440, 942450, 942480, 942510, 942520, 942521, 950100); none only
  at PL1.
- benign-browse-v0: PL1 {911100, 920420, 932260, 949110}; PL2 adds
  {932236, 932239, 950100}.
- benign-hard-v0: PL1 {930120, 932140, 932160, 932235, 932250, 932260, 932380,
  934110, 942100, 949110}; PL2 adds 17 IDs (920320, 931130, 932200, 932236,
  932240, 942120, 942130, 942131, 942150, 942200, 942260, 942330, 942410,
  942430, 942440, 942480, 950100).

**Conclusion (T1):** "identical at PL1 and PL2" in step 04 was REAL as
observed blocking behaviour but was NOT a comparison of two blocking levels:
PL2 rules executed and logged (proven above) but never scored, because
`blocking_paranoia_level` stayed 1. The cause was fixed in
`deploy/compose.yml`; all "PL2" runs in this document are TRUE blocking PL2
(`blocking_paranoia_level=2` verified in the container).

## 2. attacks-v0 re-run on the current runner (T2)

Default config, true PL1/PL2, rule 13. Runner commit recorded in `run.json`
(`git_commit` = `1260392…` = repo HEAD at run time; verified equal to
`git rev-parse HEAD`).

| family | step-04 PL1 | step-05 PL1 | step-04 "PL2" (blocking=1) | step-05 PL2 (blocking=2) |
|---|---|---|---|---|
| command-injection | 224/300 | 224/300 (=) | 224/300 | 278/300 |
| path-traversal | 298/300 | 298/300 (=) | 298/300 | 300/300 |
| sqli | 132/154 | 132/154 (=) | 132/154 | 148/152* |
| xss | 300/300 | 300/300 (=) | 300/300 | 300/300 |

*sqli shows 152 not 154: 2 samples errored at true PL2 (below). Sample-level:
PL1 identical (0 differences); PL2 +72 newly flagged, 0 lost.

**Every difference at true PL2 traces to one artifact:** the runner sends no
`User-Agent` header, and CRS rule `920320` ("Missing User Agent Header",
paranoia-level/2, +5) fired on **all 1054** requests at true PL2 (1054/1054
audit entries contain it). Every request with any other match therefore
crossed the threshold of 5. The +72 are threshold crossings from the missing
UA, not new detection capability. Additionally, 2 samples
(`sqli-730d16ce-q`, `sqli-730d16ce-login`, payload `' '`) errored with
`IncompleteRead` at true PL2 in both configs: the target returned 500 for
them, CRS scored the response body (950100 "The Application Returned a
500-Level Status Code", 959100 outbound threshold) and cut the response
mid-stream. Classified `error` by the outcome tool (never "not flagged").

> **CORRECTION (2026-11-18, step-06 T2):** the claim "920320 adds +5" above
> is WRONG. The rule carries `severity:'NOTICE'` and
> `tx.notice_anomaly_score=2` (REQUEST-901-INITIALIZATION.conf line 180), so
> it adds **+2**. Verified by probe: a UA-less request to an unmatched path at
> true PL2 logs 920320 (severity 5 = NOTICE) with NO 949110 message, status
> 200 — it does not cross the threshold of 5 alone. Re-analysis of the +72:
> 70 of them have inbound score ≥ 7 (blocked even without the +2 — real PL2
> detection rules scoring once blocking_paranoia_level=2), and only 2 have
> score exactly 5 (blocked only thanks to the +2). The corrected finding:
> the +72 are mostly genuine PL2 detection-rule scoring, with 920320's +2
> assisting 2 borderline crossings. The UA confound remains real (a harness
> artifact present on every request) but is far smaller than first stated.

**Content-Type check (T2):** audit entry for login sample `sqli-01f86083-login`
(PL1 default run) records request headers `Host, Accept-Encoding,
X-Kortex-Sample-Id, Content-Type: application/json, Content-Length: 33` —
exactly **one** Content-Type.

## 3. Policy vs detection split (T3)

Classification defined in `docs/rule-classes.md` BEFORE analysis:
policy = 911/920 files; detection = 930/931/932/933/934(incl. NodeJS)/941/
942/943/944 files; 949110/950100/959100 = threshold rules (neither);
901/905/913/921/922/95x/98x files = unclassified (stated there).

Blocked requests by class of their non-threshold rules (counts with 95% Wilson
intervals; default config; benign PL2 rows are the true-PL2 v05 runs):

| dataset | PL | policy-only | detection-only | both | neither |
|---|---|---|---|---|---|
| attacks-v0 | 1 | 0 (0.00%) | 918 (96.23%, 94.82–97.26%) | 36 (3.77%, 2.74–5.18%) | 0 |
| attacks-v0 | 2 | 2 (0.19%) | 0 (0.00%) | 1024 (99.81%, 99.29–99.95%) | 0 |
| benign-browse-v0 | 1 | 32 (94.12%, 80.91–98.37%) | 2 (5.88%) | 0 | 0 |
| benign-browse-v0 | 2 | 31 (91.18%) | 2 (5.88%) | 1 (2.94%) | 0 |
| benign-hard-v0 | 1 | 0 | 22 (100%) | 0 | 0 |
| benign-hard-v0 | 2 | 0 | 0 | 78 (100%) | 0 |

Note: benign-hard PL2 (78 blocked) includes the 920320 missing-UA artifact
(see §2); every blocked hard sample at PL2 matched 920320.

## 4. Policy-aligned configuration (T4)

Settings, defaults, URLs and rationale: `docs/baseline-config.md` (committed
before the runs). In short: `allowed_methods` default `GET HEAD POST OPTIONS`
→ aligned adds `PUT`; `allowed_request_content_type` image default (no
`text/plain`) → aligned adds `|text/plain|`; nothing else changed. Observed in
ALL 214 browse samples: methods GET×135, POST×67, PUT×12; content types
application/json (59), text/plain;charset=UTF-8 (20), none (135).

Rates (blocked/total, 95% Wilson; errors listed separately, never counted as
pass or block):

| dataset | PL | crs-default | crs-policy-aligned |
|---|---|---|---|
| attacks-v0 | 1 | 954/1054 = 90.51% (88.59–92.14) | 954/1054 = 90.51% (88.59–92.14) |
| attacks-v0 | 2 | 1026/1054 = 97.34% (96.19–98.16) +2 err | 1026/1054 = 97.34% (96.19–98.16) +2 err |
| benign-browse-v0 | 1 | 34/214 = 15.89% (11.60–21.38) | **2/214 = 0.93% (0.26–3.34)** |
| benign-browse-v0 | 2 | 34/214 = 15.89% (11.60–21.38) | **3/214 = 1.40% (0.48–4.04)** |
| benign-hard-v0 | 1 | 22/180 = 12.22% (8.21–17.81) | 22/180 = 12.22% (8.21–17.81) |
| benign-hard-v0 | 2 | 78/180 = 43.33% (36.31–50.64) +18 err | 78/180 = 43.33% (36.31–50.64) +18 err |

Rule IDs of every still-blocked request (distinct non-threshold ID sets):

- attacks-v0 PL1 (both configs): detection rules only (930/932/933/934/941/
  942 families + occasional 920260/920270/921130), threshold 949110. Full
  combination table produced by the analysis script; largest sets:
  {941100,941120,941160,941390}×184, {942100}×128, {930100,930110,930120}×58.
- attacks-v0 PL2 (both configs): every blocked request includes 920320
  (missing UA) plus detection rules; 2 error requests:
  {920320, 950100, 959100}.
- benign-browse PL1 aligned: {932260}×2 (whoami). PL2 aligned:
  {932236,932239,932260}×2, {932236}×1 (review edit).
- benign-hard PL1 (both configs): {932260}×6, {934110}×4, {942100}×4,
  {932140,942100}×2, {932235}×2, {930120,932235,932250,932260}×2,
  {932160,932235,932260,932380}×2. PL2 (both configs): all include 920320;
  largest sets {920320,932236}×18, {920320,931130}×8, {920320,942131}×8;
  18 error requests {920320,950100,959100}.

**Reading:** the aligned config removes ALL policy-class false positives on
natural browsing (34 → 2 at PL1) without changing attack recall at PL1
(954/1054 in both configs). The true-PL2 numbers are dominated by the
missing-User-Agent artifact and must not be read as "PL2 detects more".

## 5. Cluster-aware reporting (T5)

Classes defined in `tools/benign_clusters.py` before analysis (static:
`/assets/` prefix or fixed extension list; socket.io; API: `/api/`,`/rest/`;
other). Results on the aligned runs:

benign-browse-v0 PL1 (PL2 in parentheses where different):

| class | samples | distinct endpoints | blocked | FP rate | 95% Wilson |
|---|---|---|---|---|---|
| static | 46 | 46 | 0 | 0.00% (0.00–7.71) | — |
| socket.io | 73 | 2 | 0 | 0.00% (0.00–5.00) | — |
| API | 94 | 19 | 2 (3 at PL2) | 2.13% (0.59–7.43); PL2 3.19% (1.09–8.97) | — |
| other | 1 | 1 | 0 | 0.00% | — |
| all | 214 | 68 | 2 (3) | 0.93% (0.26–3.34); PL2 1.40% (0.48–4.04) | — |

Per-endpoint within classes with blocks: `GET /rest/user/whoami` 2/2 (API);
at PL2 additionally `PUT /rest/products/{id}/reviews` 1/10 (932236).

benign-hard-v0 (PL1 and PL2 identical composition): API 180 samples, 2
distinct endpoints; blocked 22 (12.22%, 8.21–17.81) at PL1, 78 (43.33%,
36.31–50.64) at PL2 (920320 artifact). Distinct injection values: **90**;
values with ≥1 blocked request: 11 (12.22%) at PL1, 39 (43.33%) at PL2.

**Session fraction: n/a (deviation).** The frozen browse samples' `source`
field does not contain a session number — the recorder wrote one source string
for all samples, and the content-hash dedupe removed the session dimension.
The fraction of sessions with ≥1 blocked request cannot be computed from the
frozen data. Fix for a future recording version: include `session-<n>` in the
source field BEFORE dedupe.

**Dedupe fields (also added to the dataset README):** the content hash covers
(method, path, query, content_type, body). Headers are NOT part of the hash;
two requests differing only in headers collapse to one sample (first-seen
headers kept).

## 6. Coverage and environment notes (T6)

Natural-benign coverage of the attack injection points (214 browse samples):

- search with non-empty `q`: **0** (UI search is client-side in Juice Shop
  v20.4.0 — see the dataset README; no per-term search request reaches the
  server).
- login with `email` value: **10** (of 10 login requests; each login body
  carries both fields).
- login with `password` value: **10**.

Environment: `docs/recording-env.md` (Playwright 1.65.2, Chromium
159.0.8154.6, Juice Shop image v20.4.0 reporting 20.4.0-SNAPSHOT,
LD_LIBRARY_PATH workaround, non-reproducible without those libraries).

## Limitations carried forward

1. True-PL2 attack/benign numbers are confounded by the runner not sending a
   User-Agent (920320 +5 on every request). Question for instructor: may the
   runner send a default `User-Agent` (or should attack samples record one)?
2. The 2 (attacks) / 18 (hard) `IncompleteRead` errors at true PL2 are
   outbound-blocking cut responses (950100+959100); they are counted as
   errors, not passes or blocks.
3. Session-level attribution is impossible in benign-browse-v0 (see §5).
4. No numeric targets are set anywhere in this document.
