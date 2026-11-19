# Baseline v0.5 (step-10)

Extends docs/baseline-v0.4.md. New in this version: per-sample encoding
error rows in the runner (T1), the 3,840-vs-3,823 reconciliation (T2),
capture-integrity numbers for the four WCP baseline runs (T3), a
decomposition of the WCP false positives (T4), a blocked-side label audit
(T5), a held-out-host policy experiment (T6), a cookie-sensitivity
experiment (T7), and a Coraza engine-parity check (T8). Engine parity rule:
rules 27–28 (AGENTS.md).

## 1. Runner hardening (T1)

A sample whose header names/values or request line cannot be encoded now
produces a per-sample error row (`error_class: "encoding"`) and the run
continues; the runner still exits non-zero when `error_count > 0`.
Authorised additive exception to the no-engine-changes rule. Tested with a
non-latin-1 header value and a non-latin-1 request line (unit tests).
Old runs are not re-run.

## 2. 3,840 vs 3,823 (T2)

The reach-check would-block set (DetectionOnly PL1, n=19,999) has 3,840
members; the default PL1 blocking run (n=19,994) blocked 3,823. The blocked
set is a strict subset of the would-block set. The 17 extra would-blocks
are exactly the requests that in blocking mode are denied with **status
400** by the image's body-parser rules — 200002 ("Failed to parse request
body") and 200007 ("Failed to fully parse request body due to large
argument count"), both `deny, status:400` from
`/etc/modsecurity.d/modsecurity.conf` — instead of the 403 threshold block.
In DetectionOnly those rules only log, so the anomaly score accumulated and
949110 fired. Our block discriminator (403 + nginx marker) does not count a
400 as a block, so these 17 are classified `inconsistent` in the blocking
run — visible, not silently passed. Configs: both runs had B=D=P=1 and no
ALLOWED_* overrides; they differ only in engine mode (DetectionOnly vs On)
and in the 5 reach-failed samples absent from the baseline manifest.

## 3. Capture integrity (T3)

Per WCP baseline run (blocking, stub backend, in-container audit file):

| run | audit entries | unparseable | samples with entry | blocked w/o entry |
|---|---|---|---|---|
| default PL1 | 3,887 | 0 | 3,887/19,994 | 0 |
| default PL2 | 9,281 | 0 | 9,281/19,994 | 0 |
| aligned PL1 | 6,622 | 0 | 6,622/19,994 | 0 |
| aligned PL2 | 10,442 | 0 | 10,442/19,994 | 0 |

Every blocked sample has an audit entry in all four runs.

## 4. WCP block decomposition (T4, default config)

Definitions fixed in tools/wcp_decompose.py before analysis (sole-rule
attribution = highest-severity non-threshold rule, ties by rule ID;
attribution convention, not a counterfactual).

PL1 (3,823 blocks / 19,994 = 19.12%):

- Sole-rule attribution top 5: 920420 2,931 (76.7% of blocks), 920340 88,
  943110 86, 932235 72, 932370 71.
- The 20 "neither" requests (non-threshold rules that are neither policy
  nor detection class) are all 921130 only.
- 920420 by content type: the top blocked types are text/plain variants
  (1,943 + 787 + 19 + 17 + 8 + 5 requests), application/csp-report (38),
  message/ohttp-req (25), application/vnd.chrome.uma (23),
  application/x-protobuf (18) — each blocked type is blocked at 100% of its
  requests (the type is simply not in the allowed list).
- 911100 by method: PUT 33/33, DELETE 13/13, PATCH 1/1 (100% each).
- Per host: 839/3,038 hosts have >=1 block; macro-average over the 912
  hosts with >=5 requests 20.52%; micro 19.12% (18.58–19.67). Top hosts:
  www.google-analytics.com 113/327, analytics.tiktok.com 94/106,
  play.google.com 53/61, ingest.quantummetric.com 49/49,
  www.pinterest.com 43/48.
- Bounds from rule presence (NOT counterfactual): detection-only blocks
  661/19,994 = 3.31% (3.07–3.56); detection-involved 758/19,994 = 3.79%
  (3.54–4.06).

PL2 (8,949 blocks / 19,994 = 44.76%):

- Sole-rule attribution top 5: 931130 3,809 (42.6%), 920420 2,931 (32.8%),
  942200 630, 942120 304, 931131 195.
- No "neither" requests.
- 920420 and 911100 patterns identical to PL1 (same policy rules).
- Per host: 1,563/3,038 hosts with >=1 block; macro (912 hosts) 41.08%;
  micro 44.76% (44.07–45.45). Top hosts: www.facebook.com 334/366,
  www.google-analytics.com 326/327, www.google.com 266/440,
  googleads.g.doubleclick.net 214/231, www.googleadservices.com 158/163.
- Bounds: detection-only 4,409/19,994 = 22.05% (21.48–22.63);
  detection-involved 6,623/19,994 = 33.12% (32.48–33.78).

Rule 18 confound (repeated with the new label): 920420 is in 30.4% of all
audit entries in the aligned runs and is the sole attribution for 76.7% of
default PL1 blocks — a CONFIG-MISMATCH signal (the corpus exercises content
types and methods the default config forbids), not a harness artifact.
931130 is in 22.5% of default PL2 entries.

## 5. Blocked-side label audit (T5, preregistered in docs/plan-wcp-blocked-audit.md)

Seed 0, 100 from default PL1 detection-involved blocks (population 758),
50 from default PL2 (population 6,623), no overlap between the two draws.
Each request read manually (method, path, host, content type, body
excerpt, rule IDs).

| draw | ordinary benign | plausibly malicious | cannot tell |
|---|---|---|---|
| PL1 (100) | 98 | 0 | 2 |
| PL2 (50) | 47 | 0 | 3 |

The 5 "cannot tell" are opaque encoded bodies (2 gzip session-replay
blobs to rs.fullstory.com; 1 base64 array, 1 encoded blob, 1 encrypted
telemetry payload). No sampled request looked like an attack payload.
Per-id table with rule IDs is in reports/step-10.md. This is an audit of
100 and 50, not a proof; the frozen dataset is unchanged. No credential,
key or email VALUES are quoted (rule 25).

## 6. Held-out-host policy config (T6, preregistered in docs/plan-wcp-heldout.md)

Host split (seed 0, sha256("wcp-heldout-v0|host") % 2, fixed before any
run): 1,488 TRAIN hosts / 9,949 requests, 1,550 TEST hosts / 10,051
requests (manifests: 9,947 and 10,047 after the 4 quarantined samples that
fall in the split). crs-policy-wcp-train = image default UNION
TRAIN-observed values, restricted to what the CRS config mechanism can
express (single-token content types; see docs/baseline-config.md for the
two documented failures: comma and semicolon in recorded values break
seclang setvar parsing): methods `GET HEAD POST OPTIONS PUT DELETE PATCH`,
content types = 5 defaults + 13 single-token TRAIN types.

Blocking runs against the stub backend, recorded UAs, rule 13 hygiene
(fresh container per run, workers 1):

| hosts | config | PL1 | PL2 |
|---|---|---|---|
| TEST (out-of-sample) | crs-default | 1,769/10,047 = 17.61% (16.87–18.36) | 4,206/10,047 = 41.86% (40.90–42.83) |
| TEST (out-of-sample) | crs-policy-wcp-train | 3,181/10,047 = 31.66% (30.76–32.58) | 4,820/10,047 = 47.97% (47.00–48.95) |
| TRAIN (in-sample) | crs-default | 2,054/9,947 = 20.65% (19.87–21.46) | 4,743/9,947 = 47.68% (46.70–48.66) |
| TRAIN (in-sample) | crs-policy-wcp-train | 3,377/9,947 = 33.95% (33.03–34.89) | 5,363/9,947 = 53.92% (52.93–54.89) |

**The TRAIN-derived policy is worse than default everywhere — including
in-sample.** Composition (sole-rule attribution classes): under
wcp-train PL1 TEST, 2,788/3,181 blocks are policy-only vs 1,376/1,769
under default — allowing more content types lets those requests past 920420
into body inspection, where detection rules (and the threshold) block them
anyway; the policy change converts cheap early blocks into later, more
expensive ones and adds new blocks (PATCH now allowed but 911100-style
method blocks disappear while content-type-driven blocks appear on the
newly-inspected bodies). Macro rates over hosts with >=5 requests: TEST
default 17.71% / wcp-train 32.38% (PL1).

Consequence for the project: request-policy widening is not a promising
FP-reduction lever on third-party browsing traffic; the default policy's
early 920420 blocks are doing most of the FP work at PL1.

## 7. Cookie sensitivity (T7, local only)

Seeded (seed 1) 2,000 requests from the 13,266 cookie-dropped rows of the
baseline manifest; ORIGINAL cookie values restored by streaming the source
zip (script committed: tools/restore_wcp_cookies.py; the restored manifest
stays under the gitignored out/ path — cookie values are credentials, rule
25). Authorization stays dropped. Integrity check: restored rows differ
from the baseline rows ONLY in the cookie header value. 4 runs (fresh
container each, default config, stub backend):

| variant | PL1 | PL2 |
|---|---|---|
| cookies dropped (baseline values) | 430/2,000 = 21.50% (19.76–23.35) | 832/2,000 = 41.60% (39.46–43.77) |
| cookies restored | 961/2,000 = 48.05% (45.87–50.24) | 1,717/2,000 = 85.85% (84.25–87.31) |

Restoring cookies **more than doubles** the false-positive rate. Dominant
new attribution: 932270 ("Remote Code Execution: Unix shell-like pattern")
434 blocks at PL1 restored — cookie values (session/tracking blobs) match
shell-code patterns. This means the v0.4 headline FPs are an
**underestimate** for real traffic that carries cookies: with cookies
present, third-party browsing would trip CRS at roughly twice the measured
rate. Denominators: 2,000 in all four runs; errors: 0 in all four.

## 8. Coraza parity (T8, rules 27–28)

- Distribution: coreruleset/coraza-crs-docker, nginx variant
  `ghcr.io/coreruleset/coraza-crs:4.25.2-nginx-lts` pinned by digest
  `sha256:ffefe71585b42daa5ead5653206b086b37090f498e4cde9ed6e4c52f05cc93e7`.
  Chosen because it is built by the CRS project itself, bundles CRS, and
  mirrors the baseline's nginx reverse-proxy shape and env knobs.
  Engine: libcoraza v1.8.0 (from the image build definition at repo tag
  20261011; image created 2026-10-19).
- CRS version equality, proven from inside both containers:
  ModSecurity side: CRS 4.25.2 image tag
  (`owasp/modsecurity-crs:4.25.2-nginx-lts`), libModSecurity 3.0.17
  (nginx banner inside the container). Coraza side:
  `producer.rulesets: ["OWASP_CRS/4.25.2"]` in the audit log and
  `tx.crs_setup_version=4252` in
  `/opt/coraza/config/crs-setup.conf` (read via docker exec).
- Config parity (shown from inside the container): CORAZA_RULE_ENGINE=On,
  PARANOIA=1, BLOCKING_PARANOIA=1 (the image has no separate
  DETECTION_PARANOIA knob; our PL1 config has detection == blocking == 1,
  so the rendered config is equivalent — noted as a limitation).
  Allowed methods/content types: crs-default uses the CRS defaults, which
  are identical in both images' crs-setup.conf (methods GET HEAD POST
  OPTIONS PUT DELETE; content types application/json
  application/x-www-form-urlencoded multipart/form-data text/xml
  application/soap+xml).
- Block discriminator: unchanged (403 + `<center>nginx</center>`); the
  Coraza nginx variant serves the stock nginx 403 page. Audit log format
  and samples documented in docs/block-discriminator.md; sample-id header
  present, so rule IDs are verified.
- Runs (PL1 default, BACKEND=target = Juice Shop, recorded UAs, rule 13):

| dataset | ModSecurity blocked | Coraza blocked | per-sample diff |
|---|---|---|---|
| smoke | 6/12 | 6/12 | 0 |
| attacks-v0 | 954/1,054 | 954/1,054 | 0 |
| benign-browse-v1 | 184/774 | 184/774 | 0 |
| benign-hard-v0 | 22/180 | 22/180 | 0 |

  **Blocked sets are identical on every dataset — zero per-sample
  differences.** Per-sample rule-set comparison (samples with audit
  entries): benign-browse-v1 347/347 identical, benign-hard-v0 116/116
  identical, smoke 11/12 (one startup artifact: an empty-id entry where
  Coraza logged 920100/920280 for a malformed probe request; all 12
  real samples identical), attacks-v0 999/1,007 — the 8 differing samples
  are all path-traversal requests where ModSecurity fires 920260 (Unicode
  encoding abuse) and Coraza does not; all 8 are still blocked by the same
  final verdict (930120/930100 + 949110). WCP was NOT run on Coraza
  (per task).

## pytest

88 passed (`.venv/bin/python -m pytest -q`), including the 2 new T1
encoding tests and the 5 T5 stub-backend tests from step-09.
