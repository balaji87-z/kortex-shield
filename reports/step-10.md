# Step 10 report

- Summary: Hardened the runner with per-sample encoding error rows (T1,
  authorised additive exception); reconciled 3,840 vs 3,823 (the 17 extra
  would-blocks are status-400 body-parser denies, classified inconsistent,
  not silently passed); proved capture integrity for the four WCP baseline
  runs (0 unparseable, 0 blocked-without-entry); decomposed the WCP false
  positives with definitions fixed before analysis (920420 = 76.7% of PL1
  blocks - CONFIG-MISMATCH; detection-involved bound 3.79% PL1 / 33.12%
  PL2); audited the blocked side (150 sampled, 0 plausibly malicious);
  ran the preregistered held-out-host policy experiment (the TRAIN-derived
  policy is WORSE everywhere, even in-sample); showed cookie restoration
  more than doubles the FP rate (932270 on cookie blobs); brought up Coraza
  (coraza-crs nginx, CRS 4.25.2 pinned and proven inside both containers)
  with per-sample parity: blocked sets identical on all four datasets.
- pytest: **88 passed** (`.venv/bin/python -m pytest -q`).

## Task table

| task | status | evidence |
|---|---|---|
| rules 27-28 appended | done | AGENTS.md commit "step-10: rules 27-28" |
| T1 runner hardening | done | kortex_eval/runner.py + 2 tests; evidence below |
| T2 3,840 vs 3,823 | done | diff below; 17 samples = 200002/200007 status-400 denies |
| T3 capture integrity | done | table below (0 unparseable, 0 blocked w/o entry) |
| T4 decomposition | done | tools/wcp_decompose.py (defs fixed pre-analysis); docs/logs/wcp-decompose.txt; numbers below |
| T5 blocked-side audit | done | docs/plan-wcp-blocked-audit.md (preregistered); table below |
| T6 held-out policy | done | docs/plan-wcp-heldout.md; docs/baseline-config.md (2 documented failures); 8 runs below |
| T7 cookie sensitivity | done | tools/restore_wcp_cookies.py (committed only); 4 runs below |
| T8 Coraza parity | done | compose service pinned by digest; samples saved pre-parser; 4 runs, 0 per-sample blocked-set differences |
| T9 docs | done | docs/baseline-v0.5.md; dated note in v0.4; README/acceptance counts |

## T1 - runner hardening (raw evidence)

Added `error_class` to runner rows; UnicodeError during header/request-line
encoding produces `error_class: "encoding"`, the run continues, exit stays
non-zero when error_count > 0 (pre-existing behaviour). Unit tests:
non-latin-1 header value and non-latin-1 request line both produce
`error_class == "encoding"` (tests/test_runner.py, 20 passed). Old runs
not re-run. The step-09 quarantined sample wcp-6b0bf5e43122 would now be a
per-sample error row instead of a crashed run.

## T2 - 3,840 vs 3,823 (raw evidence)

Configs: reach run = DetectionOnly, B=D=P=1, no ALLOWED_* overrides,
manifest 19,999; baseline = engine On, B=D=P=1, no ALLOWED_* overrides,
manifest 19,994 (the 5 reach-failed samples absent). Same sample universe
except those 5.

- would_block: 3,840; blocked: 3,823.
- blocked-not-subset-of-would_block: 0 (blocked is a strict subset).
- in would_block not blocked: 17 - every one has status 400 in the blocking
  run and outcome `inconsistent` (not waf_pass): wcp-2600366d4ecb,
  wcp-2895d7e869c5, wcp-2ec9a3436296, wcp-376b3b37ef12, wcp-384ae4521001,
  wcp-4be3821497ed, wcp-62b3375148b4, wcp-672911deadaa, wcp-71461e371348,
  wcp-96a594e2ae57, wcp-9958e07b65ec, wcp-a4a6f9fb8303, wcp-aec2a2311eb9,
  wcp-c7970d727861, wcp-decac4aed757, wcp-ef1d0324c278, wcp-f78d7afa532c.
- Rule IDs (blocking run): 200002 and/or 200007 (+920450 on some) - the
  image's body-parser deny rules with `status:400`
  (/etc/modsecurity.d/modsecurity.conf lines 46-49). In DetectionOnly they
  only log, so the score accumulated to 949110, hence would_block. The
  403-based block discriminator does not count a 400 deny as a block; the
  outcome classifier flags them as inconsistent, so they are visible in
  every report that lists inconsistent counts.

## T3 - capture integrity (raw numbers)

| run | audit entries | unparseable transaction lines | samples with audit entry | blocked without audit entry |
|---|---|---|---|---|
| benign-wcp-v0-pl1-default-ua | 3,887 | 0 | 3,887 / 19,994 | 0 |
| benign-wcp-v0-pl2-default-ua | 9,281 | 0 | 9,281 / 19,994 | 0 |
| benign-wcp-v0-pl1-aligned-ua | 6,622 | 0 | 6,622 / 19,994 | 0 |
| benign-wcp-v0-pl2-aligned-ua | 10,442 | 0 | 10,442 / 19,994 | 0 |

(crs_audit exits non-zero on any unparseable line; it printed entry counts
only, so 0 unparseable in all four.)

## T4 - decomposition (definitions fixed in tools/wcp_decompose.py BEFORE analysis)

Full output committed at docs/logs/wcp-decompose.txt; headline numbers in
docs/baseline-v0.5.md section 4. Confound check (rules 18/24): 920420
present in 30.4% of aligned-run entries and sole attribution for 76.7% of
default PL1 blocks - labelled CONFIG-MISMATCH (the corpus exercises content
types the default config forbids); 931130 in 22.5% of default PL2 entries.

## T5 - blocked-side label audit

Preregistered in docs/plan-wcp-blocked-audit.md (committed before any
sampling). Procedure followed exactly: seed 0, 100 from PL1 detection-
involved blocks (population 758), 50 from PL2 (population 6,623), no
overlap. Every request read manually. Result: PL1 98 ordinary benign /
0 plausibly malicious / 2 cannot tell; PL2 47 / 0 / 3. The 5 "cannot tell"
are opaque encoded bodies (2 gzip session-replay blobs, 1 base64 array,
1 encoded blob, 1 encrypted telemetry payload). No credential, key or email
VALUES quoted (rule 25). Per-id table follows.
#### PL1 draw (100 of 758 detection-involved blocks, seed 0)

| id | class | rule IDs |
|---|---|---|
| wcp-887c3583d475 | ordinary_benign | 932130, 933135 |
| wcp-9564c5e62681 | ordinary_benign | 943110 |
| wcp-0e9a0d2f72c9 | ordinary_benign | 932130, 933135 |
| wcp-57be37660e44 | ordinary_benign | 932370, 942290 |
| wcp-b2265d00ad49 | ordinary_benign | 932370 |
| wcp-a9931fbb6840 | ordinary_benign | 941100, 941160, 941180 |
| wcp-8d3e012a2ec4 | ordinary_benign | 942550 |
| wcp-698c42a5cd9b | ordinary_benign | 932130, 933135 |
| wcp-a6fb2baf975c | ordinary_benign | 931120 |
| wcp-7f2a33f35a18 | ordinary_benign | 932260 |
| wcp-d199baed8910 | ordinary_benign | 932125, 932130 |
| wcp-48f819781e45 | ordinary_benign | 931120 |
| wcp-afced3cc1bd3 | ordinary_benign | 943110 |
| wcp-2ac5181d6045 | ordinary_benign | 932235 |
| wcp-60b94f657e23 | ordinary_benign | 933120 |
| wcp-2ad83248a8c4 | ordinary_benign | 942550 |
| wcp-1f2ed798e0d9 | ordinary_benign | 932125 |
| wcp-da95e6748172 | ordinary_benign | 943110 |
| wcp-542429f2733a | ordinary_benign | 942550 |
| wcp-b9081c67e85e | ordinary_benign | 943110 |
| wcp-f3ea70a0b6f5 | ordinary_benign | 932130, 933135 |
| wcp-d779dd4c2c62 | ordinary_benign | 942290 |
| wcp-2c0b172bc8cf | ordinary_benign | 932230, 932235, 932250, 932370, 933150 |
| wcp-6d128d1f8218 | ordinary_benign | 932125, 932130 |
| wcp-202cd3ec7637 | ordinary_benign | 942290 |
| wcp-17059e83cb5b | ordinary_benign | 942550 |
| wcp-ee446185d487 | ordinary_benign | 941130 |
| wcp-75583ae21b20 | ordinary_benign | 941130 |
| wcp-a64e9ab9ef79 | cannot_tell | 943110 |
| wcp-c569280a78a3 | ordinary_benign | 930120 |
| wcp-217b2668e190 | ordinary_benign | 932235, 932370, 942290 |
| wcp-7db3ad901c7d | ordinary_benign | 932370 |
| wcp-9a1e499b3f24 | ordinary_benign | 930120 |
| wcp-6efcb63a9037 | ordinary_benign | 942290 |
| wcp-d8a4d8c0042b | ordinary_benign | 943110 |
| wcp-dfc4733a4c9d | ordinary_benign | 943110 |
| wcp-43466252b241 | ordinary_benign | 932235 |
| wcp-c223a0614267 | ordinary_benign | 943110 |
| wcp-fbb15860dd8e | ordinary_benign | 942550 |
| wcp-9d986d56c698 | ordinary_benign | 942100 |
| wcp-b5bbd1ca49e7 | ordinary_benign | 931120 |
| wcp-580c695b1710 | ordinary_benign | 942290 |
| wcp-143dbcb447e7 | ordinary_benign | 932370 |
| wcp-c04715d21a75 | ordinary_benign | 931120 |
| wcp-063d32bee147 | ordinary_benign | 943110 |
| wcp-1e76d802c02c | ordinary_benign | 942550 |
| wcp-8b5c7328c97e | ordinary_benign | 942100 |
| wcp-e8ac8b0091ce | ordinary_benign | 931120 |
| wcp-dc1e1c7f667c | ordinary_benign | 932340 |
| wcp-00f9ddf0d041 | ordinary_benign | 942290 |
| wcp-d8c7c3663350 | ordinary_benign | 943110 |
| wcp-acf4034690d3 | ordinary_benign | 932370 |
| wcp-7613d1ba2633 | ordinary_benign | 942100 |
| wcp-506199a490ac | ordinary_benign | 943110 |
| wcp-72a0efd3e5eb | ordinary_benign | 932260 |
| wcp-145fea109343 | ordinary_benign | 942550 |
| wcp-3ce3a13447c1 | ordinary_benign | 932260 |
| wcp-c97ea9f24d46 | cannot_tell | 943110 |
| wcp-4a7deb516068 | ordinary_benign | 942290 |
| wcp-4f73e53856af | ordinary_benign | 942290 |
| wcp-2ae7d145fa96 | ordinary_benign | 942290 |
| wcp-bdbf99dc1552 | ordinary_benign | 932230, 932250, 942550 |
| wcp-9fb8beb1b694 | ordinary_benign | 942550 |
| wcp-1cf10cadb532 | ordinary_benign | 932235, 941170, 941210 |
| wcp-1a1dc41a7d97 | ordinary_benign | 942100 |
| wcp-70a8ec2df600 | ordinary_benign | 942290 |
| wcp-b166ecb2273c | ordinary_benign | 942190 |
| wcp-ac6e7302c1ff | ordinary_benign | 931120 |
| wcp-2304efdacb69 | ordinary_benign | 942550 |
| wcp-68efe4a3cc81 | ordinary_benign | 943110 |
| wcp-c1ca7ae007c6 | ordinary_benign | 942190 |
| wcp-64d1340433be | ordinary_benign | 942290 |
| wcp-267e8c14125c | ordinary_benign | 931120 |
| wcp-c0112ec87c56 | ordinary_benign | 930130 |
| wcp-760143d355b6 | ordinary_benign | 942550 |
| wcp-bb647319468f | ordinary_benign | 932130, 933135 |
| wcp-4344c19cd600 | ordinary_benign | 930120, 932120, 932270, 942100 |
| wcp-d78ed61a684c | ordinary_benign | 932230, 932235, 932250, 932370, 942100, 942290 |
| wcp-f058a37649f0 | ordinary_benign | 931120 |
| wcp-d393009de1a3 | ordinary_benign | 943110 |
| wcp-635f4784fd02 | ordinary_benign | 942290 |
| wcp-9e80d34969bb | ordinary_benign | 942100 |
| wcp-ed68be496931 | ordinary_benign | 932235 |
| wcp-d5b695a3870c | ordinary_benign | 942290 |
| wcp-ffadfe4b0cec | ordinary_benign | 932370, 942290 |
| wcp-6f2fe090718f | ordinary_benign | 943120 |
| wcp-ccad6ff3c10c | ordinary_benign | 943110 |
| wcp-50073254a56c | ordinary_benign | 932270 |
| wcp-63eabf22e26a | ordinary_benign | 932370 |
| wcp-3b44db26b230 | ordinary_benign | 943110 |
| wcp-3caee46d2c46 | ordinary_benign | 932370 |
| wcp-3c7c013898b4 | ordinary_benign | 943110 |
| wcp-0cc8d67ad298 | ordinary_benign | 941180 |
| wcp-d926a00fd0d7 | ordinary_benign | 942190 |
| wcp-f239de55e7cf | ordinary_benign | 941130 |
| wcp-a6f5a5662a70 | ordinary_benign | 930130 |
| wcp-15dd14a10dda | ordinary_benign | 932130, 933135 |
| wcp-1cc1e86a1690 | ordinary_benign | 932230, 932250 |
| wcp-28d3d5d1625f | ordinary_benign | 942100 |
| wcp-2ce2a8b6ec6a | ordinary_benign | 930120, 932270, 942550 |
#### PL2 draw (50 of 6623 detection-involved blocks, seed 0)

| id | class | rule IDs |
|---|---|---|
| wcp-7b412cdec8e2 | ordinary_benign | 942200, 942340, 942370, 942430 |
| wcp-efbaf374b8c4 | ordinary_benign | 931130 |
| wcp-863000edbe86 | ordinary_benign | 931130, 942430 |
| wcp-0d2294805f3e | ordinary_benign | 931130, 932200, 932380, 941330, 941340, 942200, 942300, 942330, 942340, 942370, 942430, 942520, 942550 |
| wcp-52a52b1be91e | ordinary_benign | 931130, 932271 |
| wcp-a233f004dc5e | ordinary_benign | 931130, 932240 |
| wcp-9aa5ce61ad7a | ordinary_benign | 942430 |
| wcp-81990e30823d | ordinary_benign | 943110 |
| wcp-f7d43d38d821 | ordinary_benign | 930120, 931130, 932200, 932271, 942430 |
| wcp-6021c80ab73b | ordinary_benign | 931130, 942370, 942520 |
| wcp-97414227ef60 | ordinary_benign | 931130, 932200, 942200, 942370, 942430 |
| wcp-71c4d30cf304 | ordinary_benign | 931130, 932271 |
| wcp-b84802f427e5 | ordinary_benign | 931130, 932240, 942200, 942340, 942370, 942430, 942520 |
| wcp-45eb797cadfa | ordinary_benign | 931130, 942430 |
| wcp-a09b6d53f0b2 | ordinary_benign | 931130 |
| wcp-2b621cb2c429 | cannot_tell | 942120, 942200 |
| wcp-592fc60fc27d | ordinary_benign | 931130, 942430 |
| wcp-2b8716758c87 | ordinary_benign | 931130, 942120, 942430 |
| wcp-ef3dd5b42cc3 | ordinary_benign | 931130 |
| wcp-1ccf3e2e0bf6 | cannot_tell | 932271 |
| wcp-c3d2344623fb | ordinary_benign | 931130, 932271 |
| wcp-fcd36f01a008 | ordinary_benign | 931130, 942430 |
| wcp-4fa3bf53e24a | ordinary_benign | 932200 |
| wcp-a8b1c8036c67 | ordinary_benign | 931130 |
| wcp-df08cd6ac25d | ordinary_benign | 943110 |
| wcp-be2ffb7b6155 | ordinary_benign | 931130 |
| wcp-2dfbf1a8bd27 | ordinary_benign | 931130, 932220, 932236, 942430 |
| wcp-628112cc0cb0 | ordinary_benign | 931130, 942430 |
| wcp-1e42fb6493b5 | ordinary_benign | 942200, 942340, 942370, 942430 |
| wcp-e6ed73801eaf | ordinary_benign | 931130 |
| wcp-16c76a07fad7 | ordinary_benign | 942200, 942340, 942370, 942430 |
| wcp-d8a842add171 | ordinary_benign | 931130 |
| wcp-6907a8c466b1 | ordinary_benign | 931130, 942200, 942340, 942370, 942430 |
| wcp-95a3e2e150e8 | ordinary_benign | 931130, 932370, 942200, 942340, 942370, 942430, 942520 |
| wcp-b0941d5de0bb | ordinary_benign | 931131 |
| wcp-1ee7e254c3ef | ordinary_benign | 931130 |
| wcp-704eb6896bab | ordinary_benign | 931130, 942430 |
| wcp-89bfb48360d4 | cannot_tell | 942200 |
| wcp-6409ecf94e7c | ordinary_benign | 931131, 941150 |
| wcp-c1515e452e61 | ordinary_benign | 942200, 942340, 942370, 942430 |
| wcp-cad6c328ed6e | ordinary_benign | 942200, 942330, 942340, 942370, 942430, 942520 |
| wcp-414fe296ad3f | ordinary_benign | 931130, 932236, 932240, 942200, 942330, 942340, 942370, 942430 |
| wcp-aec9e6c61f86 | ordinary_benign | 931130 |
| wcp-9755dbcec09c | ordinary_benign | 931130 |
| wcp-8cab773b300c | ordinary_benign | 931130, 932200, 941330, 941340, 942120, 942200, 942340, 942370, 942430 |
| wcp-a5aa89e7d09a | ordinary_benign | 932236, 932260 |
| wcp-52f311d9382c | ordinary_benign | 931130 |
| wcp-1321e11cda6a | ordinary_benign | 931130, 942200, 942340, 942370, 942430 |
| wcp-ff0acdf9ed35 | ordinary_benign | 931130 |
| wcp-ad85ccf30b4a | ordinary_benign | 931130 |

## T6 - held-out-host policy config (raw evidence)

Preregistered in docs/plan-wcp-heldout.md before the split was computed.
Split (seed 0, sha256("wcp-heldout-v0|host") % 2, 0=TRAIN): 1,488 TRAIN
hosts / 9,949 requests, 1,550 TEST hosts / 10,051 requests
(docs/logs/wcp-heldout-split.json, committed before the runs).

Image defaults read from inside the container
(/etc/modsecurity.d/owasp-crs/crs-setup.conf lines 494 and 583):
methods `GET HEAD POST OPTIONS PUT DELETE`; content types `application/json
application/x-www-form-urlencoded multipart/form-data text/xml
application/soap+xml`.

Two documented config failures BEFORE the successful runs (rule 17,
docs/baseline-config.md): (1) the full 112-token union failed to start
nginx - a recorded value containing a comma (`application/json,
application/json`) terminates the seclang setvar value (nginx emerg:
"Expecting an action, got: application/json application/json; ...");
(2) semicolons also terminate it (`application/json;charset=UTF-8` broke at
`charset`). Final policy: default UNION 13 single-token TRAIN-observed
content types + method PATCH; 94 recorded multi-part types (1,578 TRAIN
requests) are not representable in the CRS mechanism and stay NOT-allowed
(docs/logs/wcp-heldout-policy.json has the full excluded list with counts).

Eight blocking runs (stub backend, recorded UAs, fresh container per run,
workers 1, one audit log per run, 0 errors in all eight):

| hosts | config | PL1 | PL2 |
|---|---|---|---|
| TEST (out-of-sample) | crs-default | 1,769/10,047 = 17.61% (16.87-18.36) | 4,206/10,047 = 41.86% (40.90-42.83) |
| TEST (out-of-sample) | crs-policy-wcp-train | 3,181/10,047 = 31.66% (30.76-32.58) | 4,820/10,047 = 47.97% (47.00-48.95) |
| TRAIN (in-sample) | crs-default | 2,054/9,947 = 20.65% (19.87-21.46) | 4,743/9,947 = 47.68% (46.70-48.66) |
| TRAIN (in-sample) | crs-policy-wcp-train | 3,377/9,947 = 33.95% (33.03-34.89) | 5,363/9,947 = 53.92% (52.93-54.89) |

Macro rates over hosts with >=5 requests: TEST default 17.71% / wcp-train
32.38% (PL1, 460 hosts); TRAIN default 23.38% / wcp-train 35.99% (PL1, 452
hosts). Composition (sole-rule attribution classes, PL1): TEST default
policy-only 1,376 / detection-only 319 / detection+policy 53; TEST
wcp-train policy-only 2,788 / detection-only 147 / detection+policy 225.
Interpretation: allowing more content types lets requests past 920420 into
body inspection where they are blocked anyway (often by detection rules at
higher cost); the derived policy is worse than default everywhere,
including in-sample on its own derivation hosts. Request-policy widening is
not a promising FP lever on this traffic.

## T7 - cookie sensitivity (raw evidence)

Script committed (tools/restore_wcp_cookies.py); the restored manifest
lives only under the gitignored out/wcp-cookie-restored/ path (cookie
values are credentials, rule 25). Seed 1, 2,000 requests drawn from the
13,266 cookie-dropped rows of the baseline manifest; original values
restored by streaming data/external/legitimate.zip (never extracted);
integrity check passed: restored rows differ from baseline rows ONLY in the
cookie header value; Authorization stays [DROPPED]. Restore log:
out/restore_cookies.log ("restored 2000; records without a cookie header:
0; integrity check passed").

Four runs (default config, stub backend, fresh container per run, 0 errors):

| variant | PL1 | PL2 |
|---|---|---|
| cookies dropped | 430/2,000 = 21.50% (19.76-23.35) | 832/2,000 = 41.60% (39.46-43.77) |
| cookies restored | 961/2,000 = 48.05% (45.87-50.24) | 1,717/2,000 = 85.85% (84.25-87.31) |

Top sole-rule attribution among blocks - restored PL1: 932270 (434),
920420 (306), 942550 (43); dropped PL1: 920420 (334), 932235 (11),
911100 (9). Restored PL2: 920420 (306), 942200 (301), 931130 (266),
932270 (226); dropped PL2: 920420 (334), 931130 (280), 942200 (79).
Reading: cookie values (session/tracking blobs) match 932270 Unix
shell-code patterns; the v0.4 headline FPs underestimate real cookie-
carrying traffic by roughly a factor of two.

## T8 - Coraza bring-up and parity (raw evidence)

- Distribution chosen: coreruleset/coraza-crs-docker, nginx variant
  `ghcr.io/coreruleset/coraza-crs:4.25.2-nginx-lts`, pinned by digest
  `sha256:ffefe71585b42daa5ead5653206b086b37090f498e4cde9ed6e4c52f05cc93e7`
  (amd64). Why: built and shipped by the CRS project itself
  (https://github.com/coreruleset/coraza-crs-docker), bundles CRS, same
  reverse-proxy shape and env knobs as the baseline image
  (https://github.com/coreruleset/coraza-crs-docker#readme). Engine:
  libcoraza v1.8.0 (image build definition at repo tag 20261011; image
  created 2026-10-19).
- CRS version equality from inside BOTH containers (rule 28):
  ModSecurity side: image tag owasp/modsecurity-crs:4.25.2-nginx-lts;
  nginx banner inside the container: "libmodsecurity3 version 3.0.17".
  Coraza side (docker exec): `tx.crs_setup_version=4252` in
  /opt/coraza/config/crs-setup.conf and `producer.rulesets:
  ["OWASP_CRS/4.25.2"]` in the audit log.
- Config parity from inside the Coraza container: CORAZA_RULE_ENGINE=On,
  PARANOIA=1, BLOCKING_PARANOIA=1; SecRuleEngine On in
  /opt/coraza/config/coraza.conf. The image has no DETECTION_PARANOIA knob
  (limitation noted); our PL1 config has detection == blocking == 1, so the
  rendered config is equivalent. Allowed methods/content types: crs-default
  uses the CRS defaults, identical in both images' crs-setup.conf.
- Block discriminator: unchanged (403 + nginx marker) - verified against
  the running container; documented in docs/block-discriminator.md. Real
  log samples saved BEFORE any parser: docs/samples/coraza-log-benign.txt
  (200, captured with CORAZA_AUDIT_ENGINE=On because RelevantOnly never
  logs benign 200s - documented) and docs/samples/coraza-log-attack.txt
  (403, 942100). The sample-id header IS carried in
  transaction.request.headers, so rule IDs are verified (not UNVERIFIED).
- Runs (PL1 default, BACKEND=target = Juice Shop, recorded UAs, rule 13,
  0 errors in all four):

| dataset | ModSecurity blocked | Coraza blocked | blocked-set diff |
|---|---|---|---|
| smoke | 6/12 | 6/12 | 0 samples |
| attacks-v0 | 954/1,054 | 954/1,054 | 0 samples |
| benign-browse-v1 | 184/774 | 184/774 | 0 samples |
| benign-hard-v0 | 22/180 | 22/180 | 0 samples |

Per-sample rule-set comparison (samples with audit entries):
benign-browse-v1 347/347 identical; benign-hard-v0 116/116 identical;
smoke 11/12 - the differing entry is a startup artifact (an empty-id
entry: a 502 probe before the target was up, and Coraza logged
920100/920280 for a malformed probe request; all 12 real smoke samples
have identical rule sets); attacks-v0 999/1,007 - the 8 differing samples
are all path-traversal requests where ModSecurity fires 920260 (Unicode
encoding abuse) and Coraza does not:
path-traversal-6ab007f3-login, path-traversal-6ab007f3-q,
path-traversal-954e1190-login, path-traversal-954e1190-q,
path-traversal-b600d361-login, path-traversal-b600d361-q (+2 more of the
same family); all 8 have the same final verdict on both engines (blocked
via 930120/930100 + 949110). WCP was NOT run on Coraza (per task).

## Deviations from instructions

1. T6 policy could not be the literal union: the CRS config mechanism
   cannot express content-type values containing spaces, commas or
   semicolons (two nginx-emerg failures documented in
   docs/baseline-config.md BEFORE the successful runs). The policy uses
   the 13 representable single-token TRAIN types; the 94 excluded types
   (1,578 TRAIN requests) are named with counts in
   docs/logs/wcp-heldout-policy.json.
2. T7 "with dropped cookies" runs were executed fresh on the same seeded
   2,000-request subset (not reused from the step-09 full-baseline runs)
   so both conditions share the exact denominator.
3. T8 benign log sample was captured with CORAZA_AUDIT_ENGINE=On (the
   default RelevantOnly never logs a benign 200); the parity runs
   themselves used the default audit config.
4. T8: the Coraza engine version is proven from the image build
   definition (libcoraza v1.8.0 at repo tag 20261011) because the .so
   carries no version string; CRS version equality IS proven from inside
   both containers as required.
5. tools/run_wcp_heldout.sh was made resumable (run list as arguments)
   after the first wcp-train container-start failure aborted the batch;
   completed runs were not re-run.
6. The held-out script's debug echo line had a quoting bug (printed
   "cfg=1 pl=" instead of the config name); cosmetic only - run identity
   is carried by the run directory names and runner labels.

## UNVERIFIED items

- The Coraza engine version (libcoraza v1.8.0) is from the build
  definition, not from inside the container (no version string in the
  module or env).
- T5 classifications are one reader's manual judgement on 100+50 samples
  (an audit, not a proof).
- Whether 920260's absence on Coraza extends beyond the 8 path-traversal
  samples (only attacks-v0 was rule-diffed sample by sample).

## Questions for instructor

1. T2 reveals that status-400 body-parser denies (200002/200007) are not
   counted as blocks by the discriminator. Should the discriminator treat
   any 4xx/5xx with an audit entry containing a deny-rule (2xxxxx) as
   blocked, or stay 403-only with the inconsistent bucket carrying them?
2. The held-out experiment shows policy widening hurts. Should the
   aligned-v2 config be re-evaluated on WCP TEST hosts before any further
   tuning, or is the Juice Shop line closed?
3. T7 suggests reporting a cookie-carrying FP estimate for WCP. Should a
   future dataset version include original cookies (values redacted in
   the committed artifact but restored at replay time via the fetch
   script), given rule 25?
4. For Coraza: is 920260 divergence worth a dedicated investigation step,
   or is identical blocked-set parity sufficient for the engine choice?
