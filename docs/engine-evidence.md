# Engine evidence (step-11, rule 28; updated step-12 2026-11-20 — see the
# dated section at the end; superseded step-11 text is kept above unchanged)

Every claim below was read from inside the running container during a run or
probe on 2026-11-19. Raw proofs live in the run logs (out/step11-parity-batch3.log)
and docs/logs/.

## Versions

| | ModSecurity | Coraza |
|---|---|---|
| Image | owasp/modsecurity-crs:4.25.2-nginx-lts@sha256:6296ce685cb88ba4012998b935b25dabbd9e0ff326088c1149447102544de661 | ghcr.io/coreruleset/coraza-crs:4.25.2-nginx-lts@sha256:ffefe71585b42daa5ead5653206b086b37090f498e4cde9ed6e4c52f05cc93e7 |
| Engine | libmodsecurity3 3.0.17, ModSecurity-nginx v1.0.4 (nginx notice line at start) | no version string found in the container (UNVERIFIED); CRS 4.25.2 proven via tx.crs_setup_version=4252 |
| Ruleset | OWASP_CRS/4.25.2 (audit entries) | OWASP_CRS/4.25.2 (audit entries, tx.crs_setup_version=4252) |

## Effective config (rule 29), read from inside each container

| setting | ModSecurity | Coraza |
|---|---|---|
| SecRuleEngine / rule engine | On (modsecurity.conf) | On (CORAZA_RULE_ENGINE) |
| blocking paranoia | tx.blocking_paranoia_level=1 or 2 (pinned per run) | =1 or =2 (crs-setup.conf) |
| detection paranoia | tx.detection_paranoia_level pinned = blocking | defaults to blocking via 901125 (image ignores DETECTION_PARANOIA env) |
| SecRequestBodyNoFilesLimit | 131072 (image default, unchanged) | 131072 after in-container pin (ships 524288; sed + nginx -s reload; probe: 200,000-byte body -> 400) |
| SecRequestBodyLimit | 13107200 | 13107200 |
| SecRequestBodyLimitAction | Reject | (same behaviour observed) |
| SecResponseBodyAccess | on (modsecurity.conf:14) | on (coraza.conf:9) |
| SecResponseBodyMimeType | text/plain text/html text/xml | text/plain text/html text/xml |
| outbound threshold | tx.outbound_anomaly_score_threshold=4 (crs-setup.conf:343) | same default (959100 fired at Total Score 4) |
| audit | JSON format, RelevantStatus "^(?:5|4(?!04))" (only 4xx/5xx logged) | logs all transactions (incl. 200s) |

## Parity results (fixed harness, same stub backend, frozen benign-wcp-v0)

- Blocked-set diff (discriminator): PL1 6 only-modsec / 7 only-coraza;
  PL2 6 only-modsec / 8 only-coraza. Most are the 400-vs-403 status asymmetry
  (body-parser deny vs inbound 403 block on the same oversized/unparseable
  bodies), plus 1 timeout and 1 oversized-body 413.
- Rule-presence: large and real. Examples (only-coraza, PL2): 931130 612,
  942200 2,385, 942370 2,331, 942340 2,120, 932200 1,095; (PL1): 932370 303,
  921150 379, 942550 296, 920270 273, 932130 225. Only-coraza was verified
  against the raw ModSecurity audit for a spot-checked sample (rule absent
  there), so it is not an extraction artifact. Interpretation: Coraza's regex
  engine matches additional CRS rules; the extra matches rarely change the
  block outcome (threshold arithmetic absorbs them). Reported per rule 28 as
  per-sample differences; no totals-only claims.
- The reverse direction also exists but is small (e.g. 942430 only-modsec 233
  at PL2).
- 920260 differential probes: 30 probes, 0 disagreements (PL1, default).
- Coraza parity caveat: PARANOIA env is a no-op on the Coraza image;
  DETECTION_PARANOIA defaults to BLOCKING via rule 901125 - PL2 parity holds
  because blocking paranoia is genuinely 2 (proven from crs-setup.conf).

---

# Step-12 update (2026-11-20): what is and is not covered after step-12

## Covered (proven from inside containers during step-12)

| | ModSecurity | Coraza |
|---|---|---|
| Image | owasp/modsecurity-crs:4.25.2-nginx-lts@sha256:6296ce68… (unchanged, re-pinned by digest) | ghcr.io/coreruleset/coraza-crs:4.25.2-nginx-lts@sha256:bfbfe70b… (old digest ffefe715… deleted from ghcr; new build created 2026-11-13) |
| Engine | libmodsecurity3 3.0.17, ModSecurity-nginx v1.0.4 | coraza v3.7.0 (Go build info inside /usr/local/lib/libcoraza.so); the OLD image's engine version remains UNVERIFIED (image no longer pullable) |
| Ruleset | OWASP_CRS/4.25.2 (tx.crs_setup_version=4252) | OWASP_CRS/4.25.2 (tx.crs_setup_version=4252) |
| detection paranoia | tx.detection_paranoia_level=1/2 per run (rule-29 print) | tx.detection_paranoia_level=1/2 per run — the NEW image honours DETECTION_PARANOIA; step-11 runs (old image) never reported D and used the 901125 fallback |
| SecRequestBodyNoFilesLimit | 131072 (image default) | **524,288 effective in ALL runs to date** — the sed+reload pin never took effect (valid 200,000-byte JSON: Coraza 200, ModSecurity 400/200002; docs/logs/step12-sizeprobe-*.log). Non-binding for the small datasets (max body 1,080 bytes). |
| SecRequestBodyLimit | 13107200 | 13107200 (rendered; same file the engine fails to re-read on reload — treated UNVERIFIED at runtime) |

- Small-dataset parity (smoke, attacks-v0, benign-browse-v1, benign-hard-v0 x
  PL1/PL2) re-proven on the pinned images after the stub-drain fix: 0
  blocked-set and 0 worst-case-set differences in all 8 cells
  (docs/logs/step12-t2-parity-small.txt).
- WCP parity (step-11 runs, accepted via the T7 reproduction): blocked-set
  diff 6/7 (PL1) and 6/8 (PL2); worst-case-set diff 1 only-modsec / 17
  only-coraza at PL1 — 10 of the 17 are the >524,288-byte bodies Coraza 413s
  and ModSecurity passes (body-limit axis, not engine disagreement).
- 20 matched-shape probes at PL1: 0 block disagreements; 1 rule-logging
  difference (920260, ModSecurity only, both 200).

## NOT covered

- Any Coraza run with an effective NoFilesLimit of 131,072 (no such run
  exists; the pin mechanism must move to the image env before one is tried).
- The old Coraza image's engine version (image deleted upstream).
- Whether ModSecurity and Coraza agree on bodies between 131,072 and 524,288
  bytes with a parseable body in a type both engines buffer (attacks-v0 has
  none; benign-wcp-v0 has exactly one, wcp-672911deadaa at 172,221 bytes:
  ModSecurity 400/200002+920450, Coraza blocked 403 on inspection — listed,
  not judged).
- Recall impact of widening the allowed content-type list: attacks-v0 cannot
  measure it (every attacks-v0 body uses a type the 901162 fallback already
  allows); see docs/baseline-v0.7.md.

---

# Step-13 update (2026-11-20): evidence against the acceptance criteria (decision 0002)

All step-13 numbers below come from the digest-pinned images with the aligned
proxy config (docs/baseline-v0.8.md). Diagnostic runs (rule 34) are marked and
never enter these numbers. This section reports what was measured; it makes no
verdict and no recommendation (decision 0002, Non-criteria).

## C1 — blocked-set parity, per sample: MEASURED

Full-scale benign-wcp-v0, n=20,000 per cell (docs/logs/step13-t5-parity.txt):

| quantity (rule 32) | ModSecurity | Coraza | sym-diff |
|---|---|---|---|
| PL1 blocked set | 3,823 (19.11%) | 3,824 (19.12%) | 13 |
| PL1 worst-case set | 3,888 (19.44%) | 3,891 (19.45%) | 5 |
| PL2 blocked set | 8,949 (44.74%) | 8,951 (44.76%) | 14 |
| PL2 worst-case set | 9,015 (45.08%) | 9,026 (45.13%) | 11 |

Policy-clear subset (14,279 body-less / 2,743 body-bearing, never merged):

| subset | ModSecurity | Coraza | sym-diff (blocked) |
|---|---|---|---|
| body-less PL1 | 410 (2.87%) | 410 (2.87%) | 0 |
| body-bearing PL1 | 435 (15.86%) | 441 (16.08%) | 8 |
| body-less PL2 | 4,130 (28.92%) | 4,130 (28.92%) | 0 |
| body-bearing PL2 | 1,841 (67.12%) | 1,848 (67.37%) | 9 |

Every differing id is listed with status and defect tags in
docs/logs/step13-t5-parity.txt. Attribution: the blocked-set differences are
body-limit/defect samples (body_over_131072, recorded_cl_mismatch,
gzip_header_mismatch) plus one Coraza timeout (wcp-80a49c991b2d, see C2) and
the encoding sample wcp-6b0bf5e43122; 0 unexplained remain at PL1 after
attribution. Rule-ID presence on the policy-clear subset is tabulated in
docs/logs/step13-t5-rule-presence.txt: at PL1 body-bearing, 5 rules
only-ModSec vs 50 rules only-Coraza (top only-Coraza: 920270, 921150, 942100,
941100); at PL2 body-bearing, 9 vs 86. The T6 diagnostic (DIAGNOSTIC,
docs/decisions/0003-step13-t6-hypothesis.md, PROVEN) attributes the
only-Coraza body-rule presence to body access on policy-rejected content
types: ModSecurity recorded body-derived rules on 6/100 seeded samples where
Coraza recorded 97/100, and 97/100 after the content type was rewritten to an
allowed one. Per rule 4, no engine is called correct anywhere.

## C2 — oversize bodies and latency: MEASURED

- Effective limits proven in-container for every run (C3 lines in the run
  logs; e.g. coraza PL1: E=On B=1 P=1 D=1, nofiles=131072 total=13107200,
  client_max_body_size 0). ModSecurity enforces SecRequestBodyNoFilesLimit
  131,072 (json/urlencoded 400 at >= 131,072; multipart passes to the total
  limit). Coraza v3.7.0 does NOT enforce SecRequestBodyNoFilesLimit
  (131,072 configured and read back; 140,000–1,000,000-byte bodies pass) — a
  documented engine difference, no engine code changed
  (docs/logs/step13-t4-bisect.txt). SecRequestBodyLimit 13,107,200 is enforced
  byte-exact by Coraza; ModSecurity passes at exactly 13,107,200 (one-byte
  boundary difference).
- Latency pathology characterised (DIAGNOSTIC): Coraza super-linear (≈
  quadratic from 128 KB up) on bodies it scans in full (text/plain, empty CT,
  urlencoded); dominant cost PROVEN to be engine-internal body processing,
  not a CRS rule (all 8 matched body-derived rules removed -> unchanged ~40 s;
  SecRequestBodyAccess Off -> 3–5 ms). Multipart up to 2.8 MB fast (14–50 ms).
  ModSecurity flat at PL1 and PL2. docs/logs/step13-t7-evidence.txt. The
  internal mechanism is HYPOTHESIS.

## C3 — effective-config proof: PRESENT for every run cited

Every step-13 run log carries its rule-29 line printed from inside the running
container (engine mode, B/P/D paranoia, allowed methods/content types, body
limits, nginx client_max_body_size). Examples: docs/logs/step13-t5-coraza-wcp.log,
docs/logs/step13-t1-crs-setup-lines.txt, docs/logs/step13-t4-bisect.txt.

# Step-14 update (2026-11-20): evidence against the acceptance criteria

## C1 — blocked-set parity, per sample: MEASURED (attacks side now too)

- Benign side: unchanged from step-13 (MEASURED per sample on benign-wcp-v0,
  PL1 and PL2, worst-case sets).
- Attack side (NEW): attacks-ct-v0, 8 cells x 320 frozen samples
  (docs/logs/step14-t3-analysis.txt). Default config: blocked totals identical
  across engines (304/320 PL1, 316/320 PL2). crs-ct-wide: modsec 224/236 vs
  coraza 292/312 — the difference is entirely the text-plain and
  octet-stream carriers, where ModSecurity has no body processor (0 detection
  blocks) and Coraza inspects the raw body (34-38/40 detection blocks).
  Per-sample disagreement counts are in the analysis log.
- Encoding differential (NEW): encoding-diff-v0, 4 cells x 192 samples —
  per-encoding blocked counts identical across engines and 0 per-sample
  disagreements at PL1 and PL2 (docs/logs/step14-t4-analysis.txt).

## C2 — oversize bodies and latency: MEASURED, mechanism now localised

- The 11 step-12 oversize divergences are fully explained by the Coraza
  image's missing nginx client_max_body_size (1 MiB default); after the
  step-13 alignment all 10 multipart samples are 200 on both engines at both
  PLs (docs/logs/step14-t1-oversize.txt). Residual status-class difference on
  the no-CT PUT is a rule-set difference, not a size effect.
- The ~44 s latency pathology on wcp-80a49c991b2d REPRODUCES in coraza
  v3.7.0 loaded as a plain Go library with no nginx or connector (44,206 ms,
  403, same rule set as the container run): PROVEN engine-internal, now
  localised to the library body-processing path, connector excluded
  (docs/logs/step14-t5-probe.txt). The exact internal code path stays
  HYPOTHESIS.
- Library probe also confirms: SecRequestBodyNoFilesLimit is not enforced by
  coraza v3.7.0 (140,000-byte JSON passes in-library, 200).
- Transient step-13 timeouts do not reproduce (3x replay, both engines);
  only wcp-80a49c991b2d is a real, reproducible timeout.

## C3 — effective-config proof: PRESENT for every step-14 run

Every step-14 run logged a rule-29 line from inside the container (engine
mode, blocking/detection paranoia, env_CT list, body limits). Rule-36 audit
completeness controls (20 before + 20 after) were run and printed for every
step-14 T3/T4 cell. Audit-derived ModSecurity tables from earlier steps that
used edit-and-reload WITHOUT completeness checks are marked "completeness
unproven" in docs/baseline-v0.9.md (T1e); HTTP-response-based results are not
affected.

## Not covered (updated)

- All v0.8 "not covered" items stand, except: the latency pathology is no
  longer "engine vs connector unknown" — it is PROVEN inside the library.
- NEW: transient-timeout cause (not reproducible, HYPOTHESIS host load).
- NEW: whether the crs-ct-wide detection behaviour generalises beyond the 40
  frozen payloads.

---

# Step-15 update (2026-11-20): the engine skeleton (decision 0004)

## What was built

`engine/` — a Go reverse proxy wrapping Coraza v3.7.0 (Go module
github.com/corazawaf/coraza/v3 v3.7.0, engine/go.mod) with the CRS 4.25.2
rule files copied verbatim from the pinned Coraza container
(ghcr.io/coreruleset/coraza-crs@sha256:bfbfe70b…). Set hash recorded in
engine/RULES.sha256 (7c55eb49…). Design: docs/engine-design.md; decision:
docs/decisions/0004-engine-core.md (status: provisional pending T1 and T4).

## Acceptance tests (rule 37)

E1-E9 committed failing first (1de93ef), implementation second (1b7dcb9):
`go test -buildvcs=false -count=1 ./...` in engine/ -> `ok kortexshield/engine`
(9/9; re-run 2026-11-20: 0.288s). Binary verification:
docs/logs/step15-t5-verify.txt (403 block incl. 942100, 413 limit + event,
loopback config JSON, crs_audit parses the engine audit log).

## Effective config (rule 29 analogue), proven per run

The engine prints its effective config at startup and serves it as JSON on
loopback /__kortex/config. Printed in docs/logs/step15-t6-runs.txt for both
PLs and in docs/logs/step15-t4-skeleton-replay.txt for both replay configs:
rule_engine=On, blocking/detection paranoia 1 or 2, max_body_bytes=13,107,200,
max_inspected_bytes=131,072 (replay config B: 13,107,200),
engine_time_budget_ms=2000, rules_dir=engine/crs.

## T6 (DIAGNOSTIC): engine skeleton vs Coraza connector, per-sample diff

Runs: docs/logs/step15-t6-runs.txt (fresh engine per PL, workers 1);
analysis: docs/logs/step15-t6-analysis.txt (blocked set + worst-case set per
rule 32, on common ids; counts on difference-chosen sets, not rates, rule 35).
Reference: the step-12/14 Coraza connector default-policy runs.

| dataset | PL | engine blocked | ref blocked | diff (common ids) |
|---|---|---|---|---|
| smoke | 1 | 7/12 | 6/12 | 1 (trav-01: engine 403 block, ref proxy_reject 400) |
| smoke | 2 | 7/12 | 6/12 | 1 (same) |
| attacks-v0 | 1 | 909/1054 | 954/1054 | 65 (55 ref-only blocks the engine passes at 401/500; 10 engine-only) |
| attacks-v0 | 2 | 1040/1054 | 1024/1054 | 16 (all engine-only blocks) |
| benign-browse-v1 | 1 | 124/774 | 184/774 | 60 (all ref-block / engine-pass-400) |
| benign-browse-v1 | 2 | 214/774 | 184/774 | 150 (90 engine-only, 60 ref-only) |
| benign-hard-v0 | 1 | 35/180 | 22/180 | 23 (18 engine-only, 5 ref-only) |
| benign-hard-v0 | 2 | 129/180 | 78/180 | 51 (all engine-only) |
| attacks-ct-v0 | 1 | 279/320 | 304/320 | 25 (all ref-only: JSON/octet-stream/text-plain/unknown-CT carriers) |
| attacks-ct-v0 | 2 | 312/320 | 316/320 | 4 (all ref-only command-injection carriers) |

Reading (per rule 33, HYPOTHESIS unless said otherwise):
- attacks-ct-v0 PL1 ref-only blocks are exactly the non-urlencoded body
  carriers (JSON, octet-stream, text-plain, unknown-CT) — the connector
  blocks them, the engine passes them. PROVEN pattern from the id list; the
  cause (which rule fires in the connector but not in the engine config) is
  HYPOTHESIS until a rule-level diff is done.
- benign-hard-v0 PL2: the engine blocks 51 samples the connector passes —
  the engine is MORE aggressive there; per-sample ids listed in the analysis.
- Errors: 0 in every engine run; inconsistent: 0 in every engine run
  (rule 30: nothing to add to worst case beyond blocked).

## Confound check (rule 18/24)

docs/logs/step15-t6-confound.txt. The engine writes audit entries essentially
only for blocked transactions, so denominators are blocked sets. 949110
appears in 100% of entries per dataset — that is the blocking-evaluation rule
itself, expected, not a harness artifact. Detection rules at >=20% of blocked
entries: attacks-v0 PL1 930120 35%, 941390 34%, 941100/941120 25%; PL2
942430/942200 51%, 942520 38%, 942370 35%; benign-browse-v1 PL2 942340/942200/
942430 56%; benign-hard-v0 PL2 942200 71%, 942430 67%. On the benign datasets
these are CONFIG-MISMATCH signals (real browsing traffic exercises parameter
patterns PL2 forbids), consistent with the step-13/14 WCP findings; they are
the FP drivers, not a measurement artifact.

## Time budget vs single-shot bodies (PROVEN)

docs/logs/step15-t4-skeleton-replay.txt: 481,798-byte text/plain body,
max_inspected_bytes=13,107,200 (config B): 41.8/42.5/43.5 s per rep, all
ending in a normal 403 block — the 2,000 ms budget never fired (one
ProcessRequestBody call has no phase boundary inside it). Config A (default
131,072 cap): 413 kortex-decision=limit in 1.1-2.9 ms, 3/3. The
"budget bounds the pathology" claim in the pre-run design text is corrected
in docs/engine-design.md.

## Harness fixes made for T6 (additive; container-dialect path unchanged)

- crs_audit: the engine's Coraza audit dialect lowercases header names and
  stores list values, puts messages at top level (sibling of "transaction"),
  and carries rule id/msg/severity in error_message brackets. Attribution and
  rule/score extraction now handle both dialects; the container-dialect
  real-sample tests are unchanged and pass (pytest 105 passed).
- First T6 pass used the default nginx block marker and scored every engine
  block blocked=false (status 403 was right, marker was not); re-run with
  --block-marker 'kortex-decision=block'. First-pass log kept:
  docs/logs/step15-t6-runs-firstpass-nginxmarker.txt (rule 12).
- Per-run engine-audit-full.log copies are cumulative within each PL (the run
  script does not truncate between datasets); per-dataset confound numbers
  filter entries by sample-id prefix. Outcomes are unaffected (attribution is
  by unique sample id).

## Step-16: T1 classification, T2 fix + re-run, T3 budget bounding

### T1 - every diff classified (rule 39)

396 differing ids across the five datasets at PL1/PL2 (step-15 T6 engine vs
the connector reference): 252 BUG + 141 DESIGN-C4 + 1 UNEXPLAINED (at T1
time) + 2 DESIGN-FRONT cells (1 id). Per-id dump
docs/logs/step16-t1-classes.txt, summary docs/logs/step16-t1-summary.txt,
tool tools/analyze_step16_t1.py. (The summary's "253 BUG" double-counts the
UNEXPLAINED id; the cells sum to 252.)

BUG root cause PROVEN: the engine lacked the connector image's
body-processor selection rules (200000 XML, 200001 JSON) and
body-parse-failure rules (200002 REQBODY_ERROR, 200003 MULTIPART_STRICT_ERROR,
200007 &ARGS>=1000, each deny 400; /opt/coraza/config/coraza.conf lines
31-41). Without a processor selection, Coraza v3.7.0's
internal/corazawaf/transaction.go ProcessRequestBody falls back to
`rbp = "URLENCODED"` under CRS 901340's forced body variable — the raw JSON
body is parsed as urlencoded, producing argument NAMES like `{"email":`
(engine audit matched-vars evidence) which both miss real detections and
invent false ones.

### T2 - fix, harness artifacts, re-run

Fix (test-first, E10-E15 failing in 5807afe, fix 7d438fa): the five image
rules added to engine/config.go directives(); Proxy.block() honors
it.Status (400 denies).

Harness artifacts found and documented (rules 18/24), both PROVEN by raw
socket bisection and a Go tx probe:

- Missing User-Agent on the engine side (run scripts omitted
  --default-user-agent): CRS 920320 (NOTICE) adds +2 to
  tx.inbound_anomaly_score_pl2 on EVERY engine-side request. Engine audit
  totals were 5*n_crit + 3*n_warn + 2; the connector's 5*n_crit + 3*n_warn.
  This flipped exactly the two marginal attacks-v0 PL2 ids
  (command-injection-036c522d-q/-login: 920230 +3 alone passes, +2 blocks).
  The T1 "UNEXPLAINED" id and the "stale ref" hypothesis are thereby
  explained; docs/logs/step16-t1-920230-replay.txt has the CORRECTION (the
  DIAGNOSTIC replay's "current container blocks it" was itself the
  numeric-IP-Host artifact below).
- Numeric-IP Host in manual replays: CRS 920350 (WARNING) +3 —
  `Host: 127.0.0.1:8082` blocks what `Host: localhost:8082` passes.

Re-run (engine side with the UA fix; tools/run_step16_t2.sh ENGINE_ONLY=1;
runs docs/logs/step16-t2-runs.txt with per-run effective-config lines,
analysis docs/logs/step16-t2-analysis.txt, confound check
docs/logs/step16-t2-confound.txt):

| dataset | PL | engine | ref | diff | class of diff |
|---|---|---|---|---|---|
| smoke | 1/2 | 7/12 | 6/12 | 1+1 | DESIGN-FRONT (trav-01) |
| attacks-v0 | 1 | 954 | 954 | 0 | - |
| attacks-v0 | 2 | 1024 | 1024 | 0 | - |
| benign-browse-v1 | 1 | 124 | 184 | 60 | DESIGN-C4 (920420) |
| benign-browse-v1 | 2 | 124 | 184 | 60 | DESIGN-C4 (920420) |
| benign-hard-v0 | 1 | 22 | 22 | 0 | - |
| benign-hard-v0 | 2 | 78 | 78 | 0 | - |
| attacks-ct-v0 | 1 | 286 | 304 | 18 | DESIGN-C4 (920420) |
| attacks-ct-v0 | 2 | 310 | 316 | 6 | DESIGN-C4 (920420) |

146 differing ids, ALL DESIGN (144 C4 + 2 front-proxy cells); zero BUG, zero
UNEXPLAINED. 0 errors / 0 waf_deny_status / 0 inconsistent on both sides in
every cell. The three attacks-ct PL2 C4 diffs that T1 did not list
(command-injection-f48aa068/-ecb32a80 x 3 carriers) are the BUG mask
lifting: CRS 920240's chain requires REQBODY_PROCESSOR == URLENCODED, so its
T6 engine blocks were fallback artifacts; with the correct processor the
engine passes and only the C4 policy difference remains.

Confound check (rule 18/24): detection rules at >=20% of a dataset's audit
entries are listed per side in docs/logs/step16-t2-confound.txt. The
ref-side benign-browse 911100 flag (120/184) is a CONFIG-MISMATCH-flavored
DESIGN note: the connector enforces a method allow-list (crs-setup 900200),
the engine sets no tx.allowed_methods so 911100 never fires there; every
such sample is blocked by the engine via other rules, so no blocked-set diff
exists. benign-hard PL2 932236 (44%) fires equally on both sides (dataset by
design).

### T3 - budget bounds body processing; abandoned-call ownership

E16 (failing bda1678, fix 6235777): ProcessRequestBody runs in a goroutine
bounded by the remaining budget; expiry answers 503 kortex-decision=timeout.

E17 (failing 7d78963, fix 39324c9): the handler's deferred tx.Close() ran on
the timeout path and killed the in-flight abandoned call — it "finished" at
budget+12 ms with a stale 949110/403 interruption. The first-pass T3 run
even shows the engine CRASHING under concurrency (copy16 and the
post-concurrency benign probe got status 000 — the use-after-close panicked
the process; first-pass log kept:
docs/logs/step16-t3-runs-firstpass-txclose.txt). The abandoned goroutine now
owns and closes the transaction.

Re-run measurements (docs/logs/step16-t3-runs.txt, fixed binary):

- single replay: 503 at 2.002 s (budget 2000 ms); the abandoned call ran to
  completion at elapsed_ms=45114 with the real result (949110/403) — the
  unfettered cost measured separately: 403 at 42.41 s with a 60 s budget.
- benign latency before the burst: 5.0 ms.
- 20 concurrent copies: 20/20 answered 503 in 2.00-2.08 s (none wedged).
- post-burst benign latency and the abandoned-finish events: see the run
  log (measured with the 20 ~45 s CPU-bound goroutines still running).

### T4 - real engine-dialect audit samples

docs/samples/kortex-audit-{attack,benign,limit,timeout}.txt: attack entry
from the T2 engine run (sample sqli-01); benign/limit/timeout captures prove
the engine writes NO coraza audit entry for passed/limited/timed-out
requests (0-byte audit logs, RelevantOnly) — their decisions appear as
kortex-events rows. crs_audit handles both dialects additively; pytest 110
passed.

## Step-17 (2026-11-20, current host; the lab host was unreachable)

- T1 C4 replay: tools/run_step17_t1_engine.sh -> out/s17-t1-engine-*,
  analysis docs/logs/step17-t1-c4-replay.txt. Per-carrier table identical
  to the committed lab analysis (36/36/36/36, 34/34/34, 40=34+6 at PL1;
  39x4, 38x3, 40=39+1 at PL2); cross-carrier gaps identical
  (dc2932d5, 6e47f23b PL1; ecb32a80 PL2). Engine totals 286/320 (PL1) and
  310/320 (PL2) match the s16-t2 engine runs exactly.
- T2 re-run: docs/logs/step17-t2-runs.txt — smoke 7/12, benign-browse-v1
  PL1 124/774, 0 errors, config proof shows allowed_methods and
  max_inflight_body.
- T3 measurement: docs/logs/step17-t3-runs.txt — Phase A/B numbers in
  docs/baseline-v1.2.md; Phase B: 12 overload (47-282 ms) + 8 timeout
  (~2.0 s), all 8 abandoned-finish events captured.
- T4 engine runs: docs/logs/step17-t4-runs.txt (frozen manifest sha proven
  in-run), analysis docs/logs/step17-t4-analysis.txt. PL1 2,128 blocked /
  58 deny_status / 4 errors; PL2 8,845 / 58 / 4 / 1 inconsistent. 3
  timeouts at PL1 (max 2,043.5 ms), 32 limits per PL, 0 overload. Per-id
  connector comparison NOT COMPUTED (reference files on the unreachable
  lab host; no docker here).
- Harness fix (rule 40): crs_audit newline-only splitting; failing test
  first (tests/test_crs_audit.py), 108 passed / 3 skipped after.
- go test 23/23 PASS with the real 481,798-byte fixture (rebuilt from the
  frozen manifest; sha c8ce11f2... reproduced bit-exact by the step-09
  builder — the current builder writes a NEW manifest sha 8c6c20ed...
  because of the step-13 cookie canonicalization, which is why the v0
  builder is pinned in git history).

## Step-18 (2026-11-21, same host as step-17)

- Durable evidence (rule 42): tools/preserve_run.sh; 24 files under
  docs/logs/runs/ after T1; step-17 run dirs back-filled (s17-t2
  audit/outcome regenerated from raw logs, counts match).
- T3 413 fix (E22 failing first, 13e0b13 -> e198ead): the engine drains
  the body before answering 413/503; the three step-17 reset ids now
  return 413 with a readable body (docs/logs/step18-t3-replay.txt).
- T4 body fidelity (E23-E25 failing first, 1964793 -> 3f3f440; scope fix
  E26, 02bac43): SecRuleUpdateTargetById adds REQUEST_BODY to 166 CRS
  rules (REQUEST-930..944 families; 921 excluded after it manufactured
  126 PL1 false positives on raw multi-line bodies). Pre/post runs of all
  five datasets at PL1+PL2 with rule-29 config proofs; final numbers and
  the flip-corrected gain/loss lists in docs/baseline-v1.3.md and
  docs/logs/step18-t4-analysis.txt.
- NEW engine behaviour (UNEXPLAINED, counted, pre-existing): occasional
  pass-through of a would-block request; replay evidence and rates in
  docs/logs/step18-t4-flip-replay.txt.
- Abandoned-call cost A/B (PROVEN): 62,658 ms PRE vs 389,118 ms POST on
  the 481,798-byte fixture, uncontended (docs/logs/step18-t4-abandoned-cost.txt);
  E20's 120 s deadline fails on POST as a result.
- T2 connector comparison: BLOCKED (no docker/sudo on this host);
  decision 0004 stays provisional.

## Step-20 (2026-11-21, post-reboot host — rule 43)

- T1 dup-args (preregistered docs/plan-dup-args.md): NO bypass on the 8
  preregistered shapes on any of the three engines (identical counts;
  errors counted separately). The step-19 flip defect is confined to its
  captured context and is FIXED by the coraza v3.8.1 bump (E30 48/2000
  -> 0/2000; flip_repro PL2 0/2500). Evidence: docs/logs/step20-t1-summary.txt,
  docs/logs/runs/s20-t1-dupargs/, docs/logs/runs/s20-t1-e30/.
- T2 availability: lanes shipped (SMALL cap 8, LARGE cap 2, defaults
  documented before running); E29 rewritten deterministically (rule 48
  test hook) and now PASSING; large-lane attack run serves 269/269
  benign POSTs (step-19: 0/131); small-lane residual exposure measured
  (6/276). DIAGNOSTIC subprocess-kill spike: caps post-deadline CPU to
  <=500 ms but respawn costs 1.3-2.7 s — not proposed for shipping.
  Evidence: docs/logs/step20-t2-*.txt, docs/logs/runs/s20-t2-*.
- T3 cost: pathology content costs 5-12x same-size benign prose
  (PL1 128 KB: 83.4 s post vs 6.5 s prose); post-engine PL2 pathology
  131 KB bimodal 30-120 s (UNEXPLAINED); 942100 raw-body target
  contributes 0 blocks on benign-wcp-v1 and 2/23 on a directed SQLi
  canary (PL1), 0 at PL2. Options measured, no change shipped.
  Evidence: docs/logs/step20-t3-cost-analysis.txt.
- T4 canary (rule 47): body inspection PROVEN for the A3 request class
  (engine 98/100, connector 99/100 with an appended XSS canary);
  application/json+protobuf NOT raw-body inspected (JSON processor gap,
  both engines). Audit of the 42 new benign-wcp-v1 blocks: 0/42 look
  like attacks (all browser telemetry) -> classified false positives.
  Token count corrected 6 -> 8. Evidence: docs/logs/step20-t4-*.txt.

## Step-23 (2026-11-27, macOS host of step 22; no container, no network)

Engine changes, each test-first (docs/acceptance.md E35 to E41), and what
the runs show. Numbers and raw outputs: reports/step-23.md,
docs/baseline-v1.8.md.

- T1 framing events: every refusal of the framing gate now writes a
  `framing` event (5 of 5 cases wrote none before). In the parsing
  differential all 12 gate refusals have their event.
- T2 deterministic matching: the engine builds against a vendored coraza
  v3.8.1 with one patch (sorted key order for map-backed collections).
  E37: 2,000 replays each of syn-chain and syn-dup, one status and one
  rule-id set (stock: 1,564 / 436 and two sets). flip_repro PL2 0 of 2,500.
  In-process against worker mode on the wcp datasets: 0 rule-id set
  differences in 60,000 pairs (step 22: 3 ids). Against the stock-coraza
  runs: 0 status differences, 1 rule-id set difference (942130), DESIGN
  (order by key, documented before the run). Limit, measured: a tautology
  under a key that sorts before a harmless x=y member is passed 300 of 300
  times (E39). Evidence: docs/logs/step23-e37-*.log, step23-flip-pl2.txt,
  step23-parity.txt, step23-coraza-vendor-check.txt.
- T3 compressed-looking bodies: log-only event (E40, E41). benign-wcp-v0:
  14 events, benign-wcp-v1: 2, all zlib `78 01`, all text/plain POSTs that
  the rules already block at PL1 and PL2. Evidence:
  docs/logs/step23-magic-analysis.txt.
- T4 worker-mode evidence: the four wcp runs in worker mode now carry
  `engine_decision`; the worst-case sets with the fail-closed classes are
  equal to the in-process ones (2,284, 8,967, 1,133, 4,480). A real 503
  overload reaches kortex_eval: 46 of 48 (in-process) and 47 of 48 (worker)
  with the runner at 8 workers (DIAGNOSTIC,
  docs/logs/step23-overload-DIAGNOSTIC.txt).
- T5 strict parsing differential, first slice: 61 hand-written cases
  against the engine, a Python http.server and a Go net/http backend. The
  engine forwards 14, refuses 47 (framing gate 12, rules 16, body read 2,
  its Go HTTP parser 17). Disagreements with the Python backend: 50 (47
  engine stricter, 3 re-framed chunked bodies); with the Go backend: 23
  (all engine stricter). No case where the engine forwards something a
  backend then refuses or reads differently, and no canary reaches a
  backend. BUG, not fixed (rule 39): the 17 parser refusals carry no
  kortex marker and no event. Evidence: docs/logs/step23-parsing-diff.txt.
- Suites at 9754a0d: Go 55 PASS / 0 FAIL / 5 SKIP, with the fixture 60 / 0
  / 0; pytest 234 passed, 4 skipped.
- NOT MEASURED in step 23: the attack datasets and the connector /
  ModSecurity images with the patched engine; a controlled timing of the
  patch; E37 in worker mode; the parsing cases at PL2 and against other
  backends.

## Step-24 evidence (2026-11-27, baseline v1.9)

- T1 parser refusals: BUG of step 23 fixed, test first (E42 failing 33 of
  33 in 323ed49). The gate refuses with `400 kortex-decision=framing` and a
  `framing` event what Go's net/http answered itself. Measured: the 61
  differential cases have 0 refusals without a marker (step 23: 17), 44
  cases unchanged; 19,257 seeded damaged heads, 0 decided differently by
  the gate and by net/http (E45). Evidence: docs/logs/step24-e42-*.log,
  step24-parsing-diff.txt, step24-parsing-diff-vs-step23.txt.
- T2 two holes of the framing gate, both BUG, both PROVEN by failing tests
  (5cd6fc2) and fixed (40c57ad): a framing header after a bare LF was not
  seen (E46, 4 of 4 forwarded before), and a second request on a
  connection left open by `OPTIONS *` or the admin paths was not gated
  (E48, 6 of 6 reached the backend before). Evidence:
  docs/logs/step24-e46-e48-*.log.
- T4 own datasets, Host localhost, patched engine: attacks-v0 954 and 1,024
  of 1,054 blocked at PL1 and PL2, attacks-ct-v0 292 and 313 of 320 (both
  IN-SAMPLE), encoding-diff-v0 137 and 147 of 192 (counts), benign-browse-v1
  124 of 774, benign-hard-v0 22 and 78 of 180. In-process against worker
  and patched against stock coraza (DIAGNOSTIC): 0 differences of any kind
  in 5,040 pairs each. Evidence: docs/logs/step24-own-summary.txt.
- T5 wcp datasets: unchanged sample by sample against step 23 (60,000
  pairs, 0 differences); worst cases 2,284, 8,967, 1,133, 4,480; 0 framing
  events. Evidence: docs/logs/step24-parity.txt.
- NOT MEASURED in step 24: connector / ModSecurity images, timing, the
  differential with the new shapes against real backends, PL2 with a
  numeric Host.

## Step-25 evidence (2026-11-27, baseline v2.0)

- A1, the CRS v4.25.2 regression suite (go-ftw 2.1.0, DetectionOnly, PL4,
  4,987 tests), first time on the engine: 4,862 passed, 125 failed
  (97.49%); 4,863 / 124 with the CRS project's coraza-overrides. A1 is
  failing. Worker mode, a repeat and a DIAGNOSTIC build on stock coraza
  v3.8.1: 0 tests with a different result or rule-id set. Reference (stock
  coraza v3.8.1 as Go middleware, with response inspection): 4,970 / 17.
  Evidence: docs/logs/s25-ftw.txt, s25-ftw-fixed.txt,
  step25-ftw-final-diffs.txt.
- The 125 failed tests (rule 39), 0 UNEXPLAINED: 78 need response
  inspection (DESIGN; the reference passes all 78); 19 expect 920420
  (DESIGN, PROVEN: DIAGNOSTIC without rule 900220, exactly these 19 more
  pass); 15 are matches of the REQUEST_BODY targets where the suite says
  the rule must not match (DESIGN, PROVEN: DIAGNOSTIC without the target
  updates, these 15 pass; potential false positives); 3 are refused by the
  gate (DESIGN; `framing 400` in the per-test probe); 10 are failed by the
  reference in the same way (no difference). Evidence:
  docs/logs/step25-failed-tests.txt, step25-failed-probe.txt.
- Five BUG-class differences fixed, test first: the request target and the
  protocol as sent (E52), Transfer-Encoding (E53), the Host line as sent
  and the same in worker mode (E54), 942130 without the REQUEST_BODY target
  (E55), Content-Length once (E56). Effect on the suite: 5 tests from
  failed to passed (4,857 -> 4,862), none the other way. Evidence:
  docs/logs/step25-e52-e55-*.log, step25-e55-revised-failing.log,
  step25-e56-*.log.
- Own datasets against the step-24 runs: 0 status and 0 worst-case-set
  differences in 10,080 pairs; rule-id sets differ only by 942130 at PL2
  (attacks-ct-v0: lost on 28, gained on 7; encoding-diff-v0: gained on 12).
  wcp datasets: 0 status and 0 outcome differences in 60,000 pairs, worst
  cases 2,284, 8,967, 1,133, 4,480; rule-id sets differ on 4 requests, by
  942130. Evidence: docs/logs/step25-own-vs-step24.txt, step25-parity.txt.
- NOT MEASURED in step 25: the suite on the connector and ModSecurity
  images, in blocking mode, or at another paranoia level; the 11 other
  chain-starting rules that keep the REQUEST_BODY target; timing.

## Step-26 evidence (2026-11-28, baseline v2.1)

- A2, attack side: attacks-v1 frozen (2,670 requests, 1,335 distinct
  payloads, 9 families, 5 of them new; no payload shared with attacks-v0;
  plan committed before the build, reach check before the freeze). With
  attacks-v0: 1,862 distinct payloads. Evidence: docs/plan-attacks-v1.md,
  data/attacks-v1/README.md, docs/logs/step26-build.log, step26-reach.txt.
- Held-out recall of the engine (no engine code changed in this step): PL1
  2,214/2,670 = 82.92% (95% Wilson 81.45 to 84.30), PL2 2,444/2,670 =
  91.54% (90.42 to 92.53); best case equals worst case; in-process equals
  worker per sample. In-sample attacks-v0: 90.51% and 97.15%. Weakest
  family ldap (8 and 14 of 60). Evidence: docs/logs/step26-engine.txt,
  step26-summary.txt.
- Baselines on the same manifest: Coraza connector image 2,214 and 2,444
  (0 status differences against the engine), ModSecurity image 2,210 and
  2,444 (8 status differences at PL1, 0 at PL2). Rule 36 controls 20/20
  before and after. Evidence: docs/logs/step26-baseline.txt.
- Engine against connector, 4 rule-id-set differences at PL2 (942330):
  PROVEN to follow from the connector's build tag
  `coraza.rule.no_regex_multiline`. Evidence:
  docs/logs/step26-DIAGNOSTIC-942330.txt.
- DIAGNOSTIC without the REQUEST_BODY targets: 0 differences on attacks-v1;
  the same binary differs on attacks-ct-v0 (canary, 6 requests). Evidence:
  docs/logs/step26-DIAGNOSTIC-no-body-targets.txt,
  step26-DIAGNOSTIC-canary.txt.
- NOT MEASURED in step 26: the benign side of A2, body carriers that fit
  the new families, timing.
