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
