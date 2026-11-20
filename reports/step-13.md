# Step-13 report

- Summary: Closed the engine-evidence tasks T1–T8: corrected the step-11
  Coraza body-limit claim (the 413s were nginx, and Coraza v3.7.0 enforces no
  NoFilesLimit at all), aligned the proxy config, re-ran full-scale WCP parity
  on both engines (PL1/PL2), PROVED the only-Coraza body-rule pattern is a
  body-access difference (T6) and the Coraza latency pathology is
  engine-internal, not a CRS rule (T7); wrote baseline v0.8 and the
  criteria-mapped engine evidence. pytest: **103 passed** (`.venv/bin/python
  -m pytest -q`, raw output below).
- Task table:

| task | status | evidence |
|---|---|---|
| T1 image/version + wcp-train + supersession + forensics | done | docs/logs/step13-t1-evidence.txt, step13-t1-crs-setup-lines.txt, step13-smoke-rerun.log |
| T2 replay-defect inventory + future-only builder fixes | done | data/benign-wcp-v0/replay-defects.jsonl (git-added), tests/test_build_benign_wcp.py |
| T3 engine criteria before analysis | done | docs/decisions/0002-engine-criteria.md, tools/policy_clear.py, out/step13-policy-clear-wcp.jsonl |
| T4 body-limit knob + bisect + alignment | done | docs/logs/step13-t4-{coraza-env,bisect,nginx-conf}.txt, deploy/coraza-nginx.conf.template |
| T5 Coraza WCP PL1+PL2 re-run + parity | done | out/step13-t5-coraza-wcp.log, docs/logs/step13-t5-{parity,integrity,rule-presence}.txt |
| T6 content-type swap test | done (PROVEN) | docs/decisions/0003-step13-t6-hypothesis.md, tools/run_step13_t6.sh + pick/build/analyze |
| T7 latency pathology | done (PROVEN engine-internal) | docs/logs/step13-t7-evidence.txt + 8 raw logs |
| T8 baseline v0.8 + engine evidence vs C1–C3 | done | docs/baseline-v0.8.md, docs/engine-evidence.md (step-13 section) |

## Key numbers (rule 31 — in the body, not only files)

**T1.** Images: juice-shop digest unchanged (9bbaecc4…); ModSecurity pinned
digest 6296ce68… used for every run (floating tag drifted to 98d448750b86 on
2026-11-19; drifted pull deleted, never used); Coraza re-pinned bfbfe70b…
(old ffefe715… deleted from ghcr — old Coraza runs unverifiable from image;
engine version UNVERIFIED for that image). Engines: libmodsecurity3 3.0.17 /
coraza v3.7.0; CRS 4.25.2 both. Default-signature check: 12/12 runs pass.
wcp-train blocked counts (frozen runs): TEST default PL1 1,769/10,047
(17.61%; worst 1,803 = 17.95%), PL2 4,206 (41.86%); TEST wcp-train PL1 514
(5.12%), PL2 3,229 (32.14%); TRAIN default PL1 2,054/9,947 (20.65%), PL2
4,743 (47.68%); TRAIN wcp-train PL1 474 (4.77%), PL2 3,554 (35.73%).
Step-10 "3,181" superseded by 514 — PROVEN: harness rendering bug made 920420
fire on every typed request (1,264/1,264 json + 338/338 form-urlencoded in
the step-10 audit); step-12 T7 reproduced 514 with identical id sets.
6 absent ids reconciled: wcp-6b0bf5e43122 (non-latin-1 header value) + 5
URI-too-long (8,357–10,900 B, quarantined, rule 12 file committed path
out/benign-wcp-v0-reach-quarantine.jsonl). Empty-ModSec-audit forensics:
PROVEN reload race (old workers audit to stdout after `nginx -s reload`);
step-12 smoke rule-ID comparisons INVALID, superseded by re-run — sqli-01 now
`403 waf_block [942100, 949110]` on BOTH engines, PL1 sym-diff 0 (6=6).

**T2.** data/benign-wcp-v0/replay-defects.jsonl: 752 rows, 700 unique
samples — recorded_cl_mismatch 653, json_members_over_1000 42,
body_over_131072 32, gzip_header_mismatch 19, uri_too_long 5, non_latin1 1.
Rates with/without defect samples are reported separately wherever used
(rule 14); v0 manifest untouched; builder fixes gated to future versions
(6 tests pass).

**T3.** Criteria C1–C3 committed before T5/T6 analysis (decision 0002; no
numeric targets, no recommendation). Policy-clear subset of WCP:
17,022/20,000 = 14,279 body-less + 2,743 body-bearing.

**T4.** 524,288 source PROVEN: image ENV `CORAZA_REQ_BODY_NOFILES_LIMIT`
(rendered into coraza.conf at container start — why sed+reload never worked).
All historical Coraza 413s came from nginx (`client_max_body_size` unset →
1 MiB default; ModSecurity image sets 0). Bisect (1 KB resolution, both
engines): ModSecurity enforces NoFilesLimit 131,072 (json/urlenc 400 at
≥131,072; multipart passes to total limit); Coraza v3.7.0 does NOT enforce
NoFilesLimit (131,072 configured and read back; 140,000–1,000,000-byte bodies
pass) — documented engine difference. SecRequestBodyLimit 13,107,200:
Coraza byte-exact (13,107,199→200, 13,107,200→413); ModSecurity passes at
13,107,200. Post-alignment: 2 MB multipart→200, 20 MB→413 on both.

**T5.** n=20,000 per cell, worst case = waf_block + waf_deny_status +
inconsistent + error (rule 32), Wilson 95%:
- PL1 blocked: modsec 3,823 (19.11%) vs coraza 3,824 (19.12%), sym-diff 13
  (6/7). PL1 worst-case: 3,888 (19.44%) vs 3,891 (19.45%), sym-diff 5.
- PL2 blocked: 8,949 (44.74%) vs 8,951 (44.76%), sym-diff 14 (6/8). PL2
  worst-case: 9,015 (45.08%) vs 9,026 (45.13%), sym-diff 11.
- Policy-clear body-less (n=14,279): PL1 410 vs 410 (2.87%), sym-diff 0;
  PL2 4,130 vs 4,130 (28.92%), sym-diff 0. Policy-clear body-bearing
  (n=2,743): PL1 435 (15.86%) vs 441 (16.08%), sym-diff 8; PL2 1,841
  (67.12%) vs 1,848 (67.37%), sym-diff 9. Never merged (rule 14).
- Error recurrence: step-12's 9 Coraza + 3 ModSecurity errors do not recur at
  that count — Coraza PL1 6 (5 timeouts + 1 encoding), modsec PL1 1 (same
  encoding sample wcp-6b0bf5e43122); PL2 3 vs 1.
- The 11 oversize 413 divergences: removed as a class by the nginx alignment
  (wcp-34940e7ffce1, 1,620,081 B: now 403 on Coraza, was 413); bodies above
  SecRequestBodyLimit still 413 on both where the limit applies.
- All four runs' capture integrity checked (audit∩resp complete, outcomes
  = 20,000; docs/logs/step13-t5-integrity.txt).

**T6 (DIAGNOSTIC).** Hypothesis written first. On 100 seeded samples:
Coraza recorded ≥1 body-derived rule on 97/100, ModSecurity on 6/100; after
rewriting CT to application/x-www-form-urlencoded ModSecurity records 97/100.
Rule 200007: Coraza 2, ModSecurity 0 recorded / 1 rewritten. PROVEN: the
only-Coraza body-rule pattern is body access on policy-rejected CTs, not a
regex difference. Neither engine called correct (rule 4).

**T7 (DIAGNOSTIC).** wcp-80a49c991b2d (477,231 B text/plain POST): Coraza
16 KB ~0.3 s → 477 KB ~44 s (super-linear, ≈quadratic from 128 KB up; all
403); ModSecurity flat 7–92 ms at PL1 AND PL2 (27–68 ms at PL2). Dominant
cost PROVEN engine-internal, not a CRS rule: removing all 8 matched
body-derived rules → unchanged ~40 s; SecRequestBodyAccess Off (verified
in-container) → 3–5 ms; DetectionOnly → still ~42 s; urlencoded same size →
1.8 s; multipart 2.8 MB → 14–50 ms; direct-to-stub → 3 ms. Slow bodies are
exactly those Coraza scans in full and ModSecurity skips. Internal mechanism:
HYPOTHESIS (no CPU profile; upstream coraza #1176/#1796 related but same-code-
path claim UNVERIFIED for v3.7.0).

**T8.** docs/baseline-v0.8.md (dated corrections: step-11 body-limit claim
DISPROVEN and replaced; step-10 3,181 superseded by 514; "parity" wording
per rule 32) and docs/engine-evidence.md step-13 section mapping results to
C1 (measured, per-sample), C2 (measured: limits + bisect + latency), C3
(rule-29 proofs present for every cited run) — no verdict, no
recommendation. README/acceptance updated with counts only.

## Raw evidence (exact commands; outputs in the named files)

- pytest: `.venv/bin/python -m pytest -q` → `103 passed in 14.04s` (one
  benign stderr line from the audit-socket test: "Exception occurred during
  processing of request from ('127.0.0.1', 47680)" — pre-existing, test
  passes).
- Full-scale runs: `tools/run_coraza_parity.sh benign-wcp-v0
  data/benign-wcp-v0/manifest.jsonl 1|2` (log out/step13-t5-coraza-wcp.log,
  rule-29 lines inside); ModSecurity PL1/PL2 runs from step-12 with the
  post-alignment proxy (rule-29 lines in run logs).
- Bisect/controls: `tools/run_step13_t4_bisect.sh`,
  `tools/run_step13_t7_bisect.sh <ids>`, `tools/run_step13_t7_controls.sh`
  (outputs under docs/logs/step13-t4-*.txt, step13-t7-*.txt).
- Trimmed where noted: step13-t1-evidence.txt contains the full computed
  tables; step13-t5-parity.txt lists every differing sample id.

## Deviations from instructions

- Mid-step the execution environment moved from the essentials lab to the
  Docker lab (docker access required for T4/T6/T7 containers); the Docker lab
  stopped once mid-T7 and was redeployed (images re-pulled by digest and
  verified before continuing). No data was lost (shared storage).
- T7 bisect first removed all 8 candidate rules as a group, then subsets —
  a bisect by sets, not strictly one-at-a-time; sufficient because the
  all-8 run already exonerated the rules.
- The first SecRequestBodyAccess-Off control silently did not apply its
  override; it was redone with in-container mount+content verification and
  only the verified redo is cited (both attempts are in the logs).

## UNVERIFIED items

- Engine version of the OLD Coraza image (deleted upstream, not pullable).
- The exact Coraza internal code path behind the latency pathology (external
  behaviour PROVEN; mechanism HYPOTHESIS).
- Whether upstream coraza issues #1176/#1796 describe the same code path in
  coraza v3.7.0.

## Questions for instructor

1. Should Coraza's non-enforcement of SecRequestBodyNoFilesLimit be treated
   as a config-parity failure (to be worked around in deploy config) or
   accepted as a documented engine difference in later steps?
2. The T5 worst-case PL2 sym-diff (11) is entirely only-coraza on large
   multipart body_over_131072 samples that Coraza passes (200) and
   ModSecurity does not — is this stratum worth a dedicated dataset version,
   or does the documented difference suffice?
