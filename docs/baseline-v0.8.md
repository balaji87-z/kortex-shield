# Baseline v0.8 (step-13, 2026-11-20)

Supersedes v0.7 (kept in docs/baseline-v0.7.md; superseded text is not repeated
here). This version closes the engine-evidence tasks of step-13: the Coraza
body-limit alignment, the full-scale WCP parity re-run, the content-type swap
test, and the latency pathology. No frozen dataset changed and no kortex_eval
behaviour changed (97 tests pass, see reports/step-13.md). Engine criteria were
fixed BEFORE analysis in docs/decisions/0002-engine-criteria.md (C1–C3).

## Corrections of earlier claims (dated notes)

1. **Step-11/v0.7 "Coraza effective NoFilesLimit 524,288" — DISPROVEN and
   replaced (2026-11-20).** The 524,288 figure is the Coraza image's ENV
   default `CORAZA_REQ_BODY_NOFILES_LIMIT` (docs/logs/step13-t4-coraza-env.txt),
   but every historical Coraza 413 actually came from **nginx**, not Coraza:
   the Coraza image ships no `client_max_body_size`, so nginx's 1 MiB default
   rejected the bodies (ModSecurity image sets `client_max_body_size 0`;
   docs/logs/step13-t4-nginx-conf.txt). Furthermore Coraza v3.7.0 **does not
   enforce `SecRequestBodyNoFilesLimit` at all**: with 131,072 configured and
   read back from inside the running container, 140,000–1,000,000-byte
   json/urlencoded/xml bodies pass (docs/logs/step13-t4-bisect.txt). The
   v0.7 wording "every Coraza run to date ran with an effective NoFilesLimit
   of 524,288" is therefore wrong on both the mechanism (nginx, not Coraza)
   and the enforcement (no such limit is enforced).
2. **Step-10 wcp-train "3,181 blocked" — superseded by 514 (PL1).** The
   step-10 number was inflated by a harness rendering bug: the unwrapped
   content-type list made rule 920420's `@within` match nothing, so it fired
   on every typed request (1,264/1,264 json + 338/338 form-urlencoded in the
   step-10 audit). The step-12 re-run reproduced 514 exactly (identical id
   sets); the step-13 T1 table recomputes all four wcp-train cells from the
   frozen runs (docs/logs/step13-t1-evidence.txt).
3. **"Parity" wording (rule 32).** From step-13 on, a parity claim must name
   the quantity compared (blocked set; worst-case set; rule-ID sets) and list
   differences per sample id. The step-12 sentence "0 blocked-set and 0
   worst-case-set differences in all 8 cells" remains true for the four small
   datasets; the full-scale WCP cells below do NOT show zero differences and
   are reported per rule 32.

## Config changes (documented BEFORE the runs they affect, rule 17)

- `deploy/compose.yml` coraza service: `CORAZA_REQ_BODY_NOFILES_LIMIT:-131072`
  and `CORAZA_REQ_BODY_LIMIT:-13107200` (the image renders these into
  `/templates/coraza.conf` at container start — that is why the step-12
  sed+reload pin never took effect).
- `deploy/coraza-nginx.conf.template` mounted to `/templates/nginx.conf`:
  the image's nginx template plus `client_max_body_size 0;` in both location
  blocks, so nginx no longer 413s large bodies before Coraza sees them.
  Documented in docs/baseline-config.md before the step-13 runs.
- Audit-capture fix in `tools/run_modsec_parity.sh` (T1): after
  `nginx -s reload`, the script now sends blocked warm-up probes until the
  audit FILE is non-empty (max 10 tries, else exit 1). Cause PROVEN: after a
  reload, old workers keep auditing to stdout, so requests finished ~1 s after
  reload produced empty audit files and outcome.py correctly marked the 403s
  `inconsistent` (docs/logs/step13-t1-evidence.txt). Step-12 smoke numbers are
  superseded by the re-run: sqli-01 is now `403 waf_block [942100, 949110]` on
  BOTH engines; PL1 symmetric difference 0 (6 = 6).

## Full-scale WCP parity after alignment (T5, baseline numbers)

Denominator: frozen benign-wcp-v0 manifest, 20,000 samples per cell
(19,994 reachable; 6 quarantined for URI length/header encoding — rule 12
file out/benign-wcp-v0-reach-quarantine.jsonl). Rates are worst-case unless
stated (rule 21); Wilson 95% intervals in docs/logs/step13-t5-parity.txt.

- **PL1 blocked set**: ModSecurity 3,823 (19.11%) vs Coraza 3,824 (19.12%);
  symmetric difference 13 (6 only-modsec / 7 only-coraza).
- **PL1 worst-case set** (waf_block + waf_deny_status + inconsistent + error):
  3,888 vs 3,891; symmetric difference 5.
- **PL2 blocked set**: ModSecurity 8,949 (44.74%) vs Coraza 8,951 (44.76%);
  symmetric difference 14 (6 only-modsec / 8 only-coraza).
- **PL2 worst-case set**: 9,015 (45.08%) vs 9,026 (45.13%); symmetric
  difference 11.
- Policy-clear subsets at PL2: body-less — both engines 4,130 blocked
  (28.92%), symmetric difference 0; body-bearing — ModSecurity 1,841 (67.12%)
  vs Coraza 1,848 (67.37%), symmetric difference 9.
- Per-sample difference lists (both PLs, with statuses and rule IDs where
  applicable): docs/logs/step13-t5-parity.txt; rule-ID presence tables:
  docs/logs/step13-t5-rule-presence.txt.
- **Policy-clear subset** (decision 0002 definition; 17,022 of 20,000 =
  14,279 body-less + 2,743 body-bearing, never merged, rule 14):
  body-less PL1 — both engines 410 blocked (2.87%), symmetric difference 0;
  body-bearing PL1 — ModSecurity 435 (15.86%) vs Coraza 441 (16.08%),
  symmetric difference 8.
- Error recurrence (T5 question): the step-12 9 Coraza + 3 ModSecurity errors
  do NOT recur at that count — step-13 Coraza PL1 has 6 errors (5 timeouts +
  1 encoding) and ModSecurity 1 (the same encoding sample); PL2 3 vs 1.
- The 11 oversize 413 divergences from step-12: the nginx alignment removes
  them as a class — e.g. wcp-34940e7ffce1 (1,620,081 B) is now 403 on Coraza
  (was 413); bodies above `SecRequestBodyLimit` still 413 on both engines
  where the limit applies.
- Blocked-set differences are dominated by body-limit/defect samples
  (body_over_131072, recorded_cl_mismatch, gzip_header_mismatch), statuses
  400/403 — attributed per decision 0002, not called engine errors.

## Content-type swap test (T6, DIAGNOSTIC)

Hypothesis written first (docs/decisions/0003-step13-t6-hypothesis.md): on a
content type the policy rejects, ModSecurity does not populate body-derived
variables while Coraza does. Result: **PROVEN** — on 100 seeded samples that
only Coraza had flagged body rules on: Coraza recorded ≥1 body-derived rule on
97/100, ModSecurity on 6/100; after rewriting the content type to
application/x-www-form-urlencoded, ModSecurity records 97/100. Rule 200007:
Coraza 2, ModSecurity 0 (recorded) / 1 (rewritten). So the step-11/12
"only-Coraza body-rule" pattern is a body-access difference, not a regex
difference. Neither engine is called correct (rule 4); diagnostic only
(rule 34).

## Latency pathology (T7, DIAGNOSTIC)

On wcp-80a49c991b2d (477,231-byte text/plain POST): Coraza grows
super-linearly (≈quadratic from 128 KB up: 16 KB ~0.3 s → 477 KB ~44 s, all
403); ModSecurity is flat (7–92 ms, PL1 and PL2). The dominant cost is
**PROVEN to be Coraza engine-internal request-body processing, not any CRS
rule**: removing all 8 matched body-derived rules left the latency unchanged
(~40 s), while `SecRequestBodyAccess Off` (verified in-container) dropped the
same request to 3–5 ms. Multipart bodies up to 2.8 MB are fast on Coraza
(14–50 ms); the slow bodies are exactly the ones Coraza scans in full and
ModSecurity skips (text/plain, empty content type, one urlencoded 958 KB
body). The internal mechanism is HYPOTHESIS (no CPU profile taken). Full
evidence: docs/logs/step13-t7-evidence.txt.

## Not covered (unchanged or new)

- Coraza NoFilesLimit enforcement: non-existent in v3.7.0 — there is no run
  to align; the difference stays documented, no engine code changed.
- The exact Coraza internal code path behind the latency pathology (rule 33:
  HYPOTHESIS).
- The old Coraza image's engine version (image deleted upstream).
- Recall impact of widening the allowed content-type list (unchanged from
  v0.7; attacks-v0 cannot measure it).
