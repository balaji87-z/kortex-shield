# Baseline v0.9 (step-14, 2026-11-20)

Dated notes on top of v0.8 (docs/baseline-v0.8.md, kept unchanged). Corrections
are listed here, never applied to older text.

## Step-12 Coraza PL2 directory was stale (corrected 2026-11-20)

out/coraza-benign-wcp-v0-pl2-default/ was a step-12 (pre-alignment) run: the
step-13 T5 log for that cell ended at "pre-run probe: 200" and the run.json
was dated 2026-11-19 14:47. The step-13 T5 PL2 Coraza numbers therefore came
from a pre-alignment container. Re-run 2026-11-20 06:51-07:14 with the aligned
compose (rule-29 line in out/step14-t1-coraza-pl2.log: E=On B=2 P=2 D=2,
nofiles=131072 total=13107200): blocked 8,951/19,994, errors 5 (4 timeouts
+ 1 encoding), which matches the step-13 T5 PL2 Coraza count of
8,951 — the PL2 totals were unaffected; per-sample statuses for the 11
oversize samples changed (413 -> 200). The stale directory is replaced by the
re-run; the old run is not kept as evidence.

## T1a: the 11 step-12 oversize-divergent samples (2026-11-20)

Before alignment every one of the 11 had Coraza 413 while ModSecurity passed
(10 multipart POSTs, 200) or blocked on its own rules (1 PUT, 403). All 11
bodies are larger than 1 MiB (723,995-2,829,426 bytes), so the nginx 1 MiB
default on the Coraza image explains every 413 (PROVEN per sample: bytes >
1,048,576 AND 413 disappears when client_max_body_size 0 is deployed). After
the alignment: the 10 multipart samples are 200 on both engines at PL1 and
PL2; the PUT (wcp-4ff99580bb57) is modsec 403 / coraza 400 at both PLs — the
residual difference is the engines' different rule sets on a no-content-type
PUT (920340/920640/949110 vs 911100/920320/920450/200007), not a size effect.
wcp-34940e7ffce1: after alignment it is 200 waf_pass on BOTH engines; the
interim step-14 note claiming a post-alignment "Coraza 403" on this sample was
wrong and is corrected here. Table: docs/logs/step14-t1-oversize.txt.

## T1b: step-13 Coraza timeouts/errors replayed (DIAGNOSTIC, 2026-11-20)

9 unique samples, 3 replays each on both engines at PL1 with a 60 s timeout
(tools/t14_timeout_replay.py, docs/logs/step14-t1-timeout-replay.txt):
- wcp-80a49c991b2d: reproduces 3/3 on Coraza (44.3-45.6 s, 403); ModSecurity
  16-51 ms. The only reproducible timeout.
- The 5 step-13 PL1 timeouts (00f2f589e97a, 96bd5332ae15, 50071536f159,
  ab265f963540, 7df6cb91aaf0) and the other PL2 timeouts (0bdd37cedc4b,
  eeeb13d052ce): do NOT reproduce (all 200 within 66 ms on both engines).
  Classed transient; cause not established (HYPOTHESIS: host load during the
  step-13 run).
- wcp-6b0bf5e43122: the encoding error reproduces identically on both engines
  (runner-side non-latin-1 header, not an engine difference).

## T1c: 20 largest-body replays (DIAGNOSTIC)

docs/logs/step14-t1-analysis.txt. Caveat PROVEN from the tool code: the T7
replay tool sent the RECORDED Content-Length (the recorded_cl_mismatch
defect), so replay statuses differ from full-run statuses on both engines;
timings remain valid.

## T1d: the 8 PL1 + 9 PL2 body-bearing policy-clear differences classified

From out/step13-policy-clear-wcp.jsonl and the step-13 audits (counts only,
rule 35 — this set was chosen from observed differences):
- PL1 (8 total): 1 only-modsec (wcp-96b9ef51be10: modsec 920340/920640/949110
  vs coraza 200007 large-argument-count, 400) — cause class "known engine
  difference (arg-count limit)"; 7 only-coraza policy-clear body-bearing
  (672911deadaa, 71461e371348, 8dc97426f4b3, 93fd2b577bc9, 96a594e2ae57,
  bf3ad3695dc3, c7970d727861) — modsec side shows 200002 (body parse) and/or
  920450 (restricted content-encoding) on samples carrying gzip/CL defects;
  coraza side shows detection rules on the parsed body — cause class "replay
  defect + body-access difference".
- PL2 (9 total): the same 8 plus wcp-aa98de364e37 (modsec 200002 only, coraza
  no audit entry post-alignment — coraza PL2 re-run gives it 403 via
  932240/942131/949110, i.e. a detection block; classed "replay defect").
- Unexplained: 0.

## T1e: reload-race scope (rule 36 motivation)

10 scripts use edit-and-reload for ModSecurity audit capture; only
run_modsec_parity.sh (after the step-13 fix) and run_step13_t6.sh check audit
completeness. Audit-derived rule-ID tables from the unchecked runs are marked
"completeness unproven"; HTTP-response-based results are not affected.
Full list: docs/logs/step14-t1-analysis.txt.

## T1f: T6 variable-class correction (2026-11-20)

Matched variable classes for the 100 swap samples (docs/logs/
step14-t1-analysis.txt): REQUEST_BODY matches are 0 on both engines in both
variants — body-derived matches go through ARGS/ARGS_NAMES. ModSecurity's
recorded-variant matches are TX/REQUEST_HEADERS only (0 body variables);
after the CT rewrite they become ARGS_NAMES/ARGS. Rule 35 note: the 97/100
and 6/100 figures are counts on a difference-selected set, not rates.

## Step-14 T3: attacks-ct-v0 (counts, no interpretation)

8 cells x 320 frozen samples (docs/plan-attacks-ct-v0.md, manifest sha256
69d0447c...). Blocked counts and the 920420-only vs detection split are in
docs/logs/step14-t3-analysis.txt. Rule-36 controls 20 before + 20 after in
every cell. Headline counts: default config blocks 304/320 (PL1) and 316/320
(PL2) on BOTH engines; crs-ct-wide: modsec 224/236, coraza 292/312 — on
ModSecurity, allowing text/plain and application/octet-stream removes the
policy block AND no detection appears on those carriers (0 detection blocks),
while Coraza detects 34-38/40 on them. Detection blocks default->ct-wide drop
by 1 sample on coraza PL2 (rule 920240 on command-injection-ecb32a80,
text-plain and octet-stream carriers); 0 on modsec.

## Step-14 T4: encoding-diff-v0 (counts, no interpretation)

4 cells x 192 frozen samples (docs/plan-encoding-diff.md, manifest sha256
ff00384d...). Blocked counts per encoding are IDENTICAL on both engines
(137/192 PL1, 146/192 PL2) and per-sample disagreements are 0 at both PLs.
Overlong UTF-8: 0/32 blocked on both engines. Work-order discrepancy (12 vs
16 payloads) recorded in the plan before the build.

## Step-14 T5: coraza as a library (DIAGNOSTIC)

tools/go-probe (coraza v3.7.0 module, CRS 4.25.2 files copied from the
coraza image digest bfbfe70b...; PL1; same limits as the container):
- 140,000-byte JSON body: PASSES (200, 648 ms) — confirms at library level
  that SecRequestBodyNoFilesLimit 131072 is not enforced by coraza v3.7.0
  (PROVEN; matches the step-13 T4 container finding).
- wcp-80a49c991b2d body (481,798 bytes text/plain): 403 after 44,206 ms —
  the ~44 s latency REPRODUCES in the library with no nginx/connector.
  PROVEN: the pathology is inside coraza engine body processing. The exact
  internal code path remains HYPOTHESIS (upstream coraza issues #1176/#1796
  related, same-code-path claim UNVERIFIED).
- T6 swap samples (100, recorded and swapped): blocked 100/100 in both
  variants; body-derived detection rules on 100/100 in both (container runs:
  97/100 recorded). The recorded->swapped rewrite changes the body-derived
  rule set on 1/100 samples in-library. The library numbers are close to but
  not identical with the container numbers; the probe is DIAGNOSTIC and
  produces no parity numbers (rule 34).
- 5 plain controls: 4 pass; text/plain POST blocked by 920420 (policy) —
  mirrors the container default config.

## Acceptance criterion added (instructor answer, 2026-11-20)

Coraza's non-enforcement of SecRequestBodyNoFilesLimit is accepted as a
documented engine difference and NOT worked around. It becomes an acceptance
criterion for OUR engine: our configured limits must be explicit, actually
enforced, and provable from inside the running container (rule-29-style
proof + a limit-probing check). Implementing the automated check is left to
the step that builds our engine; the criterion is recorded here.

## Not covered (new)

- Cause of the transient step-13 timeouts (not reproducible).
- Recall impact of the crs-ct-wide config on attacks-v0 at large (only the
  40-payload attacks-ct-v0 set measures it).
- Whether the 1/100 in-library rule-set change on the T6 swap corresponds to
  the container behaviour sample-by-sample (probe is DIAGNOSTIC).
