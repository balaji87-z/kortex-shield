# Step-12 Report

- Summary: Closed step-11 evidence gaps: re-pinned drifted engine images by digest and documented before runs; re-ran all 16 small-dataset parity cells (0 blocked-set diff) plus the wcp-train TEST PL1 cell (514 = 514, identical); forensicated the 17 status-400 samples, the 8+1 timeout/error samples, the 11 413 divergences (root cause: Coraza body-limit pin never effective), and the cookie-restore population bug (case-sensitive selection; full 13,261-row re-run executed); ran 20 matched-shape probes with 0 block disagreements.

## Task table

| Task | Status | Evidence |
|---|---|---|
| T1 image defaults + 901160/901162 fallback | done | docs/baseline-config.md (step-12 section), docs/logs/step12-default-signature.txt (12/12 runs pass true-default signature), docs/logs/step12-t1-heldout-classes.txt |
| T1 wcp-train rendered config + class table + neither-class ids | done | docs/logs/step12-t1-heldout-classes.txt (compositions below); 11 neither-class ids all sole-rule 921130 |
| T1 denominator reconciliation | done | 20,000 built / 1 quarantined (wcp-6b0bf5e43122) / 19,994 baseline rows (13,261 dropped + 6,733 absent); step-11 parity runs used the frozen 20,000 |
| T2 re-run small datasets post-fix | done | out/step12-batch1.log; docs/logs/step12-t2-parity-small.txt (0/0 diffs all 8 cells) |
| T3 status-400 forensics | done | docs/logs/step12-status400-forensics.txt |
| T3 WCP parity deep-dive | done | docs/logs/step12-t3-wcp-deepdive.txt, docs/logs/step12-rule-pl-tags.txt |
| T3 matched-shape probes (≤20) | done | tools/probe_matched_shapes.py, docs/logs/step12-t3-probes-*.jsonl |
| T4 rule-29 proof table | done | docs/logs/step12-rule29-table.txt (48 proof lines, 32 distinct runs) |
| T4 oversize probes + 400-vs-413 reconciliation | done | docs/logs/step12-sizeprobe-*.log, docs/logs/step12-oversize-*.log |
| T4 Coraza detection-paranoia mechanism | done | docs/baseline-config.md step-12 section; REQUEST-901-INITIALIZATION.conf lines 126–133 (901125) |
| T4 libcoraza version | done (new image) | docs/logs/step12-coraza-version.txt (`coraza/v3@v3.7.0`); old image UNVERIFIED |
| T5 restored population + re-run | done | tools/restore_wcp_cookies.py fix; out/step12-restored-all.log; docs/logs/step12-t5-cookie-strata.txt |
| T6 timeout/error replay | done | tools/replay_timeouts.py, docs/logs/step12-t6-replay-*.jsonl |
| T7 wcp-train TEST PL1 re-run | done | out/step12-batch1.log; identical to step-11 run |
| T8 docs | done | docs/baseline-v0.7.md; dated notes in docs/baseline-config.md, docs/engine-evidence.md; README + docs/acceptance.md counts |

## Raw evidence (commands and outputs)

### T2: timing vs fix commit + re-run results

Fix commit 37bc833 timestamped 2026-11-19 12:47; all step-11 small-dataset parity
logs (coraza 01:54–05:36, modsec 11:08–11:11 on 2026-11-19) predate it → re-runs
required. Old run dirs backed up to `out/backup-step11-small/` (16 dirs).

Command: `tools/run_step12_batch1.sh` (16 small cells + T7 cell). Result summary
(docs/logs/step12-t2-parity-small.txt):

```
##### smoke PL1
blocked modsec 6  coraza 6  both 6  only-modsec 0  only-coraza 0
##### smoke PL2
blocked modsec 6  coraza 6  both 6  only-modsec 0  only-coraza 0
##### attacks-v0 PL1
blocked modsec 954  coraza 954  both 954  only-modsec 0  only-coraza 0
##### attacks-v0 PL2
blocked modsec 1024  coraza 1024  both 1024  only-modsec 0  only-coraza 0
##### benign-browse-v1 PL1
blocked modsec 184  coraza 184  both 184  only-modsec 0  only-coraza 0
##### benign-browse-v1 PL2
blocked modsec 184  coraza 184  both 184  only-modsec 0  only-coraza 0
##### benign-hard-v0 PL1
blocked modsec 22  coraza 22  both 22  only-modsec 0  only-coraza 0
##### benign-hard-v0 PL2
blocked modsec 78  coraza 78  both 78  only-modsec 0  only-coraza 0
```

Outcome-class note (trimmed): in several cells ModSecurity classifies the same
denied samples as `inconsistent` where Coraza classifies `waf_block` (e.g. smoke
PL1: modsec inconsistent=6 vs coraza waf_block=6); blocked sets match.

### T1: image defaults and per-run default signature

From both images' crs-setup.conf lines 494/583: the allowed-methods /
content-type env settings exist only as commented examples; the effective
default comes from the 901160/901162 fallback (`GET HEAD POST OPTIONS`; CT list
without text/plain; 901370 adds the `application/*+json` wildcard).

Per-run true-default signature check over 12 runs (docs/logs/
step12-default-signature.txt): all 12 print `true-default signature OK` —
920420 never fires on a 901162-allowed content type, 911100 fires only on
PUT/DELETE/PATCH, and text/plain blocks are present (e.g. modsec WCP PL1:
text/plain-blocked 2783; restored-all PL1: 1859).

wcp-train / heldout class composition (docs/logs/step12-t1-heldout-classes.txt,
trimmed to composition lines):

```
wcp-heldout-test-default-pl1: blocked 1769 {policy-only 1379, detection-only 326, detection+policy 53, neither 11}
wcp-heldout-test-default-pl2: blocked 4206 {policy-only 1067, detection+policy 911, detection-only 2228}
wcp-heldout-train-default-pl1: blocked 2054 {policy-only 1666, detection-only 335, detection+policy 44, neither 9}
wcp-heldout-train-default-pl2: blocked 4743 {detection+policy 1303, detection-only 2181, policy-only 1259}
wcp-heldout-test-wcp-train-pl1: blocked 514 {policy-only 124, detection-only 373, detection+policy 6, neither 11}
```

All 11 neither-class blocked ids in TEST PL1 (default and wcp-train) match only
rule 921130; TRAIN PL1 has 9 different 921130-only ids. Note: this recomputation
differs slightly from step-10's reported split (1376/319/53+21) — sole-rule
attribution reproduces detection-only=319 but not the exact split; treated as a
minor methodology difference, not silently reconciled.

### T3: status-400 forensics

docs/logs/step12-status400-forensics.txt (17 samples):

```
class counts: {'malformed_original': 2, 'replay_artifact': 10, 'unknown': 5}
```

- 200002 = "Failed to parse request body" (modsecurity.conf template line 49);
  200007 = "Failed to fully parse request body due to large argument count"
  (SecArgumentsLimit).
- All 10 replay_artifact samples carry `Content-Encoding: gzip` (19 such
  samples exist in the 20,000); the runner sends the header verbatim with the
  decompressed body → engine decode fails; recorded CL ≠ sent bytes for all 10.
- 2 malformed_original: 200002 with CL matching sent bytes, invalid JSON.
- 5 unknown: valid JSON with 1,160–4,373 members hitting 200007's ≥1000
  argument limit.
- Bodies stored as text; no lone surrogates found in these 17.

### T3: WCP parity deep-dive (docs/logs/step12-t3-wcp-deepdive.txt, trimmed)

- PL1 worst-case set (blocked+deny_status+inconsistent+error): modsec 3,888,
  coraza 3,904; only-modsec 1 (wcp-aa98de364e37, 200002 deny-status), only-coraza
  17 (10× 413-inconsistent oversize bodies, several runner errors, 1 gzip 400).
- Only-Coraza rule matches: PL1 22,788 matches across 1,300 samples, all on
  masked data (unmasked 0). ModSecurity blocks are driven mainly by 920420:
  1,151/1,300 = 88.5% at PL1; 2,073/2,744 = 75.5% at PL2. 920420's share of
  only-Coraza matches: 0/22,788 (it matched on both engines).
- Paranoia-tag check (docs/logs/step12-rule-pl-tags.txt): every top only-Coraza
  rule is tagged at or below the run's paranoia level (PL1-run top rules all
  paranoia-level/1; PL2-run top rules 942430/942200/942340/942330/932200… all
  paranoia-level/2). Stronger check: the Coraza PL1 audit contains no
  PL3/PL4-tagged rule ids (78 distinct ids), PL2 audit likewise none (133 ids)
  → effective detection paranoia = run paranoia on both engines.
- Top-5 rules × 3 samples match-shape table produced (variable class +
  argname_len + matched_len, no values): e.g. 921150 on ARGS_NAMES with short
  binary matches (matched_len 2); 932370/942550/920270/942430/942200/942370/
  942340 sampled; in the sampled cases ModSecurity audit entries showed the
  matched variable class present only via REQUEST_HEADERS/TX variables.

### T3: matched-shape probes (20 probes, PL1, both engines)

Probe table documented in tools/probe_matched_shapes.py before sending; raw
statuses in docs/logs/step12-t3-probes-{modsec,coraza}.jsonl; rule extraction
in docs/logs/step12-t3-probes-{modsec,coraza}-rules.jsonl.

```
P01 NUL in arg name        modsec 403 [920270,949110]  coraza 403 [920270,949110]
P02 %86 in name            modsec 200                  coraza 200
P03 %86 in value           modsec 200                  coraza 200
P04 overlong %c0%80        modsec 200                  coraza 200
P05 CESU surrogate         modsec 200                  coraza 200
P06 %fe%fe                 modsec 200                  coraza 200
P07 raw 0xFF in line       modsec 200                  coraza 200
P08 backtick in name       modsec 200                  coraza 200
P09 "{ url" value          modsec 403 [932370,949110]  coraza 403 [932370,949110]
P10 NUL in value           modsec 403 [920270,949110]  coraza 403 [920270,949110]
P11 NUL as name            modsec 403 [920270,949110]  coraza 403 [920270,949110]
P12 %u escape              modsec 200 [920260 logged]  coraza 200 (no rules logged)
P13 valid UTF-8 control    modsec 200                  coraza 200
P14 raw space in line      modsec 400                  coraza 400
P15 JSON lone-surrogate key    modsec 200              coraza 200
P16 JSON lone-surrogate value  modsec 200              coraza 200
P17 JSON \ufffd key        modsec 200                  coraza 200
P18 urlencoded %86/%fe     modsec 200                  coraza 200
P19 1200-member JSON       modsec 400 [200007]         coraza 400 [200007]
P20 plain control          modsec 200                  coraza 200
```

0 block disagreements; the only difference is ModSecurity logging 920260 on P12
where Coraza logged nothing (both 200). The synthetic shapes did not reproduce
the recorded-traffic only-Coraza divergence.

### T4: rule-29 proof table

docs/logs/step12-rule29-table.txt (raw ordered evidence, 48 proof lines
covering 32 distinct runs across step-11/step-12 batch logs). Key results:

- Step-12 runs (out/step12-batch1.log): 8 modsec cells E=On B=1/D=1 (PL1) and
  B=2/D=2 (PL2); 8 coraza cells E=On B=1 D=1 (PL1) and B=2 D=2 (PL2); T7 cell
  E=On B=1 D=1 P=1.
- Step-11 runs: modsec cells all show B/D matching PL; coraza cells show
  `D=` empty (old image never reported it; 901125 fallback applied).
- Step-10 and earlier runs predate rule 29: no in-container proof exists.
- Body limits: not printed by the rule-29 script; captured separately today
  from inside running containers — modsec: SecRequestBodyLimit 13107200,
  SecRequestBodyNoFilesLimit 131072, SecRequestBodyLimitAction Reject;
  coraza rendered file shows the same intended values but the running engine
  keeps 524,288 (see the correction above).

Coraza detection-paranoia mechanism (PL2): the old image ignored the
DETECTION_PARANOIA env; CRS rule 901125
(`&TX:detection_paranoia_level @eq 0 → setvar:%{tx.blocking_paranoia_level}`,
REQUEST-901-INITIALIZATION.conf lines 126–133) set detection = blocking, so the
old-image PL2 runs effectively ran detection=2. The new image renders rule
900001 from DETECTION_PARANOIA; step-12 runs prove D explicitly.

libcoraza version (docs/logs/step12-coraza-version.txt):

```
# Coraza engine version proof (2026-11-20, image bfbfe70b4445)
coraza/v3@v3.7.0
```

### T4: oversize/size probes (commands in tools/run_step12_oversize.sh, tools/run_step12_sizeprobe.sh)

First pass (invalid-JSON padding bodies — measures parse-deny, kept for the
record):

```
modsec 120000-byte body -> 400    coraza 120000-byte body -> 400
modsec 200000-byte body -> 400    coraza 200000-byte body -> 400
both engines' audits: single rule 200002 "Failed to parse request body."
```

Second pass (valid bodies, tools/run_step12_sizeprobe.sh):

```
modsec V1 valid JSON 120,000B        -> 200
modsec V2 valid JSON 200,000B        -> 400   (audit: 200002 "Failed to parse request body.")
modsec V3 multipart+file 200,000B    -> 200
modsec V4 PUT no-CT 200,000B         -> 403   (audit: 911100, 920340, 920640, 949110)
coraza V1 valid JSON 120,000B        -> 200
coraza V2 valid JSON 200,000B        -> 200   (no audit entry — passed)
coraza V3 multipart+file 200,000B    -> 200
coraza V4 PUT no-CT 200,000B         -> 403   (audit: 911100, 920340, 920640, 949110)
```

400-vs-413 reconciliation: for a valid over-131,072 no-files body ModSecurity
rejects with 400 via 200002; Coraza, running at effective 524,288, passes it.
The 11 WCP divergent samples are bodies of 723,995–1,527,423 bytes (all
> 524,288): Coraza rejects 413 (SecRequestBodyLimitAction Reject); ModSecurity
passes 10 multipart POSTs with 200 and method-blocks the no-CT PUT
(wcp-4ff99580bb57) with 403. So the step-11 framing "Coraza 413 vs ModSecurity
400 for the same bodies" was incorrect — ModSecurity does not 400 these; it
passes 10 of 11 and method-blocks the 11th. The 11 divergent samples with each
engine's status (docs/logs/step12-t3-wcp-deepdive.txt):

```
wcp-4ff99580bb57  modsec 403 waf_block [911100,920340,920450,920640,949110] | coraza 413 inconsistent
wcp-34940e7ffce1  modsec 200 waf_pass  | coraza 413 inconsistent
wcp-80922154f132  modsec 200 waf_pass  | coraza 413 inconsistent
wcp-ad3399e805f1  modsec 200 waf_pass  | coraza 413 inconsistent
wcp-1140885081e1  modsec 200 waf_pass  | coraza 413 inconsistent
wcp-f83f7556fc66  modsec 200 waf_pass  | coraza 413 inconsistent
wcp-908ef72be103  modsec 200 waf_pass  | coraza 413 inconsistent
wcp-131fde29d621  modsec 200 waf_pass  | coraza 413 inconsistent
wcp-5b3f575b061d  modsec 200 waf_pass  | coraza 413 inconsistent
wcp-c5155c659149  modsec 200 waf_pass  | coraza 413 inconsistent
wcp-7dfe87a9dd28  modsec 200 waf_pass  | coraza 413 inconsistent
```

### T5: restored-cookie population and full re-run

Population finding: the frozen manifest (20,000) stores the dropped cookie as
`cookie` on 7,512 rows and `Cookie` on 5,754 rows (13,266 total); the baseline
manifest (19,994) has 7,511 + 5,750 = 13,261. tools/restore_wcp_cookies.py
selected with case-sensitive `.get("cookie")`, so out/wcp-cookie-restored-all
held only 7,511 rows — the wrong (partial) population. Fixed to
case-insensitive; rebuilt manifest = 13,261 rows, integrity check passed
("integrity check passed: only cookie values differ"; restored 13261; records
without a cookie header: 0).

Re-run (tools/run_step12_restored_all.sh; ModSecurity, PL1+PL2, fresh container
per run, rule-29 proofs):

```
PL1: total_samples 13261, responses_ok 13261, blocked 5332, error_count 0
PL2: total_samples 13261, responses_ok 13261, blocked 10775, error_count 0
rule29-modsec PL1: E=On B=1 P=1 D=1; tx.blocking_paranoia_level=1;
  tx.detection_paranoia_level=1; crs_setup_version=4252;
  SecRequestBodyLimit 13107200; SecRequestBodyNoFilesLimit 131072; Reject
rule29-modsec PL2: E=On B=2 P=2 D=2; tx.blocking_paranoia_level=2;
  tx.detection_paranoia_level=2; crs_setup_version=4252; (same body limits)
```

Strata results (docs/logs/step12-t5-cookie-strata.txt; Wilson 95% intervals;
worst case and waf_block-only both shown; denominators stated):

```
PL1 dropped via dropped (2,000 seeded, [DROPPED]):  worst 436/2000 = 21.80% (20.05–23.66) | block-only 430/2000 = 21.50%
PL1 dropped via restored (13,261, real cookie):     worst 5362/13261 = 40.43% (39.60–41.27) | block-only 5332/13261 = 40.21%
PL1 dropped via full (13,261, [DROPPED]):           worst 2682/13261 = 20.22% (19.55–20.92) | block-only 2651/13261 = 19.99%
PL1 absent  via full (6,733, no cookie):            worst 1205/6733 = 17.90% (17.00–18.83) | block-only 1172/6733 = 17.41%
PL2 dropped via dropped:  worst 838/2000 = 41.90% (39.76–44.08)  | block-only 832/2000 = 41.60%
PL2 dropped via restored: worst 10809/13261 = 81.51% (80.84–82.16) | block-only 10775/13261 = 81.25%
PL2 dropped via full:    worst 6111/13261 = 46.08% (45.24–46.93) | block-only 6080/13261 = 45.85%
PL2 absent  via full:    worst 2903/6733 = 43.12% (41.94–44.30) | block-only 2869/6733 = 42.61%
```

Top-10 sole-rule attributions (restored run, dropped stratum, worst-case
outcomes, 949110 excluded): PL1: 932270 1614, 920420 1416, 942550 321, 942290
171, 942100 85, 921140 69, 932340 52, 932370 42, 920600 40, 943110 33
(sole-rule total 4,102). PL2: 920420 419, 931130 419, 942200 337, 932271 226,
932240 147, 942440 56, 942340 53, 932236 41, 941150 32, 942120 27 (sole-rule
total 1,920). Per-host worst-case tables (dropped-run vs restored-run, counts
only) are in docs/logs/step12-t5-cookie-strata.txt.

### T6: timeout/error replay (tools/replay_timeouts.py, tools/run_step12_t6.sh)

9 samples × 5 repeats × both engines, 60 s timeout, using the runner's own
send_one (docs/logs/step12-t6-replay-{modsec,coraza}.jsonl):

```
wcp-00f2f589e97a  modsec 200 ~33ms median | coraza 200 ~81ms median
wcp-a5a302eda586  modsec 200 ~13ms        | coraza 200 ~20ms
wcp-86904cff10c3  modsec 200 ~26ms        | coraza 200 ~48ms
wcp-96bd5332ae15  modsec 200 ~25ms        | coraza 200 ~35ms
wcp-ffd61414ef24  modsec 200 ~11ms        | coraza 200 ~34ms
wcp-7df6cb91aaf0  modsec 200 ~6ms         | coraza 200 ~46ms
wcp-eeeb13d052ce  modsec 200 ~5ms         | coraza 200 ~45ms
wcp-80a49c991b2d  modsec 403 ~23ms        | coraza 403 43613–48404ms (5/5)
wcp-6b0bf5e43122  both engines: encoding error (latin-1 U+FFFD), runner-side
```

Conclusion: the slowness follows neither sample in general — 7 of 8 former
timeouts are fast on both engines (transient, load-related). One sample,
wcp-80a49c991b2d (POST text/plain, 477,231 bytes), is engine-specific:
Coraza takes ~46 s consistently where ModSecurity takes ~23 ms; both end in
403. The encoding error is client-side and engine-independent.

### T7: wcp-train TEST PL1 re-run

Command: `tools/run_step12_batch1.sh` (final cell). New run: 514 blocked = old
run's 514; id sets identical (symmetric difference 0); predictions.jsonl
identical. The other three step-11 wcp-train cells are accepted with the
caveat that they ran on the pre-fix harness and old Coraza image.

### pytest

```
$ .venv/bin/python -m pytest -q
97 passed in 14.00s
```

## Deviations from instructions

- The T5 full re-run became necessary (the restored population was wrong:
  case-sensitivity bug in tools/restore_wcp_cookies.py, not a harness count
  issue). Fix applied to the tools script only; the frozen dataset is
  untouched.
- The oversize probe script's first pass used an invalid-JSON body
  (measurement error); a corrected valid-body pass was run and the first pass
  is reported for transparency.
- The Coraza image had to be re-pinned to a newer build because the previously
  pinned digest was deleted from ghcr (documented before runs, rule 17).

## UNVERIFIED items

- Coraza engine version inside the OLD image used for step-10/11 runs (image
  no longer pullable). The new image is proven v3.7.0.
- Whether the running Coraza engine honours SecRequestBodyLimit (13,107,200)
  at all — only NoFilesLimit behaviour was probed.
- Step-10 and earlier runs have no rule-29 in-container proof (rule 29 did not
  exist then); their config values are inferred from pinned image templates.

## Questions for instructor

1. Should future Coraza runs set SecRequestBodyNoFilesLimit via the image env
   (rendered at container start) to actually achieve 131,072, and should the
   WCP coraza runs then be repeated? Under the current effective 524,288 the
   body-limit axis is a known, documented confound for the 11 divergent
   samples.
2. The dataset builder wrote the same dropped-cookie marker under two header
   casings (`cookie`/`Cookie`). Should the builder be fixed for future dataset
   versions (frozen datasets untouched)?
3. wcp-80a49c991b2d (477KB text/plain) takes Coraza ~46 s vs ModSecurity
   ~23 ms — worth profiling inside Coraza, or accept as a recorded engine
   performance characteristic?
