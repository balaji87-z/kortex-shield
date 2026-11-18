# Step 06 report — UA confound removed, outbound-cut outcome, 920320 verified, full matrix

Date: 2026-11-18. Branch `main`. Rules 18–20 appended to AGENTS.md first.
No dataset edits, no rule exclusions, no models, no engine code.

## Summary

- Runner gained `--default-user-agent` (off by default, never overrides
  recorded UA, recorded in run.json); UA = Chrome 158 stable Windows string,
  documented in docs/baseline-config.md BEFORE any run.
- 920320 verified: severity NOTICE, `tx.notice_anomaly_score=2` — the
  step-05 "+5" claim was wrong; dated correction added to
  docs/baseline-v0.1.md (old text kept). 70 of the +72 were real PL2
  detection scoring; only 2 crossed the threshold thanks to the +2.
- New outcome `waf_block_outbound` (additive) classifies the 2 attack and
  18 hard-benign step-05 errors; full 12-run matrix re-run with UA fixed.

## Task table

| task | status | evidence |
|---|---|---|
| T1 runner UA option | done | §T1 below; tests test_default_user_agent_* |
| T2 verify 920320 | done (claim corrected) | §T2; correction note in baseline-v0.1.md |
| T3 waf_block_outbound | done | §T3; docs/block-discriminator.md; tests |
| T4 full matrix | done | §T4; docs/baseline-v0.2.md |
| T5 whoami FP | done (analysis only) | §T5 |
| T6 baseline-v0.2.md | done | docs/baseline-v0.2.md; pointer in v0.1 |

## T1 — runner --default-user-agent

- Flag absent: behaviour byte-for-byte unchanged (no header added;
  `run.json.default_user_agent` is null). Tests:
  `test_default_user_agent_absent_flag_unchanged`,
  `..._added_when_sample_has_none`, `..._never_overrides_recorded`,
  `..._case_insensitive_recorded`. Full suite: 69 passed.
- UA string and rationale (committed before any run):
  `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like
  Gecko) Chrome/158.0.0.0 Safari/537.36` — current stable Chrome 158
  (released 2026-11-17), Windows reduced UA; sources
  https://www.clearcotelabs.com/chrome-user-agent,
  https://www.whatismybrowser.com/guides/the-latest-user-agent/chrome
  (checked 2026-11-18).

## T2 — 920320 evidence

From the image (`docker run --rm owasp/modsecurity-crs:4.25.2-nginx-lts`):

- `REQUEST-920-PROTOCOL-ENFORCEMENT.conf` lines 1519–1535:
  `SecRule &REQUEST_HEADERS:User-Agent "@eq 0"`, `id:920320`, phase 1,
  `severity:'NOTICE'`, tag `paranoia-level/2`,
  `setvar:'tx.inbound_anomaly_score_pl2=+%{tx.notice_anomaly_score}'`.
- `REQUEST-901-INITIALIZATION.conf` line 180:
  `setvar:'tx.notice_anomaly_score=2'` → **weight +2, not +5**.

Probe (runner itself sends no UA; scratch manifest, not a dataset):

    GET /definitely-not-a-real-page-920320probe at true PL2
    → audit entry: rules [920320], severity "5" (=NOTICE), NO 949110 message,
      status 200, not blocked.

Step-05 claim "920320 adds +5": **incorrect** (+2). Correction note added to
docs/baseline-v0.1.md (2026-11-18, old text kept). Re-analysis of the +72
newly flagged at true PL2: 70 have inbound score ≥7 (blocked even without
the +2 — genuine PL2 detection scoring once blocking_paranoia_level=2);
2 have score exactly 5 (needed the +2). Empirical confirmation in T4: with
the UA fixed, attacks PL2 inbound blocks went 1026 → 1024, and the
sample-level diff vs step-05 is exactly those 2 samples
(`command-injection-036c522d-q/-login`).

## T3 — waf_block_outbound

Definition written into docs/block-discriminator.md and committed BEFORE the
analysis: error is incomplete read/reset + audit contains 959100 + inbound
score below threshold; checked only on rows that would otherwise be `error`;
existing outcomes untouched.

- Real step-05 samples `sqli-730d16ce-q`/`-login` → `waf_block_outbound`
  (test with their recorded audit rows).
- Synthetic edges: error without 959100 → error; 959100 with inbound score ≥
  threshold → error; timeout → error; detection mode → error; clean row →
  waf_pass (all tested).
- The 18 hard-benign step-05 errors (logs kept in
  out/benign-hard-v0-pl2-on-v05) all classify `waf_block_outbound`
  (test_outbound_cut_hard_benign_step05_logs).
- Tools print the new outcome in counts (outcome.py already prints all
  outcome counts; benign_breakdown/benign_clusters treat it as blocked via
  outcome == "waf_block"; the rates below report inbound-only and
  including-outbound per rule 20).

## T4 — full matrix (UA fixed)

12 runs = 3 datasets × PL{1,2} × {crs-default, crs-policy-aligned}; every
container verified `B=PARANOIA D=PARANOIA` (raw line per run, e.g.
`=== attacks-v0 PL2 aligned container: B=2 D=2 P=2`).

Rule 18 check (rule IDs in ≥20% of audit entries):

- attacks-v0: 949110 95–98%, 930120 ~31%, 941390 ~31%, 941120 ~30%,
  941100 ~29%, 941160 ~25%, 930100 ~23% (+ at PL2: 942370 28%, 942520 27%,
  932236 24%, 941320 23%) — detection rules matching real payloads plus the
  threshold rule; not harness artifacts.
- benign-browse: default 949110 (33%); aligned: none.
- benign-hard: PL1 none; PL2 949110 (55%), 932236 (24%).

Rates (denominator = full manifest; best = errors/outbound not flagged,
worst = all flagged; rule 20):

| dataset | PL | config | inbound blocked | outbound | best case | worst case |
|---|---|---|---|---|---|---|
| attacks-v0 | 1 | default | 954/1054 | 0 | 90.51% (88.59–92.14) | = best |
| attacks-v0 | 1 | aligned | 954/1054 | 0 | 90.51% (88.59–92.14) | = best |
| attacks-v0 | 2 | default | 1024/1054 | 2 | 97.15% (95.97–98.00) | 97.34% (96.19–98.16) |
| attacks-v0 | 2 | aligned | 1024/1054 | 2 | 97.15% (95.97–98.00) | 97.34% (96.19–98.16) |
| benign-browse-v0 | 1 | default | 34/214 | 0 | 15.89% (11.60–21.38) | = best |
| benign-browse-v0 | 1 | aligned (in-sample) | 2/214 | 0 | 0.93% (0.26–3.34) | = best |
| benign-browse-v0 | 2 | default | 34/214 | 0 | 15.89% (11.60–21.38) | = best |
| benign-browse-v0 | 2 | aligned (in-sample) | 3/214 | 0 | 1.40% (0.48–4.04) | = best |
| benign-hard-v0 | 1 | default | 22/180 | 0 | 12.22% (8.21–17.81) | = best |
| benign-hard-v0 | 1 | aligned | 22/180 | 0 | 12.22% (8.21–17.81) | = best |
| benign-hard-v0 | 2 | default | 78/180 | 18 | 43.33% (36.31–50.64) | 53.33% (46.05–60.48) |
| benign-hard-v0 | 2 | aligned | 78/180 | 18 | 43.33% (36.31–50.64) | 53.33% (46.05–60.48) |

Rule IDs of every blocked request: full distinct-set table generated by the
analysis script (out/ directory; summary in docs/baseline-v0.2.md §Rule 18
and the combos below). Largest sets — attacks PL1:
{941100,941120,941160,941390,949110}×184, {942100,949110}×128; attacks PL2:
{941100,941120,941160,941320,941390,942131,942370,942520,949110}×56;
browse PL1 aligned: {932260,949110}×2; browse PL2 aligned:
{932236,932239,932260,949110}×2, {932236,949110}×1; hard PL1:
{932260,949110}×6, {934110,949110}×4, {942100,949110}×4, …; hard PL2:
{920320-free now} largest {931130,932236,949110}×8, {932236,942131,949110}×8
(920320 no longer present anywhere); outbound-cut rows:
{950100,959100} (+2 attacks) / (+18 hard).

Attacks per-family recall with UA fixed (crs-default; aligned identical):

| family | PL1 | PL2 true |
|---|---|---|
| command-injection | 224/300 (74.67%) | 276/300 (92.00%) |
| path-traversal | 298/300 (99.33%) | 300/300 (100%) |
| sqli | 132/154 (85.71%) | 148/152 (97.37%) |
| xss | 300/300 (100%) | 300/300 (100%) |

PL2 fragment/injection-point (crs-default): cmdinj complete 124/128 both
points, fragment 14/22 both; trav 150/150 everywhere; sqli complete 50/51,
fragment 24/25 both points; xss 150/150. Sample-level diff vs step-05:
PL1 +0/−0; PL2 −2/+0 (the two score-exactly-5 samples).

Aligned-config browse rows carry the **in-sample** label (rule 19): the
config was derived from browse traffic. The attack corpus exercises no PUT
or text/plain, so unchanged attack recall under aligned config is by
construction.

## T5 — whoami false positive (analysis only)

Audit entry (browse PL1 aligned-ua run), `GET /rest/user/whoami?fields=email`
→ 403:

    Matched Data: /rest/user/whoami found within REQUEST_FILENAME: /rest/user/whoami
    ruleId 932260, file REQUEST-932-APPLICATION-ATTACK-RCE.conf, line 567

Rule 932260 (CRITICAL) matches REQUEST_FILENAME|REQUEST_COOKIES|…|ARGS against
a case-insensitive alternation of Unix command names; the `whoami` branch is
`w(?:get…|ho(?:ami|is…))`. Juice Shop's route path itself contains "whoami",
so the URL path matches as a command string. Genuine CRS FP on this app's
route naming; no exclusion made.

## T6 — docs

- docs/baseline-v0.2.md (new): headline table, rule-18 check, family
  breakdowns, in-sample statement, whoami analysis, limitations.
- docs/baseline-v0.1.md: one-line pointer added at the top marking PL2
  columns "confounded by 920320, see v0.2"; numbers unchanged; the T2
  correction note is also present (dated, old text kept).
- README.md and docs/acceptance.md: counts/statuses only.
- No numeric targets anywhere.

## Deviations

- None material. The runner exits non-zero on errors, so two `&&` chains
  aborted and remaining steps were run explicitly (rule 13 held: one run per
  capture). The 920320 probe used a scratch manifest in /tmp (no dataset
  touched).

## UNVERIFIED items

- None.

## Questions for instructor

1. `waf_block_outbound` is currently blocking-mode only. Detection-mode
   equivalent (would_block_outbound) — wanted now or later?
2. The outbound-cut rows are counted as flagged only in the worst case.
   Should the headline FP number for future acceptance runs be best or worst?

## Test status

`.venv/bin/python -m pytest -q` → **69 passed**.
