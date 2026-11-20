# Plan: Coraza under widened policy, benign side (step-15 T3) — PREREGISTERED

Status: written and committed BEFORE any run of this step's cells (rule 22).

## Question

On benign held-out traffic, does Coraza's blocked set change when the
content-type policy is widened from crs-default to crs-ct-wide? Counts only,
no interpretation (the step-15 task wording).

## Data

- out/wcp-heldout-test-manifest.jsonl — 10,047 benign WCP samples on the
  step-10 held-out TEST hosts. Split rule (committed,
  docs/logs/wcp-heldout-split.json): seed 0,
  `sha256('wcp-heldout-v0|'+host) % 2; 0=TRAIN 1=TEST`. The TEST hosts were
  held out before any config work and have never been used to derive a
  configuration, so this evaluation is out-of-sample for the host split.
- The crs-ct-wide definition is the step-14 one (docs/plan-attacks-ct-v0.md):
  CRS 4.25.2 default list + `|text/plain| |application/octet-stream|`, set
  via ALLOWED_REQUEST_CONTENT_TYPE. In-sample note (rule 19): crs-ct-wide was
  defined from step-14 attack-side observations; its result here is
  out-of-sample for the benign TEST hosts but the config itself is
  attack-derived — labelled on every result.

## Cells

- coraza-default-pl1 and coraza-ct-wide-pl1 (2 runs).
- Coraza image digest bfbfe70b… (pinned), fresh container per run (rule 13),
  rule-29 line from inside the container, rule-36 controls (20 before + 20
  after, `/?audit-ctl=%27%20OR%201%3D1--`), runner --workers 1, timeout 30 s.
- Raw logs: docs/logs/step15-t3-runs.txt; per-run out/ directories
  out/s15-t3-coraza-{default,ct-wide}-pl1/.

## Analysis (stated before the runs)

- Per config: blocked count, worst-case count (waf_block + waf_deny_status +
  inconsistent + error, rule 32), Wilson 95% intervals on both, denominators
  stated (reachable samples; errors counted in the worst case per rule 20).
- The number of blocks with a detection rule (any rule id other than 920420
  and the 949110/949100 scoring rules) that are NOT blocks under default,
  with the sample ids listed.
- Per-sample diff of the blocked sets between the two configs, every
  differing id listed with both statuses and rule ids.
- Counts, no interpretation.
