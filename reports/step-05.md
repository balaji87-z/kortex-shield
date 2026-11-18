# Step 05 report — paranoia verified, attack re-runs, policy/detection split, policy-aligned config

Date: 2026-11-18. Branch `main`. Rules 16–17 appended to AGENTS.md and
committed first. No frozen dataset edited; no models, no engine code, no
rule-specific exclusions.

## Summary

- The image's baked-in `BLOCKING_PARANOIA=1` ENV meant every earlier "PL2"
  run actually had blocking_paranoia_level=1; PARANOIA only raised the
  DETECTION level. Fixed in compose; true PL2 runs done.
- attacks-v0 re-run: PL1 identical to step 04 (954/1054, 0 sample-level
  differences); true PL2 blocks 1026 + 2 errors, entirely explained by CRS
  920320 (missing User-Agent, +5, fires on all 1054 requests).
- crs-policy-aligned config (PUT + text/plain allowed) cuts the natural
  browsing FP rate from 34/214 (15.89%) to 2/214 (0.93%) at PL1 with zero
  attack-recall change.

## Task table

| task | status | evidence |
|---|---|---|
| T1 paranoia proof | done | §1 below + docs/baseline-v0.1.md §1 |
| T2 attacks re-run | done | §2 + docs/baseline-v0.1.md §2 |
| T3 policy/detection split | done | docs/rule-classes.md + §3 |
| T4 policy-aligned config | done | docs/baseline-config.md + §4 |
| T5 cluster-aware reporting | done (session fraction n/a) | tools/benign_clusters.py + §5 |
| T6 coverage + env notes | done | docs/recording-env.md + §6 |
| T7 baseline-v0.1.md | done | docs/baseline-v0.1.md |

## Raw evidence (exact commands; outputs trimmed where noted)

### T1 — paranoia takes effect

    MODSEC_RULE_ENGINE=On PARANOIA=1 docker compose -f deploy/compose.yml up -d --force-recreate baseline-crs
    docker exec deploy-baseline-crs-1 printenv PARANOIA            → 1
    docker exec deploy-baseline-crs-1 grep -n "setvar:tx.blocking_paranoia_level\|setvar:tx.detection_paranoia_level" /etc/modsecurity.d/owasp-crs/crs-setup.conf
      192:    setvar:tx.blocking_paranoia_level=1"
      220:    setvar:tx.detection_paranoia_level=1"
    # same at PARANOIA=2 BEFORE the fix:
      192:    setvar:tx.blocking_paranoia_level=1"     <-- still 1
      220:    setvar:tx.detection_paranoia_level=2"
    docker logs deploy-baseline-crs-1 | grep Configuring
      Configuring 900000 for PARANOIA with blocking_paranoia_level=2
      Configuring 900001 for PARANOIA with detection_paranoia_level=2
      Configuring 900000 for BLOCKING_PARANOIA with blocking_paranoia_level=1   <-- overwrites!
    docker exec deploy-baseline-crs-1 printenv | grep -i paranoia
      PARANOIA=2 / BLOCKING_PARANOIA=1 (image Dockerfile ENV) / DETECTION_PARANOIA unset

Which level does PARANOIA set? With this image: both are first set from
PARANOIA, then `BLOCKING_PARANOIA` (always present, image default 1)
overwrites the blocking level back to 1 — so PARANOIA effectively controlled
only `detection_paranoia_level`. The two levels can differ independently via
`BLOCKING_PARANOIA` / `DETECTION_PARANOIA`.

Fix (committed): compose now passes
`BLOCKING_PARANOIA: ${BLOCKING_PARANOIA:-${PARANOIA:-1}}` and
`DETECTION_PARANOIA: ${DETECTION_PARANOIA:-${PARANOIA:-1}}`. Verified at
PARANOIA=2: lines 192 and 220 both `=2`; printenv shows both =2.

PL2-tagged rule probe — rule 932300 ("Remote Command Execution: SMTP Command
Execution", tag `paranoia-level/2`, REQUEST-932-APPLICATION-ATTACK-RCE.conf
line 1548), request crafted from its own pattern (`\r\n` + `VRFY user@host`):

    curl -s -o /dev/null -w "%{http_code}\n" -H "X-Kortex-Sample-Id: pl2probe-1" \
      "http://localhost:8081/?q=%0d%0aVRFY%20admin%40example.com"
    # PL1: 200; docker logs captured; grep -c 932300 → 0; audit transactions → 0
    # PL2: 200; grep -c 932300 → 1, with:
    #   "ruleId":"932300","file":".../REQUEST-932-APPLICATION-ATTACK-RCE.conf",
    #   "lineNumber":"1548","data":"Matched Data: \x0d\x0aVRFY admin@example.com
    #    found within ARGS:q", tags include "paranoia-level/2"

Rule-ID sets per dataset per PL (from the step-04/05 audits): see
docs/baseline-v0.1.md §1. PL2-only IDs exist in ALL THREE datasets (attacks:
40 IDs; browse: 932236/932239/950100; hard: 17 IDs); none only at PL1.

**Conclusion:** step-04's "identical at PL1 and PL2" was real observed
behaviour but NOT a comparison of two blocking levels — PL2 rules executed
and logged but never scored (blocking stayed 1). Cause fixed; affected runs
re-done at true PL2 (T2, T4).

### T2 — attacks-v0 on the current runner

    # true PL1 (out/attacks-v0-pl1-on-v05): blocked 954/1054, 0 errors
    # true PL2 (out/attacks-v0-pl2-on-v05): blocked 1026, 2 errors, 26 pass
    # per-family comparison: PL1 all four families identical to step 04;
    #   PL2: cmdinj 224→278, trav 298→300, sqli 132→148 (+2 errors), xss 300=300
    #   sample-level: PL1 +0/-0; PL2 +72/-0
    # 920320 ("Missing User Agent Header") appears in 1054/1054 PL2 audit entries
    # error samples sqli-730d16ce-{q,login}: rules {920320, 950100, 959100},
    #   error "IncompleteRead" (target 500 + outbound block cut the response)

Content-Type check: audit entry for `sqli-01f86083-login` records request
headers `Host, Accept-Encoding, X-Kortex-Sample-Id, Content-Type:
application/json, Content-Length: 33` — exactly one Content-Type.
`run.json.git_commit` = `12603928c52f5b1aeeeaa5c02a67b3c9168b8b74` =
`git rev-parse HEAD` at run time.

Note: the runner exits non-zero when any sample errors, which aborted the
`&&` chain twice; logs/audit were then produced by running the remaining
commands explicitly (still one run per capture).

### T3 — policy vs detection

Classification written into docs/rule-classes.md and committed BEFORE the
analysis (policy = 911/920 files; detection = 930/931/932/933/934 incl.
NodeJS/941/942/943/944 files; 949110/950100/959100 = thresholds; 901/905/913/
921/922/95x/98x explicitly unclassified). Results table: docs/baseline-v0.1.md
§3. Headlines: attacks PL1 918 detection-only / 36 both; attacks PL2 1024 both
+ 2 policy-only; browse PL1 32 policy-only + 2 detection-only; hard PL1 22
detection-only; hard PL2 78 both (all include 920320).

### T4 — policy-aligned configuration

Setting names/defaults/URLs in docs/baseline-config.md (committed before the
runs): `tx.allowed_methods` default `GET HEAD POST OPTIONS`
(coreruleset/coreruleset crs-setup.conf.example; image line 494);
`tx.allowed_request_content_type` image default without text/plain (image
line 583; modsecurity-crs-docker docker-compose.yaml documents the env vars).
Observed in all 214 browse samples: GET×135, POST×67, PUT×12;
application/json×59, text/plain;charset=UTF-8×20, none×135.

Aligned values applied via image env vars; verified inside the container:

    494:    setvar:'tx.allowed_methods=GET HEAD POST OPTIONS PUT'"
    583:    setvar:'tx.allowed_request_content_type=|application/x-www-form-urlencoded| |multipart/form-data| |text/xml| |application/xml| |application/soap+xml| |application/json| |text/plain|'"

Rates (full table with rule-ID sets in docs/baseline-v0.1.md §4):

| dataset | PL | crs-default | crs-policy-aligned |
|---|---|---|---|
| attacks-v0 | 1 | 954/1054 = 90.51% | 954/1054 = 90.51% |
| attacks-v0 | 2 | 1026/1054 = 97.34% (+2 err) | 1026/1054 = 97.34% (+2 err) |
| benign-browse-v0 | 1 | 34/214 = 15.89% | 2/214 = 0.93% |
| benign-browse-v0 | 2 | 34/214 = 15.89% | 3/214 = 1.40% |
| benign-hard-v0 | 1 | 22/180 = 12.22% | 22/180 = 12.22% |
| benign-hard-v0 | 2 | 78/180 = 43.33% (+18 err) | 78/180 = 43.33% (+18 err) |

Still-blocked rule IDs (aligned): browse PL1 {932260}×2 (whoami); PL2 adds
{932236,…} on one review edit; hard PL1 unchanged detection sets; attacks
unchanged detection sets (aligned config changed nothing on the attack side;
all PL2 blocks include 920320).

### T5 — cluster-aware reporting

`tools/benign_clusters.py` (class definitions written before analysis; see
module docstring). Outputs (aligned runs) in docs/baseline-v0.1.md §5:
browse — static 46 samples/46 endpoints/0 blocked; socket.io 73/2/0; API
94/19/2 (PL2: 3); other 1/1/0. hard — API 180/2; 22 blocked PL1 (11 of 90
distinct values), 78 blocked PL2 (39 of 90 values; 920320 artifact).

**Session fraction: n/a — deviation.** The frozen browse samples' `source`
field does not contain a session number (the recorder wrote one source string
for all samples and dedupe removed the session dimension), so "fraction of
sessions with ≥1 blocked request" cannot be computed from the frozen data.
Recorded as a limitation; a future recording version must put `session-<n>`
in the source before dedupe.

Dedupe fields stated (also added to data/benign-browse-v0/README.md): hash
covers (method, path, query, content_type, body); headers NOT included.

### T6 — coverage and environment

Coverage of attack injection points in natural-benign (214 samples): search
with non-empty q: **0** (client-side search — dataset README); login email:
10; login password: 10 (every login body carries both). In
docs/baseline-v0.1.md §6. Environment: docs/recording-env.md — Playwright
1.65.2, Chromium 159.0.8154.6, Juice Shop v20.4.0 (app reports
20.4.0-SNAPSHOT), LD_LIBRARY_PATH workaround, not reproducible without those
libraries.

### T7 — docs

docs/baseline-v0.1.md written (new file); docs/baseline-v0.md kept with a
one-line "see v0.1" pointer added at the top (numbers unchanged); README and
docs/acceptance.md updated (counts/statuses only). No numeric targets set.

## Deviations from instructions

1. T5 session fraction not computable (missing session in source field) —
   reported as n/a with cause, see above.
2. The runner exits non-zero on sample errors; two `&&` chains aborted and
   the remaining pipeline steps were run explicitly (rule 13 still held:
   one run per capture).
3. Extra runs beyond the letter of T4: default-config true-PL2 runs for the
   two benign sets (out/benign-browse-v0-pl2-on-v05,
   out/benign-hard-v0-pl2-on-v05) were added so the config comparison uses
   the same blocking level on both sides.

## UNVERIFIED items

- None remaining; the session-fraction item is not "unverified" but
  **uncomputable** from the frozen data (stated above).

## Questions for instructor

1. May the runner send a default `User-Agent` header (e.g. a fixed realistic
   value) so attack runs are not confounded by CRS 920320 at PL2? Or should
   attack samples carry recorded/declared UA headers? This changes
   kortex_eval behaviour (rule 5), so it needs your decision.
2. The 2 (attacks) / 18 (hard) true-PL2 `IncompleteRead` errors come from
   outbound blocking (950100 + 959100) cutting the 500 responses mid-stream.
   Acceptable to keep reporting them as `error`, or do you want a distinct
   outcome class for "response cut by outbound block"?
3. For a future benign recording (v1): confirm `session-<n>` must be part of
   the `source` field before dedupe (fixes the T5 session-fraction gap).

## Test status

`.venv/bin/python -m pytest -q` → **62 passed**.
