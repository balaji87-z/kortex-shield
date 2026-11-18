# Step 03 report: audit-score reconciliation, outcome classification, first frozen attack corpus, attack-only numbers

## Summary
The trav-02 score gap is explained with debug-log evidence: rule 930100 scored twice (matched REQUEST_URI_RAW and ARGS:q) but logged one message, so the audit message list undercounts scoring events. `outcome.py` classifies every sample and reproduces the step-02 expectations exactly. The first frozen attack corpus `data/attacks-v0` (1054 samples, 4 families, public payload lists, frozen before any blocking run) was measured at PL1 and PL2: recall 954/1054 (90.51%) at both levels — attack-only figures, not a baseline.

## Task table

| Task | Status | Evidence |
|---|---|---|
| T1 reconcile audit scores | done | Raw evidence 1.1–1.5, docs/samples/crs-log-trav02.txt |
| T2 outcome classification | done | Raw evidence 2.1–2.2 |
| T3 corpus candidates | done | Raw evidence 3.1–3.3, docs/corpus-sources.md, docs/corpus-plan.md |
| T4 reach check + freeze | done | Raw evidence 4.1–4.2, data/attacks-v0/ |
| T5 runner provenance | done | Raw evidence 5.1 |
| T6 attack-only numbers PL1/PL2 | done | Raw evidence 6.1–6.4 |
| T7 README/acceptance | done | T7 commit |

## Raw evidence

### 1.1 trav-02 audit entry (rules as logged)
    ruleId 930100 | sev 2 | Path Traversal Attack (/../) or (/.../)   [ARGS:q]
    ruleId 930110 | sev 2 | Path Traversal Attack (/../) or (/.../)   [REQUEST_URI_RAW]
    ruleId 930110 | sev 2 | Path Traversal Attack (/../) or (/.../)   [ARGS:q]
    ruleId 930120 | sev 2 | OS File Access Attempt                     [ARGS:q]
    ruleId 932160 | sev 2 | Remote Command Execution: Unix Shell Code  [ARGS:q]
    ruleId 949110 | sev 0 | Inbound Anomaly Score Exceeded (Total Score: 30)

Severity field verified from the real samples: numeric strings; "2" = CRITICAL
(weight 5), "0" = EMERGENCY (949110 itself, no weight). Five critical rules
logged → severity sum 25, engine total 30.

### 1.2 Isolating variants (DetectionOnly, PL1)
    q=..%2F..%2F..%2Fetc%2Fpasswd  → same 5 messages, Total Score: 30
    q=../../../etc/passwd          → same 5 messages, Total Score: 30
The encoding is NOT the cause.

### 1.3 Debug-log evidence (temporary override file, MODSEC_DEBUG_LOGLEVEL=9, not committed)
    $ grep -n "inbound_anomaly_score_pl1" /tmp/modsec_debug.log
    line  379: Saving variable: TX:inbound_anomaly_score_pl1 with value: 0
    line 1413: ... value: 5      <- (Rule: 930100) matched REQUEST_URI_RAW
    line 1420: ... value: 10     <- (Rule: 930100) matched ARGS:q
    line 1462: ... value: 15     <- (Rule: 930110)
    line 1484: ... value: 20     <- (Rule: 930110)
    line 1560: ... value: 25     <- (Rule: 930120)
    line 1740: ... value: 30     <- (Rule: 932160)
Six scoring events. Debug lines around 1406–1417 show 930100 matching
    [9] Target value: "/rest/products/search?q=../../../etc/passwd" (Variable: REQUEST_URI_RAW)
    [7] Added regex subexpression TX.0: /../
    ... setvar ... value: 5 ...
    [9] Target value: "../../../etc/passwd" (Variable: ARGS:q)
    ... setvar ... value: 10 ...
i.e. 930100 applied its scoring setvar twice but only ONE 930100 message
(the ARGS:q match) reached the audit log. 930110, which has `multiMatch`,
logged one message per match event (2 messages). OBSERVED finding (stated as
observed, not as documented ModSecurity behaviour): the audit message list is
not a complete record of scoring events; a rule can score on an additional
variable without a second message. The severity-sum therefore undercounts.

### 1.4 Implementation
`crs_audit.py` now outputs per entry: `inbound_score_from_949110` (as before),
`inbound_score_from_severities` (critical=5, error=4, warning=3, notice=2;
numeric severity mapping verified against the real samples), and
`score_mismatch`. Raw trav-02 entry saved as docs/samples/crs-log-trav02.txt
with the explanation appended. New tests use it; all existing tests pass.

### 2.1 Runner change (additive)
responses.jsonl rows now also carry `body_marker` (true when the nginx error-page
marker appears in the body). Existing fields unchanged. The step-02 smoke
artifacts predated this field, so the smoke run was re-run (same manifest, same
engine settings) to regenerate consistent artifacts.

### 2.2 Real smoke data classification (blocking, threshold 5)
    $ .venv/bin/python -m kortex_eval.outcome --responses out/smoke-pl1-on/responses.jsonl \
        --audit out/smoke-pl1-on/audit.jsonl --out out/smoke-pl1-on/outcomes.jsonl --engine-mode blocking
    proxy_reject: 1
    waf_block: 6
    waf_pass: 5
Per sample (expected → actual):
    trav-01  → proxy_reject ✓ (400, nginx marker, no audit entry)
    whoami-01 → waf_block ✓  (score 5 ≥ 5)
    login-01 → waf_pass ✓    (401 target-own, audit entry with 0 rules)
    sqli-01/02, xss-01/02, trav-02 → waf_block ✓
    home/search/js/img → waf_pass ✓
No inconsistent samples. Matches the step-02 expectations exactly.

### 3.1 Clones (gitignored under data/external/)
    SecLists              6b19c2f5088c45b5dadb4d8918d2ab4f7efb03a9  MIT
    PayloadsAllTheThings  08ea40e77db3f42ef8f20c65196f3936a19b6c86  MIT
Recorded in docs/corpus-sources.md; file choices and rejections in
docs/corpus-plan.md (written before building).

### 3.2 Chosen plain-list files
    sqli:              SecLists Fuzzing/Databases/SQLi/quick-SQLi.txt (77 lines)
    xss:               SecLists Fuzzing/XSS/human-friendly/XSS-Cheat-Sheet-PortSwigger.txt (6047)
    path-traversal:    PayloadsAllTheThings File Inclusion/Intruders/Traversal.txt (4521)
    command-injection: PayloadsAllTheThings Command Injection/Intruder/command_exec.txt (448)

### 3.3 Filter counts (printed by tools/build_attacks.py)
    sqli:              raw=77   blank=0 comment=0  dup=0    -> 77   -> sampled 77
    xss:               raw=6047 blank=0 comment=0  dup=0    -> 6047 -> sampled 150
    path-traversal:    raw=4521 blank=1 comment=10 dup=2018 -> 2492 -> sampled 150
    command-injection: raw=448  blank=0 comment=0  dup=0    -> 448  -> sampled 150
    wrote 1054 candidate samples -> data/attacks-v0/candidates.jsonl
Deterministic: random.Random(0), sampled sets sorted for stable output.

### 4.1 Reach check (DetectionOnly, PL1, BEFORE any blocking run)
    runner: total 1054, responses_ok 1054, blocked 0, error_count 0
    crs_audit: 1007 audit entries
    outcome (--engine-mode detection): waf_pass: 100, waf_would_block: 954
    proxy_reject: 0, inconsistent: 0, error: 0
Filter applied only on proxy_reject/inconsistent/error → nothing excluded.
    probes.jsonl: 0 rows (per family: none)
    quarantine.jsonl: 0 rows
    manifest.jsonl: 1054 samples (sqli 154, xss 300, path-traversal 300, command-injection 300)

### 4.2 Freeze
    $ cd data/attacks-v0 && sha256sum -c MANIFEST.sha256
    manifest.jsonl: OK
    MANIFEST.sha256: 5b6a844d9521082428725b6de6b8921a6c0bdc8606e362b5046af633d4fa8540
README documents label meaning (rule 11), sources, counts, procedure, and that
the reach check ran before any blocking-mode run. Frozen before T6.

### 5.1 Provenance
run.json now records manifest_sha256 and --label key=value pairs:
    $ .venv/bin/python -m kortex_eval.runner ... --label engine_mode=On --label paranoia=1
    {"manifest_sha256": "5b6a844d...", "labels": {"engine_mode": "On", "paranoia": "1"}, ...}
Tests: run() records both; CLI computes the manifest sha256 and rejects a
malformed --label with exit 2.

### 6.1 PL1 run (engine On, PARANOIA=1, workers=1 — see deviation 2)
    runner: total 1054, ok 1054, blocked 954, errors 0
    crs_audit: 1007 entries
    outcome: waf_block 954, waf_pass 100
    report:
    | Overall attack recall | 954/1054 | 90.51% | 88.59% – 92.14% |
    | Recall: command-injection | 224/300 | 74.67% | 69.45% – 79.26% |
    | Recall: path-traversal | 298/300 | 99.33% | 97.60% – 99.82% |
    | Recall: sqli | 132/154 | 85.71% | 79.32% – 90.37% |
    | Recall: xss | 300/300 | 100.00% | 98.74% – 100.00% |
    matched rules but below threshold: 0 (all PL1 scoring rules are CRITICAL = 5)
    score_mismatch entries: 75

### 6.2 PL2 run (container force-recreated, logs captured per run)
    runner: total 1054, ok 1054, blocked 954, errors 0
    crs_audit: 1054 entries (every request matched ≥1 rule at PL2)
    outcome: waf_block 954, waf_pass 100
    report: identical table to PL1 (954/1054, same per-family numbers)
    matched rules but below threshold: 100 (sqli 22, path-traversal 2, command-injection 76)
      — at PL2 the 100 passing samples all matched ≥1 rule scoring below 5
    score_mismatch entries: 934

### 6.3 Cross-run observation
PL1 and PL2 blocking outcomes are identical on this corpus (954/1054). The PL2
difference shows in the audit log: 47 passers had NO audit entry at PL1, while
at PL2 all 100 passers have entries with sub-threshold rule matches.

### 6.4 These are attack-only figures
There is no benign set yet, so no false-positive rate exists and these numbers
are NOT a baseline. Quoted only to show the plumbing produces numbers; the
dataset was not touched after these runs (rule 10).

## Deviations from instructions
1. The step-02 smoke artifacts were regenerated (same manifest, same engine
   settings) because the stored responses.jsonl predated the new body_marker
   field; the old audit.jsonl also used the pre-T1 field names.
2. Corpus runs use --workers 1: with concurrent requests, nginx worker processes
   interleave lines on stdout and corrupt JSON audit entries (a truncated entry
   at line 544 of the first capture; also reproduced with workers=1 when the
   capture accidentally contained two runs). Rule: force-recreate the container
   per run and capture logs for exactly that run. Recorded as a Question below.
3. The debug-log investigation (T1) used a temporary, uncommitted compose
   override file with MODSEC_DEBUG_LOG/LOGLEVEL=9; the committed compose.yml is
   unchanged.

## UNVERIFIED items
- The exact ModSecurity rule for WHEN a multi-variable match logs one message
  vs several (930100 without multiMatch logged 1 of 2 matches; 930110 with
  multiMatch logged both) is stated as observed behaviour on these two rules,
  not as documented upstream behaviour.

## Questions for instructor
1. Log-capture hygiene: ok to standardise on "force-recreate container per run,
   --workers 1" for every future run? It costs ~8s per 1054 requests (fine) but
   should be a written rule before the dataset-scale runs.
2. score_mismatch is frequent (75/954 entries at PL1, 934 at PL2). Should
   outcome/threshold logic keep using inbound_score_from_949110 (engine truth)
   as it does now, with the severity sum only as a diagnostic?
3. The 100 sub-threshold passers at PL2 (mostly command-injection separators
   like `;`, `|`, backticks) — keep them in v0 as-is (frozen), and treat
   "matched but below threshold" as a reported category, or flag families for
   enrichment in a future v1?

## Test results
    $ .venv/bin/python -m pytest -q
    ................................................                         [100%]
    48 passed in 5.86s
(19 pre-existing + 10 runner + 6 crs_audit + 2 smoke-regen-era runner tests
+ 11 outcome + ... — no existing test weakened or deleted; new tests added for
trav-02 sample, outcome classifier, runner provenance.)
