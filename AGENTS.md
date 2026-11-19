# Standing rules

1. Do only the current step. Do not start later steps, add features, or
   refactor beyond what the step says.
2. Never invent facts. Anything you could not verify, mark UNVERIFIED and say why.
3. Evidence over claims. Any statement that something works or passes must come
   with the exact command and its raw output in the report.
4. If an instruction conflicts with reality (wrong image name, different port,
   failing test), stop that item, record what you found, continue with the
   other items. Never silently work around it.
5. Do not change the behaviour of kortex_eval (manifest validation, split,
   metrics) and do not weaken or delete any test. If you think a change is
   needed, put it under "Questions for instructor".
6. Security or attack tooling may only be pointed at the local testbed
   containers (localhost or the compose network). Never at any other host.
7. Pin versions. Record the exact image tags and digests actually used.
8. One commit per task, message format "step-01: <task id> <short summary>".
9. Finish by writing reports/step-NN.md using the template below, then stop.

## Report template (reports/step-NN.md)

- Summary: 3 lines maximum
- Task table: task id | done / partial / blocked | pointer to evidence
- Raw evidence: exact commands and their outputs (say where you trimmed)
- Deviations from instructions
- UNVERIFIED items
- Questions for instructor

10. Frozen datasets. A dataset version is frozen when the SHA-256 of its
    manifest is written next to it. After that no sample may be added, removed
    or edited; a change creates a new version folder. Never change a dataset
    after seeing blocking-mode results on it.
11. Label meaning. For public payload lists, "attack" means "listed under this
    family in this source", not "verified exploitable". State this in every
    dataset README.
12. Never drop a sample silently. Anything excluded goes to a named file with a
    count and a reason.

13. Capture hygiene. One run per log capture, container force-recreated before
    each run, runner --workers 1. crs_audit must exit non-zero if any line that
    starts with {"transaction" cannot be parsed, and print how many.
14. Never merge natural benign traffic and hard benign inputs into one rate.
    Report them separately every time.
15. Scenario counts: always report distinct requests AND distinct payloads (for
    attacks) or distinct endpoints (for benign). A payload sent at two injection
    points is two requests but one payload.
16. Unchanged-result check. If a result is identical under two conditions that
    should differ (for example paranoia levels), treat the condition as unproven
    until it is shown to take effect, with raw evidence from the running
    container.
17. Config changes are documented BEFORE they are run: what, why, and the
    documentation URL, in docs/baseline-config.md. Never change a frozen dataset
    in response to a result. No rule-specific exclusions (SecRuleRemoveById,
    ctl:ruleRemove*) unless a step explicitly allows them.
18. Confound check. For every run, list any rule ID present in 20% or more of
    all audit entries for that dataset. A rule that fires on most requests is
    a harness artifact until shown otherwise.
19. In-sample label. Any configuration or threshold derived from a dataset
    must be labelled "in-sample" wherever its result on that dataset is
    reported.
20. Every rate states its denominator and how errors are treated. Report the
    best case (errors not flagged) and the worst case (errors flagged).
21. Headline rule. Report the conservative number for each claim: false
    positive rate = worst case (outbound-cut flagged); recall = best case
    (outbound-cut not flagged). Always show both, and never drop samples from
    a denominator.
22. Preregistration. Any new dataset version needs a written plan (sources,
    counts, procedure) committed BEFORE it is built or run.
23. Recording logs. Every recording writes its raw log to a committed path
    (docs/logs/ or out/ with the path stated in the report). Nothing needed
    as evidence may live in /tmp.
24. Relabel. A rule that fires on most requests because the corpus
    exercises something the config forbids is a CONFIG-MISMATCH signal,
    not a harness artifact. Use that label in rule 18 reports from now on.
25. External data. Record licence and source commit/URL before use; commit
    only what the licence allows (otherwise commit a fetch script plus a
    SHA-256 of each source file). Never commit credentials, tokens or
    personal data found in external traffic; report any you find (type and
    count only).
26. Label audit. For any dataset labelled by someone else, manually read a
    seeded random sample of 100 requests per label and report how many look
    mislabelled (with ids). Label the result an audit of 100, not a proof.
27. Held-out derivation: any config derived from data must be evaluated on data
    not used in the derivation, split by host (or session) BEFORE looking at
    results. State the split rule in the plan. Anything evaluated on its own
    derivation data is labelled in-sample.
28. Engine parity: when comparing engines, pin the same ruleset version on both
    and prove it from inside each container (file path and version string).
    Differences are reported per sample, never only as totals.
29. Effective-config proof: for every run, print and save the effective values
    from inside the running container (engine mode, blocking and detection
    paranoia, allowed methods, allowed content types) into the run's log. A
    config name is a claim until this proof exists for that run.
30. Any request whose outcome is inconsistent or waf_deny_status must appear by
    count in every rate table, and is included in the worst case.
