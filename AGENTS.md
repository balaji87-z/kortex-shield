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
