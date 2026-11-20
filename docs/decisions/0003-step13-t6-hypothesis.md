# Step-13 T6: content-type swap test (DIAGNOSTIC)

## Hypothesis (written before the run)

ModSecurity does not populate ARGS (or any parsed body variables) from request
bodies whose content type the policy rejects (920420), so body-derived rules
(e.g. 200007 argument count, 94x attack rules) cannot fire on those bodies;
Coraza does populate them. Prediction: with the recorded content type, a
body-bearing sample blocked by ModSec on header rules only will show no
body-derived matches on ModSec but body-derived matches on Coraza; with
Content-Type rewritten to an allowed type (application/x-www-form-urlencoded),
ModSec will parse the body and body-derived matches appear.

## Design

- Seed 0; 100 samples drawn from the step-11/12 only-Coraza-rule set that have
  a body (script: tools/run_step13_t6.sh; manifest written to out/ ONLY,
  never committed).
- Two variants per sample: as-recorded, and Content-Type ->
  application/x-www-form-urlencoded (body unchanged).
- Both engines, PL1, stub backend, rule 13 hygiene (fresh containers).
- Per-sample status + matched rule-ID sets; matched VARIABLE classes only
  (ARGS, ARGS_NAMES, REQUEST_HEADERS...) — no values (rule 25).
- Conclusion labels PROVEN / REFUTED / INCONCLUSIVE naming the deciding
  counts. Neither engine is called correct (rule 4).
- DIAGNOSTIC: results never enter baseline or parity numbers (rule 34).

## Result (2026-11-20, runs in the docker lab; analysis docs/logs/step13-t6-analysis.txt)

PROVEN (deciding counts, 100 samples, seed 0, both engines PL1, stub backend):

- Coraza, as-recorded content types: 97/100 samples matched at least one
  body-derived rule (rule IDs outside the header-only set {920420, 920340,
  920450, 920640, 911100, 949110, 200002, 200007, 920620}).
- ModSecurity, as-recorded: 6/100.
- ModSecurity with Content-Type rewritten to application/x-www-form-urlencoded
  (body unchanged): 97/100 — the SAME count as Coraza's recorded variant.
- Rule 200007 (argument count >= 1000, a pure body-parser indicator): Coraza
  recorded 2, ModSecurity recorded 0, ModSecurity rewritten 1.
- The rewrite changes the matched rule set on 100/100 samples on BOTH engines
  (always removing 920420; on ModSecurity adding the body-derived matches).

Conclusion: the hypothesis is PROVEN — ModSecurity does not populate body
variables for content types the policy rejects, Coraza does. This explains
the only-Coraza rule matches on body-bearing samples (T5) as a body-access
difference, not a regex difference. Per rule 4: neither engine is called
correct; CRS's own intent (which engine's behaviour matches the CRS design)
is not judged here.
