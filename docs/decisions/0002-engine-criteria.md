# Decision 0002: engine-evidence acceptance criteria (written before step-13 T5/T6 analysis)

Date: 2026-11-20. Status: accepted. Applies to: step-13 engine evidence
(tasks T5/T6 and any later parity claim).

## Purpose

State, BEFORE looking at the step-13 Coraza WCP results, what will count as
"the engine evidence is finished" and how differences will be judged. No
numeric pass/fail targets are set (the instructor judges; the report makes no
recommendation). The criteria only define what must be MEASURED and REPORTED.

## Criteria

### C1 — blocked-set parity, per sample

For every dataset cell compared (both engines, same backend, same ruleset
version, same paranoia level):

- The blocked set and the worst-case set (rule 32: waf_block + waf_deny_status
  + inconsistent + error) are compared per sample id, not only as totals.
- Every differing id is listed with its status and rule IDs on each engine.
- Each difference is attributed to a cause (rule ID, body size, content type,
  capture artifact) OR counted as "unexplained". Both counts are reported;
  neither is called an engine error.
- Rule-ID presence on the policy-clear subset (definition below) is reported
  separately: only-ModSec rules, only-Coraza rules, top 20 on each side.
- Label meaning (rule 11): a difference is a measured behavioural difference
  between engines under the same config; "correct" is never claimed for
  either engine.

### C2 — oversize bodies and latency characterised

- The effective request-body limits of BOTH engines are proven from inside
  the running containers (rule 29) for every run used in a claim.
- Oversize-body behaviour is characterised by a bisect at 1 KB resolution on
  both engines (status + rule IDs at the threshold), not inferred from
  dataset samples.
- Latency outliers are characterised by replay with timings; any
  single-rule-dominant pathology is named with its rule ID and matching
  pattern shape, or marked HYPOTHESIS (rule 33).

### C3 — effective-config proof for every run

Every run cited in a claim carries its rule-29 proof line(s): engine mode,
blocking and detection paranoia, allowed methods, allowed content types, and
effective body limits, read from inside the running container and saved with
the run's log. A config name without this proof is a claim, not evidence.

## Policy-clear subset definition (used by C1)

A sample is policy-clear when BOTH hold:

1. its method is in the default allowed methods
   (901160 fallback: GET HEAD POST OPTIONS — verified in-container); and
2. it has no content type, or its content type is allowed by the default
   policy: the 901162 fallback list (application/x-www-form-urlencoded,
   multipart/form-data, text/xml, application/xml, application/soap+xml,
   application/json), the 901370 wildcard application/*+json, or the 901360
   AWS types (application/x-amz-json-1.0 / -1.1) — matched on the media type
   before any ";" parameter, case-insensitively.

Policy-clear subsets are reported split into body-less and body-bearing
samples (two separate rates, never merged — rule 14).

## Non-criteria

- No numeric similarity target is set; the instructor judges whether the
  evidence is sufficient.
- No engine is recommended or called correct anywhere in the reports.
- Diagnostic runs (rule 34) never contribute to baseline or parity numbers.

## Dated addendum (step-15, 2026-11-20): criterion C4

Instructor answer to the step-14 question 1: detection coverage per
content-type carrier is added as a criterion.

**C4 — detection blocks on a carrier must not depend on whether its content
type is on the allow-list** (measured on attacks-ct-v0). For our own engine
this becomes an acceptance test: detection blocks must not depend on whether
the content type is on the allow-list.
