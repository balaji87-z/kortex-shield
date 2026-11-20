# Decision 0004: engine core (step-15, 2026-11-20)

Status: **provisional pending T1 and T4** (step-15). T1 is complete (this
step); T4 (body-size scaling) is measured in this step — revisit this status
after both are read into the evidence base.

## Decision

Build on Coraza v3.7.0 + CRS 4.25.2 as the inspection core, wrapped by our
own proxy that enforces: (1) body size limits before the engine; (2) a
per-request time budget with a distinct outcome and a body-size cap chosen
from measured scaling; (3) strict request framing checks; (4) body inspection
independent of content type.

## Reversal triggers

- The cap needed to bound latency is too small for legitimate traffic, or
- the library fails the framing and limit tests in ways we cannot wrap.

## Evidence this rests on (pointers, no new claims here)

- Parity and body-access differences: docs/engine-evidence.md (steps 12-14).
- Latency pathology PROVEN inside the coraza library (step-14 T5, re-run in
  step-15 T1b): docs/logs/step14-t5-probe.txt, docs/logs/step15-t1-probe-rerun.txt.
- NoFilesLimit non-enforcement PROVEN in-container and in-library.
- Detection coverage per content type (C4): docs/logs/step14-t3-analysis.txt.

## Status update (step-16, 2026-11-20)

STAYS PROVISIONAL, evidence strengthened. T1 classified every engine-vs-
connector difference (rule 39): after the BUG fix (missing body-processor
selection/parse-failure rules, fixed test-first via E10-E15) the re-run
shows 146 differing ids, ALL documented DESIGN differences (144 x the C4
content-type policy, 2 cells of the nginx front proxy), zero BUG, zero
UNEXPLAINED (docs/logs/step16-t2-analysis.txt). C4 held on attacks-ct-v0:
with the correct body processor the engine blocks the attack payloads in
every carrier, so detection no longer depends on the connector's
content-type allow-list. The time budget now bounds body processing
(E16/E17, step-16 T3). Reversal triggers unchanged.
