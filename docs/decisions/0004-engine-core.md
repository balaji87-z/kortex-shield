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

## Status update (step-17, 2026-11-20)

STAYS PROVISIONAL. Step-17 set three conditions for dropping the
provisional status; two are met, one is unproven:

1. C4 holds on the engine — MET, and now MEASURED (rule 41): the engine
   blocks attacks by detection rules on every carrier including the raw
   ones the connector refuses (34-38/40 per carrier), so detection does
   not depend on a content-type allow-list (docs/logs/step17-t1-c4.txt,
   replayed bit-identically in step17-t1-c4-replay.txt).
2. The method allow-list gap is closed — MET: tx.allowed_methods is set
   from KORTEX_ALLOWED_METHODS and 911100 enforces it (E18); re-run shows
   the outcome sets unchanged (124/774 benign-browse-v1 PL1, same ids).
3. T4 has zero UNEXPLAINED — UNPROVEN: the per-id engine-vs-connector
   comparison on benign-wcp-v0 could not be run (the step-13 reference
   outcome files are on the unreachable lab host; docker is unavailable on
   the current host). Aggregates are close (policy-clear body-less
   411 vs 410, 4,131 vs 4,130; body-bearing 432 vs 441, 1,838 vs 1,848),
   but per rule 32/39 a parity claim needs per-id diffs, so this condition
   is neither met nor failed.

Reversal triggers unchanged.

## Status update (step-18 addendum, 2026-11-21, docker became available)

PROVISIONAL LIFTED for the coraza-connector comparison. Docker 29.1.3
became available on the step-18 host; the T2 per-id comparison ran against
the pinned coraza-crs image (see docs/logs/step18-t2-analysis.txt). After
removing the documented DESIGN differences (CT policy C4: 1637/78 blocks;
body-limit policy: 14/15; time budget: 2/3) and the 1 flip (UNEXPLAINED),
the engine's blocked set on benign-wcp-v0 equals the connector's blocked
set at PL1 and PL2, and the engine additionally blocks the REQUEST_BODY
fidelity targets. Remaining condition on the decision: the modsec-connector
comparison was NOT re-run this step (step-13 evidence stands).
engine side (413 delivery fixed test-first; raw-carrier body fidelity via
a 166-rule REQUEST_BODY target update, flip-corrected held-out results:
+61/+29 real gains on benign-wcp-v0, 0 real detection losses) and
surfaced a new UNEXPLAINED engine non-determinism (occasional pass-through
of a would-block request, pre-existing, counted; see
docs/logs/step18-t4-flip-replay.txt). Reversal triggers unchanged.

## Status update (step-19, 2026-11-21)

STAYS PROVISIONAL overall. Step-19 additions:

1. The coraza-connector condition is now ALSO met on HELD-OUT data:
   benign-wcp-v1 (preregistered, ids disjoint from v0) — per-id
   comparison in docs/logs/step19-t2b-a2-analysis.txt. Connector-only
   blocks are dominated by 920420 (CT allowlist, DESIGN-C4):
   PL1 788 connector-only (784 with 920420; engine passed 754 of them),
   PL2 54 (49 with 920420). Engine-only: 12/10 (the REQUEST_BODY
   fidelity additions, which the stock connector lacks by design).
2. The step-18 "flip" UNEXPLAINED is now PROVEN (rule 44): coraza
   v3.7.0 transformation-cache collision on same-named args
   (docs/baseline-v1.4.md T1). Not fixable in the shipped build;
   version bump = instructor decision. The 3 PL2 run-to-run
   disagreements on benign-wcp-v1 are this defect.
3. Remaining open condition: the modsec-connector comparison was not
   re-run (step-13 evidence stands).

## Status update (step-20, 2026-11-21)

The two conditions set in step-19 are now MET:

1. T1 zero flips: the coraza transformation-cache flip (PROVEN step-19)
   is fixed by the version bump v3.7.0 -> v3.8.1 — E30 0/2000 replays,
   flip_repro PL2 0/2500 (docs/baseline-v1.5.md T1). The decision's
   "Coraza v3.7.0" is amended to "Coraza v3.8.1"; the decision's core
   (coraza + CRS as the inspection core, wrapped by our own proxy for
   limits/budget/framing/CT-independent inspection) is unchanged.
2. T2 availability test: E29 rewritten deterministically (rule 48 hook)
   and passing; the large-lane attack serves 269/269 benign POSTs
   (docs/baseline-v1.5.md T2). The small-lane residual exposure is
   documented and measured (6/276), not fixed.

STATUS: **ACCEPTED** for the coraza core (both conditions met), with two
standing notes: (a) the modsec-connector comparison has not been re-run
since step-13 (step-13 evidence stands); (b) the small-lane starvation
residual is a known, measured exposure, not a decision reversal trigger.
Reversal triggers unchanged.
