# kortex-waf

Building a WAF to an independently checkable standard. The first deliverable is
not the WAF; it is the measuring stick, so every later claim comes with counts,
provenance and a baseline.

## What exists today

| Part | State |
|---|---|
| `kortex_eval/` manifest, leak-proof split, metrics with 95% intervals, report | Written, 19 unit tests pass |
| `deploy/compose.yml` baseline testbed (target + OWASP CRS) | Syntax-checked only. Not run: the workspace it was written in has no running Docker daemon. Image and variable names are marked VERIFY |
| `docs/acceptance.md` industry bars turned into tests | Written; no numeric targets until baseline is measured |
| `docs/decisions/0001-build-on-coraza.md` | Proposed |
| Traffic generators, dataset, baseline numbers, engine | Not started |

## Run the tests

    python -m pip install pytest
    python -m pytest -q

## Evaluate a system

    python -m kortex_eval.report --manifest data/test.jsonl \
        --predictions out/crs-pl1.jsonl --name "CRS PL1"

`manifest` is JSONL, one request per line (`id`, `label`, `family`, `source`,
`method`, `path`, ...). A sample with no `source` is rejected. `predictions` is
JSONL of `{"id": ..., "flagged": true|false}`; a sample with no prediction is an
error, never skipped.

## Rules this repo follows

1. Every sample records where it came from.
2. Test attack families are never in training.
3. Every rate is reported with its count and a 95% interval.
4. Every comparison includes the ModSecurity + CRS baseline.
5. A number is only quoted if one command regenerates it.

## Next steps, in order

1. Check the VERIFY items in `deploy/compose.yml` and run the testbed on a machine with Docker.
2. Write traffic generators: attack tools through the baseline, and a recorded benign browsing script. Record every tool and version as the sample's `source`.
3. Build the dataset manifest; split with `kortex_eval.split`.
4. Measure CRS at paranoia levels 1 and 2. Set the numeric targets in `docs/acceptance.md` from those results.
5. Only then start the engine work (ADR 0001).
