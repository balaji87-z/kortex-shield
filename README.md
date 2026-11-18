# kortex-waf

Building a WAF to an independently checkable standard. The first deliverable is
not the WAF; it is the measuring stick, so every later claim comes with counts,
provenance and a baseline.

## What exists today

| Part | State |
|---|---|
| `kortex_eval/` manifest, leak-proof split, metrics with 95% intervals, report | Written, 35 unit tests pass |
| `kortex_eval/runner.py` verbatim request runner (stdlib http.client, sample-id header, block discriminator) | Written, smoke-tested against the live baseline |
| `kortex_eval/crs_audit.py` CRS audit-log parser and sample correlation via `X-Kortex-Sample-Id` | Written, tested on real audit samples |
| `deploy/compose.yml` baseline testbed (target + OWASP CRS) | Running and verified: Juice Shop v20.4.0 behind owasp/modsecurity-crs 4.25.2-nginx-lts; ports/engine/paranoia are env vars with defaults |
| `docs/block-discriminator.md` WAF-block vs target-error discrimination rule | Written from captured evidence |
| `data/smoke/` 12-sample plumbing-validation manifest | Written; plumbing validation only, not a dataset |
| `docs/acceptance.md` industry bars turned into tests | Written; no numeric targets until baseline is measured |
| `docs/decisions/0001-build-on-coraza.md` | Proposed |
| Traffic generators, dataset, baseline numbers, engine | Not started |

## Run the tests

    python -m pip install pytest
    python -m pytest -q

## Request convention

In a Sample, `path`, `query` and `body` are the raw request content exactly as
it goes on the wire: `query` is the raw query string with no leading "?",
already percent-encoded exactly as intended; `body` is the raw body as sent;
`path` is the raw path. The runner (`kortex_eval/runner.py`) sends them
unmodified and never re-encodes the request line. Every request carries the
header `X-Kortex-Sample-Id: <sample id>`; ids must match
`[A-Za-z0-9._:-]{1,64}` and are never rewritten.

## Replaying samples and reading the audit log

    python -m kortex_eval.runner --manifest data/smoke/manifest.jsonl \
        --base-url http://localhost:8081 --out out/<run-name>/
    docker logs <baseline-container> > out/<run-name>/docker-logs.txt
    python -m kortex_eval.crs_audit --logs out/<run-name>/docker-logs.txt \
        --out out/<run-name>/audit.jsonl
    python -m kortex_eval.report --manifest data/smoke/manifest.jsonl \
        --predictions out/<run-name>/predictions.jsonl --name "CRS PL1"

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

1. ~~Check the VERIFY items in `deploy/compose.yml` and run the testbed on a machine with Docker.~~ Done in step-01.
2. Write traffic generators: attack tools through the baseline, and a recorded benign browsing script. Record every tool and version as the sample's `source`.
3. Build the dataset manifest; split with `kortex_eval.split`.
4. Measure CRS at paranoia levels 1 and 2. Set the numeric targets in `docs/acceptance.md` from those results.
5. Only then start the engine work (ADR 0001).
