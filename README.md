# kortex-waf

Building a WAF to an independently checkable standard. The first deliverable is
not the WAF; it is the measuring stick, so every later claim comes with counts,
provenance and a baseline.

## What exists today

| Part | State |
|---|---|
| `kortex_eval/` manifest, leak-proof split, metrics with 95% intervals, report | Written, 48 unit tests pass |
| `kortex_eval/runner.py` verbatim request runner (stdlib http.client, sample-id header, block discriminator, manifest sha256 + labels in run.json) | Written, smoke-tested and used for the corpus runs |
| `kortex_eval/crs_audit.py` CRS audit-log parser, sample correlation via `X-Kortex-Sample-Id`, dual score readings (949110 total vs severity sum) | Written, tested on real audit samples |
| `kortex_eval/outcome.py` per-sample outcome classifier (error / waf_block / waf_would_block / waf_pass / proxy_reject / inconsistent) | Written, tested on synthetic + real data |
| `deploy/compose.yml` baseline testbed (target + OWASP CRS) | Running and verified: Juice Shop v20.4.0 behind owasp/modsecurity-crs 4.25.2-nginx-lts; ports/engine/paranoia are env vars with defaults |
| `docs/block-discriminator.md` WAF-block vs target-error discrimination rule | Written from captured evidence |
| `tools/build_attacks.py` + `data/attacks-v0/` first frozen ATTACK corpus (1054 samples, 527 distinct payloads × 2 injection points, 4 families) | Frozen (MANIFEST.sha256) |
| `tools/record_benign.py` + `data/benign-browse-v0/` frozen NATURAL benign browsing corpus (214 unique requests from 20 real UI sessions via Playwright) | Frozen (MANIFEST.sha256) |
| `tools/build_benign_hard.py` + `data/benign-hard-v0/` frozen HARD benign corpus (180 samples, 90 hand-written attack-adjacent values — overstates natural FP rate, never merge rates) | Frozen (MANIFEST.sha256) |
| `kortex_eval/endpoints.py` endpoint templating (numeric/hex/UUID segments → `{id}`) | Written, 10 tests |
| `tools/attack_breakdown.py`, `tools/benign_breakdown.py` stratified breakdowns with 95% Wilson intervals | Written, used for docs/baseline-v0.md |
| `docs/baseline-v0.md` first full CRS false-positive baseline (PL1 = PL2: 34/214 natural, 22/180 hard) | Written from real runs |
| `docs/acceptance.md` industry bars turned into tests | Written; no numeric targets until baseline is measured |
| `docs/decisions/0001-build-on-coraza.md` | Proposed |
| Dataset-scale expansion (1,600 attacks / 1,400 legitimate), engine | Not started — current: 1,054 attacks / 394 benign |

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
2. ~~Write traffic generators: attack tools through the baseline, and a recorded benign browsing script.~~ Done (step-03 attacks, step-04 benign browsing + hard benign).
3. Build the dataset manifest; split with `kortex_eval.split`.
4. Measure CRS at paranoia levels 1 and 2. Set the numeric targets in `docs/acceptance.md` from those results.
5. Only then start the engine work (ADR 0001).
