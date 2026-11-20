# kortex-waf

Building a WAF to an independently checkable standard. The first deliverable is
not the WAF; it is the measuring stick, so every later claim comes with counts,
provenance and a baseline.

## What exists today

| Part | State |
|---|---|
| `kortex_eval/` manifest, leak-proof split, metrics with 95% intervals, report | Written, 97 unit tests pass |
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
| `docs/baseline-v0.md` / `v0.1` / `v0.2` / `v0.3` CRS false-positive baseline (crs-default: 34/214 natural v0, 184/774 natural v1, 22/180 hard; crs-policy-aligned in-sample 2/214, out-of-sample 34/774 on v1; crs-policy-aligned-v2: 2/214 v0, 4/774 v1 at PL1; UA confound removed in v0.2; v0.4: external WCP benign-wcp-v0 out-of-sample — default 19.12% PL1 / 44.76% PL2, aligned-v2 32.80% PL1 / 50.93% PL2; v0.5: WCP FPs decomposed (920420 = 76.7% of PL1 blocks, detection-involved bound 3.79% PL1), held-out-host policy widening made rates WORSE (31.66% vs 17.61% PL1 TEST), cookie restoration doubled the rate (48.05% vs 21.50% PL1), Coraza parity: blocked sets identical on all 4 datasets; v0.6: stub-drain fix, parity re-proven; v0.7 (step-12): images digest-pinned after upstream drift, small-dataset parity 0 diff in all 8 cells on both engines, Coraza body-limit pin proven ineffective (effective 524,288 — explains all 11 413 divergences), 17 status-400 samples classified (10 gzip replay artifacts / 2 malformed / 5 over-1000-argument JSON), 7 of 8 Coraza timeouts transient + 1 engine-specific (477KB text/plain: ModSecurity 23 ms vs Coraza ~46 s), 20 matched-shape probes 0 block disagreements, cookie restore was incomplete (case-sensitive bug, 7,511 of 13,261) — fixed and re-run: restored-cookie stratum 40.43% PL1 / 81.51% PL2 vs 20.22% / 46.08% with the placeholder) | Written from real runs |
| `docs/acceptance.md` industry bars turned into tests | Written; no numeric targets until baseline is measured |
| `docs/decisions/0001-build-on-coraza.md` | Proposed |
| Dataset-scale expansion (1,600 attacks / 1,400 legitimate), engine | In progress — current: 1,054 attacks / 1,168 Juice Shop benign (214 v0 natural + 180 hard + 774 v1) + 19,994 external WCP benign (benign-wcp-v0, out-of-sample, replayed against a stub backend — not one app's traffic; built 20,000, 1 quarantined) |

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
