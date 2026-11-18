# Plan: held-out-host policy config (step-10 T6, preregistered)

Written 2026-11-18 BEFORE computing the split and BEFORE looking at any
result. Nothing below has run.

## Question

A request policy (allowed methods + content types) derived from half the
WCP hosts — does it generalise to the other half better than the
Juice-Shop-derived aligned-v2 policy did (step-09: aligned-v2 was worse
than default out-of-sample: 32.80% vs 19.12% at PL1)?

## Split rule (fixed before any run)

- Host universe: the 3,038 distinct hosts in the frozen benign-wcp-v0
  sample (data/benign-wcp-v0/annotations.jsonl, field `host`).
- For each host: `h = sha256("wcp-heldout-v0|" + host)` interpreted as a
  big-endian integer; `bit = h % 2`. bit == 0 -> TRAIN, bit == 1 -> TEST.
- Seed is 0, embedded in the salt string above. The split is computed once,
  written to docs/logs/wcp-heldout-split.json (with counts) and committed
  BEFORE any run. It is not tuned after seeing results.

## Config derivation (fixed before any run)

- From the running crs-default container, print the image's default
  ALLOWED_METHODS and ALLOWED_REQUEST_CONTENT_TYPE (from
  /etc/modsecurity.d/owasp-crs/crs-setup.conf inside the container).
- TRAIN-observed values: methods and content types of the benign-wcp-v0
  requests whose host is in TRAIN (from the frozen manifest).
- crs-policy-wcp-train = default UNION TRAIN-observed (never narrower than
  the default). The union list is written into docs/baseline-config.md
  BEFORE the first run.

## Runs (rule 13: fresh container per run, workers 1, one log per run)

Eight blocking runs against the stub backend, recorded UAs kept:

| manifest | config | PL |
|---|---|---|
| TEST hosts only | crs-default | 1, 2 |
| TEST hosts only | crs-policy-wcp-train | 1, 2 |
| TRAIN hosts only | crs-default | 1, 2 |
| TRAIN hosts only | crs-policy-wcp-train | 1, 2 |

- TEST is the out-of-sample result. TRAIN is labelled in-sample.
- Reported per request, per host (macro over hosts with >=5 requests,
  micro), and policy-vs-detection composition (sole-rule attribution as
  defined in tools/wcp_decompose.py).
- Denominator: the TEST/TRAIN subset sizes of the 19,994-request baseline
  manifest (the 5 quarantined samples are excluded from both subsets, as
  they are excluded from the dataset denominator).
