# data/attacks-v0 — first frozen ATTACK corpus (attacks only)

**This dataset is FROZEN.** SHA-256 of `manifest.jsonl` is recorded in
`MANIFEST.sha256` (5b6a844d9521082428725b6de6b8921a6c0bdc8606e362b5046af633d4fa8540).
No sample may be added, removed or edited; a change creates a new version folder.
The freeze happened BEFORE any blocking-mode run on this data (see procedure below).

## Label meaning (standing rule 11)

"attack" means **"listed under this family in this source"**, NOT "verified
exploitable" and not "this exact string is a working attack against this
target". Every sample's `source` field records `<repo>@<commit>:<file>:<line>`.

## Sources

- SecLists https://github.com/danielmiessler/SecLists @ 6b19c2f5088c45b5dadb4d8918d2ab4f7efb03a9 (MIT)
- PayloadsAllTheThings https://github.com/swisskyrepo/PayloadsAllTheThings @ 08ea40e77db3f42ef8f20c65196f3936a19b6c86 (MIT)

Full source list and file choices with reasons: docs/corpus-sources.md, docs/corpus-plan.md.

## Counts

Built by `tools/build_attacks.py` (deterministic, seed 0, max 150 payloads/family;
each payload yields a GET search request and a POST login request):

| family | raw lines | blank removed | comment removed | duplicates removed | after filters | sampled | samples (×2 requests) |
|---|---|---|---|---|---|---|---|
| sqli | 77 | 0 | 0 | 0 | 77 | 77 | 154 |
| xss | 6047 | 0 | 0 | 0 | 6047 | 150 | 300 |
| path-traversal | 4521 | 1 | 10 | 2018 | 2492 | 150 | 300 |
| command-injection | 448 | 0 | 0 | 0 | 448 | 150 | 300 |
| **total** | | | | | | | **1054** |

## Reach-check procedure (ran BEFORE any blocking-mode run)

1. All 1054 candidates replayed against the baseline with
   `MODSEC_RULE_ENGINE=DetectionOnly`, `PARANOIA=1` (runner → docker logs →
   crs_audit → outcome `--engine-mode detection`).
2. Filter applied ONLY on `proxy_reject`, `inconsistent`, `error`.
   NEVER on `waf_would_block` vs `waf_pass`.
3. Result: 0 proxy_reject, 0 inconsistent, 0 error. All 1054 candidates reached
   the engine and are kept. `probes.jsonl` (0 rows) and `quarantine.jsonl`
   (0 rows) are written anyway so nothing is dropped silently (rule 12).

## Files

- `candidates.jsonl` — all 1054 candidates as built (pre-reach-check).
- `probes.jsonl` — samples excluded as proxy_reject (0 rows; kept with counts).
- `quarantine.jsonl` — samples excluded as inconsistent/error (0 rows; kept with reasons).
- `manifest.jsonl` — the frozen dataset (1054 samples).
- `MANIFEST.sha256` — SHA-256 of manifest.jsonl at freeze time.
