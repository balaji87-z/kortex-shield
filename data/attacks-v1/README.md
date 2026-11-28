# data/attacks-v1: held-out attack dataset (attacks only)

**This dataset is FROZEN.** SHA-256 of `manifest.jsonl` is recorded in
`MANIFEST.sha256`
(7a82a51622e311f26f00fffff1f39b718f1528d907a20da89e30372cc6723066). No
sample may be added, removed or edited; a change creates a new version
folder. The freeze happened BEFORE any blocking-mode run on this data.
Plan, written and committed before the build: docs/plan-attacks-v1.md.

## Label meaning (standing rule 11)

"attack" means **"listed under this family in this source"**, NOT "verified
exploitable" and not "this exact string is a working attack against this
target". The request shapes are those of attacks-v0 (a Juice Shop search and
a login); most payloads of the new families would do nothing to Juice Shop.
The dataset measures whether a WAF flags the string, nothing else. Every
sample's `source` field records `<repo>@<commit>:<file>:<line>`.

## Held-out

No engine setting of this project was chosen with these payloads: none of
them was sent to any engine before the plan was committed, and every payload
that is also a payload of attacks-v0 (and so of attacks-ct-v0 and
encoding-diff-v0, which drew from it) is excluded. Two kinds of families:

- seen families, unseen payloads: sqli, xss, path-traversal,
  command-injection (families attacks-v0 has, from files it did not use);
- new families: lfi, xxe, ssti, nosql, ldap.

## Source

PayloadsAllTheThings https://github.com/swisskyrepo/PayloadsAllTheThings @
08ea40e77db3f42ef8f20c65196f3936a19b6c86 (MIT). 48 files, listed with their
SHA-256, their order and the family caps in
`tools/fetch/attacks_v1_sources.sha256`; fetched and checked by
`tools/fetch/fetch_attacks_v1_sources.sh`.

## Counts

Built by `tools/build_attacks_v1.py build` (deterministic, seed 1; each
payload yields a GET search request and a POST login request). Raw lines
are counted per line of text, so a last line without a newline counts
(`wc -l` gives 3 fewer for sqli, 2 fewer for xss and lfi, 1 fewer for ssti,
nosql and ldap). "blank" is a line with nothing but whitespace.

| family | kind | files | raw lines | blank | duplicates | in attacks-v0 | in an earlier family | unsendable | after filters | cap | payloads | requests |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| sqli | seen | 21 | 1,466 | 1 | 99 | 77 | 0 | 1 | 1,288 | 300 | 300 | 600 |
| xss | seen | 12 | 2,434 | 56 | 473 | 0 | 0 | 2 | 1,903 | 300 | 300 | 600 |
| path-traversal | seen | 3 | 1,939 | 0 | 471 | 8 | 0 | 0 | 1,460 | 200 | 200 | 400 |
| command-injection | seen | 1 | 83 | 0 | 4 | 8 | 0 | 0 | 71 | all | 71 | 142 |
| lfi | new | 4 | 2,159 | 0 | 763 | 3 | 70 | 0 | 1,323 | 200 | 200 | 400 |
| xxe | new | 2 | 116 | 1 | 13 | 0 | 1 | 0 | 101 | all | 101 | 202 |
| ssti | new | 1 | 107 | 0 | 0 | 0 | 0 | 0 | 107 | all | 107 | 214 |
| nosql | new | 2 | 46 | 0 | 20 | 0 | 0 | 0 | 26 | all | 26 | 52 |
| ldap | new | 2 | 66 | 0 | 33 | 0 | 3 | 0 | 30 | all | 30 | 60 |
| **total** | | 48 | 8,416 | 58 | 1,876 | 96 | 74 | 3 | 6,309 | | **1,335** | **2,670** |

Requests and distinct payloads (rule 15): 2,670 requests, 1,335 distinct
payloads; seen families 1,742 requests / 871 payloads, new families 928
requests / 464 payloads. Together with attacks-v0 (527 payloads, none
shared): 1,862 distinct payloads.

Nothing is dropped silently (rule 12):

- `excluded-in-v0.jsonl` (96): the payload is a payload of attacks-v0.
- `excluded-cross-family.jsonl` (74): an earlier family's files list the
  same payload; it stays with the first family.
- `excluded-unsendable.jsonl` (3): 1 line that is not valid UTF-8, 2 longer
  than 2,000 bytes. Source, size and hash only.

## Reach check (ran BEFORE the freeze and before any blocking-mode run)

1. All 2,670 candidates were replayed once against the engine, in-process,
   `KORTEX_RULE_ENGINE=DetectionOnly`, PL1
   (`tools/run_step26_attacks_v1.sh reach`, docs/logs/step26-reach.txt,
   docs/logs/runs/s26-reach/).
2. A candidate is removed only when the rules did not judge it: `error`
   (the client could not send it), `waf_fail_closed_*` (the engine's gate
   or limits answered), `inconsistent`. NEVER on would-block against pass.
3. Result: 0 error, 0 fail-closed, 0 inconsistent; 2,671 `pass` events of
   the engine and 0 framing events; every request was forwarded (status
   200). All 2,670 candidates are kept; `quarantine.jsonl` has 0 rows.
   The run also shows, as it did for attacks-v0, how many candidates would
   be blocked at PL1 (2,214 of 2,670); that number was not used for
   anything.

## Files

- `candidates.jsonl`: all 2,670 candidates as built.
- `manifest.jsonl`: the frozen dataset (2,670 samples; identical to the
  candidates, nothing was quarantined).
- `MANIFEST.sha256`: SHA-256 of manifest.jsonl at freeze time.
- `quarantine.jsonl`: candidates removed by the reach check (0 rows).
- `annotations.jsonl`: per sample id: `family`, `payload`,
  `injection_point` ("q" or "login") and `family_kind` ("seen-family" or
  "new-family").
- `excluded-*.jsonl`: see above.
- `build-stats.json`: the counts of the table.

## Limits

- One public source, one commit. Payload lists are written to be found by
  scanners and WAFs; recall on them says little about a targeted attacker.
- The new families are sent through two carriers, a query argument and a
  JSON string. An XXE payload in a JSON string is not XML to a WAF: its XML
  body processor never sees it.
- Whether a payload also occurs in a CRS regression test (which informed
  one engine change in step 25) is not checked.
