# Step-26 plan: attacks-v1, a held-out attack dataset (written BEFORE it is built or run, rule 22)

Brief (instructor, 2026-11-27): "do all 4"; this is the second of the four
steps: acceptance A2, the attack side.

## Why

- Every recall number the project reports is in-sample. attacks-v0 and
  attacks-ct-v0 informed the REQUEST_BODY target choice of step 18 (rules
  19, 45), and the CRS regression suite informed the 942130 change of step
  25. No attack dataset exists that no engine setting was chosen with.
- A2 asks for at least 1,600 attack scenarios with held-out attack
  families. Today: 1,054 requests, 527 distinct payloads, 4 families
  (docs/acceptance.md).

No payload of the files below has been sent to any engine of this project
when this plan is written. The files were downloaded and their lines
counted (the table); no line was read for its effect on a rule.

## Source (rule 25)

PayloadsAllTheThings, https://github.com/swisskyrepo/PayloadsAllTheThings ,
commit 08ea40e77db3f42ef8f20c65196f3936a19b6c86, the commit attacks-v0 used
(docs/corpus-sources.md), licence MIT (LICENSE in the repository). Files
are fetched one by one from raw.githubusercontent.com at that commit by
`tools/fetch/fetch_attacks_v1_sources.sh`, which checks each file against
its SHA-256 in `tools/fetch/attacks_v1_sources.sha256` (48 files; the same
list gives the builder its files, their order and the caps); the clone of earlier steps is not on this host. As for
attacks-v0, the samples (payloads included) are committed with the dataset;
the pre-push scan allows request bodies under `data/attacks-*`.

SecLists is not used: attacks-v0 took its sqli and xss files from it, and
one source keeps the provenance simple. Stated as a limit below.

## Label meaning (rule 11)

"attack" means "listed under this family in this source", not "verified
exploitable" and not "a working attack against this target". The request
shapes are those of attacks-v0 (a Juice Shop search and a login); most
payloads of the new families would do nothing to Juice Shop. The dataset
measures whether the WAF flags the string, nothing else.

## Families and files

One payload per line. Lines counted with `wc -l`, distinct non-empty lines
with `sort -u`.

Families attacks-v0 has, from files it did not use (held-out payloads):

| family | files (directory, then names) | lines | cap |
|---|---|---|---|
| sqli | `SQL Injection/Intruder/`: all 21 files (Auth_Bypass, Auth_Bypass2, FUZZDB_*, Generic_*, payloads-sql-blind-*, SQL-Injection, SQLi_Polyglots) | 1,463 | 300 |
| xss | `XSS Injection/Intruders/`: BRUTELOGIC-XSS-JS, BRUTELOGIC-XSS-STRINGS, IntrudersXSS, JHADDIX_XSS, MarioXSSVectors, RSNAKE_XSS, XSSDetection, XSS_Polyglots, xss_alert, xss_alert_identifiable, xss_payloads_quick, xss_swf_fuzz | 2,432 | 300 |
| path-traversal | `Directory Traversal/Intruder/`: directory_traversal, deep_traversal, traversals-8-deep-exotic-encoding | 1,939 | 200 |
| command-injection | `Command Injection/Intruder/command-execution-unix.txt` | 83 | all |

Families attacks-v0 does not have (held-out families):

| family | files | lines | cap |
|---|---|---|---|
| lfi | `File Inclusion/Intruders/`: JHADDIX_LFI, List_Of_File_To_Include, List_Of_File_To_Include_NullByteAdded, php-filter-iconv | 2,157 | 200 |
| xxe | `XXE Injection/Intruders/`: XXE_Fuzzing, xml-attacks | 116 | all |
| ssti | `Server Side Template Injection/Intruder/ssti.fuzz` | 106 | all |
| nosql | `NoSQL Injection/Intruder/`: NoSQL, MongoDB | 45 | all |
| ldap | `LDAP Injection/Intruder/`: LDAP_FUZZ, LDAP_FUZZ_SMALL | 65 | all |

Not used, and why:

- `File Inclusion/Intruders/Traversal.txt` and
  `Command Injection/Intruder/command_exec.txt`: the attacks-v0 files.
- `Directory Traversal/Intruder/dotdotpwn.txt` (21,144 generated lines of
  one pattern): it would be the whole stratum.
- `File Inclusion/Intruders/dot-slash-PathTraversal_and_LFI_pairing.txt`
  (885 lines): by its name and its first lines, bare runs of `../` meant to
  be paired with a file name, not payloads on their own.
- Word lists that are not payloads: event-handler names
  (0xcela_event_handlers, port_swigger_xss_cheatsheet_event_handlers), LDAP
  attribute names, JSONP endpoints, header names (Web Cache Deception),
  actuator paths, bare file names (Linux-files, Windows-files, Mac-files,
  BSD-files, Web-files, LFI-FD-check, LFI-WindowsFileCheck, simple-check).
- Open Redirect lists: a redirect target is not an injection payload, and
  CRS has no rule family for it; including it would be choosing a family
  for its expected result.

## Procedure

`tools/build_attacks_v1.py`, deterministic, seed 1:

1. Per family, read its files in the order listed, as bytes. A payload is
   one line without its line terminator (`\n` or `\r\n`; several files
   have CRLF endings). Drop empty lines and exact duplicates (first
   occurrence kept, counted per family). Unlike the v0 builder, lines
   starting with `#` are kept: in these files they are payloads (SQL
   comments), not file comments.
2. Drop every payload that is, as an exact string, a payload of attacks-v0
   (its annotations.jsonl; a trailing `\r` of a v0 payload is ignored for
   this comparison, the v0 builder kept it for CRLF files). Each one goes to
   `excluded-in-v0.jsonl` with its source (rule 12). attacks-ct-v0 and
   encoding-diff-v0 took their payloads from attacks-v0, so this covers
   them.
2a. A payload belongs to the first family, in the order of the tables
   above, whose files list it. In every later family it is dropped and
   goes to `excluded-cross-family.jsonl`. So each payload is in the dataset
   once, and distinct payloads = requests / 2.
3. Drop payloads the request shapes cannot carry: longer than 2,000 bytes
   as UTF-8 (the query would exceed common URL limits), or not valid UTF-8
   in the source file. Each goes to `excluded-unsendable.jsonl` with the
   reason.
4. If more remain than the cap, sample the cap with `random.Random(1)`,
   family by family in the table's order, and sort.
5. Each payload yields the two requests of attacks-v0: GET
   `/rest/products/search?q=<percent-encoded payload>` and POST
   `/rest/user/login` with the JSON body `{"email": payload, "password":
   "x"}`. id `v1-<family>-<sha8(payload)>-<q|login>`; `source` is
   `PayloadsAllTheThings@<commit>:<file>:<line>`. Two payloads with the
   same sha8 stop the build.
6. Reach check before the freeze, as for v0: all candidates are replayed
   once against the engine in DetectionOnly mode at PL1 (the ModSecurity
   container was used for v0; the engine is what this host runs natively,
   and DetectionOnly never blocks). A candidate is removed only when it was
   not judged by the rules: the client could not send it (`error`), the
   engine's gate or limits answered it (`waf_fail_closed_*`), or the outcome
   is `inconsistent`. Never on would-block against pass. Removed candidates
   go to `quarantine.jsonl` with the reason and are reported by count; the
   gate refusing an attack request is itself a result and is reported as
   such.
7. Freeze: `manifest.jsonl`, its SHA-256 in `MANIFEST.sha256`, README with
   the counts, before any blocking-mode run.

Expected size, from the line counts: at most 1,415 payloads and 2,830
requests before the exclusions of steps 2, 3 and 6. With attacks-v0 that
is at most 1,942 distinct payloads; the bar of 1,600 attack scenarios is
met on distinct payloads if at least 1,073 survive. If fewer survive, the
report says so and the dataset is not padded.

## Runs (after the freeze)

Engine code of the step-25 commit (497d585; no change under engine/ in
this step), config of baseline v2.0, Host `localhost`,
runner `--workers 1`, one engine process and one audit log per run, rule-29
proof per run:

1. Engine, blocking, PL1 and PL2, in-process and worker: 4 runs.
2. Baseline (README rule 4, rules 7, 13, 28, 29, 36): the ModSecurity image
   and the Coraza connector image of deploy/compose.yml, same manifest,
   stub backend, PL1 and PL2: 4 runs, with 20 control requests before and
   after each ModSecurity run.
3. DIAGNOSTIC, engine without the REQUEST_BODY target updates, PL1 and PL2:
   what the step-18 setting is worth on data it was not chosen with.

## What is reported

- Requests and distinct payloads per family (rule 15).
- Recall per run: best case (only `waf_block`; headline, rule 21) and worst
  case (errors, deny_status, inconsistent and fail-closed answers also
  count), denominator all requests of the frozen manifest, with a 95%
  Wilson interval; per family and per injection point. Held-out for every
  engine setting; labelled so.
- Seen families from unseen files and unseen families are reported apart
  and together.
- Rule 18 (ids in 20% or more of audit entries), rule 30 counts.
- Engine against each baseline per sample id: status, worst-case set,
  rule-id set (rules 28, 32); in-process against worker.
- The missed requests by family and injection point, with ids. No setting
  is changed in this step in response to them (rule 17); what they suggest
  goes under questions.
- A2 in docs/acceptance.md: new counts of requests and distinct payloads.

## Limits stated in advance

- The CRS regression tests, which informed the 942130 change of step 25,
  hold attack strings too. Whether a payload of this dataset also occurs in
  a CRS test is not checked.

- One public source, one commit. Payload lists are written to be found by
  scanners and WAFs; recall on them says little about a targeted attacker.
- The new families are judged through two carriers (a query argument and a
  JSON string). An XXE payload in a JSON string is not XML to the WAF: the
  XML body processor never sees it. That is a property of this dataset's
  request shapes, stated with the result.
- The benign side of A2 is not touched in this step.
