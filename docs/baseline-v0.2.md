# CRS baseline v0.2 — UA confound removed, outbound-cut outcome, full matrix re-run

Supersedes the PL2 interpretation of `docs/baseline-v0.1.md` (whose PL2 columns
are marked "confounded by 920320, see v0.2"). All runs follow rule 13; every
run used `--default-user-agent` (Chrome 158 string, see
`docs/baseline-config.md`) and labels `config=<name> user_agent=fixed`;
`BLOCKING_PARANOIA` and `DETECTION_PARANOIA` verified equal to `PARANOIA`
inside the container before every run (printed per run in the step-06 report).

## Headline numbers

Denominator = all samples in the frozen manifest (rule 20). Best case =
inbound blocks only (`waf_block_outbound` and `error` not flagged); worst
case = outbound blocks and errors flagged. 95% Wilson intervals.

| dataset | PL | config | inbound blocked | outbound-cut | errors | best case | worst case |
|---|---|---|---|---|---|---|---|
| attacks-v0 | 1 | crs-default | 954/1054 | 0 | 0 | 90.51% (88.59–92.14) | same |
| attacks-v0 | 1 | crs-policy-aligned | 954/1054 | 0 | 0 | 90.51% (88.59–92.14) | same |
| attacks-v0 | 2 | crs-default | 1024/1054 | 2 | 0 | 97.15% (95.97–98.00) | 97.34% (96.19–98.16) |
| attacks-v0 | 2 | crs-policy-aligned | 1024/1054 | 2 | 0 | 97.15% (95.97–98.00) | 97.34% (96.19–98.16) |
| benign-browse-v0 | 1 | crs-default | 34/214 | 0 | 0 | 15.89% (11.60–21.38) | same |
| benign-browse-v0 | 1 | crs-policy-aligned **(in-sample)** | 2/214 | 0 | 0 | 0.93% (0.26–3.34) | same |
| benign-browse-v0 | 2 | crs-default | 34/214 | 0 | 0 | 15.89% (11.60–21.38) | same |
| benign-browse-v0 | 2 | crs-policy-aligned **(in-sample)** | 3/214 | 0 | 0 | 1.40% (0.48–4.04) | same |
| benign-hard-v0 | 1 | crs-default | 22/180 | 0 | 0 | 12.22% (8.21–17.81) | same |
| benign-hard-v0 | 1 | crs-policy-aligned | 22/180 | 0 | 0 | 12.22% (8.21–17.81) | same |
| benign-hard-v0 | 2 | crs-default | 78/180 | 18 | 0 | 43.33% (36.31–50.64) | 53.33% (46.05–60.48) |
| benign-hard-v0 | 2 | crs-policy-aligned | 78/180 | 18 | 0 | 43.33% (36.31–50.64) | 53.33% (46.05–60.48) |

Notes on the table:

- **benign-hard PL2**: the 18 `waf_block_outbound` rows are the former
  `IncompleteRead` errors — the target returned 500 and CRS cut the response
  (950100 + 959100, inbound score 2 < 5). They are now classified, not
  errors. Best/worst case bounds them (rule 20).
- **attacks PL2**: the same 2 samples (`sqli-730d16ce-q/-login`) are
  `waf_block_outbound`. With the UA fix, inbound blocks dropped 1026 → 1024:
  exactly the 2 samples whose step-05 score was exactly 5 including
  920320's +2 (see the correction in `docs/baseline-v0.1.md`). Sample-level
  diff vs step-05: PL1 +0/−0; PL2 −2 (`command-injection-036c522d-q/-login`),
  +0.
- **No numeric targets are set.**

## Rule 18 confound check (rule IDs in ≥20% of audit entries)

- attacks-v0 (all four runs): 949110 (95–98%), 930120 (~31%), 941390 (~31%),
  941120 (~30%), 941100 (~29%), 941160 (~25%), 930100 (~23%); PL2 adds
  942370 (28%), 942520 (27%), 932236 (24%), 941320 (23%). These are the
  attack corpus doing its job (payloads match many detection rules); 949110
  is the threshold rule present on every block. Not harness artifacts.
- benign-browse PL1/PL2 crs-default: 949110 (33%). Aligned runs: none.
- benign-hard PL1 (both configs): none. PL2 (both configs): 949110 (55%),
  932236 (24%).

## Attacks: per-family recall with UA fixed (crs-default; aligned identical)

| family | PL1 | PL2 (true) |
|---|---|---|
| command-injection | 224/300 (74.67%, 69.45–79.26) | 276/300 (92.00%, 88.46–94.65) |
| path-traversal | 298/300 (99.33%, 97.60–99.82) | 300/300 (100%) |
| sqli | 132/154 (85.71%, 79.32–90.37) | 148/152* (97.37%, 93.55–99.04) |
| xss | 300/300 (100%) | 300/300 (100%) |

*sqli denominator at PL2 is 152: the 2 `waf_block_outbound` samples are
excluded from the prediction file by the runner (errors); they are reported
separately above. Distinct payloads (rule 15): 150/150/77/150 requests per
family = 2 injection points each.

Family × injection_point × fragment at true PL2 (crs-default; fragment rule
is exploratory, defined after v0 — rule from step-04):

- command-injection: q complete 124/128, q fragment 14/22, login complete
  124/128, login fragment 14/22
- path-traversal: 150/150 everywhere
- sqli: complete 50/51, fragment 24/25 (both injection points)
- xss: 150/150 everywhere (all complete)

## In-sample statement (rule 19)

- The **crs-policy-aligned** configuration was derived from the observed
  methods and content types of `benign-browse-v0` itself. Every aligned
  result on benign-browse-v0 in this document and in `docs/baseline-v0.1.md`
  is therefore **in-sample**: it shows the config removes the FPs it was
  derived from, and nothing more. An out-of-sample check needs a future
  recording (v1) that the config has never seen.
- The attack corpus does not exercise PUT or text/plain content types (its
  two injection points are GET search and POST login with application/json),
  so unchanged attack recall under the aligned config is **by construction**,
  not evidence of anything.

## Whoami false positive (T5, analysis only — no exclusion)

Audit entry (benign-browse PL1 aligned run), `GET /rest/user/whoami?fields=email`
→ 403:

    Matched Data: /rest/user/whoami found within REQUEST_FILENAME: /rest/user/whoami
    ruleId 932260, file REQUEST-932-APPLICATION-ATTACK-RCE.conf, line 567

Rule 932260 ("Remote Command Execution: Direct Unix Command Execution",
severity CRITICAL) matches `REQUEST_FILENAME|REQUEST_COOKIES|
REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:*|XML://@*` against a large
case-insensitive alternation of Unix command names — including `whoami`
(the `w(?:get…|ho(?:ami|is…))` branch). The Juice Shop route path itself
contains the word `whoami`, so the rule matches the URL path as if it were a
command string. This is a genuine CRS false positive on this application's
route naming; per the step instructions no exclusion was made.

## Limitations

1. Aligned-config results on browse are in-sample (above).
2. PL2 hard-benign numbers are dominated by the outbound-cut mechanism
   (target 500s + response scoring); the inbound-only view (43.33%) and the
   worst case (53.33%) bracket it.
3. The natural corpus has no per-term search traffic (client-side search,
   dataset README), so the search injection point is covered only by the
   hard-benign set.
4. Session-level attribution remains impossible in benign-browse-v0 (step-05).
