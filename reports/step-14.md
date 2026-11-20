# Step-14 report

- Summary: reconciled all step-13 loose ends (T1a–T1f), built and ran two new
  frozen attack-side datasets (attacks-ct-v0 320 samples, 8 cells;
  encoding-diff-v0 192 samples, 4 cells) with rule-36 audit controls in every
  run, and ran a coraza-as-library diagnostic probe that localises the 44 s
  latency pathology inside the coraza library and re-confirms the
  NoFilesLimit non-enforcement. Docs updated (baseline v0.9, engine-evidence,
  decision 0001 addendum); pytest 103 passed; all work committed.

## Task table

| task | status | evidence |
|---|---|---|
| T1a oversize forensics (11 samples + wcp-34940e7ffce1) | done | docs/logs/step14-t1-oversize.txt; numbers below |
| T1b timeout/error replays 3x both engines | done (DIAGNOSTIC) | docs/logs/step14-t1-timeout-replay.txt; numbers below |
| T1c 20 largest-body replay table | done (DIAGNOSTIC) | docs/logs/step14-t1-analysis.txt (T1c section) |
| T1d policy-clear difference classification | done | docs/baseline-v0.9.md T1d section; counts below |
| T1e reload-race scope | done | docs/logs/step14-t1-analysis.txt (T1e section) |
| T1f T6 variable-class correction | done | docs/logs/step14-t1-analysis.txt (T1f section) |
| T2 preregister attacks-ct-v0 | done | docs/plan-attacks-ct-v0.md (committed before build); manifest sha256 69d0447c… |
| T3 run attack-side set + analysis | done | docs/logs/step14-t3-analysis.txt; numbers below |
| T4 encoding differential | done | docs/plan-encoding-diff.md; docs/logs/step14-t4-analysis.txt; numbers below |
| T5 coraza-as-library probe | done (DIAGNOSTIC) | tools/go-probe/; docs/logs/step14-t5-probe.txt; numbers below |
| T6 docs | done | docs/baseline-v0.9.md, docs/engine-evidence.md, docs/decisions/0001 addendum, README/acceptance counts |
| pytest | done | 103 passed in 13.93s |

## Key results (rule 31 — in the body)

### T1a — the 11 step-12 oversize-divergent samples

All 11 bodies are 723,995–2,829,426 bytes, i.e. all above nginx's 1 MiB
default. Before the alignment every one had Coraza 413 (nginx) while
ModSecurity passed (10 multipart POSTs, 200) or blocked on its own rules (1
no-content-type PUT, 403 via 911100/920340/920640/949110). After the
alignment: the 10 multipart samples are **200 on both engines at PL1 and
PL2**; the PUT (wcp-4ff99580bb57) is modsec 403 / coraza 400 at both PLs —
the residual difference is the engines' rule sets on a no-CT PUT (modsec
920340/920640/949110 vs coraza 911100/920320/920450/200007), not a size
effect. **PROVEN per sample**: bytes > 1,048,576 AND the 413 disappears when
client_max_body_size 0 is deployed.

wcp-34940e7ffce1: after alignment it is **200 waf_pass on both engines**; no
Coraza 403 exists post-alignment, so there are no rule IDs to report for one.
The interim claim of a post-alignment "Coraza 403" on this sample was an
error and is corrected in docs/baseline-v0.9.md.

### T1b — timeout/error replays (DIAGNOSTIC, 3x each, 60 s, PL1)

- wcp-80a49c991b2d (477 KB text/plain): Coraza 44.5/45.6/44.3 s → 403 (3/3);
  ModSecurity 50.6/16.5/19.8 ms → 403. **The only reproducible timeout.**
- The 5 step-13 PL1 timeouts and the other PL2 timeouts (0bdd37cedc4b,
  eeeb13d052ce): **do not reproduce** — all 200 within 66 ms on both engines.
  Classed transient; cause HYPOTHESIS (host load during the step-13 run).
- wcp-6b0bf5e43122: the encoding error reproduces identically on both
  engines — runner-side (non-latin-1 header), not an engine difference.

### T1d — 8 PL1 + 9 PL2 body-bearing policy-clear differences classified

- PL1: 1 only-modsec (wcp-96b9ef51be10 — coraza 200007 large-argument-count
  400 vs modsec 920340/920640/949110): class "known engine difference".
  7 only-coraza: modsec side shows 200002 (body parse) and/or 920450
  (restricted content-encoding) on samples carrying gzip/CL replay defects;
  coraza side shows detection rules on the parsed body: class "replay defect
  + body-access difference".
- PL2: the same 8 + wcp-aa98de364e37 (modsec 200002 only; coraza PL2 re-run
  blocks it via 932240/942131/949110): class "replay defect".
- Unexplained: **0**.

### T1f — T6 variable-class correction

REQUEST_BODY matches: **0 on both engines in both variants** — body-derived
matches go through ARGS/ARGS_NAMES. ModSecurity recorded-variant matches are
TX (200)/REQUEST_HEADERS (14)/REQUEST_METHOD (1) only; after the CT rewrite
they become ARGS_NAMES (79)/ARGS (63)/TX (104)/REQBODY_ERROR (2). Coraza is
nearly unchanged by the swap (ARGS_NAMES 119, ARGS 64 at match level in both
variants). Rule 35 note: the 97/100 and 6/100 figures are counts on a
difference-selected set, never rates of traffic.

### T3 — attacks-ct-v0 (8 cells x 320; counts, no interpretation)

Blocked per cell (out of 320):

| cell | modsec | coraza |
|---|---|---|
| default PL1 | 304 | 304 |
| default PL2 | 316 | 316 |
| ct-wide PL1 | 224 | 292 |
| ct-wide PL2 | 236 | 312 |

- Default config: identical totals and identical per-carrier counts on both
  engines (query/urlencoded/json/multipart 36/39 by PL; text-plain,
  octet-stream, unknown-ct 40 = policy-only on modsec but 34–39 detection +
  policy on coraza; no-ct 40 detection on both).
- 920420-only vs detection: modsec default 120/184 (PL1), coraza default
  18/286 (PL1). Under ct-wide modsec policy-only drops to 40 (unknown-ct
  only) and its text-plain/octet-stream detection stays **0**; coraza keeps
  detecting 34–38/40 on those carriers.
- Carriers where one engine blocked fewer: ct-wide text-plain (modsec 0 vs
  coraza 34/38) and octet-stream (modsec 0 vs coraza 34/38); default: none.
- Detection blocks dropping default→ct-wide: modsec 0/0; coraza PL2: 2
  (command-injection-ecb32a80 on text-plain and octet-stream, rule 920240
  present under default, absent under ct-wide); coraza PL1: 0.
- Payloads detected under one carrier but not another (same engine+cell):
  modsec 36/39/36/39 payloads detected on exactly
  {query,urlencoded,json,multipart,no-ct} and never on the three unparsed-CT
  carriers; coraza 34–39 payloads detected on ALL 8 carriers (PL2 default:
  39/39 on all 8). Full per-payload carrier lists are in
  docs/logs/step14-t3-analysis.txt.
- Rule-36 controls: 20 before + 20 after in every cell (all 8 cells printed
  20/40). Rule-29 lines printed for every cell (env_CT rendered value shown
  for ct-wide cells).

### T4 — encoding-diff-v0 (4 cells x 192; counts, no interpretation)

Blocked per encoding (out of 16 per encoding-carrier cell):

| encoding | query | urlencoded |
|---|---|---|
| plain | 6/16 | 15–16/16 |
| single-pct | 15–16/16 | 15–16/16 |
| double-pct | 14–15/16 | 14–15/16 |
| pct-u | 14–15/16 | 14–15/16 |
| mixed-case-hex | 15–16/16 | 15–16/16 |
| overlong-utf8 | **0/16** | **0/16** |

Totals identical across engines: 137/192 (PL1), 146/192 (PL2). **Per-sample
disagreements: 0 at both PLs** — there are no disagreement cells, so no
"which side decodes" attribution is needed. Overlong UTF-8 is decoded by
neither engine (0/32 on both). Work-order discrepancy (12 vs 16 payloads)
recorded in the plan BEFORE the build; we built 16 (4 per family).

### T5 — coraza v3.7.0 as a library (DIAGNOSTIC)

Go probe (tools/go-probe), coraza v3.7.0 module, CRS 4.25.2 files copied from
the coraza image (digest bfbfe70b…; version string OWASP_CRS/4.25.2 printed
from the copied files), PL1, SecRequestBodyLimit 13107200 /
NoFilesLimit 131072 / LimitAction Reject:

- (a) 140,000-byte JSON: **200 (passed), 648 ms** — the library does not
  enforce SecRequestBodyNoFilesLimit 131072. PROVEN (matches the step-13 T4
  container finding; now proven at library level).
- (b) wcp-80a49c991b2d body (481,798 bytes, text/plain): **403 after
  44,206 ms** with the same rule set as the container run (920420, 932120,
  932380, 933180, 941100, 941130, 941170, 941210, 942190, 949110). PROVEN:
  the ~44 s pathology is inside the coraza library body processing, with no
  nginx and no connector in the path. The exact internal code path remains
  HYPOTHESIS (upstream coraza #1176/#1796 related; same-code-path claim
  UNVERIFIED).
- (c) T6 swap samples (all 100, recorded and swapped): blocked 100/100 in
  both variants; ≥1 body-derived detection rule on 100/100 in both
  (container: 97/100 recorded). The recorded→swapped rewrite changes the
  body-derived rule set on 1/100 in-library. The library numbers are close
  to but not identical with the container numbers (probe header handling
  differs slightly); DIAGNOSTIC, no parity numbers (rule 34).
- (d) 5 plain controls: 4 pass (200); text/plain POST blocked by 920420
  (policy) — mirrors the container default config, validating the setup.

## Deviations from instructions

- T3 first pass wrote both engines' outputs into the same out/ directories
  (tag lacked the engine name); the coraza runs overwrote the modsec runs.
  The modsec cells were re-run with corrected tags; the coraza outputs were
  renamed in place. No data was mixed: each kept directory holds one engine's
  run only (run.json labels verify).
- T4: work order said "12 base payloads (4 per family)"; 4 families x 4 = 16.
  Built 16 (192 samples) and recorded the discrepancy in the plan before the
  build (rule 4).
- The instructor answer on NoFilesLimit ("becomes an acceptance test") is
  recorded as a criterion in docs/baseline-v0.9.md; implementing the
  automated limit-probing check is left to the step that builds our engine
  (no engine code exists yet to test).
- T1b replays ran at PL1 on both engines (the step-13 timeouts were observed
  in PL1 and PL2 runs; the pathology is PL-independent per step-13 T7).

## UNVERIFIED items

- The exact coraza internal code path behind the latency pathology
  (HYPOTHESIS; no CPU profile taken).
- Cause of the transient step-13 timeouts (not reproducible; HYPOTHESIS host
  load).
- Whether the coraza-coreruleset module version inside the library probe
  matches the container's byte-for-byte (rules FILES were copied from the
  container and the CRS version string 4.25.2 was printed from them; the Go
  module's built-in coraza-coreruleset package was not used for rules).
- Whether the 1/100 in-library rule-set change on the T6 swap corresponds
  sample-by-sample to container behaviour.

## Questions for instructor

1. T3 shows that widening the content-type policy on ModSecurity REMOVES all
   detection on text/plain and application/octet-stream carriers (policy
   block was the only block), while Coraza keeps detecting. Should the
   engine criteria (decision 0002) get an explicit criterion covering
   "detection coverage per content-type carrier", or is the current
   per-sample blocked-set criterion sufficient?
2. The transient step-13 timeouts did not reproduce. Should future full-scale
   runs record per-request host-load markers (e.g. container CPU) so
   transient timeouts can be attributed, or is the 3x-replay protocol
   sufficient evidence?

## Raw evidence

- docs/logs/step14-t1-oversize.txt — 11-sample table (bytes/chars/CT/method,
  before/after statuses, both PLs)
- docs/logs/step14-t1-timeout-replay.txt — 9 samples x 3 replays x 2 engines
- docs/logs/step14-t1-analysis.txt — T1c table + T1e scope + T1f classes
- docs/logs/step14-t3-runs.txt, step14-t3-modsec-rerun.txt — 8 cells with
  rule-29 lines and rule-36 control counts
- docs/logs/step14-t3-analysis.txt — per-cell/carrier/payload analysis
- docs/logs/step14-t4-runs.txt, step14-t4-analysis.txt — 4 cells + analysis
- docs/logs/step14-t5-setup.txt, step14-t5-probe.txt, step14-t5-analysis.txt
- out/step14-t1-coraza-pl2.log — the corrected Coraza PL2 re-run
- Commits: rules 35-36 → plan-attacks-ct-v0 → attacks-ct-v0 frozen →
  T3 tooling → T3 runs+analysis → T4 plan → T4 manifest frozen → T4 runs →
  T5 probe → baseline-v0.9 → engine-evidence → decision-0001 addendum →
  README/acceptance.
