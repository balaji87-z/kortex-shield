# Step-26 report

Host and versions (rule 43: same host as step 25; the image set is used
again in this step, so versions and digests are restated). macOS 27.0
(26A425), Darwin 27.0.0 arm64, Apple M6 12 cores; go1.27.4 darwin/arm64;
Python 3.15.2, pytest 9.2.0. Docker client 29.10.1, server 29.5.2
linux/arm64, kernel 6.8.0-117-generic (colima). Images:
`owasp/modsecurity-crs:4.25.2-nginx-lts@sha256:6296ce685cb88ba4012998b935b25dabbd9e0ff326088c1149447102544de661`,
`ghcr.io/coreruleset/coraza-crs:4.25.2-nginx-lts@sha256:bfbfe70b4445c1ef1dc389c2de12cfdb194c9616746c33dc8a7131461c28f4a6`,
both linux/arm64, both with OWASP_CRS/4.25.2 read inside the container
(rule 28). Engine: no file under engine/ changed in this step; binary
sha256 761ef5ad...702792fb (engine code of 497d585), coraza v3.8.1 with the
step-23 patch, CRS 4.25.2. Rule 29: every run log carries the effective
configuration read from the running engine or container; examples below.
Network: used by `tools/fetch/fetch_attacks_v1_sources.sh` only.

The step-26 brief is the instructor's "do all 4"; this is the second of
the four steps, acceptance A2 on the attack side: a held-out attack
dataset. Plan written and committed before the build:
docs/plan-attacks-v1.md (efa286d). Step 25 was pushed (origin/main
4b3472f) before the runs of this step.

- Summary: attacks-v1 is frozen: 2,670 requests, 1,335 distinct payloads, 9 families (5 new), none shared with attacks-v0; A2's
  attack count is met (1,862 distinct payloads). Held-out recall of the engine: PL1 82.92% (2,214/2,670), PL2 91.54% (2,444/2,670);
  in-sample it was 90.51% and 97.15%. Coraza connector: same blocks; ModSecurity: 8 status differences at PL1, 0 at PL2. No engine code changed.

- Task table:

| task | status | evidence |
|---|---|---|
| T0 plan, config note, source list with hashes, fetch script, before the build | done | docs/plan-attacks-v1.md, docs/baseline-config.md (step 26), tools/fetch/attacks_v1_sources.sha256, docs/logs/step26-fetch.log; commit efa286d |
| T1 builder with tests, candidates | done: 2,670 candidates, 1,335 payloads | tools/build_attacks_v1.py, tests/test_build_attacks_v1.py (9 tests), docs/logs/step26-build.log; commit 1b7a645 |
| T2 reach check, freeze, README | done: 0 quarantined, manifest sha256 7a82a516...6723066 | docs/logs/step26-reach.txt, docs/logs/runs/s26-reach/, data/attacks-v1/; commit 62a099e |
| T3 engine, blocking, PL1 and PL2, in-process and worker | done: 2,214 and 2,444 blocked; 0 per-sample differences between the modes | docs/logs/step26-engine.txt, docs/logs/runs/s26-engine/ |
| T4 baselines: ModSecurity image and Coraza connector image, PL1 and PL2 | done: connector 2,214 / 2,444, ModSecurity 2,210 / 2,444; controls 20/20 before and after | docs/logs/step26-baseline.txt, docs/logs/runs/s26-baseline/ |
| T5 DIAGNOSTIC without the REQUEST_BODY targets, with a canary; DIAGNOSTIC for the 942330 difference | done: 0 differences on attacks-v1, 6 on the canary; 942330 PROVEN to follow from a build tag of the connector | docs/logs/step26-DIAGNOSTIC-no-body-targets.txt, step26-DIAGNOSTIC-canary.txt, step26-DIAGNOSTIC-942330.txt |
| T6 tables with intervals, docs, report | done | tools/step26_summary.py (5 tests), tools/step26_summary.sh, docs/logs/step26-summary.txt, step26-not-blocked-ids.txt, docs/baseline-v2.1.md, docs/engine-design.md, docs/engine-evidence.md, docs/acceptance.md (A2), this report |
| Final suites | done: Go 70 PASS / 0 FAIL / 5 SKIP; pytest 266 passed, 0 failed, 4 skipped. Go with the fixture: not re-run, see deviations | docs/logs/step26-t6-go-test.log, step26-t6-pytest.log |

## Raw evidence

Long lines are cut where marked `[...]`; the files named hold them in full.
"attack" means "listed under this family in this source", not "verified
exploitable" (rule 11).

### T0. Sources (rule 25)

PayloadsAllTheThings at 08ea40e77db3f42ef8f20c65196f3936a19b6c86, licence
MIT. The dataset's samples are committed (MIT allows it; the pre-push scan
allows request bodies under data/attacks-*); the source files are not, the
fetch script checks them against the committed hash list.

```
# step-26: fetch of the attacks-v1 source files, 2026-11-28T07:18:38Z, git 4b3472fa7a8b702e0c09dcffe331fc4a875dda82
# bash tools/fetch/fetch_attacks_v1_sources.sh out/step26/fresh-fetch   (a fresh download into an empty directory)
PayloadsAllTheThings@08ea40e77db3f42ef8f20c65196f3936a19b6c86: 48 files in out/step26/fresh-fetch, 48 downloaded now, every sha256 as in tools/fetch/attacks_v1_sources.sha256 (list sha256 0e98cb7a888f17630607dcc27e933d53e7b207ffd8e67fbc4b1b0dabdcbf1336)
# bash tools/fetch/fetch_attacks_v1_sources.sh   (the files the builder reads)
PayloadsAllTheThings@08ea40e77db3f42ef8f20c65196f3936a19b6c86: 48 files in data/external/patt-08ea40e, 0 downloaded now, every sha256 as in tools/fetch/attacks_v1_sources.sha256 (list sha256 0e98cb7a888f17630607dcc27e933d53e7b207ffd8e67fbc4b1b0dabdcbf1336)
```

### T1. Build

```
# step-26 T1: build of the attacks-v1 candidates, 2026-11-28T12:11:56Z, git efa286d4401eae9d909214651000a616f0cf0f1f + tools/build_attacks_v1.py, Python 3.15.2
$ .venv/bin/python tools/build_attacks_v1.py build
| family | files | raw lines | blank | duplicates | in attacks-v0 | in an earlier family | unsendable | after filters | cap | sampled | requests |
|---|---|---|---|---|---|---|---|---|---|---|---|
| sqli | 21 | 1466 | 1 | 99 | 77 | 0 | 1 {'not-utf8': 1} | 1288 | 300 | 300 | 600 |
| xss | 12 | 2434 | 56 | 473 | 0 | 0 | 2 {'longer-than-2000-bytes': 2} | 1903 | 300 | 300 | 600 |
| path-traversal | 3 | 1939 | 0 | 471 | 8 | 0 | 0  | 1460 | 200 | 200 | 400 |
| command-injection | 1 | 83 | 0 | 4 | 8 | 0 | 0  | 71 | all | 71 | 142 |
| lfi | 4 | 2159 | 0 | 763 | 3 | 70 | 0  | 1323 | 200 | 200 | 400 |
| xxe | 2 | 116 | 1 | 13 | 0 | 1 | 0  | 101 | all | 101 | 202 |
| ssti | 1 | 107 | 0 | 0 | 0 | 0 | 0  | 107 | all | 107 | 214 |
| nosql | 2 | 46 | 0 | 20 | 0 | 0 | 0  | 26 | all | 26 | 52 |
| ldap | 2 | 66 | 0 | 33 | 0 | 3 | 0  | 30 | all | 30 | 60 |
candidates: 2670 requests, 1335 distinct payloads -> data/attacks-v1/candidates.jsonl
$ shasum -a 256 data/attacks-v1/candidates.jsonl
7a82a51622e311f26f00fffff1f39b718f1528d907a20da89e30372cc6723066  data/attacks-v1/candidates.jsonl
$ wc -l data/attacks-v1/*.jsonl
    2670 data/attacks-v1/annotations.jsonl
    2670 data/attacks-v1/candidates.jsonl
      74 data/attacks-v1/excluded-cross-family.jsonl
      96 data/attacks-v1/excluded-in-v0.jsonl
       3 data/attacks-v1/excluded-unsendable.jsonl
    5513 total
# second build into out/step26/rebuild: identical candidates?
identical
# kortex_eval.manifest loads the candidates:
2670 samples valid; 2670 distinct request contents
```

Builder tests: `tests/test_build_attacks_v1.py`, 9 tests (line terminators
and `#` lines, the two request shapes, attacks-v0 overlap, first family
owns a payload, unsendable payloads, cap and seed, source hash check, the
freeze never filters on would-block, the freeze needs every outcome).

### T2. Reach check and freeze (before any blocking-mode run)

```
# Step-26: reach check of the attacks-v1 candidates (before the freeze): engine in-process, DetectionOnly, PL1
== 2026-11-28T12:13:24Z, macOS 27.0 Darwin 27.0.0 arm64, go version go1.27.4 darwin/arm64, Python 3.15.2, load at start: load averages: 4.94 4.58 3.84
== git 1b7a6454aef41e88b8430cd6bcd012960f41be49, tracked paths changed in the working tree: 1, under engine/: 0
== candidates data/attacks-v1/candidates.jsonl sha256 7a82a51622e311f26f00fffff1f39b718f1528d907a20da89e30372cc6723066, 2670 requests
== engine binary sha256 761ef5adacb501c596a0dc67b1df0ec3bdb9f50b8ca9330c0205c320702792fb built from 1b7a6454aef41e88b8430cd6bcd012960f41be49 with go version go1.27.4 darwin/arm64
== attacks-v1-reach-detection-pl1 rule29 2026-11-28T12:13:25Z load: load averages: 4.86 4.57 3.84: {"backend_url":"http://127.0.0.1:13004","rule_engine":"DetectionOnly","blocking_paranoia":1,"detection_paranoia":1,"max_body_bytes":13107200,"max_inspected_bytes":131072,"engine_time_budget_ms":2000,"rules_dir":"/Users/ivan/work/kortex-shield-next/engine/crs","listen_addr":"127.0.0.1:8097","events_file":"/Users/ivan/work/kortex-shield-next/out/s22-s26-attacks-v1-reach-detection-pl1.events.jsonl","audit_log":"/Users/ivan/work/kortex-shield-next/out/s22-s26-attacks-v1-reach-detection-pl1.audit.log","allowed_methods":"GET HEAD POST OPTIONS","max_inflight_body":8,"max_inflight_body_large":2,"body_l [...]
== attacks-v1-reach-detection-pl1 stats after run: {"inflight_small":0,"inflight_large":0,"abandoned_running":0,"kills":0,"overloads":0,"refused_before_inspection":0,"penalised_clients":0,"client_inflight_small":0,"client_inflight_large":0,"workers":{"pool":0,"busy":0,"spares":0,"recycled":0}}
== attacks-v1-reach-detection-pl1 kortex_eval.crs_audit and kortex_eval.outcome (detection) output:
crs_audit: 2214 audit entr(ies) -> out/s26-attacks-v1-reach-detection-pl1/audit.jsonl
waf_pass: 456
waf_would_block: 2214
docs/logs/runs/s26-reach/attacks-v1-reach-detection-pl1/audit.index.jsonl: 2214 records, 1107 with a body, 108013 body bytes in the source
== attacks-v1-reach-detection-pl1 events: 2671 events {'pass': 2671}; compressed-body events 0 {}; framing events 0 {}; kept 0
== reach outcomes: {'waf_pass': 456, 'waf_would_block': 2214}; statuses {200: 2670}; client errors by class {}
== load at end: load averages: 4.71 4.55 3.83
S26-reach-DONE

# freeze, 2026-11-28T12:13:41Z
$ .venv/bin/python tools/build_attacks_v1.py freeze docs/logs/runs/s26-reach/attacks-v1-reach-detection-pl1/outcomes.jsonl
reach check: 2670 candidates, outcomes {'waf_pass': 456, 'waf_would_block': 2214}
kept 2670, quarantined 0 
manifest sha256 7a82a51622e311f26f00fffff1f39b718f1528d907a20da89e30372cc6723066
$ cat data/attacks-v1/MANIFEST.sha256; shasum -a 256 data/attacks-v1/manifest.jsonl; cmp data/attacks-v1/manifest.jsonl data/attacks-v1/candidates.jsonl; wc -l data/attacks-v1/manifest.jsonl data/attacks-v1/quarantine.jsonl
7a82a51622e311f26f00fffff1f39b718f1528d907a20da89e30372cc6723066  manifest.jsonl
7a82a51622e311f26f00fffff1f39b718f1528d907a20da89e30372cc6723066  data/attacks-v1/manifest.jsonl
manifest.jsonl is identical to candidates.jsonl
    2670 data/attacks-v1/manifest.jsonl
       0 data/attacks-v1/quarantine.jsonl
    2670 total
```

The reach run also shows how many candidates would be blocked at PL1
(2,214). No candidate was removed or kept because of it; the freeze removes
only `error`, `waf_fail_closed_*`, `inconsistent` (0 of each).

### T3. Engine runs (blocking)

```
# Step-26: attacks-v1 on the engine, blocking, PL1 and PL2, in-process and worker
== 2026-11-28T12:14:14Z, macOS 27.0 Darwin 27.0.0 arm64, go version go1.27.4 darwin/arm64, Python 3.15.2, load at start: load averages: 5.96 4.95 4.01
== git 62a099eb2344916928168f142e600b0370b2e6a7, tracked paths changed in the working tree: 0, under engine/: 0
== manifest data/attacks-v1/manifest.jsonl sha256 7a82a51622e311f26f00fffff1f39b718f1528d907a20da89e30372cc6723066 (frozen: 7a82a51622e311f26f00fffff1f39b718f1528d907a20da89e30372cc6723066), 2670 requests
== coraza module of engine/: github.com/corazawaf/coraza/v3 v3.8.1 => ./third_party/coraza-v3.8.1-kortex
== engine binary sha256 761ef5adacb501c596a0dc67b1df0ec3bdb9f50b8ca9330c0205c320702792fb built from 62a099eb2344916928168f142e600b0370b2e6a7 with go version go1.27.4 darwin/arm64
== attacks-v1-inprocess-pl1 rule29 2026-11-28T12:14:16Z load: load averages: 5.72 4.91 4.01: {"backend_url":"http://127.0.0.1:13004","rule_engine":"On","blocking_paranoia":1,"detection_paranoia":1,"max_body_bytes":13107200,"max_inspected_bytes":131072,"engine_time_budget_ms":2000,"rules_dir":"/Users/ivan/work/kortex-shield-next/engine/crs","listen_addr":"127.0.0.1:8097","events_file":"/Users/ivan/work/kortex-shield-next/out/s22-s26-attacks-v1-inprocess-pl1.events.jsonl","audit_log":"/Users/ivan/work/kortex-shield-next/out/s22-s26-attacks-v1-inprocess-pl1.audit.log","allowed_methods":"GET HEAD POST OPTIONS","max_inflight_body":8,"max_inflight_body_large":2,"body_lane_threshold":65536,"worker_mode":false,"client_max_inflight":0,"client_max_inflight_small":4,"client_max_inflight_large":1,"request_body_target_updates":165,"error_log":"","crs_test_setup":false}
== attacks-v1-inprocess-pl1 events: 2671 events {'block': 2214, 'pass': 457}; compressed-body events 0 {}; framing events 0 {}; kept 0
== attacks-v1-worker-pl1 rule29 2026-11-28T12:14:21Z load: load averages: 5.74 4.93 4.02: {"backend_url":"http://127.0.0.1:13004","rule_engine":"On","blocking_paranoia":1,"detection_paranoia":1,"max_body_bytes":13107200,"max_inspected_bytes":131072,"engine_time_budget_ms":2000,"rules_dir":"/Users/ivan/work/kortex-shield-next/engine/crs","listen_addr":"127.0.0.1:8098","events_file":"/Users/ivan/work/kortex-shield-next/out/s22-s26-attacks-v1-worker-pl1.events.jsonl","audit_log":"/Users/ivan/work/kortex-shield-next/out/s22-s26-attacks-v1-worker-pl1.audit.log","allowed_methods":"GET HEAD POST OPTIONS","max_inflight_body":8,"max_inflight_body_large":2,"body_lane_threshold":65536,"worker_mode":true,"client_max_inflight":0,"client_max_inflight_small":4,"client_max_inflight_large":1,"request_body_target_updates":165,"error_log":"","crs_test_setup":false}
== attacks-v1-worker-pl1 events: 2671 events {'block': 2214, 'pass': 457}; compressed-body events 0 {}; framing events 0 {}; kept 0
== diff attacks-v1 PL1 (a=inprocess b=worker):
samples compared: 2670 (a=2670 b=2670 only-a=0 only-b=0)
status counts a: {200: 456, 403: 2214}
status counts b: {200: 456, 403: 2214}
status diffs: 0
no status in a (counted as error): 0
no status in b (counted as error): 0
worst-case set a: 2214/2670 (error=0 blocked=2214 deny_status=0 inconsistent=0 fail_closed_413=0 fail_closed_415=0 fail_closed_400=0 fail_closed_503_timeout=0 fail_closed_503_overload=0)
worst-case set b: 2214/2670 (error=0 blocked=2214 deny_status=0 inconsistent=0 fail_closed_413=0 fail_closed_415=0 fail_closed_400=0 fail_closed_503_timeout=0 fail_closed_503_overload=0)
worst-case set diffs: 0 (only-a 0 only-b 0)
== attacks-v1-inprocess-pl2 rule29 2026-11-28T12:14:28Z load: load averages: 5.60 4.92 4.02: {"backend_url":"http://127.0.0.1:13004","rule_engine":"On","blocking_paranoia":2,"detection_paranoia":2,"max_body_bytes":13107200,"max_inspected_bytes":131072,"engine_time_budget_ms":2000,"rules_dir":"/Users/ivan/work/kortex-shield-next/engine/crs","listen_addr":"127.0.0.1:8097","events_file":"/Users/ivan/work/kortex-shield-next/out/s22-s26-attacks-v1-inprocess-pl2.events.jsonl","audit_log":"/Users/ivan/work/kortex-shield-next/out/s22-s26-attacks-v1-inprocess-pl2.audit.log","allowed_methods":"GET HEAD POST OPTIONS","max_inflight_body":8,"max_inflight_body_large":2,"body_lane_threshold":65536,"worker_mode":false,"client_max_inflight":0,"client_max_inflight_small":4,"client_max_inflight_large":1,"request_body_target_updates":165,"error_log":"","crs_test_setup":false}
== attacks-v1-inprocess-pl2 events: 2671 events {'block': 2444, 'pass': 227}; compressed-body events 0 {}; framing events 0 {}; kept 0
== attacks-v1-worker-pl2 rule29 2026-11-28T12:14:36Z load: load averages: 7.00 5.24 4.15: {"backend_url":"http://127.0.0.1:13004","rule_engine":"On","blocking_paranoia":2,"detection_paranoia":2,"max_body_bytes":13107200,"max_inspected_bytes":131072,"engine_time_budget_ms":2000,"rules_dir":"/Users/ivan/work/kortex-shield-next/engine/crs","listen_addr":"127.0.0.1:8098","events_file":"/Users/ivan/work/kortex-shield-next/out/s22-s26-attacks-v1-worker-pl2.events.jsonl","audit_log":"/Users/ivan/work/kortex-shield-next/out/s22-s26-attacks-v1-worker-pl2.audit.log","allowed_methods":"GET HEAD POST OPTIONS","max_inflight_body":8,"max_inflight_body_large":2,"body_lane_threshold":65536,"worker_mode":true,"client_max_inflight":0,"client_max_inflight_small":4,"client_max_inflight_large":1,"request_body_target_updates":165,"error_log":"","crs_test_setup":false}
== attacks-v1-worker-pl2 events: 2671 events {'block': 2444, 'pass': 227}; compressed-body events 0 {}; framing events 0 {}; kept 0
== diff attacks-v1 PL2 (a=inprocess b=worker):
samples compared: 2670 (a=2670 b=2670 only-a=0 only-b=0)
status counts a: {200: 226, 403: 2444}
status counts b: {200: 226, 403: 2444}
status diffs: 0
no status in a (counted as error): 0
no status in b (counted as error): 0
worst-case set a: 2444/2670 (error=0 blocked=2444 deny_status=0 inconsistent=0 fail_closed_413=0 fail_closed_415=0 fail_closed_400=0 fail_closed_503_timeout=0 fail_closed_503_overload=0)
worst-case set b: 2444/2670 (error=0 blocked=2444 deny_status=0 inconsistent=0 fail_closed_413=0 fail_closed_415=0 fail_closed_400=0 fail_closed_503_timeout=0 fail_closed_503_overload=0)
worst-case set diffs: 0 (only-a 0 only-b 0)
== load at end: load averages: 7.56 5.39 4.20
S26-engine-DONE
```

### T4. Baseline images

```
# Step-26: attacks-v1 on the ModSecurity image and the Coraza connector image, PL1 and PL2 (default config, stub backend)
== 2026-11-28T16:13:14Z, macOS 27.0 Darwin 27.0.0 arm64, go version go1.27.4 darwin/arm64, Python 3.15.2, load at start: load averages: 5.25 2.89 2.10
== git 62a099eb2344916928168f142e600b0370b2e6a7, tracked paths changed in the working tree: 1, under engine/: 0
== manifest data/attacks-v1/manifest.jsonl sha256 7a82a51622e311f26f00fffff1f39b718f1528d907a20da89e30372cc6723066 (frozen: 7a82a51622e311f26f00fffff1f39b718f1528d907a20da89e30372cc6723066), 2670 requests
== docker client 29.10.1 server 29.5.2 linux/arm64 kernel 6.8.0-117-generic
== attacks-v1-modsec-pl1 rule29/28 2026-11-28T16:13:16Z load: load averages: 5.25 2.89 2.10
   image: owasp/modsecurity-crs:4.25.2-nginx-lts@sha256:6296ce685cb88ba4012998b935b25dabbd9e0ff326088c1149447102544de661 id sha256:6296ce685cb88ba4012998b935b25dabbd9e0ff326088c1149447102544de661 platform linux/arm64 repo digests owasp/modsecurity-crs@sha256:6296ce685cb88ba4012998b935b25dabbd9e0ff326088c1149447102544de661
   env: E=On B=1 P=1 D=1 BACKEND=http://stub-backend:3000 CT=[] M=[]
   conf: SecRuleEngine On SecRequestBodyLimit 13107200 SecRequestBodyNoFilesLimit 131072 
   crs-setup: tx.blocking_paranoia_level=1 tx.detection_paranoia_level=1 tx.crs_setup_version=4252
   ruleset: ver:'OWASP_CRS/4.25.2 in /etc/modsecurity.d/owasp-crs/rules (27 .conf files)
crs_audit: 2251 audit entr(ies) -> out/s26-attacks-v1-modsec-pl1/audit.jsonl
warning: 41 audit entr(ies) could not be attributed to a sample id
waf_block: 2210
waf_pass: 460
docs/logs/runs/s26-baseline/attacks-v1-modsec-pl1/audit.index.jsonl: 2251 entries
   rule36 attacks-v1-modsec-pl1: control entries in the audit: pre 20/20, post 20/20; audit entries 2251 (2210 with a v1 sample id, 1 without a sample id)
   result attacks-v1-modsec-pl1: n=2670 outcomes={'waf_block': 2210, 'waf_pass': 460}
   result attacks-v1-modsec-pl1: status counts={200: 460, 403: 2210}
== attacks-v1-modsec-pl1 done 2026-11-28T16:13:32Z load: load averages: 5.96 3.16 2.21
== attacks-v1-coraza-pl1 rule29/28 2026-11-28T16:13:44Z load: load averages: 5.59 3.17 2.22
   image: ghcr.io/coreruleset/coraza-crs:4.25.2-nginx-lts@sha256:bfbfe70b4445c1ef1dc389c2de12cfdb194c9616746c33dc8a7131461c28f4a6 id sha256:bfbfe70b4445c1ef1dc389c2de12cfdb194c9616746c33dc8a7131461c28f4a6 platform linux/arm64 repo digests ghcr.io/coreruleset/coraza-crs@sha256:bfbfe70b4445c1ef1dc389c2de12cfdb194c9616746c33dc8a7131461c28f4a6
   env: E=On B=1 P=1 D=1 CT=[] body=[nofiles=131072 total=13107200]
   crs-setup: tx.blocking_paranoia_level=1 tx.detection_paranoia_level=1 tx.crs_setup_version=4252
   ruleset: ver:'OWASP_CRS/4.25.2 in /opt/coraza/owasp-crs/rules (27 .conf files)
coraza_audit: 2254 audit entr(ies) -> out/s26-attacks-v1-coraza-pl1/audit.jsonl
warning: 40 audit entr(ies) could not be attributed to a sample id
waf_block: 2214
waf_pass: 456
docs/logs/runs/s26-baseline/attacks-v1-coraza-pl1/audit.index.jsonl: 2254 entries
   rule36 attacks-v1-coraza-pl1: control entries in the audit: pre 20/20, post 20/20; audit entries 2254 (2214 with a v1 sample id, 0 without a sample id)
   result attacks-v1-coraza-pl1: n=2670 outcomes={'waf_block': 2214, 'waf_pass': 456}
   result attacks-v1-coraza-pl1: status counts={200: 456, 403: 2214}
== attacks-v1-coraza-pl1 done 2026-11-28T16:14:09Z load: load averages: 4.64 3.15 2.24
== attacks-v1-modsec-pl2 rule29/28 2026-11-28T16:14:20Z load: load averages: 6.61 3.63 2.43
   image: owasp/modsecurity-crs:4.25.2-nginx-lts@sha256:6296ce685cb88ba4012998b935b25dabbd9e0ff326088c1149447102544de661 id sha256:6296ce685cb88ba4012998b935b25dabbd9e0ff326088c1149447102544de661 platform linux/arm64 repo digests owasp/modsecurity-crs@sha256:6296ce685cb88ba4012998b935b25dabbd9e0ff326088c1149447102544de661
   env: E=On B=2 P=2 D=2 BACKEND=http://stub-backend:3000 CT=[] M=[]
   conf: SecRuleEngine On SecRequestBodyLimit 13107200 SecRequestBodyNoFilesLimit 131072 
   crs-setup: tx.blocking_paranoia_level=2 tx.detection_paranoia_level=2 tx.crs_setup_version=4252
   ruleset: ver:'OWASP_CRS/4.25.2 in /etc/modsecurity.d/owasp-crs/rules (27 .conf files)
crs_audit: 2537 audit entr(ies) -> out/s26-attacks-v1-modsec-pl2/audit.jsonl
warning: 41 audit entr(ies) could not be attributed to a sample id
waf_block: 2444
waf_pass: 226
docs/logs/runs/s26-baseline/attacks-v1-modsec-pl2/audit.index.jsonl: 2537 entries
   rule36 attacks-v1-modsec-pl2: control entries in the audit: pre 20/20, post 20/20; audit entries 2537 (2496 with a v1 sample id, 1 without a sample id)
   result attacks-v1-modsec-pl2: n=2670 outcomes={'waf_block': 2444, 'waf_pass': 226}
   result attacks-v1-modsec-pl2: status counts={200: 226, 403: 2444}
== attacks-v1-modsec-pl2 done 2026-11-28T16:14:37Z load: load averages: 5.81 3.60 2.44
== attacks-v1-coraza-pl2 rule29/28 2026-11-28T16:14:49Z load: load averages: 5.61 3.63 2.46
   image: ghcr.io/coreruleset/coraza-crs:4.25.2-nginx-lts@sha256:bfbfe70b4445c1ef1dc389c2de12cfdb194c9616746c33dc8a7131461c28f4a6 id sha256:bfbfe70b4445c1ef1dc389c2de12cfdb194c9616746c33dc8a7131461c28f4a6 platform linux/arm64 repo digests ghcr.io/coreruleset/coraza-crs@sha256:bfbfe70b4445c1ef1dc389c2de12cfdb194c9616746c33dc8a7131461c28f4a6
   env: E=On B=2 P=2 D=2 CT=[] body=[nofiles=131072 total=13107200]
   crs-setup: tx.blocking_paranoia_level=2 tx.detection_paranoia_level=2 tx.crs_setup_version=4252
   ruleset: ver:'OWASP_CRS/4.25.2 in /opt/coraza/owasp-crs/rules (27 .conf files)
coraza_audit: 2484 audit entr(ies) -> out/s26-attacks-v1-coraza-pl2/audit.jsonl
warning: 40 audit entr(ies) could not be attributed to a sample id
waf_block: 2444
waf_pass: 226
docs/logs/runs/s26-baseline/attacks-v1-coraza-pl2/audit.index.jsonl: 2484 entries
   rule36 attacks-v1-coraza-pl2: control entries in the audit: pre 20/20, post 20/20; audit entries 2484 (2444 with a v1 sample id, 0 without a sample id)
   result attacks-v1-coraza-pl2: n=2670 outcomes={'waf_block': 2444, 'waf_pass': 226}
   result attacks-v1-coraza-pl2: status counts={200: 226, 403: 2444}
== attacks-v1-coraza-pl2 done 2026-11-28T16:15:08Z load: load averages: 6.03 3.84 2.56
== load at end: load averages: 5.71 3.85 2.58
S26-baseline-DONE
```

### T5. DIAGNOSTIC runs (rule 34: no baseline number)

Without the REQUEST_BODY target updates, on attacks-v1:

```
# Step-26 DIAGNOSTIC: attacks-v1 on the engine built without the REQUEST_BODY target updates, in-process, PL1 and PL2
== 2026-11-28T16:12:06Z, macOS 27.0 Darwin 27.0.0 arm64, go version go1.27.4 darwin/arm64, Python 3.15.2, load at start: load averages: 3.52 2.15 1.80
== git 62a099eb2344916928168f142e600b0370b2e6a7, tracked paths changed in the working tree: 0, under engine/: 0
== manifest data/attacks-v1/manifest.jsonl sha256 7a82a51622e311f26f00fffff1f39b718f1528d907a20da89e30372cc6723066 (frozen: 7a82a51622e311f26f00fffff1f39b718f1528d907a20da89e30372cc6723066), 2670 requests
== DIAGNOSTIC scratch engine sha256 7726e6f3d4660fd28228baa80ccbe039a764fe9e7a3c85ced480e5e1cef68e85; files that differ from engine/: 1; diff of config.go against engine/config.go:
192c192
< 	return base + renderBodyTargetUpdates(bodyTargets), nil
---
> 	return base, nil
== attacks-v1-inprocess-pl1-DIAGNOSTIC-no-body-targets events: 2671 events {'block': 2214, 'pass': 457}; compressed-body events 0 {}; framing events 0 {}; kept 0
== diff attacks-v1 PL1 (a=engine b=DIAGNOSTIC without the REQUEST_BODY targets):
samples compared: 2670 (a=2670 b=2670 only-a=0 only-b=0)
status counts a: {200: 456, 403: 2214}
status counts b: {200: 456, 403: 2214}
status diffs: 0
no status in a (counted as error): 0
no status in b (counted as error): 0
worst-case set a: 2214/2670 (error=0 blocked=2214 deny_status=0 inconsistent=0 fail_closed_413=0 fail_closed_415=0 fail_closed_400=0 fail_closed_503_timeout=0 fail_closed_503_overload=0)
worst-case set b: 2214/2670 (error=0 blocked=2214 deny_status=0 inconsistent=0 fail_closed_413=0 fail_closed_415=0 fail_closed_400=0 fail_closed_503_timeout=0 fail_closed_503_overload=0)
worst-case set diffs: 0 (only-a 0 only-b 0)
== attacks-v1-inprocess-pl2-DIAGNOSTIC-no-body-targets events: 2671 events {'block': 2444, 'pass': 227}; compressed-body events 0 {}; framing events 0 {}; kept 0
== diff attacks-v1 PL2 (a=engine b=DIAGNOSTIC without the REQUEST_BODY targets):
samples compared: 2670 (a=2670 b=2670 only-a=0 only-b=0)
status counts a: {200: 226, 403: 2444}
status counts b: {200: 226, 403: 2444}
status diffs: 0
no status in a (counted as error): 0
no status in b (counted as error): 0
worst-case set a: 2444/2670 (error=0 blocked=2444 deny_status=0 inconsistent=0 fail_closed_413=0 fail_closed_415=0 fail_closed_400=0 fail_closed_503_timeout=0 fail_closed_503_overload=0)
worst-case set b: 2444/2670 (error=0 blocked=2444 deny_status=0 inconsistent=0 fail_closed_413=0 fail_closed_415=0 fail_closed_400=0 fail_closed_503_timeout=0 fail_closed_503_overload=0)
worst-case set diffs: 0 (only-a 0 only-b 0)
== load at end: load averages: 4.01 2.32 1.86
S26-diag-DONE
```

Rule 16 (a result identical under two conditions): the DIAGNOSTIC result
equals the engine's, and `/__kortex/config` prints
`request_body_target_updates: 165` for the DIAGNOSTIC binary too, because
that field counts the target list, not what was rendered. So the condition
is shown to take effect another way: the same binary (sha256 7726e6f3...)
on attacks-ct-v0 at PL1, where the targets are known to matter:

```
# Step-26 DIAGNOSTIC canary: attacks-ct-v0 at PL1 on the engine built without the REQUEST_BODY target updates
== 2026-11-28T16:12:59Z, macOS 27.0 Darwin 27.0.0 arm64, go version go1.27.4 darwin/arm64, Python 3.15.2, load at start: load averages: 3.56 2.40 1.91
== git 62a099eb2344916928168f142e600b0370b2e6a7, tracked paths changed in the working tree: 1, under engine/: 0
== manifest data/attacks-ct-v0/manifest.jsonl sha256 69d0447c5b33ca63e37c2993e8c7e87add2a16d56dd89201978883905f923251 (frozen: 69d0447c5b33ca63e37c2993e8c7e87add2a16d56dd89201978883905f923251), 320 requests
== DIAGNOSTIC scratch engine sha256 7726e6f3d4660fd28228baa80ccbe039a764fe9e7a3c85ced480e5e1cef68e85; files that differ from engine/: 1; diff of config.go against engine/config.go:
192c192
< 	return base + renderBodyTargetUpdates(bodyTargets), nil
---
> 	return base, nil
== attacks-ct-v0-inprocess-pl1-DIAGNOSTIC-no-body-targets events: 321 events {'block': 286, 'pass': 35}; compressed-body events 0 {}; framing events 0 {}; kept 0
== diff attacks-ct-v0 PL1 (a=engine, step-25 run docs/logs/runs/s25-own/attacks-ct-v0-inprocess-pl1; b=DIAGNOSTIC without the REQUEST_BODY targets):
samples compared: 320 (a=320 b=320 only-a=0 only-b=0)
status counts a: {200: 28, 403: 292}
status counts b: {200: 34, 403: 286}
status diffs: 6
  actv0-octet-stream-command-injection-dc2932d5: a=403 b=200
  actv0-octet-stream-sqli-6e47f23b: a=403 b=200
  actv0-text-plain-command-injection-dc2932d5: a=403 b=200
  actv0-text-plain-sqli-6e47f23b: a=403 b=200
  actv0-unknown-ct-command-injection-dc2932d5: a=403 b=200
  actv0-unknown-ct-sqli-6e47f23b: a=403 b=200
no status in a (counted as error): 0
no status in b (counted as error): 0
worst-case set a: 292/320 (error=0 blocked=292 deny_status=0 inconsistent=0 fail_closed_413=0 fail_closed_415=0 fail_closed_400=0 fail_closed_503_timeout=0 fail_closed_503_overload=0)
worst-case set b: 286/320 (error=0 blocked=286 deny_status=0 inconsistent=0 fail_closed_413=0 fail_closed_415=0 fail_closed_400=0 fail_closed_503_timeout=0 fail_closed_503_overload=0)
worst-case set diffs: 6 (only-a 6 only-b 0)
  only-a actv0-octet-stream-command-injection-dc2932d5: a=blocked (status 403) b status 200
  only-a actv0-octet-stream-sqli-6e47f23b: a=blocked (status 403) b status 200
  only-a actv0-text-plain-command-injection-dc2932d5: a=blocked (status 403) b status 200
  only-a actv0-text-plain-sqli-6e47f23b: a=blocked (status 403) b status 200
  only-a actv0-unknown-ct-command-injection-dc2932d5: a=blocked (status 403) b status 200
  only-a actv0-unknown-ct-sqli-6e47f23b: a=blocked (status 403) b status 200
== load at end: load averages: 5.68 2.85 2.07
S26-diag-canary-DONE
```

The 942330 difference between the engine and the connector image:

```
# Step-26 DIAGNOSTIC: CRS 942330 on four attacks-v1 requests, 25 sends each, PL2
== 2026-11-28T16:19:28Z, git 62a099eb2344916928168f142e600b0370b2e6a7, go version go1.27.4 darwin/arm64, load at start: load averages: 3.95 3.85 2.92
== manifest out/step26-942330-manifest.jsonl: 100 requests (not committed: copies of 4 frozen samples)
== engine binary sha256 761ef5adacb501c596a0dc67b1df0ec3bdb9f50b8ca9330c0205c320702792fb built from 62a099eb2344916928168f142e600b0370b2e6a7 with go version go1.27.4 darwin/arm64
== engine (patched coraza) engine binary sha256 761ef5adacb501c596a0dc67b1df0ec3bdb9f50b8ca9330c0205c320702792fb
   engine (patched coraza): v1-command-injection-0a2a074b-login: audit entries 25 of 25 sends, with 942330 in 25; rule-id sets seen: {'920230 932160 932200 942330 942520 949110': 25}; scores at 949110: {'28': 25}
   engine (patched coraza): v1-command-injection-0a2a074b-q: audit entries 25 of 25 sends, with 942330 in 25; rule-id sets seen: {'920230 932160 932200 942330 942520 949110': 25}; scores at 949110: {'28': 25}
   engine (patched coraza): v1-command-injection-7dc8718c-login: audit entries 25 of 25 sends, with 942330 in 25; rule-id sets seen: {'920230 932160 942330 942520 949110': 25}; scores at 949110: {'18': 25}
   engine (patched coraza): v1-command-injection-7dc8718c-q: audit entries 25 of 25 sends, with 942330 in 25; rule-id sets seen: {'920230 932160 942330 942520 949110': 25}; scores at 949110: {'18': 25}
== engine (patched coraza): 942330 in 100 of 100 audit entries
== DIAGNOSTIC scratch engine coraza module: github.com/corazawaf/coraza/v3 v3.8.1
== DIAGNOSTIC engine on stock coraza v3.8.1 engine binary sha256 1e0fac89229d34bb92f2d0989fc9d00ed0d6236fdcccffb5f1f49779b2e9315c
   DIAGNOSTIC engine on stock coraza v3.8.1: v1-command-injection-0a2a074b-login: audit entries 25 of 25 sends, with 942330 in 25; rule-id sets seen: {'920230 932160 932200 942330 942520 949110': 25}; scores at 949110: {'28': 25}
   DIAGNOSTIC engine on stock coraza v3.8.1: v1-command-injection-0a2a074b-q: audit entries 25 of 25 sends, with 942330 in 25; rule-id sets seen: {'920230 932160 932200 942330 942520 949110': 25}; scores at 949110: {'28': 25}
   DIAGNOSTIC engine on stock coraza v3.8.1: v1-command-injection-7dc8718c-login: audit entries 25 of 25 sends, with 942330 in 25; rule-id sets seen: {'920230 932160 942330 942520 949110': 25}; scores at 949110: {'18': 25}
   DIAGNOSTIC engine on stock coraza v3.8.1: v1-command-injection-7dc8718c-q: audit entries 25 of 25 sends, with 942330 in 25; rule-id sets seen: {'920230 932160 942330 942520 949110': 25}; scores at 949110: {'18': 25}
== DIAGNOSTIC engine on stock coraza v3.8.1: 942330 in 100 of 100 audit entries
== DIAGNOSTIC scratch engine coraza module: github.com/corazawaf/coraza/v3 v3.7.0; files that differ from engine/ other than go.mod, go.sum and third_party: 0
== DIAGNOSTIC engine on coraza v3.7.0 engine binary sha256 6af92efacd03f24c41f5e388dada3d2012f4b915744dbfda153d8628e805a122
   DIAGNOSTIC engine on coraza v3.7.0: v1-command-injection-0a2a074b-login: audit entries 25 of 25 sends, with 942330 in 25; rule-id sets seen: {'920230 932160 932200 942330 942520 949110': 25}; scores at 949110: {'28': 25}
   DIAGNOSTIC engine on coraza v3.7.0: v1-command-injection-0a2a074b-q: audit entries 25 of 25 sends, with 942330 in 25; rule-id sets seen: {'920230 932160 932200 942330 942520 949110': 25}; scores at 949110: {'28': 25}
   DIAGNOSTIC engine on coraza v3.7.0: v1-command-injection-7dc8718c-login: audit entries 25 of 25 sends, with 942330 in 25; rule-id sets seen: {'920230 932160 942330 942520 949110': 25}; scores at 949110: {'18': 25}
   DIAGNOSTIC engine on coraza v3.7.0: v1-command-injection-7dc8718c-q: audit entries 25 of 25 sends, with 942330 in 25; rule-id sets seen: {'920230 932160 942330 942520 949110': 25}; scores at 949110: {'18': 25}
== DIAGNOSTIC engine on coraza v3.7.0: 942330 in 100 of 100 audit entries
== DIAGNOSTIC engine built from engine/ unchanged with -tags coraza.rule.no_regex_multiline
== DIAGNOSTIC engine with -tags coraza.rule.no_regex_multiline engine binary sha256 adb78c994fa42e94dee217a0dc111f80017803da720fe7712a6b5ac3edd7e51a
   DIAGNOSTIC engine with -tags coraza.rule.no_regex_multiline: v1-command-injection-0a2a074b-login: audit entries 25 of 25 sends, with 942330 in 0; rule-id sets seen: {'920230 932160 932200 942520 949110': 25}; scores at 949110: {'23': 25}
   DIAGNOSTIC engine with -tags coraza.rule.no_regex_multiline: v1-command-injection-0a2a074b-q: audit entries 25 of 25 sends, with 942330 in 0; rule-id sets seen: {'920230 932160 932200 942520 949110': 25}; scores at 949110: {'23': 25}
   DIAGNOSTIC engine with -tags coraza.rule.no_regex_multiline: v1-command-injection-7dc8718c-login: audit entries 25 of 25 sends, with 942330 in 0; rule-id sets seen: {'920230 932160 942520 949110': 25}; scores at 949110: {'13': 25}
   DIAGNOSTIC engine with -tags coraza.rule.no_regex_multiline: v1-command-injection-7dc8718c-q: audit entries 25 of 25 sends, with 942330 in 0; rule-id sets seen: {'920230 932160 942520 949110': 25}; scores at 949110: {'13': 25}
== DIAGNOSTIC engine with -tags coraza.rule.no_regex_multiline: 942330 in 0 of 100 audit entries
== coraza version inside the connector image (grep in /usr/local/lib/libcoraza.so):  154 corazawaf/coraza/v3@v3.7.0;
== build tags named inside the connector image's libcoraza.so:  2 -tags=coraza.rule.no_regex_multiline;
== connector image: ghcr.io/coreruleset/coraza-crs:4.25.2-nginx-lts@sha256:bfbfe70b4445c1ef1dc389c2de12cfdb194c9616746c33dc8a7131461c28f4a6; E=On B=2 D=2
   Coraza connector image: v1-command-injection-0a2a074b-login: audit entries 25 of 25 sends, with 942330 in 0; rule-id sets seen: {'920230 932160 932200 942520 949110': 25}; scores at 949110: {'23': 25}
   Coraza connector image: v1-command-injection-0a2a074b-q: audit entries 25 of 25 sends, with 942330 in 0; rule-id sets seen: {'920230 932160 932200 942520 949110': 25}; scores at 949110: {'23': 25}
   Coraza connector image: v1-command-injection-7dc8718c-login: audit entries 25 of 25 sends, with 942330 in 0; rule-id sets seen: {'920230 932160 942520 949110': 25}; scores at 949110: {'13': 25}
   Coraza connector image: v1-command-injection-7dc8718c-q: audit entries 25 of 25 sends, with 942330 in 0; rule-id sets seen: {'920230 932160 942520 949110': 25}; scores at 949110: {'13': 25}
== Coraza connector image: 942330 in 0 of 100 audit entries
== load at end: load averages: 3.14 3.67 2.88
S26-942330-DONE
```

| explanation tested | experiment | result |
|---|---|---|
| matching is not repeatable | 25 sends per request on each WAF | same rule ids on all 25, on every WAF: rejected |
| the step-23 coraza patch | engine on stock coraza v3.8.1 | 942330 in 100 of 100, as the patched engine: rejected |
| the coraza version (the image has v3.7.0) | engine on coraza v3.7.0 | 942330 in 100 of 100: rejected |
| the build tag `coraza.rule.no_regex_multiline` named in the image's libcoraza.so | engine's own source built with that tag | 942330 in 0 of 100, rule ids and scores equal to the connector's: PROVEN |

### T6. Tables

`bash tools/step26_summary.sh > docs/logs/step26-summary.txt`. Engine
in-process, PL1 and PL2 (the worker runs give the same lines; the
ModSecurity, connector and DIAGNOSTIC blocks are in the file):

```
# step-26: attacks-v1 (held-out for every engine setting), tables
# 2026-11-28T16:15:53Z git 62a099eb2344916928168f142e600b0370b2e6a7
# "attack" means "listed under this family in this source", not "verified exploitable" (rule 11)

== PL1: rates and counts per run
engine-inprocess-pl1: requests 2670, distinct payloads 1335; outcomes: waf_block 2214, waf_pass 456
    recall best case (only waf_block) 2214/2670 = 82.92% (95% Wilson 81.45 to 84.30); worst case (every outcome that is not a pass) 2214/2670 = 82.92% (95% Wilson 81.45 to 84.30)
    per family kind:
      seen-family: best 1488/1742 = 85.42% (95% Wilson 83.68 to 87.00); worst 1488/1742 = 85.42% (95% Wilson 83.68 to 87.00)
      new-family: best 726/928 = 78.23% (95% Wilson 75.46 to 80.77); worst 726/928 = 78.23% (95% Wilson 75.46 to 80.77)
    per family:
      sqli: best 488/600 = 81.33% (95% Wilson 78.02 to 84.25); worst 488/600 = 81.33% (95% Wilson 78.02 to 84.25)
      xss: best 556/600 = 92.67% (95% Wilson 90.30 to 94.49); worst 556/600 = 92.67% (95% Wilson 90.30 to 94.49)
      path-traversal: best 346/400 = 86.50% (95% Wilson 82.80 to 89.50); worst 346/400 = 86.50% (95% Wilson 82.80 to 89.50)
      command-injection: best 98/142 = 69.01% (95% Wilson 60.99 to 76.04); worst 98/142 = 69.01% (95% Wilson 60.99 to 76.04)
      lfi: best 330/400 = 82.50% (95% Wilson 78.47 to 85.91); worst 330/400 = 82.50% (95% Wilson 78.47 to 85.91)
      xxe: best 186/202 = 92.08% (95% Wilson 87.52 to 95.07); worst 186/202 = 92.08% (95% Wilson 87.52 to 95.07)
      ssti: best 158/214 = 73.83% (95% Wilson 67.56 to 79.26); worst 158/214 = 73.83% (95% Wilson 67.56 to 79.26)
      nosql: best 44/52 = 84.62% (95% Wilson 72.48 to 91.99); worst 44/52 = 84.62% (95% Wilson 72.48 to 91.99)
      ldap: best 8/60 = 13.33% (95% Wilson 6.91 to 24.17); worst 8/60 = 13.33% (95% Wilson 6.91 to 24.17)
    per injection point:
      q: best 1107/1335 = 82.92% (95% Wilson 80.81 to 84.84); worst 1107/1335 = 82.92% (95% Wilson 80.81 to 84.84)
      login: best 1107/1335 = 82.92% (95% Wilson 80.81 to 84.84); worst 1107/1335 = 82.92% (95% Wilson 80.81 to 84.84)
    payloads blocked at both injection points 1107, at one 0, at none 228
    per payload (blocked at both injection points): 1107/1335 = 82.92% (95% Wilson 80.81 to 84.84)
    rule 18: 2214 audit entries; rule ids in >=20% of them: 949110=2214, 941100=620, 941390=500, 941160=482
    not blocked, by family and injection point: sqli/q 56, sqli/login 56, xss/q 22, xss/login 22, path-traversal/q 27, path-traversal/login 27, command-injection/q 22, command-injection/login 22, lfi/q 35, lfi/login 35, xxe/q 8, xxe/login 8, ssti/q 28, ssti/login 28, nosql/q 4, nosql/login 4, ldap/q 26, ldap/login 26
engine-inprocess-pl2: requests 2670, distinct payloads 1335; outcomes: waf_block 2444, waf_pass 226
    recall best case (only waf_block) 2444/2670 = 91.54% (95% Wilson 90.42 to 92.53); worst case (every outcome that is not a pass) 2444/2670 = 91.54% (95% Wilson 90.42 to 92.53)
    per family kind:
      seen-family: best 1628/1742 = 93.46% (95% Wilson 92.20 to 94.52); worst 1628/1742 = 93.46% (95% Wilson 92.20 to 94.52)
      new-family: best 816/928 = 87.93% (95% Wilson 85.68 to 89.87); worst 816/928 = 87.93% (95% Wilson 85.68 to 89.87)
    per family:
      sqli: best 578/600 = 96.33% (95% Wilson 94.51 to 97.57); worst 578/600 = 96.33% (95% Wilson 94.51 to 97.57)
      xss: best 576/600 = 96.00% (95% Wilson 94.12 to 97.30); worst 576/600 = 96.00% (95% Wilson 94.12 to 97.30)
      path-traversal: best 364/400 = 91.00% (95% Wilson 87.79 to 93.43); worst 364/400 = 91.00% (95% Wilson 87.79 to 93.43)
      command-injection: best 110/142 = 77.46% (95% Wilson 69.92 to 83.56); worst 110/142 = 77.46% (95% Wilson 69.92 to 83.56)
      lfi: best 356/400 = 89.00% (95% Wilson 85.55 to 91.70); worst 356/400 = 89.00% (95% Wilson 85.55 to 91.70)
      xxe: best 190/202 = 94.06% (95% Wilson 89.90 to 96.57); worst 190/202 = 94.06% (95% Wilson 89.90 to 96.57)
      ssti: best 206/214 = 96.26% (95% Wilson 92.80 to 98.09); worst 206/214 = 96.26% (95% Wilson 92.80 to 98.09)
      nosql: best 50/52 = 96.15% (95% Wilson 87.02 to 98.94); worst 50/52 = 96.15% (95% Wilson 87.02 to 98.94)
      ldap: best 14/60 = 23.33% (95% Wilson 14.44 to 35.44); worst 14/60 = 23.33% (95% Wilson 14.44 to 35.44)
    per injection point:
      q: best 1222/1335 = 91.54% (95% Wilson 89.92 to 92.91); worst 1222/1335 = 91.54% (95% Wilson 89.92 to 92.91)
      login: best 1222/1335 = 91.54% (95% Wilson 89.92 to 92.91); worst 1222/1335 = 91.54% (95% Wilson 89.92 to 92.91)
    payloads blocked at both injection points 1222, at one 0, at none 113
    per payload (blocked at both injection points): 1222/1335 = 91.54% (95% Wilson 89.92 to 92.91)
    rule 18: 2444 audit entries; rule ids in >=20% of them: 949110=2444, 942520=756, 941100=620, 942430=606, 941390=500, 942370=492, 941320=490
    not blocked, by family and injection point: sqli/q 11, sqli/login 11, xss/q 12, xss/login 12, path-traversal/q 18, path-traversal/login 18, command-injection/q 16, command-injection/login 16, lfi/q 22, lfi/login 22, xxe/q 6, xxe/login 6, ssti/q 4, ssti/login 4, nosql/q 1, nosql/login 1, ldap/q 23, ldap/login 23
```

Per run, headline lines of all runs:

```
engine-inprocess-pl1: requests 2670, distinct payloads 1335; outcomes: waf_block 2214, waf_pass 456
    recall best case (only waf_block) 2214/2670 = 82.92% (95% Wilson 81.45 to 84.30); worst case (every outcome that is not a pass) 2214/2670 = 82.92% (95% Wilson 81.45 to 84.30)
    per payload (blocked at both injection points): 1107/1335 = 82.92% (95% Wilson 80.81 to 84.84)
    rule 18: 2214 audit entries; rule ids in >=20% of them: 949110=2214, 941100=620, 941390=500, 941160=482
engine-worker-pl1: requests 2670, distinct payloads 1335; outcomes: waf_block 2214, waf_pass 456
    recall best case (only waf_block) 2214/2670 = 82.92% (95% Wilson 81.45 to 84.30); worst case (every outcome that is not a pass) 2214/2670 = 82.92% (95% Wilson 81.45 to 84.30)
    per payload (blocked at both injection points): 1107/1335 = 82.92% (95% Wilson 80.81 to 84.84)
    rule 18: 2214 audit entries; rule ids in >=20% of them: 949110=2214, 941100=620, 941390=500, 941160=482
modsecurity-pl1: requests 2670, distinct payloads 1335; outcomes: waf_block 2210, waf_pass 460
    recall best case (only waf_block) 2210/2670 = 82.77% (95% Wilson 81.29 to 84.16); worst case (every outcome that is not a pass) 2210/2670 = 82.77% (95% Wilson 81.29 to 84.16)
    per payload (blocked at both injection points): 1105/1335 = 82.77% (95% Wilson 80.65 to 84.70)
    rule 18: 2251 audit entries; rule ids in >=20% of them: 949110=2251, 941100=626, 941390=500, 941160=482
coraza-connector-pl1: requests 2670, distinct payloads 1335; outcomes: waf_block 2214, waf_pass 456
    recall best case (only waf_block) 2214/2670 = 82.92% (95% Wilson 81.45 to 84.30); worst case (every outcome that is not a pass) 2214/2670 = 82.92% (95% Wilson 81.45 to 84.30)
    per payload (blocked at both injection points): 1107/1335 = 82.92% (95% Wilson 80.81 to 84.84)
    rule 18: 2254 audit entries; rule ids in >=20% of them: 949110=2254, 941100=620, 941390=500, 941160=482
DIAGNOSTIC-no-body-targets-pl1: requests 2670, distinct payloads 1335; outcomes: waf_block 2214, waf_pass 456
    recall best case (only waf_block) 2214/2670 = 82.92% (95% Wilson 81.45 to 84.30); worst case (every outcome that is not a pass) 2214/2670 = 82.92% (95% Wilson 81.45 to 84.30)
    per payload (blocked at both injection points): 1107/1335 = 82.92% (95% Wilson 80.81 to 84.84)
    rule 18: 2214 audit entries; rule ids in >=20% of them: 949110=2214, 941100=620, 941390=500, 941160=482
engine-inprocess-pl2: requests 2670, distinct payloads 1335; outcomes: waf_block 2444, waf_pass 226
    recall best case (only waf_block) 2444/2670 = 91.54% (95% Wilson 90.42 to 92.53); worst case (every outcome that is not a pass) 2444/2670 = 91.54% (95% Wilson 90.42 to 92.53)
    per payload (blocked at both injection points): 1222/1335 = 91.54% (95% Wilson 89.92 to 92.91)
    rule 18: 2444 audit entries; rule ids in >=20% of them: 949110=2444, 942520=756, 941100=620, 942430=606, 941390=500, 942370=492, 941320=490
engine-worker-pl2: requests 2670, distinct payloads 1335; outcomes: waf_block 2444, waf_pass 226
    recall best case (only waf_block) 2444/2670 = 91.54% (95% Wilson 90.42 to 92.53); worst case (every outcome that is not a pass) 2444/2670 = 91.54% (95% Wilson 90.42 to 92.53)
    per payload (blocked at both injection points): 1222/1335 = 91.54% (95% Wilson 89.92 to 92.91)
    rule 18: 2444 audit entries; rule ids in >=20% of them: 949110=2444, 942520=756, 941100=620, 942430=606, 941390=500, 942370=492, 941320=490
modsecurity-pl2: requests 2670, distinct payloads 1335; outcomes: waf_block 2444, waf_pass 226
    recall best case (only waf_block) 2444/2670 = 91.54% (95% Wilson 90.42 to 92.53); worst case (every outcome that is not a pass) 2444/2670 = 91.54% (95% Wilson 90.42 to 92.53)
    per payload (blocked at both injection points): 1222/1335 = 91.54% (95% Wilson 89.92 to 92.91)
    rule 18: 2537 audit entries; rule ids in >=20% of them: 949110=2485, 942520=756, 941100=626, 942430=608
coraza-connector-pl2: requests 2670, distinct payloads 1335; outcomes: waf_block 2444, waf_pass 226
    recall best case (only waf_block) 2444/2670 = 91.54% (95% Wilson 90.42 to 92.53); worst case (every outcome that is not a pass) 2444/2670 = 91.54% (95% Wilson 90.42 to 92.53)
    per payload (blocked at both injection points): 1222/1335 = 91.54% (95% Wilson 89.92 to 92.91)
    rule 18: 2484 audit entries; rule ids in >=20% of them: 949110=2484, 942520=756, 941100=620, 942430=606, 941390=500
DIAGNOSTIC-no-body-targets-pl2: requests 2670, distinct payloads 1335; outcomes: waf_block 2444, waf_pass 226
    recall best case (only waf_block) 2444/2670 = 91.54% (95% Wilson 90.42 to 92.53); worst case (every outcome that is not a pass) 2444/2670 = 91.54% (95% Wilson 90.42 to 92.53)
    per payload (blocked at both injection points): 1222/1335 = 91.54% (95% Wilson 89.92 to 92.91)
    rule 18: 2444 audit entries; rule ids in >=20% of them: 949110=2444, 942520=756, 941100=620, 942430=606, 941390=500, 942370=492, 941320=490
```

Per sample id (rule 32):

```
== PL1: per sample id (rule 32: status, worst-case set, rule-id sets)
    engine-inprocess against engine-worker: 2670 sample ids; status differs in 0; worst-case set differs in 0 (only engine-inprocess 0, only engine-worker 0); rule-id set differs in 0
    engine against modsecurity: 2670 sample ids; status differs in 8; worst-case set differs in 8 (only engine 6, only modsecurity 2); rule-id set differs in 32
      rule ids that make up the differences: only in engine: 930120 x8, 949110 x6; only in modsecurity: 920260 x18, 941100 x6, 949110 x2
      v1-lfi-85d4f1b9-login: status 403 / 200; outcome waf_block / waf_pass; rule ids only in engine ['930120', '949110'], only in modsecurity []
      v1-lfi-85d4f1b9-q: status 403 / 200; outcome waf_block / waf_pass; rule ids only in engine ['930120', '949110'], only in modsecurity []
      v1-lfi-aafcd311-login: status 403 / 200; outcome waf_block / waf_pass; rule ids only in engine ['930120', '949110'], only in modsecurity []
      v1-lfi-aafcd311-q: status 403 / 200; outcome waf_block / waf_pass; rule ids only in engine ['930120', '949110'], only in modsecurity []
      v1-lfi-b8205086-login: status 403 / 200; outcome waf_block / waf_pass; rule ids only in engine ['930120', '949110'], only in modsecurity []
      v1-lfi-b8205086-q: status 403 / 200; outcome waf_block / waf_pass; rule ids only in engine ['930120', '949110'], only in modsecurity []
      v1-xss-06229db7-login: status 200 / 403; outcome waf_pass / waf_block; rule ids only in engine [], only in modsecurity ['941100', '949110']
      v1-xss-06229db7-q: status 200 / 403; outcome waf_pass / waf_block; rule ids only in engine [], only in modsecurity ['941100', '949110']
    engine against coraza-connector: 2670 sample ids; status differs in 0; worst-case set differs in 0 (only engine 0, only coraza-connector 0); rule-id set differs in 0
    modsecurity against coraza-connector: 2670 sample ids; status differs in 8; worst-case set differs in 8 (only modsecurity 2, only coraza-connector 6); rule-id set differs in 32
      rule ids that make up the differences: only in modsecurity: 920260 x18, 941100 x6, 949110 x2; only in coraza-connector: 930120 x8, 949110 x6
      v1-lfi-85d4f1b9-login: status 200 / 403; outcome waf_pass / waf_block; rule ids only in modsecurity [], only in coraza-connector ['930120', '949110']
      v1-lfi-85d4f1b9-q: status 200 / 403; outcome waf_pass / waf_block; rule ids only in modsecurity [], only in coraza-connector ['930120', '949110']
      v1-lfi-aafcd311-login: status 200 / 403; outcome waf_pass / waf_block; rule ids only in modsecurity [], only in coraza-connector ['930120', '949110']
      v1-lfi-aafcd311-q: status 200 / 403; outcome waf_pass / waf_block; rule ids only in modsecurity [], only in coraza-connector ['930120', '949110']
      v1-lfi-b8205086-login: status 200 / 403; outcome waf_pass / waf_block; rule ids only in modsecurity [], only in coraza-connector ['930120', '949110']
      v1-lfi-b8205086-q: status 200 / 403; outcome waf_pass / waf_block; rule ids only in modsecurity [], only in coraza-connector ['930120', '949110']
      v1-xss-06229db7-login: status 403 / 200; outcome waf_block / waf_pass; rule ids only in modsecurity ['941100', '949110'], only in coraza-connector []
      v1-xss-06229db7-q: status 403 / 200; outcome waf_block / waf_pass; rule ids only in modsecurity ['941100', '949110'], only in coraza-connector []
    engine against DIAGNOSTIC-no-body-targets: 2670 sample ids; status differs in 0; worst-case set differs in 0 (only engine 0, only DIAGNOSTIC-no-body-targets 0); rule-id set differs in 0

== PL2: per sample id (rule 32: status, worst-case set, rule-id sets)
    engine-inprocess against engine-worker: 2670 sample ids; status differs in 0; worst-case set differs in 0 (only engine-inprocess 0, only engine-worker 0); rule-id set differs in 0
    engine against modsecurity: 2670 sample ids; status differs in 0; worst-case set differs in 0 (only engine 0, only modsecurity 0); rule-id set differs in 90
      rule ids that make up the differences: only in engine: 930120 x8; only in modsecurity: 920230 x50, 920260 x18, 941100 x6, 942131 x6, 942430 x2
      v1-command-injection-09dcc86c-login: status 200 / 200; outcome waf_pass / waf_pass; rule ids only in engine [], only in modsecurity ['920230']
      v1-command-injection-09dcc86c-q: status 200 / 200; outcome waf_pass / waf_pass; rule ids only in engine [], only in modsecurity ['920230']
      v1-command-injection-639af472-login: status 200 / 200; outcome waf_pass / waf_pass; rule ids only in engine [], only in modsecurity ['920230']
      v1-command-injection-639af472-q: status 200 / 200; outcome waf_pass / waf_pass; rule ids only in engine [], only in modsecurity ['920230']
      v1-command-injection-d4904a44-login: status 200 / 200; outcome waf_pass / waf_pass; rule ids only in engine [], only in modsecurity ['920230']
      v1-command-injection-d4904a44-q: status 200 / 200; outcome waf_pass / waf_pass; rule ids only in engine [], only in modsecurity ['920230']
      v1-ldap-26ebd69f-login: status 200 / 200; outcome waf_pass / waf_pass; rule ids only in engine [], only in modsecurity ['920230']
      v1-ldap-26ebd69f-q: status 200 / 200; outcome waf_pass / waf_pass; rule ids only in engine [], only in modsecurity ['920230']
      v1-ldap-2e66d75b-login: status 200 / 200; outcome waf_pass / waf_pass; rule ids only in engine [], only in modsecurity ['920230']
      v1-ldap-2e66d75b-q: status 200 / 200; outcome waf_pass / waf_pass; rule ids only in engine [], only in modsecurity ['920230']
      v1-ldap-3367706f-login: status 200 / 200; outcome waf_pass / waf_pass; rule ids only in engine [], only in modsecurity ['920230']
      v1-ldap-3367706f-q: status 200 / 200; outcome waf_pass / waf_pass; rule ids only in engine [], only in modsecurity ['920230']
      v1-ldap-3378b00f-login: status 200 / 200; outcome waf_pass / waf_pass; rule ids only in engine [], only in modsecurity ['920230']
      v1-ldap-3378b00f-q: status 200 / 200; outcome waf_pass / waf_pass; rule ids only in engine [], only in modsecurity ['920230']
      v1-ldap-a91b7710-login: status 200 / 200; outcome waf_pass / waf_pass; rule ids only in engine [], only in modsecurity ['920230']
      v1-ldap-a91b7710-q: status 200 / 200; outcome waf_pass / waf_pass; rule ids only in engine [], only in modsecurity ['920230']
      v1-ldap-adf38caa-login: status 200 / 200; outcome waf_pass / waf_pass; rule ids only in engine [], only in modsecurity ['920230']
      v1-ldap-adf38caa-q: status 200 / 200; outcome waf_pass / waf_pass; rule ids only in engine [], only in modsecurity ['920230']
      v1-ldap-cd087341-login: status 200 / 200; outcome waf_pass / waf_pass; rule ids only in engine [], only in modsecurity ['920230']
      v1-ldap-cd087341-q: status 200 / 200; outcome waf_pass / waf_pass; rule ids only in engine [], only in modsecurity ['920230']
      v1-ldap-d13042fb-login: status 200 / 200; outcome waf_pass / waf_pass; rule ids only in engine [], only in modsecurity ['920230']
      v1-ldap-d13042fb-q: status 200 / 200; outcome waf_pass / waf_pass; rule ids only in engine [], only in modsecurity ['920230']
      v1-ldap-d30de49f-login: status 200 / 200; outcome waf_pass / waf_pass; rule ids only in engine [], only in modsecurity ['920230']
      v1-ldap-d30de49f-q: status 200 / 200; outcome waf_pass / waf_pass; rule ids only in engine [], only in modsecurity ['920230']
      v1-lfi-19d2efe5-login: status 403 / 403; outcome waf_block / waf_block; rule ids only in engine ['930120'], only in modsecurity []
      v1-lfi-19d2efe5-q: status 403 / 403; outcome waf_block / waf_block; rule ids only in engine ['930120'], only in modsecurity []
      v1-lfi-85d4f1b9-login: status 403 / 403; outcome waf_block / waf_block; rule ids only in engine ['930120'], only in modsecurity []
      v1-lfi-85d4f1b9-q: status 403 / 403; outcome waf_block / waf_block; rule ids only in engine ['930120'], only in modsecurity []
      v1-lfi-aafcd311-login: status 403 / 403; outcome waf_block / waf_block; rule ids only in engine ['930120'], only in modsecurity []
      v1-lfi-aafcd311-q: status 403 / 403; outcome waf_block / waf_block; rule ids only in engine ['930120'], only in modsecurity []
      ... and 60 more ids (all in the run files)
    engine against coraza-connector: 2670 sample ids; status differs in 0; worst-case set differs in 0 (only engine 0, only coraza-connector 0); rule-id set differs in 4
      rule ids that make up the differences: only in engine: 942330 x4; only in coraza-connector: none
      v1-command-injection-0a2a074b-login: status 403 / 403; outcome waf_block / waf_block; rule ids only in engine ['942330'], only in coraza-connector []
      v1-command-injection-0a2a074b-q: status 403 / 403; outcome waf_block / waf_block; rule ids only in engine ['942330'], only in coraza-connector []
      v1-command-injection-7dc8718c-login: status 403 / 403; outcome waf_block / waf_block; rule ids only in engine ['942330'], only in coraza-connector []
      v1-command-injection-7dc8718c-q: status 403 / 403; outcome waf_block / waf_block; rule ids only in engine ['942330'], only in coraza-connector []
    modsecurity against coraza-connector: 2670 sample ids; status differs in 0; worst-case set differs in 0 (only modsecurity 0, only coraza-connector 0); rule-id set differs in 94
      rule ids that make up the differences: only in modsecurity: 920230 x50, 920260 x18, 941100 x6, 942131 x6, 942330 x4, 942430 x2; only in coraza-connector: 930120 x8
      v1-command-injection-09dcc86c-login: status 200 / 200; outcome waf_pass / waf_pass; rule ids only in modsecurity ['920230'], only in coraza-connector []
      v1-command-injection-09dcc86c-q: status 200 / 200; outcome waf_pass / waf_pass; rule ids only in modsecurity ['920230'], only in coraza-connector []
      v1-command-injection-0a2a074b-login: status 403 / 403; outcome waf_block / waf_block; rule ids only in modsecurity ['942330'], only in coraza-connector []
      v1-command-injection-0a2a074b-q: status 403 / 403; outcome waf_block / waf_block; rule ids only in modsecurity ['942330'], only in coraza-connector []
      v1-command-injection-639af472-login: status 200 / 200; outcome waf_pass / waf_pass; rule ids only in modsecurity ['920230'], only in coraza-connector []
      v1-command-injection-639af472-q: status 200 / 200; outcome waf_pass / waf_pass; rule ids only in modsecurity ['920230'], only in coraza-connector []
      v1-command-injection-7dc8718c-login: status 403 / 403; outcome waf_block / waf_block; rule ids only in modsecurity ['942330'], only in coraza-connector []
      v1-command-injection-7dc8718c-q: status 403 / 403; outcome waf_block / waf_block; rule ids only in modsecurity ['942330'], only in coraza-connector []
      v1-command-injection-d4904a44-login: status 200 / 200; outcome waf_pass / waf_pass; rule ids only in modsecurity ['920230'], only in coraza-connector []
      v1-command-injection-d4904a44-q: status 200 / 200; outcome waf_pass / waf_pass; rule ids only in modsecurity ['920230'], only in coraza-connector []
      v1-ldap-26ebd69f-login: status 200 / 200; outcome waf_pass / waf_pass; rule ids only in modsecurity ['920230'], only in coraza-connector []
      v1-ldap-26ebd69f-q: status 200 / 200; outcome waf_pass / waf_pass; rule ids only in modsecurity ['920230'], only in coraza-connector []
      v1-ldap-2e66d75b-login: status 200 / 200; outcome waf_pass / waf_pass; rule ids only in modsecurity ['920230'], only in coraza-connector []
      v1-ldap-2e66d75b-q: status 200 / 200; outcome waf_pass / waf_pass; rule ids only in modsecurity ['920230'], only in coraza-connector []
      v1-ldap-3367706f-login: status 200 / 200; outcome waf_pass / waf_pass; rule ids only in modsecurity ['920230'], only in coraza-connector []
      v1-ldap-3367706f-q: status 200 / 200; outcome waf_pass / waf_pass; rule ids only in modsecurity ['920230'], only in coraza-connector []
      v1-ldap-3378b00f-login: status 200 / 200; outcome waf_pass / waf_pass; rule ids only in modsecurity ['920230'], only in coraza-connector []
      v1-ldap-3378b00f-q: status 200 / 200; outcome waf_pass / waf_pass; rule ids only in modsecurity ['920230'], only in coraza-connector []
      v1-ldap-a91b7710-login: status 200 / 200; outcome waf_pass / waf_pass; rule ids only in modsecurity ['920230'], only in coraza-connector []
      v1-ldap-a91b7710-q: status 200 / 200; outcome waf_pass / waf_pass; rule ids only in modsecurity ['920230'], only in coraza-connector []
      v1-ldap-adf38caa-login: status 200 / 200; outcome waf_pass / waf_pass; rule ids only in modsecurity ['920230'], only in coraza-connector []
      v1-ldap-adf38caa-q: status 200 / 200; outcome waf_pass / waf_pass; rule ids only in modsecurity ['920230'], only in coraza-connector []
      v1-ldap-cd087341-login: status 200 / 200; outcome waf_pass / waf_pass; rule ids only in modsecurity ['920230'], only in coraza-connector []
      v1-ldap-cd087341-q: status 200 / 200; outcome waf_pass / waf_pass; rule ids only in modsecurity ['920230'], only in coraza-connector []
      v1-ldap-d13042fb-login: status 200 / 200; outcome waf_pass / waf_pass; rule ids only in modsecurity ['920230'], only in coraza-connector []
      v1-ldap-d13042fb-q: status 200 / 200; outcome waf_pass / waf_pass; rule ids only in modsecurity ['920230'], only in coraza-connector []
      v1-ldap-d30de49f-login: status 200 / 200; outcome waf_pass / waf_pass; rule ids only in modsecurity ['920230'], only in coraza-connector []
      v1-ldap-d30de49f-q: status 200 / 200; outcome waf_pass / waf_pass; rule ids only in modsecurity ['920230'], only in coraza-connector []
      v1-lfi-19d2efe5-login: status 403 / 403; outcome waf_block / waf_block; rule ids only in modsecurity [], only in coraza-connector ['930120']
      v1-lfi-19d2efe5-q: status 403 / 403; outcome waf_block / waf_block; rule ids only in modsecurity [], only in coraza-connector ['930120']
      ... and 64 more ids (all in the run files)
    engine against DIAGNOSTIC-no-body-targets: 2670 sample ids; status differs in 0; worst-case set differs in 0 (only engine 0, only DIAGNOSTIC-no-body-targets 0); rule-id set differs in 0
```

Classification of the differences (rule 39):

| difference | count | class | basis |
|---|---|---|---|
| engine in-process against worker | 0 | - | - |
| engine against Coraza connector, 942330 logged only by the engine | 4 requests at PL2, no status difference | DESIGN | PROVEN build-tag difference (above). Written into docs/engine-design.md after the run, see deviations |
| engine against ModSecurity, status | 8 requests at PL1 (6 only the engine blocks, 2 only ModSecurity), 0 at PL2 | DESIGN (decision 0004: the engine is built on coraza) | measured: the Coraza connector image differs from ModSecurity on the same 8 requests in the same direction. Why coraza and ModSecurity differ on rules 930120 and 941100: HYPOTHESIS, not tested |
| engine against ModSecurity, rule ids | 32 requests at PL1, 90 at PL2 | DESIGN (same) | measured: the connector against ModSecurity gives the same lists (PL2: 94 = these 90 and the 4 above) |
| UNEXPLAINED | 0 | | |

### Final suites

```
== 2026-11-28T16:20:11Z git 62a099eb2344916928168f142e600b0370b2e6a7 go version go1.27.4 darwin/arm64 load at start: load averages: 2.89 3.58 2.86
$ go test -count=1 -v -timeout 900s ./...
# result lines counted with grep -c '^--- PASS|FAIL|SKIP': PASS 70 FAIL 0 SKIP 5
--- SKIP: TestE16BodyProcessingBoundedByTimeBudget (0.00s)
--- SKIP: TestE17AbandonedCallOwnsTransaction (0.00s)
--- SKIP: TestE19OverloadCapImmediate (0.01s)
--- SKIP: TestE20OverloadRecovery (0.01s)
--- SKIP: TestE21BenignPromptOnCapReachedEngine (0.01s)
ok  	kortexshield/engine	67.604s
== exit 0 2026-11-28T16:21:19Z load at end: load averages: 3.84 3.75 2.98

== 2026-11-28T16:21:19Z git 62a099eb2344916928168f142e600b0370b2e6a7 Python 3.15.2 load at start: load averages: 3.84 3.75 2.98
$ .venv/bin/python -m pytest -q
......................................................................ss [ 26%]
..s..................................................................... [ 53%]
........................................................................ [ 80%]
..................................................----------------------------------------
.Exception occurred during processing of request from ('127.0.0.1', 52878)
..                    [100%]
266 passed, 4 skipped in 59.07s
== exit 0 2026-11-28T16:22:18Z load at end: load averages: 2.98 3.51 2.94
```

## Deviations from instructions

1. Rule 39 wants a DESIGN property documented in engine-design.md before
   the run. The multiline regex mode was not known before the run that
   showed it; it is documented after, with the experiment.
2. The plan lists three run groups. Two DIAGNOSTIC runs were added that it
   does not name: the canary on attacks-ct-v0 (needed by rule 16, because
   the DIAGNOSTIC result on attacks-v1 equals the engine's) and the 942330
   runs (needed by rule 39, to classify a difference).
3. Plan step 1 says "drop empty lines"; the builder drops lines that hold
   nothing but whitespace (58 lines). Written in the dataset README. The
   plan's line counts are `wc -l` counts; the builder counts a last line
   without a newline too (10 lines more in total).
4. Final Go suite with the fixture body: not re-run in this step. No file
   under engine/ changed since 497d585 (`git diff 497d585 --stat -- engine`
   is empty), where it was 75 PASS / 0 FAIL / 0 SKIP
   (docs/logs/step25-t6-go-test-with-fixture.log).
5. `tools/step22_lib.sh` got one additive change: `ENGINE_RULE_MODE`
   (default `On`, as before) so that the reach check can start the engine
   in DetectionOnly.
6. Rule 26 (label audit of 100 per label for a dataset labelled by someone
   else): not done as a manual reading. The label here is "listed under
   this family in this source" (rule 11), which the builder guarantees by
   construction and the `source` field records per sample. Whether each
   string is a meaningful attack of its family was not audited: NOT
   MEASURED. See question 3.

## UNVERIFIED items

- That a payload is a working attack of its family: not verified, by
  definition of the label (rule 11), and not audited (deviation 6).
- Why coraza and ModSecurity differ on the rules listed above (930120,
  941100, 920230, 920260, 942131, 942430): HYPOTHESIS, decoding and
  libinjection differences; not tested in this step.
- What `coraza.rule.no_regex_multiline` would change on the other datasets
  (attacks-v0, the benign sets, wcp, the CRS suite): NOT MEASURED. Earlier
  engine-against-connector comparisons were made with this difference in
  place, unnoticed.
- Whether attacks-v1 payloads also occur in CRS regression tests: not
  checked (stated in the plan).
- The new families through carriers that fit them (XML body for xxe, LDAP
  filter positions, template contexts): NOT MEASURED; both carriers here
  are a query argument and a JSON string.
- The Wilson intervals assume independent requests. They are not
  independent; the per-payload interval is given beside each headline.
- Timing: NOT MEASURED.
- Carried from step 25, unchanged: `TestT3dWorkerRecycleAfterN` fails at
  cleanup about once in 100 runs (not seen in this step's run); pytest
  prints one stub-backend exception line on stderr in a passing test.

## Questions for instructor

1. Held-out recall is 82.92% at PL1 and 91.54% at PL2, 7.6 and 5.6 points
   below the in-sample numbers. A2 says "targets set after baseline": do
   you want to set recall targets now, per paranoia level, from these
   numbers?
2. ldap is at 8 of 60 (PL1) and 14 of 60 (PL2) on all three WAFs; CRS
   4.25.2 has one LDAP rule. command-injection is at 69% and ssti at 74% at
   PL1. These are CRS limits, not engine differences. Accept as measured,
   or plan own rules for them (which would need another held-out set)?
3. Rule 26 on this dataset: do you want a manual reading of 100 seeded
   samples for "is this string an attack of its family at all"?
4. The connector image is built with `coraza.rule.no_regex_multiline`, the
   engine with coraza's default (multiline, as ModSecurity). Keep the
   default (my choice for now), or build the engine with the tag to match
   the connector? Either way I suggest measuring the tag on the benign sets
   before deciding.
5. The REQUEST_BODY targets (step-25 question 4): attacks-v1 cannot answer
   it, the targets change nothing on its two carriers. Evidence so far:
   the targets add 6 blocks on attacks-ct-v0 at PL1 (in-sample) and match
   15 requests the CRS project wrote as benign. A held-out set with raw
   body carriers would be needed to weigh recall. Do you want that as its
   own step?
6. The benign side of A2 (1,400 legitimate scenarios from one application)
   is still open; wcp covers the count only as third-party traffic.
