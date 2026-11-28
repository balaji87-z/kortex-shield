# Step-22 report

Host and versions (rule 43; the host changed from the step-21 Ubuntu machine):
macOS 27.0 (26A425), Darwin 27.0.0 arm64, Apple M6 12 cores; go1.27.4
darwin/arm64; Python 3.15.2, pytest 9.2.0. Docker was absent on this host
and was added during the step without admin rights (Homebrew belongs to
another account): Lima 2.3.0, Colima 0.10.3, Docker client 29.10.1, Compose
5.8.1 as release binaries under `~/.local/kortex-docker`; server 29.5.2,
linux/arm64, Ubuntu 24.04.4, kernel 6.8.0-117, 8 cpus, 8 GB. Images:
`python:3.12-alpine@sha256:c5ba3deef00c7758561a0f03c26f44f10589263d40e732b8748e0d1f38f6dd89`,
`ghcr.io/coreruleset/coraza-crs:4.25.2-nginx-lts@sha256:bfbfe70b4445c1ef1dc389c2de12cfdb194c9616746c33dc8a7131461c28f4a6`
(linux/arm64 variant of the pinned index). Engine: coraza v3.8.1 + CRS
4.25.2, built from 50e21a3 (darwin/arm64 sha256 3739a11b4e5e...c07adb9;
linux/arm64 sha256 185014ed0061...cdff75c). Rule 29 re-proven: every run
log carries the engine's `/__kortex/config` output.

The step-22 task brief is not in the repository. Task ids and scope below
are taken from the step-22 commit messages and script headers (UNVERIFIED
against the brief).

- Summary: worker mode matches in-process on both wcp sets at PL1/PL2 (60,000 samples, 0 status diffs, before and after
  E32, E33, T3p); numeric-Host artifact removed. Follow-up: coraza rule matching is not repeatable (PROVEN, NOT FIXED).
  Close-out: suites green (Go 48/0/5, fixture 53/0/0, pytest 201/0/4); engine 413/415 are fail-closed outcomes; flip_repro 0 of 2,500 at PL2.

- Task table:

| task | status | evidence |
|---|---|---|
| T1 hygiene (rules 51-52, inventory, pre-push gate, body files removed, cleanup list) | done; 2 decisions pending with the instructor | docs/logs/step22-t1-inventory.txt, step22-prepush-tree-scan-v2.txt, step22-history-cleanup-list.txt, step22-fragment-check.txt, tests/test_prepush_scan.py |
| T2 design risk (a) per-client cap per lane (T3h-T3m, test-first) | done | docs/acceptance.md, docs/logs/step22-t3i-t3m-failing.log, step22-t3i-t3m-suite-after-fix.log |
| T2 design risk (b) shared-peer penalty | done | docs/engine-design.md, docs/logs/runs/s22-t2-penalty-demo/demo.txt |
| T2 attack cells | done (re-run after the clamp, in a container) | docs/logs/step22-t2-cells-v2-all.txt, -rest.txt, docs/logs/runs/s22-t2-cells-v2/, docs/logs/step22-t2-benign-shape-DIAGNOSTIC.txt |
| T3 in-process vs worker parity, wcp v0 + v1, PL1 + PL2 | done | docs/logs/step22-t3-parity.txt, docs/logs/runs/s22-t3-parity/, docs/logs/step22-numeric-host.txt, step22-t3-DIAGNOSTIC.txt |
| T3 note: 10 None ids and 49 x 400 | done | docs/logs/step22-t3-none-and-400.txt, superseded for the 400s by T4 below |
| T4 big-body audited re-run | done | docs/logs/step22-t4-bigbodies-audit.txt, docs/logs/runs/s22-t4-bigbodies-audit/ |
| T4 FP decomposition from existing runs | done (connector PL2 added in the follow-up, F4) | docs/logs/step22-t4-fp-decomposition.txt |
| T5 padding extension (k = 8, 32, 120000 B) | done, engine and connector | docs/logs/step22-t5.txt, step22-t5-connector.txt |
| T5 Content-Encoding / Transfer-Encoding probes | done, engine and connector; cell G measured in the follow-up (F3) | same |
| T6 docs | done | docs/baseline-v1.7.md, docs/engine-design.md, docs/acceptance.md, README.md |
| F1 rule-match non-determinism | cause PROVEN; BUG in coraza NOT FIXED (decision pending) | docs/logs/step22-variance-engine-DIAGNOSTIC.txt, step22-variance-containers-DIAGNOSTIC.txt, docs/logs/runs/s22-variance-DIAGNOSTIC/ |
| F2 ModSecurity image vs connector image, benign-wcp-v0, PL1 + PL2 | done | docs/logs/step22-modsec-connector.txt, docs/logs/runs/s22-modsec-connector/ |
| F3 encoding cell G, engine and connector | done; two variants NOT MEASURED | docs/logs/step22-t5-cellg-engine-DIAGNOSTIC.txt, step22-t5-cellg-connector-DIAGNOSTIC.txt, docs/logs/runs/s22-t5-cellg/ |
| F4 connector PL2 FP decomposition | done | docs/logs/step22-t4-fp-decomposition.txt |
| F5 E20 timing; F6 T3g and E20 test fixes (T3n, T3o) | done | docs/logs/step22-e20-timing.txt, step22-t3n-failing.log, step22-t3n-passing.log |
| F7 engine audit log lacked phase-1 rules (E32) | done: BUG, fixed test-first | docs/logs/step22-e32-failing.log, step22-e32-passing.log, docs/baseline-config.md |
| F8 engine: Content-Encoding refusal (E33, E34), refusal before inspection (T3p) | done, test-first | docs/logs/step22-e33-*.log, step22-t3p-*.log, docs/engine-design.md, docs/acceptance.md |
| F9 parity and T5 re-run with the changed engine | done | docs/logs/step22-t3-parity-after-followup.txt, step22-t5-after-e33.txt, step22-t5-cellg-engine-after-e33-DIAGNOSTIC.txt |
| F10 T2 mixed cells one factor at a time; refusal cost after T3p | done; host factor not testable here | docs/logs/step22-t2-followup-summary.txt, docs/logs/runs/s22-t2-cells-v3/, s22-t2-DIAGNOSTIC-*/ |
| F11 cleanup (step-21 amendment, v0 README, breakdown file) | done; history rewrite is a dry run only | docs/logs/step22-history-rewrite-dryrun.txt |
| F12 suites after the follow-up | done: Go 48 PASS / 5 SKIP; with fixture 53 PASS / 0 FAIL; pytest 186 passed, 4 skipped | docs/logs/step22-followup-*.log |
| C1 suites re-run at e8ed852 (close-out) | done: Go 48 PASS / 0 FAIL / 5 SKIP; with fixture 53 / 0 / 0; pytest 186 passed, 0 failed, 4 skipped | docs/logs/step22-closeout-go-test*.log, step22-closeout-pytest.log |
| C2 kortex_eval: engine 413 / 415 answers are waf_fail_closed_413 / waf_fail_closed_415, not waf_pass | done, test-first; rule 5 deviation, asked for | docs/logs/step22-c2-failing.log, step22-c2-passing.log, step22-closeout-pytest-after-c2.log, step22-c2-outcomes.txt, step22-c2-vs-f9.txt, docs/logs/runs/s22-c2-outcomes/ |
| C3 flip_repro on coraza v3.8.1, 5 x 500 at PL2 | done: 0 flips per round in every repeat; DIAGNOSTIC v3.7.0 control flips | docs/logs/step22-flip-pl2.txt, step22-flip-pl2-DIAGNOSTIC-coraza370.txt, docs/logs/runs/s22-flip-pl2*/ |

- Raw evidence (key numbers in the body per rule 31; outputs trimmed where
  marked "..."):

**Host proof and Docker (rule 43).**

```
$ sw_vers; uname -srm; go version; python3 --version
ProductName: macOS  ProductVersion: 27.0  BuildVersion: 26A425
Darwin 27.0.0 arm64
go version go1.27.4 darwin/arm64
Python 3.15.2
$ docker version --format 'client {{.Client.Version}} server {{.Server.Version}} {{.Server.Os}}/{{.Server.Arch}}'
client 29.10.1 server 29.5.2 linux/arm64
$ docker info --format '{{.NCPU}} cpus {{.MemTotal}} mem {{.OperatingSystem}} kernel {{.KernelVersion}}'
8 cpus 8307408896 mem Ubuntu 24.04.4 LTS kernel 6.8.0-117-generic
$ shasum -a 256 ~/.local/kortex-docker/dl/*
980ad8bf61a4ca370243f4cb41401a61276dcd2c2502bee7b9b86f9250169f34  colima-Darwin-arm64
c4fc3a3afe720b76a23d499a8f43d5b9774a09f7b85f1af75d9005b32a7b2cf4  docker-29.10.1.tgz
775ddf9cfad37b21a29dd83707481d3806c2a83ed2139bc5f19543857d341d81  docker-compose-darwin-aarch64
b7af444bd8f91d3c307477e562f2cf3bd7595d62b9429185e4fa841563578cfc  lima-2.3.0-Darwin-arm64.tar.gz
```

**Datasets (rule 10).** `tools/fetch/fetch_wcp_legitimate.sh` equivalent
(curl + shasum; the script's `sha256sum` does not exist on macOS):
`58faee18c54229759287a574f6f8cb1e3b951fa135e403ea9a679d2b18efd778  data/external/legitimate.zip`
(matches). Rebuilt manifests, from docs/logs/step22-t3-parity.txt:

```
== benign-wcp-v0 manifest sha256 c8ce11f26406df96d55e5a1cc6186bcbf648cb29bd628081dd834c6ccf1329d1 (frozen: c8ce11f2...1329d1)
== benign-wcp-v1 manifest sha256 049b7dea33aac475c4ef7f05c8644da610ad311a84862ef3b88d33a37dc8b5c0 (frozen: 049b7dea...c8b5c0)
```

v1 was rebuilt with the current builder. v0 was NOT reproducible with the
current builder (it gives 39830d0a819467f301f2ae0e261626f5f9982a53b4fb61aa232dab588a05fdb7);
it was rebuilt byte-exact with the builder of commit 71cb753 (see Deviations).
No dataset file was changed; only the gitignored manifest.jsonl files were
placed locally.

**T3 parity.** `bash tools/run_step22_t3_parity.sh` then
`.venv/bin/python tools/step22_t3_summary.py docs/logs/runs/s22-t3-parity`
(output in docs/logs/step22-t3-parity.txt). One of the four diffs in full,
the other three have the same shape:

```
== diff benign-wcp-v0 PL2 (a=inprocess b=worker):
samples compared: 20000 (a=20000 b=20000 only-a=0 only-b=0)
status counts a: {200: 11033, 400: 58, 403: 8876, 413: 32, None: 1}
status counts b: {200: 11033, 400: 58, 403: 8876, 413: 32, None: 1}
status diffs: 0
no status in a (counted as error): 1
  wcp-6b0bf5e43122
no status in b (counted as error): 1
  wcp-6b0bf5e43122
worst-case set a: 8935/20000 (error=1 blocked=8875 deny_status=58 inconsistent=1)
worst-case set b: 8935/20000 (error=1 blocked=8875 deny_status=58 inconsistent=1)
worst-case set diffs: 0 (only-a 0 only-b 0)
```

| dataset | PL | n | status diffs | worst-case set (both modes) | worst-case set diffs | rule-id set diffs |
|---|---|---|---|---|---|---|
| benign-wcp-v0 | 1 | 20,000 | 0 | 2,252 (error 1, blocked 2,193, deny_status 58, inconsistent 0) | 0 | 0 |
| benign-wcp-v0 | 2 | 20,000 | 0 | 8,935 (error 1, blocked 8,875, deny_status 58, inconsistent 1) | 0 | 2 |
| benign-wcp-v1 | 1 | 10,000 | 0 | 1,116 (error 0, blocked 1,091, deny_status 25, inconsistent 0) | 0 | 0 |
| benign-wcp-v1 | 2 | 10,000 | 0 | 4,463 (error 0, blocked 4,438, deny_status 25, inconsistent 0) | 0 | 1 |

Parity quantities (rule 32): status per id, the worst-case set, and the
logged rule-id set per id. Worker mode proven active per run (rule 16/29),
e.g. `"worker_mode":true` and after the run
`"workers":{"pool":4,"busy":0,"spares":4,"recycled":0}`, kills 0, overloads 0;
the in-process runs show `"worker_mode":false`.

Rates (natural external benign traffic only; no hard-benign set was run, so
nothing is merged, rule 14). Rule 20/21: denominator = all samples; best
case = errors, deny_status, inconsistent not flagged; worst case = flagged:

```
benign-wcp-v0 PL1: best 2193/20000 = 10.96%; worst 2252/20000 = 11.26%
benign-wcp-v0 PL2: best 8875/20000 = 44.38%; worst 8935/20000 = 44.67%
benign-wcp-v1 PL1: best 1091/10000 = 10.91%; worst 1116/10000 = 11.16%
benign-wcp-v1 PL2: best 4438/10000 = 44.38%; worst 4463/10000 = 44.63%
```

Scenario counts (rule 15): 20,000 and 10,000 distinct requests; distinct
endpoints NOT COMPUTED in this step (the datasets are unchanged; their
READMEs give 3,038 and 2,217 distinct hosts). Rule 18/24: PL1 v0 932370 in
466 of 2,251 audit entries; PL2 931130, 942430, 942200, 942370, 942340,
942330, 932200 on both datasets (detection rules on benign content, not a
harness artifact; listed with counts in the log). In-sample label (rules
19, 45): benign-wcp-v0 informed earlier engine choices; v1 did not.

Rule-id set differences, the 3 ids (status identical, 403 on both sides):

```
benign-wcp-v0 PL2 rule-id sets, in-process vs worker: 2 ids differ of 20000
    wcp-7b0477d1157b: only in-process [] only worker ['942130']
    wcp-f754e70f73bd: only in-process ['942130'] only worker []
benign-wcp-v1 PL2 rule-id sets, in-process vs worker: 1 ids differ of 10000
    wcp-bc05c8d4eb28: only in-process [] only worker ['942130']
```

DIAGNOSTIC B (`bash tools/run_step22_t3_diag.sh`, docs/logs/step22-t3-DIAGNOSTIC.txt),
two ids that differed in the first run, 200 replays per mode:

```
   B [inprocess] wcp-35f82c1417df: 200 audit entries, 6 distinct rule-id sets
        x139: rules outside the common core: ['941340', '942120', '942210']
        x20: rules outside the common core: ['941340', '942210']
        ...
   B [inprocess] wcp-7b0bdeda7bc7: 200 audit entries, 2 distinct rule-id sets
        x101: rules outside the common core: ['942130']
        x99: rules outside the common core: none
   B [worker] wcp-35f82c1417df: 200 audit entries, 6 distinct rule-id sets
        x150: rules outside the common core: ['941340', '942120', '942210']
        ...
   B [worker] wcp-7b0bdeda7bc7: 200 audit entries, 2 distinct rule-id sets
        x104: rules outside the common core: none
        x96: rules outside the common core: ['942130']
```

Classification (rule 39): UNEXPLAINED, count 3 ids in the parity runs. It is
PROVEN not to be a mode difference (rule 44: if it were, replays inside one
mode would give one set; they give 6 and 2). Which rules get logged for a
blocked request varies run to run; the status does not.

**Numeric-Host artifact (PROVEN).** `.venv/bin/python tools/step22_numeric_host_diff.py`
(docs/logs/step22-numeric-host.txt; id lists trimmed here, full in the log):

```
== benign-wcp-v1 PL2 in-process, n=10000
   numeric-Host run  base_url=http://127.0.0.1:8097  blocked=4590
   clean run         base_url=http://localhost:8097  blocked=4438
   earlier step run  base_url=http://localhost:8090  blocked=4436 (s19-t4-benign-wcp-v1-post-r1-pl2)
   blocked only with the numeric Host: 152; only in the clean run: 0
      x136: logged rules [942430]
      x16: logged rules [920230]
   clean run vs the earlier step run: 2 blocked only now, 0 blocked only then; ids: wcp-464f59067651 wcp-5d3fca6ceb20
      wcp-464f59067651: then status=503 outcome=waf_pass; now status=403 outcome=waf_block
      wcp-5d3fca6ceb20: then status=503 outcome=waf_pass; now status=403 outcome=waf_block
== benign-wcp-v0 PL2 in-process, n=20000
   numeric-Host run  base_url=http://127.0.0.1:8097  blocked=9160
   clean run         base_url=http://localhost:8097  blocked=8875
   earlier step run  base_url=http://localhost:8090  blocked=8871 (s18-t4-engine-benign-wcp-v0-v2-pl2)
   blocked only with the numeric Host: 285; only in the clean run: 0
      x249: logged rules [942430]
      x36: logged rules [920230]
   clean run vs the earlier step run: 4 blocked only now, 0 blocked only then; ids: wcp-2e39e9b3376a wcp-377307dc2a53 wcp-62cd1bd36bf7 wcp-f8ba3db5e5c3
```

PROVEN (rule 44): the only input changed between the first two rows is the
base URL (each run.json), the engine binary is the same, and the outcome
changes on 152 / 285 ids, all one way. The mechanism (920350, +3) is shown
by the T2 DIAGNOSTIC below, where the numeric-Host request logs 920350 in
the engine's matched-rule list. The competing explanation was tested and
rejected, DIAGNOSTIC A in docs/logs/step22-t3-DIAGNOSTIC.txt:

```
== A: scratch engine sha256 0f0b4e96...; diff of go.mod against engine/go.mod:
< require github.com/corazawaf/coraza/v3 v3.8.1
> require github.com/corazawaf/coraza/v3 v3.7.0
   diff -r of the .go files against engine/: 0 files differ
   blocked: scratch v3.7.0 on this host 4438; step-22 v3.8.1 on this host 4438; step-19 v3.7.0 on the step-19 host 4436 (n=10000 each)
   scratch v3.7.0 vs step-19 v3.7.0: blocked only in the first 2, only in the second 0
   scratch v3.7.0 vs step-22 v3.8.1: blocked only in the first 0, only in the second 0
```

The 6 ids blocked now and not in steps 18/19 (5 were 503 timeouts then, 1 is
the step-19 flip sample wcp-62cd1bd36bf7): cause HYPOTHESIS (faster host
for the five; flip fix for the one), not tested.

**T4 big-body audited re-run.** `bash tools/run_step22_t4_bigbodies_audit.sh`
(docs/logs/step22-t4-bigbodies-audit.txt), n = 402, in-process, budget 120 s:

```
== PL1: n=402 (rows in responses 402, in outcomes 402)
   load average start [1.19, 1.81, 2.06] end [1.9, 1.86, 2.06] (rule 38)
   status: {200: 97, 400: 49, 403: 207, 413: 49}
   outcome: {'waf_block': 207, 'waf_deny_status': 49, 'waf_pass': 146}
   blocked 207/402; worst case (blocked + deny_status + inconsistent + error) 256/402; best case (blocked only) 207/402
   elapsed ms: min=0.5 p50=111.5 p95=491.5 p99=597.5 max=695.4
   over 2000 ms (would be 503 at the default 2 s budget): 0/402
   band <64K: n=318 status={200: 94, 400: 41, 403: 183} p50=123.1 max=515.0
       waf_block 183/318; rule hits top 10: 921150=86, 942100=80, 920270=74, 932130=67, 941100=50, 942540=49, 941310=38, 932370=37, 932235=34, 942550=31
       status 400 by rule ids: 200007=39, 200002=2
   band 64K-<128K: n=42 status={200: 3, 400: 8, 403: 24, 413: 7} p50=459.8 max=695.4
       status 400 by rule ids: 200007=8
   band >=128K: n=42 status={413: 42} p50=1.3 max=5.4
   status vs the step-21 run (worker mode, other host), per id: 0 differ of 402
== PL2: n=402 (rows in responses 402, in outcomes 402)
   load average start [1.9, 1.86, 2.06] end [1.93, 1.88, 2.04] (rule 38)
   status: {200: 18, 400: 49, 403: 286, 413: 49}
   outcome: {'waf_block': 286, 'waf_deny_status': 49, 'waf_pass': 67}
   blocked 286/402; worst case (blocked + deny_status + inconsistent + error) 335/402; best case (blocked only) 286/402
   elapsed ms: min=0.7 p50=217.1 p95=911.5 p99=1109.5 max=1240.3
   over 2000 ms (would be 503 at the default 2 s budget): 0/402
   band <64K: n=318 status={200: 17, 400: 41, 403: 260} p50=235.8 max=946.9
       waf_block 260/318; rule hits top 10: 942430=238, 942200=214, 942370=196, 942330=169, 932200=166, 941340=155, 931130=151, 942520=146, 942340=128, 942440=125
   band 64K-<128K: n=42 status={200: 1, 400: 8, 403: 26, 413: 7} p50=794.3 max=1240.3
   band >=128K: n=42 status={413: 42} p50=1.6 max=5.7
   status vs the step-21 run (worker mode, other host), per id: 1 differ of 402
     wcp-43ad8735b4fe: step-21=403 step-22=200 size=19545
```

Counts only: the set was chosen by body size (rule 35). The 49 x 400 are
rule 200007 on 47 and 200002 on 2; this replaces the "valid JSON, other
cause: 42" class of docs/logs/step22-t3-none-and-400.txt. Seven of the 413s
sit in the 64K-128K band because the index counts characters; as UTF-8
they are 143,067 to 166,130 bytes. The FP decomposition from earlier runs
(docs/logs/step22-t4-fp-decomposition.txt) is unchanged; its
"connector v0 PL2" and "connector v1 PL2" lines stay NOT MEASURED.

**T5 padding.** `bash tools/run_step22_t5.sh` (engine, docs/logs/step22-t5.txt)
and `bash tools/run_step22_t5_connector.sh` (docs/logs/step22-t5-connector.txt):

```
engine    padding-pl1: TOTAL 108 blocked403=108 passed200=0 failclosed(400/413/503)=0 other=0
engine    padding-pl2: TOTAL 108 blocked403=107 passed200=0 failclosed(400/413/503)=1 other=0
connector padding-pl1: TOTAL 108 blocked403=108 passed200=0 failclosed(400/413/503)=0 other=0
connector padding-pl2: TOTAL 108 blocked403=108 passed200=0 failclosed(400/413/503)=0 other=0
```

108 = 3 k values (8, 32, 120,000 B) x 2 payloads x 2 positions x 3 content
types x 3 reps. Engine: all 403s log a 941 or 942 rule (`payload-detected`
in every cell of the log). The fail-closed cell:
`{"status": 503, "elapsed_ms": 2005, "resp_head": "503 kortex-decision=timeout", "id": "t5a-pl2-k120000-xss-after-plain-r2"}`.
Timing of the 120,000-byte text/plain cells, PL2: min 1,362, median 1,564,
max 2,005 ms (PL1: 661 / 799 / 891), host load 6.4 at the start of that run
(other users' jobs). Two earlier runs of the matrix on this host at load
about 2 gave 108/108 at both levels; their logs were replaced by this run.
Connector effective config from inside the container (rules 28/29), per run:

```
   image: ghcr.io/coreruleset/coraza-crs:4.25.2-nginx-lts@sha256:bfbfe70b...f4a6 id sha256:bfbfe70b...f4a6 platform linux/arm64
   env: E=On B=2 P=2 D=2 CT=[] body=[nofiles=131072 total=13107200]
   crs-setup: tx.blocking_paranoia_level=2 tx.detection_paranoia_level=2 tx.crs_setup_version=4252
   ruleset: ver:'OWASP_CRS/4.25.2 in /opt/coraza/owasp-crs/rules (27 .conf files)
```

**T5 encoding probes, PL1.** Status counts on both sides:
`STATUS COUNTS: Counter({403: 30, 400: 6})`, 0 passed.

| cell | engine status and rules | connector status and rules |
|---|---|---|
| A gzip + header, B deflate + header (12) | 8 x 403 [920270] (XSS text/plain also 921150); 4 x 400 json | 8 x 403 [920270, 920450] (+920420 on text/plain); 4 x 400 [920450] |
| C gzip, no header (6) | 4 x 403 [920270]; 2 x 400 json | 4 x 403 [920270] (+920420 on text/plain); 2 x 400 |
| D raw control (6) | 6 x 403 on 942100 or 941100/941110/941160/941390 | 5 on the same rules; SQLi text/plain on 920420 only |
| E chunked, split at 2 offsets (12) | 12 x 403 on the same 941/942 rules | 10 on the same rules; 2 SQLi text/plain on 920420 only |

DIAGNOSTIC cells (rule 34), engine:

```
   cell ('F', 'plain', 'benign'): {403: 2}        benign gzip / deflate + header, rules [920270]
   cell ('G', 'plain', 'sqli'): {None: 1}         NOT MEASURED: no NUL/CR/LF-free stream found
   cell ('G', 'plain', 'xss'): {None: 1}          NOT MEASURED
   cell ('H', 'plain', 'sqli'): {403: 1}          raw canary control, [942100]
   cell ('H', 'plain', 'xss'): {403: 1}           raw canary control, [941100,941110,941160,941390]
   cell ('I', 'plain', 'benign'): {403: 1}        benign, NOT compressed, Content-Encoding: gzip header
   cell ('J', 'plain', 'benign'): {200: 1}        same body, no header
   block pages that list rule 920450 among the matched rules: 3 ['t5d-benign-F-gzip', 't5d-benign-F-deflate', 't5d-benign-I-header-only']
```

Connector: F 2 x 403 [920270, 920420, 920450]; I 403 [920420, 920450]; J 403
[920420] (its text/plain policy, DESIGN C4); G NOT MEASURED.

- PROVEN (I vs J on the engine): a Content-Encoding header alone gets the
  request refused at PL1; the block page names 920450.
- HYPOTHESIS, not PROVEN: "no compressed attack body can pass". Cell G,
  the direct test, is NOT MEASURED.
- Neither side decodes Content-Encoding: no 941/942 match in any A-C cell
  on either side, while the same canaries match in D.
- UNEXPLAINED (rule 39), decisions identical: the connector audit log has a
  920450 message on 15 of 15 cells with a Content-Encoding header, the
  engine audit log on 0 of 15.

**T2 attack cells.** `bash tools/run_step22_t2_container.sh all` (stopped by
a script error after four cells, see Deviations) then `... rest`;
`.venv/bin/python tools/step22_t2_cells_summary.py docs/logs/runs/s22-t2-cells docs/logs/runs/s22-t2-cells-v2`
(docs/logs/step22-t2-cells-summary.txt). Raw cell lines:

```
== in container: Linux 6.8.0-117-generic aarch64; Python 3.12.16; cpus 8; load 0.00 0.00 0.00 1/210 13
cell large-one: preflight=[200, 200] post 301/301 {200: 301} get 301/301 {200: 301} kills=24 overloads=276 minpool=3 cpu=2.7s recovery=8.2s
cell large-eight: preflight=[200, 200] post 301/301 {200: 301} get 301/301 {200: 301} kills=172 overloads=2228 minpool=2 cpu=4.9s recovery=8.2s
cell small-one: preflight=[200, 200] post 300/300 {200: 300} get 300/300 {200: 300} kills=24 overloads=276 minpool=3 cpu=3.2s recovery=4.1s
cell small-eight: preflight=[200, 200] post 291/300 {503: 9, 200: 291} get 300/300 {200: 300} kills=192 overloads=2217 minpool=0 cpu=5.4s recovery=5.1s
cell mixed-one: preflight=[200, 200] post 301/301 {200: 301} get 301/301 {200: 301} kills=75 overloads=2298728 minpool=1 cpu=576.2s recovery=1.0s
cell mixed-eight: preflight=[200, 200] post 294/301 {503: 7, 200: 294} get 301/301 {200: 301} kills=200 overloads=1761481 minpool=0 cpu=561.6s recovery=2.5s
killstorm: kills=80 (0.67/s) minpool=0 minidle=0 cpu=214.8s
```

Effective caps in every cell json (rule 29): `client_max_inflight=2`,
`client_max_inflight_small=2`, `client_max_inflight_large=1`,
`worker_mode=true`. Benign POST latency: p99 8.4 / 50.7 / 11.4 ms in the
first three cells; 2,002.6 ms in small-eight and 2,002.1 ms in mixed-eight
(the refused requests waited out the 2 s budget). First recording for
comparison (same summary tool): large-one 301/301, large-eight 301/301,
small-one 0/301, small-eight 0/300, mixed-one 105/301, mixed-eight 275/300.

T2 DIAGNOSTIC (`bash tools/run_step22_t2_benign_shape_diag.sh`,
docs/logs/step22-t2-benign-shape-DIAGNOSTIC.txt), idle engine, no attack:

```
PL1   old probe  POST status: 200  GET status: 200      (x3)
PL1   new probe  POST status: 200  GET status: 200      (x3)
PL2   old probe  POST status: 403  GET status: 403      (x3)
PL2   new probe  POST status: 200  GET status: 200      (x3)
   event decision=block status=403 92x check rules matched=['920350', '920320']
   small-one: pl=2 benign_post_ok=0/301 benign_get_ok=0/301 recovery_s=None benign POST ms p50=6.7 first recovery sample with pool>=4, penalised=0, inflight=0: t=12.2 s of 352 samples
   small-eight: pl=2 benign_post_ok=0/300 benign_get_ok=0/300 recovery_s=None benign POST ms p50=5.9 first recovery sample with pool>=4, penalised=0, inflight=0: t=7.6 s of 355 samples
```

PROVEN (rule 44): the old probe is refused at PL2 with no attack running and
accepted at PL1; had the 0/301 been starvation, the idle engine would have
answered 200. The sentence in docs/engine-design.md that read "the pool
never re-stocked within the recovery watch" is corrected.

Penalty demo (`tools/run_step22_t2_penalty_demo.py` in the same container
image, docs/logs/runs/s22-t2-penalty-demo/demo.txt):

```
0) innocent POST from 127.0.0.2 before any kill -> 200
1) held 131071-byte request from 127.0.0.2 (budget 300 ms) -> 503
   stats: {... "kills": 1, "overloads": 0, "penalised_clients": 1, ...}
2) innocent POST from the SAME address 127.0.0.2 -> 503
3) innocent POST from a DIFFERENT address 127.0.0.5 -> 200
4) innocent POST from 127.0.0.2 after 3000 ms + 1 s -> 200
   stats: {... "kills": 1, "overloads": 1, "penalised_clients": 0, ...}
```

**T2 design risk (a), T1, earlier in the step (commits d74aecb..50e21a3).**
T3h-T3m were committed failing first (24e5acd, 20f3e8a; log
docs/logs/step22-t3i-t3m-failing.log) and pass after the fixes (862abbf,
5dfdd19). T1: rules 51-52 (d74aecb), pre-push scan with 43 tests
(tests/test_prepush_scan.py), tree scan of a2b2477 with 21 body-dump and 37
credential-shape findings in 50 files (docs/logs/step22-prepush-tree-scan.txt),
six wcp body files removed and replaced by body-less indexes (e3aeb91),
cleanup list of 27 paths, fragment check with 15 files still quoting body
fragments, all on the list (c97882b). Counts only; no value was printed.

**Suites on this host.**

Go, without the fixture (docs/logs/step22-final-go-test.log; 47 top-level
tests + 9 subtests: 42 PASS, 5 SKIP, 0 FAIL; the 5 skips are the fixture
tests E16, E17, E19, E20, E21). Trimmed: `=== RUN`, `--- PASS`, event rows.

```
# step-22 final suite, 2026-11-27T18:24:59Z, go version go1.27.4 darwin/arm64, load at start: load averages: 3.96 7.40 8.02
$ cd engine && go test -buildvcs=false -count=1 -v ./...
--- SKIP: TestE16BodyProcessingBoundedByTimeBudget (0.00s)
--- SKIP: TestE17AbandonedCallOwnsTransaction (0.00s)
--- SKIP: TestE19OverloadCapImmediate (0.01s)
--- SKIP: TestE20OverloadRecovery (0.01s)
--- SKIP: TestE21BenignPromptOnCapReachedEngine (0.01s)
PASS
ok  	kortexshield/engine	48.056s
# exit status of go test: 0
# load at end: load averages: 3.70 6.78 7.76
```

Go, WITH the recorded wcp fixture (docs/logs/step22-final-go-test-with-fixture.log;
the fixture is the body of wcp-80a49c991b2d, 481,798 bytes, sha256
5c718716...de2f2480, taken from the rebuilt frozen manifest, not committed):
**45 PASS, 0 SKIP, 2 FAIL of 47 top-level tests; exit status 1.** Trimmed as above.

```
# 2026-11-27T18:28:42Z, go version go1.27.4 darwin/arm64, load at start: load averages: 3.99 5.32 6.95
$ cd engine && KORTEX_TEST_WCP_BODY=$PWD/../out/step14-t5/wcp-80a49c991b2d.body go test -buildvcs=false -count=1 -timeout 900s -v ./...
--- PASS: TestE16BodyProcessingBoundedByTimeBudget (2.01s)
--- PASS: TestE17AbandonedCallOwnsTransaction (2.76s)
--- PASS: TestE19OverloadCapImmediate (0.23s)
=== RUN   TestE20OverloadRecovery
    step17_test.go:204: E20: abandoned call did not finish within 120s
--- FAIL: TestE20OverloadRecovery (120.28s)
--- PASS: TestE21BenignPromptOnCapReachedEngine (0.22s)
=== RUN   TestT3gBoundedCPUAfterKill
    worker_test.go:303: T3g: killed worker pid 60097; parent CPU 12m6.627332s -> 12m12.603383s (+5.976051s) over 1.2s after the kill
    worker_test.go:305: T3g: parent CPU grew by 5.976051s in 1.2s after the kill (limit 150ms)
--- FAIL: TestT3gBoundedCPUAfterKill (1.63s)
FAIL
FAIL	kortexshield/engine	187.671s
FAIL
# exit status of go test: 1
# load at end: load averages: 10.05 8.13 7.83
```

The two failures (DIAGNOSTIC, docs/logs/step22-t3g-fixture-DIAGNOSTIC.log;
same fixture env, no baseline number comes from it):

```
## A: T3g alone, fixture env set
$ ... go test -buildvcs=false -count=1 -timeout 300s -v -run '^TestT3gBoundedCPUAfterKill$' ./...
    worker_test.go:303: T3g: killed worker pid 63276; parent CPU 118.337ms -> 118.462ms (+125µs) over 1.2s after the kill
--- PASS: TestT3gBoundedCPUAfterKill (1.66s)
ok  	kortexshield/engine	2.000s
## B: E19 (leaves one abandoned in-process call on the wcp body running in the test process) then T3g, fixture env set
$ ... go test -buildvcs=false -count=1 -timeout 300s -v -run '^(TestE19OverloadCapImmediate|TestT3gBoundedCPUAfterKill)$' ./...
--- PASS: TestE19OverloadCapImmediate (0.27s)
    worker_test.go:303: T3g: killed worker pid 63299; parent CPU 735.017ms -> 1.952854s (+1.217837s) over 1.2s after the kill
    worker_test.go:305: T3g: parent CPU grew by 1.217837s in 1.2s after the kill (limit 150ms)
--- FAIL: TestT3gBoundedCPUAfterKill (1.61s)
## C: E20 alone, fixture env set
# 2026-11-27T18:33:14Z, load at start: load averages: 3.68 6.62 7.28
    step17_test.go:204: E20: abandoned call did not finish within 120s
--- FAIL: TestE20OverloadRecovery (120.69s)
FAIL	kortexshield/engine	120.918s
# load at end: load averages: 1.98 4.99 6.54
```

- T3g: PROVEN (experiments A and B) that the failure comes from the test's
  measurement, not from the worker kill. T3g reads the CPU time of the whole
  test process; a fixture test that ran earlier in the same process leaves an
  abandoned in-process call on the wcp body that keeps one core busy. Alone,
  T3g passes with +125 µs; after E19 it fails with +1.218 s in 1.2 s (one
  core). Had the kill itself left work in the parent, A would have failed
  too. In the suite run the growth was 5.976 s in 1.2 s; that this is the
  five fixture tests (E16, E17, E19, E20, E21) at one core each is a
  HYPOTHESIS (consistent count, not separated per test). T3g is therefore
  valid only when no fixture test ran before it in the same process. This
  T3g was rewritten in this step (fae6a70) to read the test process's own
  CPU (no /proc on macOS); the step-21 version passed with the fixture on
  the Linux host (docs/acceptance.md). Not changed (rule 5); see Questions.
- E20: fails on this host with the fixture, alone as well as in the suite,
  at load 3.7 falling to 2.0 (C). The abandoned in-process call on this body
  does not finish within the test's 120 s. How long it does take on this
  host is NOT MEASURED; why it is slower than on the step-17 host (suite
  `ok` in 54.3 s there) is UNEXPLAINED. The same failure was recorded on the
  step-21 host (docs/logs/step21-e20-preworker.log, 288.33 s). The
  sentence "The E20 test is kept and still passes" in docs/acceptance.md
  does not hold on this host. In worker mode the call is killed at the
  budget instead (T3b, T3c, T3f pass in the same run; T2 kill storm: 80
  kills), so this concerns the default in-process mode only.

Python (docs/logs/step22-final-pytest.log; run after tests/test_step22_tools.py
was added). Trimmed: progress dots and one stderr traceback printed by a
test's local HTTP server ("Exception occurred during processing of request",
1 occurrence; no test failed).

```
# 2026-11-27T18:35:15Z, Python 3.15.2, load at start: load averages: 1.98 4.99 6.54
$ .venv/bin/python -m pytest -q
181 passed, 4 skipped in 55.49s
# exit status of pytest: 0
# load at end: load averages: 1.95 4.51 6.27
```

**Pre-push scan over the staged content (rule 51).**

```
$ git add -A docs tools tests reports README.md
$ bash tools/prepush_scan.sh; echo "exit=$?"
prepush: large file: docs/logs/runs/s22-numeric-host/benign-wcp-v0-inprocess-pl2-numeric-host/outcomes.jsonl (3730153 bytes)
prepush: large file: docs/logs/runs/s22-numeric-host/benign-wcp-v1-inprocess-pl2-numeric-host/outcomes.jsonl (1860535 bytes)
prepush: large file: docs/logs/runs/s22-t3-DIAGNOSTIC/DIAGNOSTIC-coraza370-benign-wcp-v1-pl2/outcomes.jsonl (1859633 bytes)
[trimmed: 19 more "large file" notes, all under docs/logs/runs/; full output in out/prepush-staged.txt (gitignored)]
prepush: OK, 148 staged path(s) scanned
exit=0
```

Run again after this block was added to the report: same result line.
The largest staged file is 3,730,153 bytes, under the 5 MB limit of rule 42.

## Follow-up work (2026-11-27, after the first push of this report at 6e2b666)

Asked for after the report was first pushed: close the measurement gaps
listed above, fix the two failing tests, do the cleanup items, and make the
two engine changes raised under Questions. Engine code changed in this part
(commits d7e5760, c586b76, 37074bf), so the engine numbers of sections T3
and T5 above describe the engine at 50e21a3; the re-runs with the changed
engine are in F9. Host, tool versions and images are those at the top of
this report, plus `owasp/modsecurity-crs:4.25.2-nginx-lts@sha256:6296ce685cb88ba4012998b935b25dabbd9e0ff326088c1149447102544de661`
(linux/arm64, libmodsecurity3 3.0.17, pulled 2026-11-27).

**F1. Rule-match non-determinism: two mechanisms PROVEN (the "rule-id set
varies between replays" item, UNEXPLAINED in the T3 section above).**
`bash tools/run_step22_variance_diag.sh engine` (docs/logs/step22-variance-engine-DIAGNOSTIC.txt,
DIAGNOSTIC C, rule 34; counts in docs/logs/runs/s22-variance-DIAGNOSTIC/). 200
replays of each request, PL2, in-process, four builds: `stock` (engine/ at
6e2b666, coraza v3.8.1), `nocache` (coraza patched so `transformArg` never
uses the transformation cache), `sorted` (coraza patched so map-backed
collections iterate in sorted key order), `upstream` (coraza main at
4cc95a33a6a2, which contains PR #1682). Synthetic requests are my own;
the two wcp ids are the ones from DIAGNOSTIC B.

```
   [stock] syn-chain: statuses {'200': 69, '403': 131}
   [stock] syn-chain-rev: statuses {'200': 131, '403': 69}
   [stock] syn-chain-single: statuses {'403': 200}
   [stock] syn-dup: 200 audit entries, 2 distinct rule-id set(s), 8 distinct inbound score(s) {33: 5, 38: 22, 43: 42, 48: 62, 53: 47, 58: 18, 63: 3, 68: 1}
        x163: rules outside the common core: ['941390']
        x37: rules outside the common core: none
   [stock] syn-dup-single: 200 audit entries, 1 distinct rule-id set(s), 1 distinct inbound score(s) {48: 200}
   [stock] wcp-35f82c1417df: 200 audit entries, 8 distinct rule-id set(s), 9 distinct inbound score(s) {104: 5, 109: 22, 114: 35, 119: 65, 124: 43, 129: 15, 134: 12, 139: 2, 144: 1}
   [stock] wcp-7b0bdeda7bc7: 200 audit entries, 2 distinct rule-id set(s), 2 distinct inbound score(s) {42: 110, 47: 90}
   [nocache] syn-chain: statuses {'200': 78, '403': 122}
   [nocache] syn-dup: 200 audit entries, 1 distinct rule-id set(s), 1 distinct inbound score(s) {48: 200}
   [nocache] wcp-35f82c1417df: 200 audit entries, 1 distinct rule-id set(s), 1 distinct inbound score(s) {119: 200}
   [nocache] wcp-7b0bdeda7bc7: 200 audit entries, 2 distinct rule-id set(s), 2 distinct inbound score(s) {42: 109, 47: 91}
   [sorted] syn-chain: statuses {'403': 200}
   [sorted] syn-chain-rev: statuses {'403': 200}
   [sorted] syn-dup: 200 audit entries, 1 distinct rule-id set(s), 1 distinct inbound score(s) {48: 200}
   [sorted] wcp-35f82c1417df: 200 audit entries, 1 distinct rule-id set(s), 1 distinct inbound score(s) {119: 200}
   [sorted] wcp-7b0bdeda7bc7: 200 audit entries, 1 distinct rule-id set(s), 1 distinct inbound score(s) {42: 200}
   [upstream] syn-chain: statuses {'200': 64, '403': 136}
   [upstream] syn-dup: 200 audit entries, 1 distinct rule-id set(s), 1 distinct inbound score(s) {48: 200}
   [upstream] wcp-35f82c1417df: 200 audit entries, 1 distinct rule-id set(s), 1 distinct inbound score(s) {119: 200}
   [upstream] wcp-7b0bdeda7bc7: 200 audit entries, 2 distinct rule-id set(s), 2 distinct inbound score(s) {42: 100, 47: 100}
```

(Trimmed to the lines used below; every request has status 403 in every
replay except syn-chain and syn-chain-rev.)

- Common cause: coraza iterates its map-backed collections (ARGS, headers,
  cookies) in Go's random map order, on every call
  (internal/collections/map.go, `FindAll`).
- H1, capture order, PROVEN (rule 44): CRS 942130 captures both sides of
  `x=y` from each matching variable and a chained rule compares TX:1 with
  TX.2. The chain sees the captures of the variable evaluated last.
  `syn-chain` is `{"filter":"color=blue","note":"1=1"}`: both values match
  the regex, only `1=1` is a tautology. It is blocked in 131 of 200 replays
  and **passed in 69** on the stock engine (with the two members swapped:
  blocked 69, passed 131), blocked 200 of 200 without the decoy member,
  and blocked 200 of 200 once iteration is ordered. Turning the cache off
  does not remove it (122 / 78), so it is not H2. Had the order not been
  the cause, `sorted` would still vary.
- H2, transformation cache, PROVEN (rule 44): the cache key is (pointer to
  the key string, position in the value list, variable, transformation id)
  (internal/corazawaf/rule.go, `transformArg`). Values under one key share
  the pointer and the position moves with the iteration order, so a rule
  can be handed the cached transformation of the other value. `syn-dup`
  (key `tag` twice) gets 8 inbound scores from 33 to 68 and loses 941390 in
  37 of 200 replays; the same body without the duplicate gets 48 every
  time; with the cache off it gets 48 every time. Had the cache not been
  the cause, `nocache` would still vary.
- The two wcp ids: wcp-35f82c1417df (text/plain body with repeated keys)
  follows H2 (constant on `nocache`), wcp-7b0bdeda7bc7 (JSON, 942130)
  follows H1 (varies on `nocache`, constant on `sorted`). This replaces
  "UNEXPLAINED, count 3 ids" in the T3 section: the 3 parity ids differ by
  942130 only, which is H1.
- Upstream: H2 is coraza issue #1681, fixed on main by PR #1682 ("key the
  transformation cache by value identity", merged 2026-10-19, not in a
  release: v3.8.1 is the newest tag). On the `upstream` build syn-dup and
  wcp-35f82c1417df are constant, so H2 is fixed there (rule 49: fixed
  empirically, changed code identified as PR #1682; the build also moves
  libinjection-go 0.3.3 -> 0.3.7 and Go 1.25 -> 1.26, see the go.mod diff
  in the log). The issue text says matching is unaffected; with repeated
  keys it is affected (scores above). H1 is NOT fixed upstream (syn-chain
  136/64).
- H2 is the mechanism step 19 proved for the v3.7.0 status flip (commit
  b9136a0). New here: it is still present in v3.8.1, and H1 is a second,
  separate mechanism.
- What this means for earlier results: step 20 recorded the duplicate-arg
  flip of wcp-62cd1bd36bf7 as fixed by the v3.8.1 bump (E30, 0/2000). That
  sample no longer flips, but the cache defect is still in v3.8.1 at the
  score level. Any block that rests on 942130, or on a single rule over a
  repeated key, can differ between two replays of one request. Count in
  this step's evidence: statuses, 0 differences in 60,000 parity pairs;
  rule-id sets, 3 ids. A recall or false-positive figure from one replay
  therefore carries this noise; how large it is on the attack sets is
  NOT MEASURED.
- Classification (rule 39): BUG, in the coraza dependency, present in the
  engine and in the connector image (F2b). NOT FIXED: the fix is to
  iterate collections in a stable order inside coraza, which the engine
  cannot do from outside. No failing test was added to the suite, because
  it would stay red until that decision is made (Questions).

**F2. ModSecurity image against the Coraza connector image, benign-wcp-v0,
PL1 and PL2 (was "not re-run on this host").** `bash tools/run_step22_modsec_connector.sh`
(docs/logs/step22-modsec-connector.txt, rows in
docs/logs/runs/s22-modsec-connector/, per-sample list from
`.venv/bin/python tools/step22_modsec_connector_summary.py`). Default image
config on both sides, stub backend, 20,000 samples, one worker. Rule 28 and
29, read from inside each running container:

```
== modsec-benign-wcp-v0-pl1 rule29/28 2026-11-27T18:53:18Z
   image: owasp/modsecurity-crs:4.25.2-nginx-lts@sha256:6296ce685cb88ba4012998b935b25dabbd9e0ff326088c1149447102544de661 ... platform linux/arm64
   env: E=On B=1 P=1 D=1 BACKEND=http://stub-backend:3000 CT=[] M=[]
   conf: SecRuleEngine On SecRequestBodyLimit 13107200 SecRequestBodyNoFilesLimit 131072
   ruleset: ver:'OWASP_CRS/4.25.2 in /etc/modsecurity.d/owasp-crs/rules (27 .conf files)
   libmodsecurity3 version 3.0.17
== coraza-benign-wcp-v0-pl1 rule29/28 2026-11-27T18:55:11Z
   image: ghcr.io/coreruleset/coraza-crs:4.25.2-nginx-lts@sha256:bfbfe70b4445c1ef1dc389c2de12cfdb194c9616746c33dc8a7131461c28f4a6 ... platform linux/arm64
   env: E=On B=1 P=1 D=1 CT=[] body=[nofiles=131072 total=13107200]
   ruleset: ver:'OWASP_CRS/4.25.2 in /opt/coraza/owasp-crs/rules (27 .conf files)
```

Rule 36, each of the four runs: control entries in the audit pre 20/20,
post 20/20. Rates are on benign-labelled natural traffic (rule 14: no hard
benign set is mixed in); denominator 20,000; errors are not flagged in
"blocked only" and are flagged in the worst case (rules 20, 21, 30).

| run | waf_block | deny_status | inconsistent | proxy_reject | error | waf_pass | blocked only | worst case (headline) |
|---|---|---|---|---|---|---|---|---|
| ModSecurity PL1 | 3,823 | 64 | 0 | 5 | 1 | 16,107 | 19.11% | 3,893 = 19.46% |
| connector PL1 | 3,824 | 61 | 0 | 5 | 12 | 16,098 | 19.12% | 3,902 = 19.51% |
| ModSecurity PL2 | 8,949 | 64 | 1 | 5 | 1 | 10,980 | 44.75% | 9,020 = 45.10% |
| connector PL2 | 8,951 | 61 | 1 | 5 | 7 | 10,975 | 44.76% | 9,025 = 45.12% |

Parity, per quantity (rule 32), every differing id is in the summary output:

- Blocked set (the 403 discriminator). PL1: both 3,817, only ModSecurity 6,
  only connector 7. PL2: both 8,943, only ModSecurity 6, only connector 8.
  In 12 of the 13 PL1 ids and 13 of the 14 PL2 ids the other side answers
  400 (deny_status) where this side answers 403; the remaining id,
  wcp-80a49c991b2d (the 481,798-byte body), is blocked by ModSecurity and
  times out on the connector. No id is blocked on one side and passed on
  the other. PL1 ids: wcp-2574cf69006b, wcp-4ff99580bb57, wcp-80a49c991b2d,
  wcp-82f508a89f65, wcp-96b9ef51be10, wcp-de8021cfbd94 (only ModSecurity);
  wcp-672911deadaa, wcp-71461e371348, wcp-8dc97426f4b3, wcp-93fd2b577bc9,
  wcp-96a594e2ae57, wcp-bf3ad3695dc3, wcp-c7970d727861 (only connector).
  PL2: the same 13 plus wcp-aa98de364e37 (only connector).
- Worst-case set (blocked + deny_status + inconsistent + proxy_reject +
  error). PL1: only ModSecurity 1, only connector 10. PL2: only
  ModSecurity 0, only connector 5. All 15 connector-only ids are connector
  timeouts on requests ModSecurity passed (PL1: wcp-00f2f589e97a,
  wcp-50071536f159, wcp-7df6cb91aaf0, wcp-86904cff10c3, wcp-96bd5332ae15,
  wcp-a5a302eda586, wcp-ab265f963540, wcp-b1785dde1f51, wcp-eeeb13d052ce,
  wcp-ffd61414ef24; PL2: wcp-7df6cb91aaf0, wcp-a5a302eda586,
  wcp-ab265f963540, wcp-d75ff52b9fa3, wcp-eeeb13d052ce). The one
  ModSecurity-only id is wcp-aa98de364e37 at PL1: ModSecurity 400,
  connector 200. That is the only id where one image refuses and the other
  passes.
- Rule-id sets, on the ids blocked by both: 1,290 of 3,817 differ at PL1
  and 2,739 of 8,943 at PL2. The connector's sets are the larger ones
  (PL1: 921150 on 379 ids, 932370 on 298, 942550 on 293, 920270 on 272;
  PL2: 942430 on 2,533, 942200 on 2,378, 942370 on 2,325, 942340 on
  2,114). Rules only in the ModSecurity sets: 932340 on 6 ids, 942360 on 1
  (PL1); 932340 on 6, 942200 on 3, 942130 on 2, 942362 and 942360 on 1
  each (PL2). Of the 2,533 ids where only the connector has 942430, 2,316
  are POST text/plain and 84 POST with no content type. HYPOTHESIS: the
  connector runs the detection rules over bodies whose content type has no
  body processor and ModSecurity does not; both then refuse them on the
  content-type rule 920420, which is why the blocked sets agree. No
  discriminating run was made.
- Errors. One id errors on both sides in both runs (wcp-6b0bf5e43122, a
  request the runner cannot encode). The connector adds 11 timeouts at PL1
  and 6 at PL2; ModSecurity has none. Five of the 11 PL1 ids also timed
  out on the connector in step 13 (wcp-00f2f589e97a, wcp-50071536f159,
  wcp-96bd5332ae15, wcp-ab265f963540, wcp-80a49c991b2d), six did not.
  The connector runs took 17 and 12 minutes against 2 and 3 for
  ModSecurity, and other jobs of this step ran on the host at the same
  time (load 4 to 12, see Deviations). Whether the six new timeouts come
  from the load is NOT MEASURED.
- Against step 13 (docs/logs/step13-t5-parity.txt, another host): the
  blocked counts are the same four numbers (3,823 / 3,824 and 8,949 /
  8,951) and the blocked-set differences are the same 13 ids at PL1 and
  the same 14 at PL2. One answer changed: wcp-4ff99580bb57 got 413 from
  the connector at PL2 then and 400 now. The worst-case figures differ
  from step 13 (3,888 / 3,891 and 9,015 / 9,026 there) because the
  timeouts differ and this summary counts the 5 proxy_reject rows.

**F2b. Connector and ModSecurity sides of F1 and F3 (DIAGNOSTIC).**

Non-determinism, `bash tools/run_step22_variance_diag.sh containers`
(docs/logs/step22-variance-containers-DIAGNOSTIC.txt), the same seven
requests, 200 replays each, PL2:

```
== DIAGNOSTIC-variance-modsec-pl2 ... libmodsecurity3 version 3.0.17
   syn-chain: statuses {'403': 200}
   syn-chain-rev: statuses {'200': 200}
   [modsec] syn-dup: 200 audit entries, 1 distinct rule-id set(s), 1 distinct inbound score(s) {30: 200}
   [modsec] wcp-35f82c1417df: 200 audit entries, 1 distinct rule-id set(s), 1 distinct inbound score(s) {23: 200}
   [modsec] wcp-7b0bdeda7bc7: 200 audit entries, 1 distinct rule-id set(s), 1 distinct inbound score(s) {47: 200}
== DIAGNOSTIC-variance-coraza-pl2
   syn-chain: statuses {'200': 88, '403': 112}
   syn-chain-rev: statuses {'200': 105, '403': 95}
   syn-chain-single: statuses {'403': 200}
   [coraza] syn-dup: 200 audit entries, 15 distinct rule-id set(s), 9 distinct inbound score(s) {10: 1, 15: 4, 20: 13, 25: 40, 30: 73, 35: 44, 40: 22, 45: 2, 50: 1}
   [coraza] syn-dup-single: 200 audit entries, 1 distinct rule-id set(s), 1 distinct inbound score(s) {30: 200}
   [coraza] wcp-35f82c1417df: 200 audit entries, 22 distinct rule-id set(s), 11 distinct inbound score(s) {71: 1, 76: 2, 81: 4, 86: 11, 91: 32, 96: 84, 101: 38, 106: 23, 111: 3, 116: 1, 121: 1}
   [coraza] wcp-7b0bdeda7bc7: 200 audit entries, 2 distinct rule-id set(s), 2 distinct inbound score(s) {42: 109, 47: 91}
```

- The connector image has both defects: it passes the tautology request in
  88 of 200 replays and scores the duplicate-key request anywhere from 10
  to 50. So the reference this project measures against is itself not
  repeatable at PL2, and an exact rule-id parity target between engine and
  connector cannot be met by either side.
- ModSecurity 3.0.17 is repeatable on all seven requests. Its 942130
  result depends on member order instead: `syn-chain` (tautology last) is
  blocked 200 of 200 and `syn-chain-rev` (tautology first, harmless `a=b`
  member last) is passed 200 of 200. So the weakness behind H1 is in how
  the 942130 chain reads its captures, on both engines; coraza adds the
  random order. Two synthetic requests, not a rate.

Cell G, `bash tools/run_step22_t5_cellg.sh connector`
(docs/logs/step22-t5-cellg-connector-DIAGNOSTIC.txt), same eight requests
per level, connector default config:

```
== DIAGNOSTIC-cellg-connector-pl1: 8 requests
   ('G', 'clean-deflate+header', 'sqli', 'plain'): status 403 policy-only=1
       rules [920420,920450] x1
   ('G0', 'clean-deflate+header', 'benign', 'plain'): status 403 policy-only=1
       rules [920420,920450] x1
   ('H', 'raw', 'sqli', 'plain'): status 403 policy-only=1
       rules [920420] x1
   ('H', 'raw', 'xss', 'plain'): status 403 payload-detected=1
       rules [920420,941100,941110,941160,941390] x1
   ('K', 'clean-deflate-no-header', 'sqli', 'plain'): status 403 policy-only=1
       rules [920420] x1
   ('K0', 'clean-deflate-no-header', 'benign', 'plain'): status 403 policy-only=1
       rules [920420] x1
   PASSED (evasion candidates): 0
```

- The connector refuses all eight at both levels, and no 941 or 942 rule
  matches the compressed canary (G, K) at PL1: it does not decode either.
  Every text/plain request here carries 920420, the connector's
  content-type policy (DESIGN C4: the engine does not apply it), so K is
  refused on the connector for its content type, not for its content. At
  PL2 920271 is added, as on the engine.
- NOT MEASURED: cell K on the connector with a content type its policy
  allows. The script only sends text/plain.

**F3. Encoding cell G (was NOT MEASURED).** `bash tools/run_step22_t5_cellg.sh engine`
and `... connector` (DIAGNOSTIC, docs/logs/step22-t5-cellg-engine-DIAGNOSTIC.txt,
docs/logs/step22-t5-cellg-connector-DIAGNOSTIC.txt, rows in
docs/logs/runs/s22-t5-cellg/). The first search only appended spaces and
every stream ended in NUL bytes. The new one puts the canary between seeded
filler words and uses Z_HUFFMAN_ONLY; the streams (81 and 67 bytes) hold no
NUL, CR or LF and decompress to text that contains the canary. Cells: G =
compressed canary + `Content-Encoding: deflate`; K = the same bytes without
the header; H = the same text uncompressed; G0/K0 = benign text. Engine at
6e2b666:

```
== DIAGNOSTIC-cellg-engine-pl1: 8 requests
   cell ('G', 'plain', 'sqli'): {403: 1}
   cell ('G', 'plain', 'xss'): {403: 1}
   cell ('G0', 'plain', 'benign'): {403: 1}
   cell ('H', 'plain', 'sqli'): {403: 1}
   cell ('H', 'plain', 'xss'): {403: 1}
   cell ('K', 'plain', 'sqli'): {200: 1}
   cell ('K', 'plain', 'xss'): {200: 1}
   cell ('K0', 'plain', 'benign'): {200: 1}
   ('G', 'clean-deflate+header', 'sqli', 'plain'): status 403 no-check-rule=1
   ('H', 'raw', 'sqli', 'plain'): status 403 payload-detected=1
       rules [942100] x1
   ('H', 'raw', 'xss', 'plain'): status 403 payload-detected=1
       rules [941100,941110,941160,941390] x1
   block pages that list rule 920450 among the matched rules: 3 ['t5g-e-pl1-xss-G', 't5g-e-pl1-sqli-G', 't5g-e-pl1-benign-G0']
== DIAGNOSTIC-cellg-engine-pl2: 8 requests
   cell ('G', 'plain', 'sqli'): {403: 1}
   cell ('G', 'plain', 'xss'): {403: 1}
   cell ('G0', 'plain', 'benign'): {403: 1}
   cell ('K', 'plain', 'sqli'): {403: 1}
   cell ('K', 'plain', 'xss'): {403: 1}
   cell ('K0', 'plain', 'benign'): {403: 1}
   ('K', 'clean-deflate-no-header', 'sqli', 'plain'): status 403 policy-only=1
       rules [920271,932200] x1
   ('K', 'clean-deflate-no-header', 'xss', 'plain'): status 403 policy-only=1
       rules [920271] x1
   ('K0', 'clean-deflate-no-header', 'benign', 'plain'): status 403 payload-detected=1
       rules [920271,942131,942440] x1
```

(Trimmed to the cell lines and the rule lines used below.)

- PROVEN (rule 44, G against K at PL1): a compressed attack body is not
  decoded and the rules do not see the canary in it. With the header it is
  refused, by the header rule 920450 alone (no 941/942 rule, and the benign
  G0 is refused the same way). Without the header the same bytes pass. This
  replaces the HYPOTHESIS "no compressed attack body can pass" in the T5
  section: with a Content-Encoding header none passed; the barrier was one
  rule on the header name.
- K is not by itself an attack on a backend that follows the header: a
  body without Content-Encoding is not decompressed by such a backend.
- At PL2 the compressed bytes are refused with or without the header, by
  920271 (bytes below 32). The benign K0 is refused too (new block,
  potential false positive, for any binary body sent as text/plain at PL2).
- NOT MEASURED: a stream with no byte below 32 at all (which would pass
  920271). None found in 8,620,836 seeded tries (4,437,694 SQLi +
  4,183,142 XSS, 200 s each; tools/step22_cellg_strict_search.py,
  docs/logs/step22-t5-cellg-strict-search.txt). A time-bounded search,
  not a proof that none exists.
- The connector's result is in F2b above.

**F4. Connector PL2 false-positive decomposition (was NOT MEASURED).**
`.venv/bin/python tools/step22_t4_fp_decomposition.py`
(docs/logs/step22-t4-fp-decomposition.txt). The step-18 connector PL2 runs
store their audit file gzip-compressed; the tool looked for the plain name
only. It now reads either (test added). No new run.

```
== connector v0 PL2: n=9013 403-blocks=9013 detection-involved=8865 (920420-only blocks=148)
connector family hits: sqli=23509, other=5941, rce=5655, protocol=3544, xss=2020
connector top 10: 931130=5114, 942430=4828, 942200=4240, 942370=3239, 942340=3102, 942330=1904, 920230=1688, 932200=1589, 942520=1078, 942120=1024
== connector v1 PL2: n=4510 403-blocks=4510 detection-involved=4437 (920420-only blocks=73)
connector family hits: sqli=11428, other=2985, rce=2743, protocol=1794, xss=975
connector top 10: 931130=2573, 942430=2377, 942200=2054, 942370=1556, 942340=1464, 942330=931, 920230=843, 932200=792, 942120=528, 942520=494
```

n is the number of audit entries with status 400, 401 or 403 (the tool's
"403-blocks" label covers all three), not the 20,000 / 10,000 samples; the
runs are the step-18 ones (2026-11-21, `localhost` base URL), with outcomes
8,951 blocked + 61 deny_status of 20,000 (v0) and 4,480 + 30 of 10,000 (v1).
Counts of an effect on audited entries, not a rate (rule 35). The same eight
rules lead the engine's PL2 list (931130, 942430, 942200, 942370, 942340,
942330, 932200, 920230).

**F5. E20: how long the abandoned call takes.** `bash tools/run_step22_e20_timing.sh 3`
and, DIAGNOSTIC, the same with the coraza v3.7.0 scratch build of
DIAGNOSTIC A (docs/logs/step22-e20-timing.txt). Same request as the test
(the 481,798-byte fixture, text/plain, budget 200 ms):

```
== repeat 1: occupier answered 503; abandoned call finished=yes after 260 s wall (1 s polling; limit 1800 s); engine process CPU time 4:17.50; next body-bearing request -> 200
== repeat 2: occupier answered 503; abandoned call finished=yes after 264 s wall (1 s polling; limit 1800 s); engine process CPU time 4:19.99; next body-bearing request -> 200
== repeat 3: occupier answered 503; abandoned call finished=yes after 280 s wall (1 s polling; limit 1800 s); engine process CPU time 4:31.70; next body-bearing request -> 200
== DIAGNOSTIC engine binary out/kortex-engine-DIAGNOSTIC-coraza370 sha256 0f0b4e96a8e587b9e66777ff0379084ccbef06d5b107b7d4fa49cb57171cde02 (...)
== repeat 1: occupier answered 503; abandoned call finished=yes after 267 s wall (1 s polling; limit 1800 s); engine process CPU time 4:23.68; next body-bearing request -> 200
== repeat 2: occupier answered 503; abandoned call finished=yes after 266 s wall (1 s polling; limit 1800 s); engine process CPU time 4:22.14; next body-bearing request -> 200
```

260 to 280 s here (load 4 to 21 during the repeats), one core for the whole
time, and the engine recovers afterwards (next body request 200). E20's
120 s wait could never pass on this host. The coraza version is ruled out
as the reason (v3.7.0: 266, 267 s; had the bump been the cause, the v3.7.0
build would be near the 54 s suite time of the step-17 host). Why the
step-17 host was faster stays UNEXPLAINED. Three notes on these runs are in
the log (Juice Shop answered on port 13000 in the first three repeats, the
script was edited while running, other jobs ran alongside).

**F6. Test fixes (T3g, E20).**

- T3n, committed failing first (bec12db, docs/logs/step22-t3n-failing.log):
  with one goroutine of the test process spinning, T3g fails
  deterministically, no fixture needed:

```
=== RUN   TestT3nT3gIgnoresOtherTestsCPU/T3g
    worker_test.go:303: T3g: killed worker pid 70582; parent CPU 559.093ms -> 1.756363s (+1.19727s) over 1.2s after the kill
    worker_test.go:305: T3g: parent CPU grew by 1.19727s in 1.2s after the kill (limit 150ms)
--- FAIL: TestT3nT3gIgnoresOtherTestsCPU (1.64s)
```

- Fix (3ea59f9): T3g runs its checks in a fresh copy of the test binary
  with only T3g selected. Limits unchanged (150 ms in 1.2 s). Canary T3o
  (rule 47): the same run with a spinning goroutine in the parent must
  fail on the CPU limit, so the test was not weakened
  (docs/logs/step22-t3n-passing.log):

```
            worker_test.go:331: T3g: killed worker pid 73434; parent CPU 100.081ms -> 100.216ms (+135µs) over 1.2s after the kill
--- PASS: TestT3gBoundedCPUAfterKill (1.71s)
    worker_test.go:377: T3o: with a busy parent T3g failed as it must: worker_test.go:333: T3g: parent CPU grew by 1.101553s in 1.2s after the kill (limit 150ms)
--- PASS: TestT3oT3gCanaryCatchesBusyParent (1.69s)
            worker_test.go:331: T3g: killed worker pid 73544; parent CPU 98.214ms -> 98.452ms (+238µs) over 1.2s after the kill
--- PASS: TestT3nT3gIgnoresOtherTestsCPU (1.77s)
ok  	kortexshield/engine	5.465s
```

- E20 (2452039): the wait is 480 s instead of 120 s, from the timings in
  F5. The assertion is unchanged. With the fixture the suite needs
  `-timeout 900s`.

**F7. Engine audit log had no phase-1 rule (the second UNEXPLAINED item):
BUG, fixed.** The engine's generated config set no `SecDefaultAction`, so
only phase 2 had coraza's built-in `log,auditlog`. Rules that match in
phase 1 (920350, 920450, 920320) scored and were on the block page but not
in the audit entry. The connector image sets the default for phases 1 to 5
(`/opt/coraza/config/crs-setup.conf` lines 98-102, read from the running
container). Test E32, failing first (5b47a00, docs/logs/step22-e32-failing.log):

```
=== RUN   TestE32Phase1MatchInAuditLog
    step22_test.go:43: E32: the audit entry names 942100 (phase 2) but not 920350 (phase 1)
--- FAIL: TestE32Phase1MatchInAuditLog (0.04s)
```

Fix (d7e5760): the same five lines in engine/config.go, documented first in
docs/baseline-config.md (rule 17). PROVEN (rule 44): with only those lines
added the test passes (docs/logs/step22-e32-passing.log); had the missing
default not been the cause, it would still fail. Effect on results: audit
entries and rule-id sets derived from them gain phase-1 ids; statuses are
checked in F9.

**F8. Engine changes asked for under Questions.**

- Content-Encoding (E33, E34; design in docs/engine-design.md before the
  code, 9579672; implementation c586b76). The engine now answers
  `415 kortex-decision=content-encoding` itself to any request with a body
  and a Content-Encoding other than identity, before a transaction is
  created, in blocking and DetectionOnly mode. It does not decode. E33
  failed first with `want 415 kortex-decision=content-encoding, got 403`
  (docs/logs/step22-e33-failing.log) and passes after
  (docs/logs/step22-e33-passing.log); E34 guards the cases that must not
  be refused. Difference from the connector (rule 39, DESIGN): 415 instead
  of 403 on these requests; criterion measured in F9 (rule 41).
- Refusals (T3p; design before the code, 41dcb78; implementation 37074bf).
  Not a rate limit: an attacker's connection still costs an accept, a
  header parse and a 503. What changed is that a penalised client's body
  request is refused before the transaction, the phase-1 rules, the lane
  slot and the body read, which is where the measured cost was. New
  counter `refused_before_inspection` on /__kortex/stats. T3p failed first
  (`/__kortex/stats has no refused_before_inspection counter`,
  docs/logs/step22-t3p-failing.log) and passes after
  (docs/logs/step22-t3p-passing.log). Visible difference: such a request
  gets 503 where the rules might have answered 403. Effect measured in F10.

**F9. Re-runs with the changed engine.**

T3 parity again, engine at 37074bf (E32, E33 and T3p in):
`STUB_PORT=13006 T3_TAG=-after-followup bash tools/run_step22_t3_parity.sh`
then `.venv/bin/python tools/step22_t3_summary.py docs/logs/runs/s22-t3-parity-after-followup`
(docs/logs/step22-t3-parity-after-followup.txt, rows in
docs/logs/runs/s22-t3-parity-after-followup/). Rule 29 is in the log per
run (`"worker_mode":false` / `true`, paranoia 1 or 2, binary sha256
1214f20810f5...).

```
== diff benign-wcp-v0 PL1 (a=inprocess b=worker):
status counts a: {200: 17716, 400: 52, 403: 2184, 413: 28, 415: 19, None: 1}
status counts b: {200: 17716, 400: 52, 403: 2184, 413: 28, 415: 19, None: 1}
status diffs: 0
worst-case set a: 2237/20000 (error=1 blocked=2184 deny_status=52 inconsistent=0)
worst-case set diffs: 0 (only-a 0 only-b 0)
== diff benign-wcp-v1 PL1 (a=inprocess b=worker):
status counts a: {200: 8867, 400: 25, 403: 1091, 413: 17}
status diffs: 0
worst-case set a: 1116/10000 (error=0 blocked=1091 deny_status=25 inconsistent=0)
== diff benign-wcp-v0 PL2 (a=inprocess b=worker):
status counts a: {200: 11033, 400: 52, 403: 8867, 413: 28, 415: 19, None: 1}
status counts b: {200: 11033, 400: 52, 403: 8867, 413: 28, 415: 19, None: 1}
status diffs: 0
worst-case set a: 8920/20000 (error=1 blocked=8866 deny_status=52 inconsistent=1)
== diff benign-wcp-v1 PL2 (a=inprocess b=worker):
status counts a: {200: 5520, 400: 25, 403: 4438, 413: 17}
status diffs: 0
worst-case set a: 4463/10000 (error=0 blocked=4438 deny_status=25 inconsistent=0)
benign-wcp-v0 PL2 rule-id sets, in-process vs worker: 3 ids differ of 20000
    wcp-35f82c1417df: only in-process ['942120'] only worker []
    wcp-7b0bdeda7bc7: only in-process [] only worker ['942130']
    wcp-f754e70f73bd: only in-process [] only worker ['942130']
```

(Trimmed: the b lines where equal to a, the per-run lines, the rate
table. v0 PL1, v1 PL1 and v1 PL2 have 0 rule-id set differences.)

- In-process against worker: 0 status differences and 0 worst-case-set
  differences in 60,000 pairs, as before. Rule-id sets: 3 ids, all on v0
  PL2, by 942130 (H1) and 942120 (H2, the id is the one from F1). The
  first run had 3 other ids (2 on v0, 1 on v1); only wcp-f754e70f73bd is
  in both. This is the noise of F1, not a mode difference.
- Against the first parity run, per id and per mode: the only status
  changes are 19 ids of benign-wcp-v0, the same 19 in all four v0 runs,
  all now 415. Before, 9 were 403, 6 were 400 and 4 were 413; none was
  200. All 19 carry `Content-Encoding: gzip` and a body; they are every
  such sample in v0, and v1 has none and has 0 changes. So E32 and T3p
  changed no status on these datasets, and E33 changed exactly the
  requests it was written for.
- Rates on benign-labelled natural traffic (rule 14: nothing merged),
  denominator all samples, both modes equal:

| dataset | PL | blocked only (best case) | worst case by the tool (headline, rule 21) | every answer other than 200 |
|---|---|---|---|---|
| benign-wcp-v0 | 1 | 2,184 = 10.92% | 2,237 = 11.19% | 2,284 = 11.42% |
| benign-wcp-v0 | 2 | 8,866 = 44.33% | 8,920 = 44.60% | 8,967 = 44.84% |
| benign-wcp-v1 | 1 | 1,091 = 10.91% | 1,116 = 11.16% | 1,133 = 11.33% |
| benign-wcp-v1 | 2 | 4,438 = 44.38% | 4,463 = 44.63% | 4,480 = 44.80% |

- The tool's v0 figures are 15 lower than in the first run (2,252 and
  8,935). That is not fewer refusals: the 9 + 6 requests that were 403 or
  400 are now 415, and kortex_eval classifies the engine's own 413 and
  415 answers as waf_pass (no audit entry, no block marker), so they
  leave the worst-case set. The last column counts them: 2,284 and 8,967
  before and after. The same holds for the 28 / 17 status-413 answers in
  every earlier engine figure. kortex_eval was not changed (rule 5); see
  Questions.
- Rule 18/24, PL2: 931130, 942430, 942200, 942370, 942340, 942330, 932200
  each on 20% or more of the audit entries, as in the first run (counts in
  the log). PL1 v0: 932370 on 466 of 2,236.

T5 again, engine at c586b76: `T5_LOG=docs/logs/step22-t5-after-e33.txt bash tools/run_step22_t5.sh`
and `CELLG_TAG=-after-e33 bash tools/run_step22_t5_cellg.sh engine`
(docs/logs/step22-t5-after-e33.txt,
docs/logs/step22-t5-cellg-engine-after-e33-DIAGNOSTIC.txt):

```
padding-pl1: TOTAL 108 blocked403=108 passed200=0 failclosed(400/413/503)=0 other=0
padding-pl2: TOTAL 108 blocked403=106 passed200=0 failclosed(400/413/503)=2 other=0
     t5a-pl2-k120000-sqli-after-plain-r1 503
     t5a-pl2-k120000-sqli-after-plain-r2 503
   cell ('A', 'json', 'sqli'): {415: 1}      (all 12 A and B cells: 415)
   cell ('C', 'json', 'sqli'): {400: 1}      (C: 2 x 400 json, 4 x 403)
   cell ('D', 'plain', 'sqli'): {403: 1}     (D: 6 x 403; E: 12 x 403)
   PASSED (evasion candidates): 0
   cell ('F', 'plain', 'benign'): {415: 2}
   cell ('I', 'plain', 'benign'): {415: 1}
   cell ('J', 'plain', 'benign'): {200: 1}
== DIAGNOSTIC-cellg-engine-pl1 (after E33)
   cell ('G', 'plain', 'sqli'): {415: 1}
   cell ('G0', 'plain', 'benign'): {415: 1}
   cell ('K', 'plain', 'sqli'): {200: 1}
== DIAGNOSTIC-cellg-engine-pl2 (after E33)
   cell ('G', 'plain', 'sqli'): {415: 1}
   cell ('K', 'plain', 'sqli'): {403: 1}
```

(Annotations in brackets are mine; trimmed to one line per cell group.)

- Padding: 0 passed. The two PL2 answers that are not 403 are 503 on the
  120,000-byte SQLi cell (fail closed; the first run had one). The host
  load was 3.5 to 10 during this run; whether the 503s come from the load
  is NOT MEASURED.
- DESIGN criterion of E33, measured (rule 41): every request with a body
  and a Content-Encoding header is answered 415 by the engine and is not
  forwarded: 12 of 12 in cells A and B, cells F, I, G and G0, and the 19
  wcp samples. The answer no longer depends on rule 920450.
- What E33 does not cover, as F3 showed: compressed bytes without the
  header (cell K) still pass at PL1.

**F10. T2 mixed cells: what separates the first recording from the re-run,
and the cost of refusals after T3p (DIAGNOSTIC except the last block).**

`KORTEX_T2_ENGINE_REF=<ref> [KORTEX_T2_OLD_PROBE=1] bash tools/run_step22_t2_container.sh <cell>`
builds the engine from that commit and, with the second variable, sends
the first recording's benign probe. Logs:
docs/logs/step22-t2-DIAGNOSTIC-{preclamp,oldprobe,preclamp-oldprobe,before-t3p}-<cell>.txt,
cell files under docs/logs/runs/s22-t2-DIAGNOSTIC-*/, one-page summary
docs/logs/step22-t2-followup-summary.txt. Same container image, VM and
cell parameters as the re-run; all cells PL1, 300 s.

```
first recording  mixed-one:  post 105/301 get 105/301 kills=18  overloads=65451   attack_status={'503': 65603, '-1': 30092} cpu=217.8s
first recording  mixed-eight: post 275/300 get 300/300 kills=196 overloads=403046  cpu=673.8s
re-run v2 (50e21a3, new probe)
cell mixed-one: preflight=[200, 200] post 301/301 {200: 301} get 301/301 {200: 301} kills=75 overloads=2298728 minpool=1 cpu=576.2s recovery=1.0s
cell mixed-eight: preflight=[200, 200] post 294/301 {503: 7, 200: 294} get 301/301 {200: 301} kills=200 overloads=1761481 minpool=0 cpu=561.6s recovery=2.5s
DIAGNOSTIC preclamp (20f3e8a, new probe)
cell mixed-one: preflight=[200, 200] post 301/301 {200: 301} get 301/301 {200: 301} kills=50 overloads=2124148 minpool=2 cpu=547.5s recovery=1.0s
cell mixed-eight: preflight=[200, 200] post 286/301 {503: 15, 200: 286} get 301/301 {200: 301} kills=200 overloads=2304829 minpool=0 cpu=552.3s recovery=2.5s
DIAGNOSTIC oldprobe (50e21a3, old probe)
cell mixed-one: preflight=[200, 200] post 301/301 {200: 301} get 301/301 {200: 301} kills=75 overloads=2595337 minpool=1 cpu=593.5s recovery=1.0s
cell mixed-eight: preflight=[200, 200] post 276/301 {503: 25, 200: 276} get 301/301 {200: 301} kills=200 overloads=2816307 minpool=0 cpu=619.1s recovery=2.5s
DIAGNOSTIC preclamp-oldprobe (20f3e8a, old probe)
cell mixed-one: preflight=[200, 200] post 301/301 {200: 301} get 301/301 {200: 301} kills=50 overloads=2582471 minpool=2 cpu=598.2s recovery=1.0s
cell mixed-eight: preflight=[200, 200] post 279/301 {503: 22, 200: 279} get 301/301 {200: 301} kills=200 overloads=2817527 minpool=0 cpu=617.1s recovery=2.5s
```

(The two "first recording" lines are from the summary tool; the others are
the raw cell lines. The labels above each pair are mine.)

- 20f3e8a is the commit before the clamp; its engine code other than tests
  is that of 862abbf (2026-11-22). The first recording's cell files do not
  name their engine commit, so "same engine as the first recording" is
  UNVERIFIED.
- mixed-one is 301/301 with the clamp removed, with the old probe, and
  with both. So on this host neither the clamp nor the probe, alone or
  together, produces the first recording's 105/301. The clamp does show
  in the cell: 50 kills and a pool that never fell below 2 without it, 75
  kills and 1 with it.
- What is left is the host (the Ubuntu machine of 2026-11-22 then; a
  container in a VM on a Mac now) and anything not recorded then. That
  cannot be tested from here: HYPOTHESIS, not PROVEN. The first recording
  itself points away from the engine's fairness logic: benign GETs failed
  as often as POSTs (105/301 each; GETs take no lane slot) and the
  attacker saw 30,092 connection errors, which no run here has.
- mixed-eight loses between 7 and 26 benign POSTs of 301 on this host in
  every variant (first recording: 25 of 300); see the repeats below.

Cost of refusals, before and after T3p. `before-t3p` is the engine built
from 41dcb78, the commit immediately before the implementation (37074bf
changes 11 lines of engine/proxy.go and the counter in engine/admin.go);
`v3` is `KORTEX_T2_OUT_DIR=docs/logs/runs/s22-t2-cells-v3 KORTEX_T2_LOG=docs/logs/step22-t2-cells-v3-rest.txt bash tools/run_step22_t2_container.sh rest`
at 37074bf (not DIAGNOSTIC; rule 29: `worker_mode: true`, per-client caps
small 2, large 1 in every cell json):

```
DIAGNOSTIC before-t3p (41dcb78, new probe)
cell mixed-one: preflight=[200, 200] post 301/301 {200: 301} get 301/301 {200: 301} kills=75 overloads=2536610 minpool=1 cpu=610.1s recovery=1.0s
cell mixed-eight: preflight=[200, 200] post 290/301 {503: 11, 200: 290} get 301/301 {200: 301} kills=200 overloads=2337277 minpool=0 cpu=591.5s recovery=2.5s
v3 (37074bf, new probe)
cell mixed-one: preflight=[200, 200] post 301/301 {200: 301} get 301/301 {200: 301} kills=75 overloads=2878063 minpool=1 cpu=300.7s recovery=1.0s
cell mixed-eight: preflight=[200, 200] post 275/301 {503: 26, 200: 275} get 301/301 {200: 301} kills=200 overloads=2742098 minpool=0 cpu=247.8s recovery=2.5s
killstorm: kills=80 (0.67/s) minpool=0 minidle=0 cpu=94.8s
```

| cell | engine | 503 answers to the attacker | of them refused before inspection | engine CPU-seconds | CPU per 503 |
|---|---|---|---|---|---|
| mixed-one | 41dcb78 | 2,542,308 | counter not present | 610.1 | 240 µs |
| mixed-one | 37074bf | 2,883,489 | 2,404,897 | 300.7 | 104 µs |
| mixed-eight | 41dcb78 | 2,341,772 | counter not present | 591.5 | 253 µs |
| mixed-eight | 37074bf | 2,747,821 | 2,725,057 | 247.8 | 90 µs |
| kill storm, 120 s | 50e21a3 (re-run v2) | 795,236 | counter not present | 214.8 | 270 µs |
| kill storm, 120 s | 37074bf | 1,425,574 | 1,421,959 | 94.8 | 67 µs |

- PROVEN (rule 44) for the two mixed cells: with only the T3p commit
  between the two engines, engine CPU falls from 610 to 301 and from 592
  to 248 CPU-seconds in 300 s while the attacker receives more answers.
  Had T3p not been the cause, the 41dcb78 engine would have shown the
  lower figure too. mixed-one is one run per engine, mixed-eight three
  (repeats below). The kill storm has no single-commit control: its
  "before" is the re-run at 50e21a3, so E32 and E33 also lie between.
- CPU is the engine's process tree (parent and workers) from /proc, 8
  cpus in the VM. In-VM load at the start of these cells was 6.8 to 8.9,
  left over from the cell before; the cells ran back to back.
- It is still not a rate limit: an unpaced attacker costs 248 to 301
  CPU-seconds per 300 s, about one core, and the attacker's own request
  rate went up (2.34 to 2.75 million answers) because each answer comes
  back sooner.

mixed-eight repeated twice more on each side of T3p (DIAGNOSTIC, same
command with `KORTEX_T2_ENGINE_REF=41dcb78` / `37074bf`, run alternately;
docs/logs/step22-t2-DIAGNOSTIC-{before,after}-t3p-r{2,3}-mixed-eight.txt):

```
before-t3p r2: cell mixed-eight: preflight=[200, 200] post 281/301 {503: 20, 200: 281} get 301/301 {200: 301} kills=200 overloads=2716063 minpool=0 cpu=612.6s recovery=2.5s
after-t3p  r2: cell mixed-eight: preflight=[200, 200] post 275/301 {503: 26, 200: 275} get 301/301 {200: 301} kills=200 overloads=3184201 minpool=0 cpu=254.0s recovery=2.5s
before-t3p r3: cell mixed-eight: preflight=[200, 200] post 281/301 {503: 20, 200: 281} get 301/301 {200: 301} kills=200 overloads=2557596 minpool=0 cpu=597.7s recovery=2.5s
after-t3p  r3: cell mixed-eight: preflight=[200, 200] post 282/301 {503: 19, 200: 282} get 301/301 {200: 301} kills=200 overloads=2502143 minpool=0 cpu=238.3s recovery=2.5s
```

| mixed-eight, 3 runs each | benign POSTs refused of 301 | engine CPU-seconds | CPU per 503 |
|---|---|---|---|
| before T3p (41dcb78) | 11, 20, 20 | 591.5, 612.6, 597.7 | 253, 225, 233 µs |
| after T3p (37074bf) | 26, 26, 19 | 247.8, 254.0, 238.3 | 90, 80, 95 µs |

- CPU: the two sets do not overlap (592 to 613 against 238 to 254), in 3
  of 3 runs. The PROVEN above holds for mixed-eight with repeats.
- Benign POSTs: 11 to 20 refused before, 19 to 26 after. The ranges
  overlap and three runs a side cannot separate them. So T3p does not
  help the benign client in this cell, and a small cost to it is neither
  shown nor excluded: NOT ESTABLISHED. The refused benign POSTs are 503
  after the 2 s budget (p99 about 2,002 ms in every run; the pool
  reaches 0 in every run); benign GETs are 301 of 301 in every run. Rule 35: these are
  counts in an attack cell, not a rate of traffic.
- The engine binary built from `git archive 37074bf` (sha256
  d904dc3da7a9...) differs from the working-tree build of the same commit
  (3ae37bb273ef...); same source, different build path.

**F11. Cleanup.**

- reports/step-21.md: an "Amendment (step-22)" section was added at the
  end, the original text is untouched. It records that the step-21 T3 and
  T4 runs used a numeric Host, that the T4 PL2 count is 286 of 402 with
  `localhost` against 287 there (the id is wcp-43ad8735b4fe), and that the
  five step-21 parity datasets were not re-run with `localhost`.
- data/benign-wcp-v0/README.md: a correction under the reproducibility
  sentence. The builder from commit 71cb753 reproduces the frozen manifest
  (c8ce11f2...); the builder at HEAD gives 39830d0a.... The dataset is
  unchanged (rule 10).
- docs/logs/wcp-baseline-breakdown.json (step 9; 7,379,959 bytes, e-mail
  and JWT shapes in its endpoint keys) is removed from the tree and
  replaced by docs/logs/wcp-baseline-breakdown-nopaths.json (4,208,491
  bytes), made by tools/step22_breakdown_sanitise.py: every number is
  kept, each endpoint key becomes `METHOD sha256:<16 hex>`. Hosts, sample
  ids and rule ids are kept. docs/baseline-v0.4.md points to the new file;
  reports/step-09.md still names the old one (old reports are not edited).
  The old file stays in history until the rewrite below.
- History rewrite: DRY RUN ONLY, in a scratch clone
  (docs/logs/step22-history-rewrite-dryrun.txt). `origin/main` was not
  rewritten and nothing was force-pushed.

```
result: HEAD 37074bf763a9e1be4a49a780537573f19b47fde5 -> dc55f37e12425626ac24185c791399cd1ea152a2; 251 commits before and after (every commit id changes); pack 26.50 MiB -> 12.47 MiB
check: commits that still touch any of the 27 paths (git log --all -- <path>, per path): 0
side effect: 21 of the 27 paths exist in the tree at HEAD today and are gone from the rewritten HEAD:
exit status 1; FAIL lines by path (commit ids removed, counts only):
```

  Three facts for the decision (Questions): the rewrite changes every
  commit id, so every clone must be re-cloned; it deletes 21 files that
  are in the tree today (mostly audit files of earlier wcp runs, which
  the decomposition tool of F4 reads; the list is in the log), so they would have to be replaced by
  body-less indexes first; and a scan of the whole rewritten history still
  fails on 14 other paths (e-mail shapes in CRS rule files and old docs,
  token shapes in two test/report files, the benign-browse and
  benign-hard candidate files, two manifests with a body field, one large
  audit log), which the 27-path list does not cover.

**F12. Suites after the follow-up (engine at 37074bf).** Run one after
another with nothing else running on my side (load 1.6 to 4.0).

```
# step-22 follow-up suite at 37074bf763a9e1be4a49a780537573f19b47fde5 ..., 2026-11-28T01:56:21Z, go version go1.27.4 darwin/arm64, load at start: load averages: 1.70 1.40 1.31
$ cd engine && go test -buildvcs=false -count=1 -v ./...
[trimmed: 48 "--- PASS", 5 "--- SKIP" (E16, E17, E19, E20, E21: fixture not set), 0 "--- FAIL"]
ok  	kortexshield/engine	51.195s
# exit status of go test: 0

# step-22 follow-up suite WITH the recorded wcp fixture (... 481,798 bytes, sha256 5c718716a795c0414b7c2500ebc1816dee4172ba094832f15bb6e1f5de2f2480; not committed, rules 25/51)
$ cd engine && KORTEX_TEST_WCP_BODY=$PWD/../out/step14-t5/wcp-80a49c991b2d.body go test -buildvcs=false -count=1 -timeout 900s -v ./...
--- PASS: TestE20OverloadRecovery (260.72s)
            worker_test.go:381: T3g: killed worker pid 38881; parent CPU 66.352ms -> 66.375ms (+23µs) over 1.2s after the kill
--- PASS: TestT3gBoundedCPUAfterKill (1.64s)
    worker_test.go:427: T3o: with a busy parent T3g failed as it must: worker_test.go:383: T3g: parent CPU grew by 1.199881s in 1.2s after the kill (limit 150ms)
--- PASS: TestT3oT3gCanaryCatchesBusyParent (1.63s)
[trimmed: 53 "--- PASS", 0 "--- SKIP", 0 "--- FAIL" in total]
ok  	kortexshield/engine	319.372s
# exit status of go test: 0

$ .venv/bin/python -m pytest -q
186 passed, 4 skipped in 55.45s
# exit status of pytest: 0
```

Logs: docs/logs/step22-followup-go-test.log,
docs/logs/step22-followup-go-test-with-fixture.log,
docs/logs/step22-followup-pytest.log. The with-fixture suite, which had 2
FAIL at the first push, is green: 53 of 53. It needs `-timeout 900s`; E20
alone took 260.72 s. The 4 Python skips are the same as before (playwright
not installed, 3 missing run artifacts). The Python suite was run again
after the last change to tests/test_step22_tools.py (a test input that
the pre-push scan flagged as an e-mail shape is now joined at run time);
the log holds that run.

**F13. Pre-push scan for the follow-up (rule 51).** Run before the commit
that holds this report; the seven follow-up commits before it and the nine
earlier ones were scanned as a range, this commit as staged content.

```
$ git fetch origin; git log --oneline -1 origin/main
6e2b666 step-22: T6 baseline v1.7, acceptance and design notes, step-22 report, ...
$ bash tools/prepush_scan.sh --range origin/main..HEAD; echo "exit=$?"
[trimmed: 29 "large file" notes, all under docs/logs/; largest docs/logs/wcp-baseline-breakdown-nopaths.json (4208491 bytes)]
prepush: OK, 188 blob(s) in origin/main..HEAD scanned
exit=0
$ git add -A README.md docs reports tests
$ bash tools/prepush_scan.sh; echo "exit=$?"
prepush: OK, 8 staged path(s) scanned
exit=0
```

The first staged scan of the follow-up failed on one finding,
`CRED_SHAPES tests/test_step22_tools.py email=1`: a test input of mine
(a made-up address in a path, used to test the breakdown sanitiser). It is
now assembled at run time. No value from external data was involved.
The largest file added is 4,208,491 bytes, under the 5 MB limit. Commits of
the follow-up, oldest first: bec12db, 3ea59f9, 5b47a00, d7e5760, 9579672,
c586b76, 2452039, 41dcb78, 37074bf (tests and engine changes), 898ed64
(F3), 13341bd (F1), 57e17f5 (F4), b340a8a (F2), 55c6a9e (F10), a5923f8
(F9), 9e32acd (F11), and the commit that holds this report (F12, F13,
docs, tool tests).

## Close-out (2026-11-27, after the follow-up push at e8ed852)

Asked for before the step is closed: (C1) re-run the Go suite and the
Python suite and give exact pass / fail / skip counts; (C2) make
kortex_eval count the engine's own 413 and 415 answers as fail-closed
decisions instead of waf_pass, with a test, and report them apart from 403
in the outcome counts; (C3) re-run the flip reproducer on the current
coraza version, 5 x 500 rounds at PL2, and give flips per round.

Host, Go, Python and pytest versions are those at the top of this report
(printed again in each log). The work was done in a second checkout of the
same repository on the same machine (`~/work/kortex-shield-work`, new
`.venv` with pytest 9.2.0). That checkout has no wcp manifests and no
fixture body (never committed, rules 25 and 51); they were read from the
first checkout, and each hash was compared with the committed or
previously reported one before use (shown below). No container image was
used. Engine code is unchanged since 37074bf; the engine binary of C2 and
C3 was built from 457de00 (sha256 be2217464eb6...ea717626, in the logs).
Port 13000 was held by a stub backend left running from the first checkout
(see UNVERIFIED), so the stub backend of these runs ran on 13004.

**C1. Suites at e8ed852 (nothing changed in the tree).** Run one after
another. Logs: docs/logs/step22-closeout-go-test.log,
docs/logs/step22-closeout-go-test-with-fixture.log,
docs/logs/step22-closeout-pytest.log.

| suite | passed | failed | skipped | time |
|---|---|---|---|---|
| Go, fixture not set | 48 | 0 | 5 (E16, E17, E19, E20, E21) | 51.879 s |
| Go, with the recorded wcp fixture, `-timeout 900s` | 53 | 0 | 0 | 322.491 s |
| pytest | 186 | 0 | 4 | 56.76 s |

```
# step-22 close-out suite at e8ed852d62e47b12085e42787f4e9a282a44bf83 (working tree clean: 0 changed paths under engine/), 2026-11-28T02:40:00Z, go version go1.27.4 darwin/arm64, load at start: load averages: 1.08 2.00 3.77
$ cd engine && go test -buildvcs=false -count=1 -v ./...
[trimmed: 48 "--- PASS", 0 "--- FAIL", 5 "--- SKIP" at top level, 53 tests run]
--- SKIP: TestE16BodyProcessingBoundedByTimeBudget (0.00s)
--- SKIP: TestE17AbandonedCallOwnsTransaction (0.00s)
--- SKIP: TestE19OverloadCapImmediate (0.01s)
--- SKIP: TestE20OverloadRecovery (0.01s)
--- SKIP: TestE21BenignPromptOnCapReachedEngine (0.01s)
ok  	kortexshield/engine	51.879s
# exit status of go test: 0
# load at end: load averages: 1.31 1.91 3.62

# step-22 close-out suite at e8ed852d62e47b12085e42787f4e9a282a44bf83 (working tree clean: 0 changed paths under engine/), 2026-11-28T02:40:53Z, go version go1.27.4 darwin/arm64, load at start: load averages: 1.31 1.91 3.62
$ cd engine && KORTEX_TEST_WCP_BODY=/Users/ivan/work/kortex-shield-dev/out/step14-t5/wcp-80a49c991b2d.body go test -buildvcs=false -count=1 -timeout 900s -v ./...
[trimmed: 53 "--- PASS", 0 "--- FAIL", 0 "--- SKIP" at top level, 53 tests run]
--- PASS: TestE20OverloadRecovery (262.75s)
            worker_test.go:381: T3g: killed worker pid 50452; parent CPU 67.046ms -> 67.069ms (+23µs) over 1.2s after the kill
    worker_test.go:427: T3o: with a busy parent T3g failed as it must: worker_test.go:383: T3g: parent CPU grew by 1.194875s in 1.2s after the kill (limit 150ms)
ok  	kortexshield/engine	322.491s
# exit status of go test: 0
# load at end: load averages: 5.38 4.49 4.28

$ shasum -a 256 ../kortex-shield-dev/out/step14-t5/wcp-80a49c991b2d.body
5c718716a795c0414b7c2500ebc1816dee4172ba094832f15bb6e1f5de2f2480  ../kortex-shield-dev/out/step14-t5/wcp-80a49c991b2d.body

# step-22 close-out Python suite at e8ed852d62e47b12085e42787f4e9a282a44bf83 (tracked files unchanged: 0 modified), 2026-11-28T02:46:31Z, Python 3.15.2, pytest 9.2.0, load at start: load averages: 5.86 4.63 4.33
$ .venv/bin/python -m pytest -q -rs
SKIPPED [1] tests/test_record_benign.py:9: could not import 'playwright': No module named 'playwright'
SKIPPED [1] tests/test_outcome.py:78: smoke run artifacts not present
SKIPPED [1] tests/test_outcome.py:96: smoke run artifacts not present
SKIPPED [1] tests/test_outcome.py:161: step-05 hard PL2 run output not present
186 passed, 4 skipped in 56.76s
# exit status of pytest: 0
# load at end: load averages: 3.71 4.34 4.25
```

The counts are those of F12. The fixture hash is the one reported in F12.
After C2 the Python suite is 201 passed, 0 failed, 4 skipped (below); the
Go suite was not run again after C2 because nothing under engine/ changed.

**C2. kortex_eval: the engine's own 413 and 415 answers are fail-closed
outcomes.** This changes kortex_eval, which rule 5 forbids; it was asked
for explicitly and answers the question raised after F9 (see Deviations).

What changed (commit 457de00):

- `kortex_eval/runner.py` writes a new field `engine_decision` in every
  responses.jsonl row: the decision named in a kortex engine answer
  ("block", "limit", "content-encoding", ...), else null. The whole
  response body must be the marker line `<status> kortex-decision=<name>`
  (optionally followed by details on the same line) and the status in
  front must be the response's own status. A backend page that quotes the
  marker, or a backend 413/415, gives null. Nothing else in the row
  changes; `blocked`, predictions.jsonl and run.json are as before.
- `kortex_eval/outcome.py` has two new outcomes, in blocking and in
  detection mode: `waf_fail_closed_413` (status 413 with decision `limit`)
  and `waf_fail_closed_415` (status 415 with decision `content-encoding`).
  The per-outcome counts the tool prints therefore show them on their own
  lines, apart from `waf_block` (403).
- A 413 or 415 without the marker stays `waf_pass` (it is the target's
  status, and "the verdict we measure is the WAF's decision"). So does
  every row of a responses.jsonl written before the field existed: old
  run files classify exactly as they did, and the figures in earlier
  reports are not changed by re-running the tool on them.
- `tools/step22_t3_summary.py` (the step-22 rate table) prints the two
  counts and includes them in the worst case. docs/block-discriminator.md
  and the README row for outcome.py name the new outcomes.
- Not changed: metrics, split, manifest validation, the block
  discriminator, `flagged` in predictions.jsonl (still 403 blocks only),
  and the 400 framing and 503 timeout/overload answers (still classified
  as before; see Questions).

Tests first (commit afb551c, then 457de00). 15 new test cases in
tests/test_outcome.py, tests/test_runner.py (against the local fake
server) and tests/test_step22_tools.py. No existing test was changed.

```
# step-22 C2 tests before the implementation, at 6463b2f... plus the new tests   (docs/logs/step22-c2-failing.log)
$ .venv/bin/python -m pytest -q tests/test_outcome.py tests/test_runner.py tests/test_step22_tools.py
FAILED tests/test_outcome.py::test_engine_413_limit_is_fail_closed_not_waf_pass[blocking]
FAILED tests/test_outcome.py::test_engine_413_limit_is_fail_closed_not_waf_pass[detection]
FAILED tests/test_outcome.py::test_engine_415_content_encoding_is_fail_closed_not_waf_pass[blocking]
FAILED tests/test_outcome.py::test_engine_415_content_encoding_is_fail_closed_not_waf_pass[detection]
FAILED tests/test_outcome.py::test_fail_closed_outcomes_are_named_and_distinct_from_block
FAILED tests/test_outcome.py::test_cli_counts_413_and_415_separately_from_403
FAILED tests/test_runner.py::test_engine_decision_recorded_for_engine_answers
FAILED tests/test_runner.py::test_engine_decision_is_null_for_answers_that_are_not_the_engines
FAILED tests/test_runner.py::test_runner_rows_classify_413_415_as_fail_closed
FAILED tests/test_step22_tools.py::test_t3_summary_counts_fail_closed_apart_from_blocks_and_in_the_worst_case
10 failed, 52 passed, 3 skipped in 47.04s
# exit status of pytest: 1

# step-22 C2 tests with the implementation   (docs/logs/step22-c2-passing.log)
$ .venv/bin/python -m pytest -q tests/test_outcome.py tests/test_runner.py tests/test_step22_tools.py
62 passed, 3 skipped in 47.14s
# exit status of pytest: 0

# step-22 close-out Python suite with the C2 change   (docs/logs/step22-closeout-pytest-after-c2.log)
$ .venv/bin/python -m pytest -q -rs
201 passed, 4 skipped in 56.99s
# exit status of pytest: 0
```

The five new cases that passed before the implementation are the ones
that pin behaviour which must not change (a 413/415 without the marker is
waf_pass, a decision must match its status, an nginx 413 with the marker
stays proxy_reject, an engine 403 block stays waf_block).

On real traffic: `STUB_PORT=13004 WCP_DATA_DIR=~/work/kortex-shield-dev/data
bash tools/run_step22_c2_outcomes.sh` (docs/logs/step22-c2-outcomes.txt;
durable files in docs/logs/runs/s22-c2-outcomes/, commit d5731c4).
In-process engine, PL1 and PL2, both wcp sets, one engine process and one
audit log per run, runner `--workers 1`, requests to `localhost`; rule 29
proof per run in the log. Manifest hashes c8ce11f2...1329d1 (v0) and
049b7dea...8b5c0 (v1) equal the committed MANIFEST.sha256 files.

```
== outcome counts (benign-labelled external traffic; every block or refusal is a potential false positive)
benign-wcp-v0 PL1 inprocess: n=20000 waf_block=2184 waf_deny_status=52 inconsistent=0 error=1 waf_fail_closed_413=28 waf_fail_closed_415=19 waf_pass=17716 other=0
    FP rate best case (errors, deny_status, inconsistent, fail-closed 413/415 not flagged) 2184/20000 = 10.92%; worst case (all flagged) 2284/20000 = 11.42%
    statuses: {200: 17716, 400: 52, 403: 2184, 413: 28, 415: 19, None: 1}
    engine_decision: {None: 17717, 'block': 2236, 'content-encoding': 19, 'limit': 28}
    outcome x status: error/None=1, waf_block/403=2184, waf_deny_status/400=52, waf_fail_closed_413/413=28, waf_fail_closed_415/415=19, waf_pass/200=17716
    rule 18: 2236 audit entries; rule ids in >=20% of them: 949110=2184, 932370=466
benign-wcp-v0 PL2 inprocess: n=20000 waf_block=8866 waf_deny_status=52 inconsistent=1 error=1 waf_fail_closed_413=28 waf_fail_closed_415=19 waf_pass=11033 other=0
    FP rate best case (errors, deny_status, inconsistent, fail-closed 413/415 not flagged) 8866/20000 = 44.33%; worst case (all flagged) 8967/20000 = 44.84%
    statuses: {200: 11033, 400: 52, 403: 8867, 413: 28, 415: 19, None: 1}
    engine_decision: {None: 11035, 'block': 8918, 'content-encoding': 19, 'limit': 28}
    outcome x status: error/None=1, inconsistent/403=1, waf_block/403=8866, waf_deny_status/400=52, waf_fail_closed_413/413=28, waf_fail_closed_415/415=19, waf_pass/200=11033
    rule 18: 8919 audit entries; rule ids in >=20% of them: 949110=8867, 931130=5853, 942430=4987, 942200=4269, 942370=3239, 942340=3087, 942330=1913, 932200=1834
benign-wcp-v1 PL1 inprocess: n=10000 waf_block=1091 waf_deny_status=25 inconsistent=0 error=0 waf_fail_closed_413=17 waf_fail_closed_415=0 waf_pass=8867 other=0
    FP rate best case (errors, deny_status, inconsistent, fail-closed 413/415 not flagged) 1091/10000 = 10.91%; worst case (all flagged) 1133/10000 = 11.33%
    statuses: {200: 8867, 400: 25, 403: 1091, 413: 17}
    engine_decision: {None: 8867, 'block': 1116, 'limit': 17}
    outcome x status: waf_block/403=1091, waf_deny_status/400=25, waf_fail_closed_413/413=17, waf_pass/200=8867
    rule 18: 1116 audit entries; rule ids in >=20% of them: 949110=1091
benign-wcp-v1 PL2 inprocess: n=10000 waf_block=4438 waf_deny_status=25 inconsistent=0 error=0 waf_fail_closed_413=17 waf_fail_closed_415=0 waf_pass=5520 other=0
    FP rate best case (errors, deny_status, inconsistent, fail-closed 413/415 not flagged) 4438/10000 = 44.38%; worst case (all flagged) 4480/10000 = 44.80%
    statuses: {200: 5520, 400: 25, 403: 4438, 413: 17}
    engine_decision: {None: 5520, 'block': 4463, 'limit': 17}
    outcome x status: waf_block/403=4438, waf_deny_status/400=25, waf_fail_closed_413/413=17, waf_pass/200=5520
    rule 18: 4463 audit entries; rule ids in >=20% of them: 949110=4438, 931130=2931, 942430=2466, 942200=2073, 942370=1558, 942340=1456, 942330=930, 932200=905
```

Outcome counts, benign-labelled natural traffic (rule 14: nothing merged;
rule 46: every block or refusal is a potential false positive),
denominator all samples, the one errored sample of v0 not flagged in the
best case and flagged in the worst case (rules 20, 21, 30):

| dataset | PL | waf_block (403) | waf_fail_closed_413 | waf_fail_closed_415 | deny_status (400) | inconsistent | error | waf_pass | best case | worst case (headline) | worst case before C2 (F9) |
|---|---|---|---|---|---|---|---|---|---|---|---|
| benign-wcp-v0 | 1 | 2,184 | 28 | 19 | 52 | 0 | 1 | 17,716 | 2,184 = 10.92% | 2,284 = 11.42% | 2,237 = 11.19% |
| benign-wcp-v0 | 2 | 8,866 | 28 | 19 | 52 | 1 | 1 | 11,033 | 8,866 = 44.33% | 8,967 = 44.84% | 8,920 = 44.60% |
| benign-wcp-v1 | 1 | 1,091 | 17 | 0 | 25 | 0 | 0 | 8,867 | 1,091 = 10.91% | 1,133 = 11.33% | 1,116 = 11.16% |
| benign-wcp-v1 | 2 | 4,438 | 17 | 0 | 25 | 0 | 0 | 5,520 | 4,438 = 44.38% | 4,480 = 44.80% | 4,463 = 44.63% |

- Every status-413 and status-415 answer of the four runs carries the
  engine marker and is classified fail-closed: 28 + 19 on v0, 17 + 0 on
  v1, none left in waf_pass, and waf_pass now equals the number of 200
  answers in each run. The tool's worst case is now the "every answer
  other than 200" column that F9 had to add by hand (2,284, 8,967, 1,133,
  4,480: equal in all four cells), so that extra column is no longer
  needed for the engine.
- Per sample against the F9 in-process runs of the same engine
  (docs/logs/step22-c2-vs-f9.txt: tools/step21_engine_diff.py plus the
  outcome transitions of every id): 0 status differences in the 60,000
  pairs of the four runs. The only outcome changes are waf_pass ->
  waf_fail_closed_413 (28, 28, 17, 17) and waf_pass -> waf_fail_closed_415
  (19, 19, 0, 0); every other sample keeps its outcome. So the change
  moved exactly the 413 and 415 answers and nothing else.

```
== benign-wcp-v0-inprocess-pl2: a = F9 run (docs/logs/runs/s22-t3-parity-after-followup/benign-wcp-v0-inprocess-pl2), b = C2 run (docs/logs/runs/s22-c2-outcomes/benign-wcp-v0-inprocess-pl2)
samples compared: 20000 (a=20000 b=20000 only-a=0 only-b=0)
status counts a: {200: 11033, 400: 52, 403: 8867, 413: 28, 415: 19, None: 1}
status counts b: {200: 11033, 400: 52, 403: 8867, 413: 28, 415: 19, None: 1}
status diffs: 0
-- outcome transitions a -> b (every sample id) and rule-id set differences:
   error -> error: 1
   inconsistent -> inconsistent: 1
   waf_block -> waf_block: 8866
   waf_deny_status -> waf_deny_status: 52
   waf_pass -> waf_fail_closed_413: 28   CHANGED
   waf_pass -> waf_fail_closed_415: 19   CHANGED
   waf_pass -> waf_pass: 11033
   rule-id sets differ on 1 of 20000 ids
      wcp-7b0bdeda7bc7: only a [] only b ['942130']; outcome a waf_block b waf_block
[the other three runs, same shape: 0 status diffs; v0 PL1 28 + 19 changed, v1 PL1 and PL2 17 changed; rule-id sets differ on 0, 0 and 1 id (wcp-bc05c8d4eb28, 942130 only in the F9 run)]
```

- Rule-id sets differ between the F9 and the C2 replay on 2 of 60,000
  ids, both by rule 942130 only and both blocked either way: the F1
  non-determinism, seen again.
- The one inconsistent sample is wcp-67cb71cd0c38 (v0 PL2, 403 without a
  qualifying audit score) and the one error is wcp-6b0bf5e43122 (v0, no
  status); both are the same ids as in F9.
- tools/step21_engine_diff.py was not changed: its "worst-case set" is
  still error + blocked + deny_status + inconsistent (2,237 above, not
  2,284). Its parity bar is the status diff, which covers 413 and 415. See
  Questions.
- Rule 18/24: PL2, both sets: 931130, 942430, 942200, 942370, 942340,
  942330, 932200 each on 20% or more of the audit entries, the same list
  as in F9 (949110 is the blocking evaluation rule). PL1 v0: 932370 on
  466 of 2,236. Not re-examined here.
- These are single replays. F1 applies: a request whose block rests on
  942130 or on one rule over a repeated key can differ between replays.

**C3. Flip reproducer on coraza v3.8.1, 5 x 500 rounds at PL2: 0 flips
per round.** `STUB_PORT=13004 WCP_V0_MANIFEST=~/work/kortex-shield-dev/data/benign-wcp-v0/manifest.jsonl
bash tools/run_step22_flip.sh 2 500 5 "localhost 127.0.0.1"`
(docs/logs/step22-flip-pl2.txt; rounds and engine events in
docs/logs/runs/s22-flip-pl2/). tools/flip_repro.py is unchanged: two wcp
samples (wcp-62cd1bd36bf7, wcp-b6f2246ef4b8, GET, blocked on the query at
PL2) replayed in a fixed order, 500 rounds, 5 repeats against one engine
process, as in step 20 (tools/run_step20_t1_flip.sh, which needs
`sha256sum` and a stub on port 13000 and so does not run here; the new
script is the same protocol on tools/step22_lib.sh). In-process engine
built from 457de00, coraza v3.8.1 (engine/go.mod), which is still the
newest coraza tag (`go list -m -versions github.com/corazawaf/coraza/v3`
on 2026-11-27 ends with v3.8.0 v3.8.1). Steps 19 and 20 sent the requests to
`127.0.0.1`; step 22 uses `localhost` because a numeric Host adds CRS
920350 to every request. Both were run.

```
== require github.com/corazawaf/coraza/v3 v3.8.1; github.com/corazawaf/libinjection-go v0.3.3 // indirect;
== manifest /Users/ivan/work/kortex-shield-dev/data/benign-wcp-v0/manifest.jsonl sha256 c8ce11f26406df96d55e5a1cc6186bcbf648cb29bd628081dd834c6ccf1329d1 (frozen: c8ce11f26406df96d55e5a1cc6186bcbf648cb29bd628081dd834c6ccf1329d1)
== engine binary sha256 be2217464eb640c97fb112b64aaf6992c8f93a183e2b92e69fd5b996ea717626 built from 457de00facc46a15736f9cbcb62562fa9d3b9e8c with go version go1.27.4 darwin/arm64
== flip-pl2-localhost rule29 2026-11-28T02:53:20Z load: load averages: 5.16 5.85 4.98: {"backend_url":"http://127.0.0.1:13004","rule_engine":"On","blocking_paranoia":2,"detection_paranoia":2,"max_body_bytes":13107200,"max_inspected_bytes":131072,"engine_time_budget_ms":2000,[trimmed],"allowed_methods":"GET HEAD POST OPTIONS",[trimmed],"worker_mode":false,[trimmed]}
host=localhost rep=1 :: rounds=500 flip_rounds=0 flips/round=0.0000 per_sample={'wcp-62cd1bd36bf7': 0, 'wcp-b6f2246ef4b8': 0} wall_s=3.7
host=localhost rep=2 :: rounds=500 flip_rounds=0 flips/round=0.0000 per_sample={'wcp-62cd1bd36bf7': 0, 'wcp-b6f2246ef4b8': 0} wall_s=3.3
host=localhost rep=3 :: rounds=500 flip_rounds=0 flips/round=0.0000 per_sample={'wcp-62cd1bd36bf7': 0, 'wcp-b6f2246ef4b8': 0} wall_s=3.7
host=localhost rep=4 :: rounds=500 flip_rounds=0 flips/round=0.0000 per_sample={'wcp-62cd1bd36bf7': 0, 'wcp-b6f2246ef4b8': 0} wall_s=3.6
host=localhost rep=5 :: rounds=500 flip_rounds=0 flips/round=0.0000 per_sample={'wcp-62cd1bd36bf7': 0, 'wcp-b6f2246ef4b8': 0} wall_s=3.6
host=127.0.0.1 rep=1 :: rounds=500 flip_rounds=0 flips/round=0.0000 per_sample={'wcp-62cd1bd36bf7': 0, 'wcp-b6f2246ef4b8': 0} wall_s=3.7
host=127.0.0.1 rep=2 :: rounds=500 flip_rounds=0 flips/round=0.0000 per_sample={'wcp-62cd1bd36bf7': 0, 'wcp-b6f2246ef4b8': 0} wall_s=3.5
host=127.0.0.1 rep=3 :: rounds=500 flip_rounds=0 flips/round=0.0000 per_sample={'wcp-62cd1bd36bf7': 0, 'wcp-b6f2246ef4b8': 0} wall_s=3.6
host=127.0.0.1 rep=4 :: rounds=500 flip_rounds=0 flips/round=0.0000 per_sample={'wcp-62cd1bd36bf7': 0, 'wcp-b6f2246ef4b8': 0} wall_s=3.5
host=127.0.0.1 rep=5 :: rounds=500 flip_rounds=0 flips/round=0.0000 per_sample={'wcp-62cd1bd36bf7': 0, 'wcp-b6f2246ef4b8': 0} wall_s=3.5
host=localhost all repeats: rounds=2500 rounds with a flip=0 flips/round=0.0000 statuses={'403': 5000}
host=localhost engine events wcp-62cd1bd36bf7-fliprepro: 1 distinct (decision, status, rule ids)
    x2500: block 403 rules=[trimmed: set-up and paranoia-level skip rules],942370,942430,[trimmed],949110
host=localhost engine events wcp-b6f2246ef4b8-fliprepro: 1 distinct (decision, status, rule ids)
    x2500: block 403 rules=[trimmed],942370,[trimmed],949110
host=127.0.0.1 all repeats: rounds=2500 rounds with a flip=0 flips/round=0.0000 statuses={'403': 5000}
host=127.0.0.1 engine events wcp-62cd1bd36bf7-fliprepro: 1 distinct (decision, status, rule ids)
    x2500: block 403 rules=[trimmed],920350,[trimmed],942370,942430,[trimmed],949110
host=127.0.0.1 engine events wcp-b6f2246ef4b8-fliprepro: 1 distinct (decision, status, rule ids)
    x2500: block 403 rules=[trimmed],920350,[trimmed],942370,[trimmed],949110
```

DIAGNOSTIC positive control (rules 34, 47; not asked for): the same script
with `FLIP_CONTROL=coraza370`, a scratch copy of engine/ in which only
go.mod differs (coraza v3.7.0, the version on which steps 19 and 20
recorded the flip). docs/logs/step22-flip-pl2-DIAGNOSTIC-coraza370.txt,
docs/logs/runs/s22-flip-pl2-DIAGNOSTIC-coraza370/.

```
== DIAGNOSTIC scratch engine sha256 184d29236b33dd1da5ce7dd7c035586b31097b15335b2ce02b260834017ac38f; .go files that differ from engine/: 0; diff of go.mod against engine/go.mod:
< require github.com/corazawaf/coraza/v3 v3.8.1
> require github.com/corazawaf/coraza/v3 v3.7.0
host=localhost rep=1: rounds=500 rounds with a 200 (flip)=175 flips/round=0.3500 statuses={'200': 188, '403': 812}
host=localhost rep=2: rounds=500 rounds with a 200 (flip)=170 flips/round=0.3400 statuses={'200': 181, '403': 819}
host=localhost rep=3: rounds=500 rounds with a 200 (flip)=144 flips/round=0.2880 statuses={'200': 158, '403': 842}
host=localhost rep=4: rounds=500 rounds with a 200 (flip)=153 flips/round=0.3060 statuses={'200': 170, '403': 830}
host=localhost rep=5: rounds=500 rounds with a 200 (flip)=166 flips/round=0.3320 statuses={'200': 177, '403': 823}
host=localhost all repeats: rounds=2500 rounds with a flip=808 flips/round=0.3232 statuses={'200': 874, '403': 4126}
host=127.0.0.1 rep=1: rounds=500 rounds with a 200 (flip)=123 flips/round=0.2460 statuses={'200': 132, '403': 868}
host=127.0.0.1 rep=2: rounds=500 rounds with a 200 (flip)=129 flips/round=0.2580 statuses={'200': 131, '403': 869}
host=127.0.0.1 rep=3: rounds=500 rounds with a 200 (flip)=137 flips/round=0.2740 statuses={'200': 145, '403': 855}
host=127.0.0.1 rep=4: rounds=500 rounds with a 200 (flip)=130 flips/round=0.2600 statuses={'200': 132, '403': 868}
host=127.0.0.1 rep=5: rounds=500 rounds with a 200 (flip)=108 flips/round=0.2160 statuses={'200': 112, '403': 888}
host=127.0.0.1 all repeats: rounds=2500 rounds with a flip=627 flips/round=0.2508 statuses={'200': 652, '403': 4348}
```

| engine | Host | flips per round, repeats 1 to 5 | rounds with a flip | answers |
|---|---|---|---|---|
| coraza v3.8.1 (current) | localhost | 0.0000, 0.0000, 0.0000, 0.0000, 0.0000 | 0 of 2,500 | 5,000 x 403 |
| coraza v3.8.1 (current) | 127.0.0.1 | 0.0000, 0.0000, 0.0000, 0.0000, 0.0000 | 0 of 2,500 | 5,000 x 403 |
| DIAGNOSTIC coraza v3.7.0 scratch build | localhost | 0.3500, 0.3400, 0.2880, 0.3060, 0.3320 | 808 of 2,500 | 4,126 x 403, 874 x 200 |
| DIAGNOSTIC coraza v3.7.0 scratch build | 127.0.0.1 | 0.2460, 0.2580, 0.2740, 0.2600, 0.2160 | 627 of 2,500 | 4,348 x 403, 652 x 200 |

- A flip is a round in which at least one of the two samples was answered
  200. flip_repro.py itself counts every answer other than 403; here the
  two definitions agree, since all 20,000 answers are 403 or 200 (no 503,
  no error).
- On v3.8.1 the status never changed and neither did the matched rules:
  one rule-id set per sample in 2,500 replays, on each Host form
  (wcp-62cd1bd36bf7: 942370 and 942430; wcp-b6f2246ef4b8: 942370). On the
  v3.7.0 control (Host localhost) wcp-62cd1bd36bf7 has 4 distinct event
  shapes (block on both rules x1,715, block on 942370 only x321, block on
  942430 only x61, pass x403) and wcp-b6f2246ef4b8 has 2 (block x2,029,
  pass x471).
- PROVEN that this reproducer detects the flip on this host: the control
  differs from the measured engine in the coraza version only and flips in
  627 to 808 of 2,500 rounds. Had the reproducer been unable to see a flip
  here, the control would have shown 0 as well.
- Rule 49, unchanged from F1: the flip of these two samples is fixed
  empirically by the v3.7.0 -> v3.8.1 bump; the changed code is not
  identified. This result does not cover F1: coraza v3.8.1 still matches
  non-repeatably on other requests (942130 chain order, repeated keys).
- Step 20 measured a median of 114 of 500 on v3.7.0 on the Ubuntu host
  (0.23 per round, Host 127.0.0.1); here the 127.0.0.1 control gives 108
  to 137 of 500. Comparison across hosts only; not a claim.
- Both runs were made twice. The first pair (docs/logs/step22-flip-pl2-run1.txt,
  docs/logs/step22-flip-pl2-DIAGNOSTIC-coraza370-run1.txt) was made before
  the script compressed the events files: v3.8.1 0 of 2,500 on both Host
  forms; control 774 and 562 of 2,500. The tables above are the second
  pair, made with the committed script.
- Load during C3 was 5 to 13 (a headless Chromium process not started by
  me used 3 to 7 cores). C3 measures statuses, not timings; no answer was
  a 503.

**C4. Pre-push scan for the close-out (rule 51).** Nothing was pushed;
the five close-out commits before this one were scanned as a range and
this commit as staged content.

```
$ git fetch origin; git log --oneline -1 origin/main
e8ed852 step-22: F12 follow-up report, baseline v1.7 follow-up section, ...
$ bash tools/prepush_scan.sh --range origin/main..HEAD; echo "exit=$?"
[trimmed: 9 "large file" notes, all under docs/logs/runs/s22-c2-outcomes/; largest benign-wcp-v0-inprocess-pl2/outcomes.jsonl (3734663 bytes)]
prepush: OK, 59 blob(s) in origin/main..HEAD scanned
exit=0
$ git add docs/acceptance.md docs/baseline-v1.7.md reports/step-22.md docs/logs/step22-c2-vs-f9.txt
$ bash tools/prepush_scan.sh; echo "exit=$?"
prepush: OK, 4 staged path(s) scanned
exit=0
```

The committed run files hold ids, statuses, timings, outcomes, scores and
rule ids only. Raw engine audit logs and parsed audit.jsonl (which quote
request data) stayed under gitignored out/. Commits of the close-out,
oldest first: 6463b2f (C1), afb551c and 457de00 (C2 tests, then code),
5132e59 (C3), d5731c4 (C2 runs on the wcp sets), and the commit that
holds this report.

- Deviations from instructions:
  - The run scripts committed earlier in the step (T3, T4, T5, T2) could not
    run on this host as written (`setsid`, `/tmp/stub200.py`, `/tmp`
    evidence paths, `/proc`, source addresses 127.0.0.2-10). They were
    rewritten around tools/step22_lib.sh, with tools/stub_backend.py as the
    backend. Whether `/tmp/stub200.py` behaved like tools/stub_backend.py is
    UNVERIFIED (that file is not in the repository).
  - Script defects fixed before the runs: the padding script labelled half
    of each run with the wrong paranoia level (now `--pl`); the encoding
    script reused one sample id for two content types and sent two Host
    headers in the chunked cells (first run: 12 connection resets, not
    counted); the T4 script dropped the manifest fields the runner requires;
    the T3 script did not pass the engine's block marker and produced no
    outcomes.jsonl.
  - First T3/T4/T5 runs used a numeric Host and are replaced by the
    `localhost` runs. Kept from them: two outcomes.jsonl + run.json under
    docs/logs/runs/s22-numeric-host/ as the evidence for the artifact. The
    raw matched-rule lists of those first runs (920350 on all 4,615 audit-
    logged requests of the v1 PL2 run) were overwritten by the re-run and
    are not available.
  - A first T4 run is INVALID for timing (a Go build ran during it). Its
    statuses and rule-id sets were identical per id to the valid run
    (0 diffs at both levels); it was discarded, not committed.
  - T2 `all` run: stopped after four cells by a NameError in my change to
    the mixed cell (the pre-attack check was inserted twice in one function
    and not at all in the other). The four finished cells are kept; in them
    the pre-attack probe ran twice. The remaining three cells were run
    with the fixed script (`rest`).
  - T2 benign probe changed (Host localhost, browser User-Agent, pre-attack
    check, statuses recorded). The re-run is therefore not the same
    experiment as the first recording in three ways at once: probe, clamp,
    host.
  - T2 ran in a container on a Colima VM on a shared Mac, not on a Linux
    host. Docker was installed without Homebrew or admin rights (see top).
  - DIAGNOSTIC runs added that the scripts did not have: T5 cells F-J, T3
    DIAGNOSTIC A (coraza v3.7.0 scratch build) and B (rule-id set
    stability), T2 benign-shape DIAGNOSTIC. None produces a baseline number.
  - Rule 42 vs rule 51: the parsed audit.jsonl of the wcp runs quotes
    request data, so it is not committed. Each run directory holds
    responses.jsonl, outcomes.jsonl, run.json and a body-less
    audit.index.jsonl instead; the raw audit logs exist only under
    gitignored out/ on this machine.
  - benign-wcp-v0: data/benign-wcp-v0/README.md says the current builder
    reproduces the manifest byte for byte. It does not (hash 39830d0a...);
    the builder at 71cb753 does. README not edited (frozen dataset folder).
  - Suites: the with-fixture Go run is not green (2 FAIL). It is reported
    as is; the three DIAGNOSTIC test runs A-C were added to explain it.
  - Rule 8 (one commit per task): the step has 24 earlier commits; the work
    of this session is committed as one commit per task id.

  - Follow-up work (sections F1 to F12), added after the first push:
    - Several follow-up runs overlapped on this shared host: the
      ModSecurity/connector runs (F2) ran while the E20 timings, the first
      cell-G engine run, the T5 re-run and the parity re-run were going
      on (load 4 to 12 in the F2 log). Status results are not affected by
      design; the connector timeouts in F2 and the two 503s of the T5
      re-run may be. The T2 cells, the variance runs and the final suites
      ran one at a time.
    - E20 timing: during the first three repeats port 13000 was answered
      by the compose `target` container (Juice Shop), not by
      tools/stub_backend.py, and the script file was edited while it ran
      (both noted in docs/logs/step22-e20-timing.txt). The backend takes
      no part in the measured call. Host engine runs now take their stub
      port from `STUB_PORT`.
    - The first cell-G engine run shared stub port 13000 with other jobs;
      it was discarded and redone with its own stub on port 13003.
    - The first cell-G search (first pass of this step) only appended
      spaces to the payload, which is why it found no stream. The new
      search (seeded filler words, Z_HUFFMAN_ONLY) is my own design.
    - F10 adds DIAGNOSTIC cells that were not in my plan when I started:
      clamp and probe reverted together, the commit before T3p, and two
      repeats of mixed-eight on each side of T3p.
    - E20's wait was raised from 120 s to 480 s and T3g now runs in its
      own process. Both change a test (rule 5); done because the user
      asked for the two failing tests to be fixed. Assertions and limits
      are unchanged, and T3o is the canary that T3g still fails when it
      should.
    - reports/step-21.md and data/benign-wcp-v0/README.md were amended
      (additions only; the manifest is untouched), as asked.
    - docs/logs/wcp-baseline-breakdown.json was removed from the tree; a
      copy is kept under gitignored out/ on this machine.
    - The engine variance diagnostic (F1) was run more than once while
      the script was being finished; the log and the status files hold
      the last run and F1 quotes that run. The counts differ from run to
      run by the nature of the defect (an earlier run had 104 blocked and
      96 passed for the same request; this one 131 and 69).
    - The coraza non-determinism is classified BUG and not fixed, with no
      failing test in the suite (rule 39 says "we fix it, test first").
      The fix is inside the dependency; see Questions.
    - Rule 8: the follow-up is one commit per task, 9 commits before this
      report was extended and the rest listed in the pre-push block.
  - Close-out (sections C1 to C3):
    - Rule 5: kortex_eval was changed (runner: one new field per row;
      outcome: two new outcomes). Done because it was asked for
      explicitly. No existing test was changed or removed; responses.jsonl
      files written before the change classify as before.
    - C2 goes beyond kortex_eval in two places: tools/step22_t3_summary.py
      now counts the two outcomes in its worst case, and the four wcp runs
      of C2 were not asked for (they show the counts on real traffic).
    - C3: the v3.7.0 positive control and the second Host form
      (127.0.0.1) were not asked for. The control is DIAGNOSTIC and gives
      no baseline number.
    - C3 was run twice; the reported run is the second (see C3). Rule 13
      (container force-recreated) does not apply to the host engine; each
      Host form had a fresh engine process, and the 5 repeats of one Host
      form share it, as in step 20.
    - Work done in a second checkout; wcp manifests and the fixture body
      read from the first checkout after a hash check.
    - Rule 8: C2 has three commits (failing tests afb551c, implementation
      457de00, real-traffic run d5731c4); C1 6463b2f; C3 5132e59.

- UNVERIFIED items (state after the follow-up; items closed there are
  listed at the end):
  - The step-22 task brief itself (not in the repository): task ids, the
    k values and the cell design are taken from commit messages and script
    headers.
  - The cause of the 6 ids blocked now but not in steps 18/19 (HYPOTHESIS
    above).
  - How much the coraza non-determinism moves recall or false-positive
    figures on the attack and benign sets (F1: NOT MEASURED; in the parity
    runs it moved 0 statuses and 3 rule-id sets in 60,000 pairs, in each
    of the two parity runs).
  - Whether a compressed attack body with no byte below 32 is refused at
    PL2 (F3: no such stream found), and what the connector answers to
    cell K with a content type its policy allows (F2b: NOT MEASURED).
  - Why the connector's rule-id sets are larger than ModSecurity's on the
    same blocked requests (F2: HYPOTHESIS), and whether the six new
    connector timeouts come from host load (NOT MEASURED).
  - What made the first T2 recording's mixed-one cell 105/301. Clamp and
    probe are ruled out on this host (F10); the host is the HYPOTHESIS
    left, and the engine commit of that recording is not recorded.
  - Host-side load during the T2 cells (shared machine; only in-VM load was
    recorded).
  - Whether any credential shape in the 27 cleanup-list paths is live.
  - Why the abandoned in-process call takes 260 to 280 s on this host and
    the step-17 host finished its suite in 54.3 s (F5: the coraza version
    is ruled out).
  - Whether the two 503s of the PL2 padding re-run come from host load.
  - Close-out: whether any backend used in earlier steps (Juice Shop)
    ever answered with a body that is exactly a kortex marker line; the
    runner would then record an engine decision for it. Not checked; the
    stub backend used in step 22 cannot.
  - Close-out: port 13000 was held during C2 and C3 by a
    tools/stub_backend.py process started from the first checkout at
    10:55 local time (pid 22470, `ps` and `lsof` after the runs). It was
    not used and was left running; who still needs it is not known.
  - Close-out: the Go suite was not re-run after C2 (no file under
    engine/ changed).
  - Closed in the follow-up: the rule-id set variance (F1, PROVEN); the
    missing 920450 / 920350 audit messages (F7, BUG fixed); cell G (F3);
    the E20 duration (F5); T3g's CPU reading in the suite (F6, fixed and
    the with-fixture suite is green); the modsec-connector comparison
    (F2); the connector PL2 decomposition (F4).

- Questions for instructor (state after the follow-up):
  - Coraza non-determinism (F1, F2b). A request that rests on CRS 942130
    can be passed or blocked at random, in the engine and in the connector
    image. Options: (a) carry a patched coraza (sorted iteration of map
    collections in internal/collections/map.go, a small patch, tested in
    F1 as the `sorted` build) via a
    `replace` in go.mod; (b) report it upstream and wait (the cache half is
    already fixed on coraza main by PR #1682, the order half is not);
    (c) accept and document. With (a) the engine stops being
    "stock coraza v3.8.1" and parity against the connector at rule-id
    level can no longer be exact. Which?
  - 942130 itself: on ModSecurity the tautology passes whenever a harmless
    `a=b` member follows it (F2b). That is a CRS rule weakness, not ours.
    Report it to the CRS project?
  - History rewrite for the 27 paths: the dry run is in F11. It changes
    every commit id, removes 21 files that are in the tree today, and
    leaves 14 other paths that still fail the scan over history. Go
    ahead as is, extend the list first, or leave history alone? Nothing
    was force-pushed.
  - ANSWERED in the close-out (C2): kortex_eval now has outcomes for the
    engine's own 413 and 415 answers. Left open by that change:
    (a) the engine's 400 framing and 503 timeout/overload answers are
    still classified as before (waf_pass unless another rule applies);
    give them fail-closed outcomes too? (b) tools/step21_engine_diff.py
    keeps its four worst-case classes; add the two fail-closed classes
    (that changes strings its existing tests assert)? (c) should
    predictions.jsonl `flagged`, which feeds kortex_eval.report, stay
    "403 block only"?
  - E33 answers 415 and does not decode. Decoding gzip/deflate before
    inspection is the alternative (the 19 benign gzip samples of
    benign-wcp-v0 would then be inspected instead of refused). Wanted?
  - Cell K: compressed bytes without a Content-Encoding header pass at
    PL1 on the engine (F3). A backend that sniffs and decompresses would
    be exposed; one that follows the header is not. Add a magic-byte
    check, or out of scope?
  - Refusals after T3p still cost about one core against an unpaced
    attacker (F10). Is a real per-address rate limit (connection level)
    in scope for the engine, or left to the layer in front?
  - Eight attacker addresses still cost benign POSTs in mixed-eight (pool
    reaches 0; F10). Accept, or raise pool/spares for the shipping config?
  - Carried from step 21: flip worker mode to default? Keep the two
    cannot-tell telemetry blobs labelled as is?
  - Answered by the follow-up request and done: the T3g and E20 test
    fixes, the breakdown file, the step-21 amendment, the benign-wcp-v0
    README correction, the engine's own Content-Encoding check.
