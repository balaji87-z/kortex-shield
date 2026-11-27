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

- Summary: worker mode matches in-process on both wcp sets at PL1/PL2 (60,000 samples,
  0 diffs); no padding or encoding evasion on engine or connector; numeric-Host artifact
  PROVEN, removed; T2 cells re-run in a container. Go suite with wcp fixture: 2 FAIL (E20, T3g).

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
| T4 FP decomposition from existing runs | partial: connector PL2 NOT MEASURED | docs/logs/step22-t4-fp-decomposition.txt |
| T5 padding extension (k = 8, 32, 120000 B) | done, engine and connector | docs/logs/step22-t5.txt, step22-t5-connector.txt |
| T5 Content-Encoding / Transfer-Encoding probes | done, engine and connector; one cell NOT MEASURED | same |
| T6 docs | done | docs/baseline-v1.7.md, docs/engine-design.md, docs/acceptance.md, README.md |

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

- UNVERIFIED items:
  - The step-22 task brief itself (not in the repository): task ids, the
    k values and the cell design are taken from commit messages and script
    headers.
  - Why the logged rule-id set of a blocked request varies between replays
    (3 ids in the parity runs; 941340, 942120, 942210, 942130).
  - Why the engine's audit log has no 920450 / 920350 message while the
    rules score and appear in the matched-rule list.
  - The cause of the 6 ids blocked now but not in steps 18/19 (HYPOTHESIS
    above).
  - Whether a compressed attack body free of NUL/CR/LF bytes is blocked
    (cell G NOT MEASURED).
  - What separates the first T2 recording from the re-run for the mixed
    cells (clamp, host or probe).
  - Host-side load during the T2 cells (shared machine; only in-VM load was
    recorded).
  - Whether any credential shape in the 27 cleanup-list paths is live.
  - How long the abandoned in-process call on the wcp fixture body takes on
    this host (E20 gives only "more than 120 s"), and why it is slower than
    on the step-17 host.
  - That the 5.976 s of parent CPU in T3g's window in the suite run is the
    five fixture tests' abandoned calls (HYPOTHESIS; one such call PROVEN).
  - The modsec-connector comparison remains not re-run since step-13
    (carried standing note). Connector PL2 FP decomposition NOT MEASURED.

- Questions for instructor:
  - The Go suite with the wcp fixture has 2 failing tests on this host (E20,
    T3g; see "Suites on this host"). T3g: may it be changed so that it does
    not count CPU of abandoned in-process calls left by earlier tests (for
    example run it in its own test process, or wait for those calls to
    end)? E20: raise its 120 s wait, mark it host-dependent, or retire the
    test? I changed neither (rule 5).
  - History rewrite for the 27 paths of
    docs/logs/step22-history-cleanup-list.txt: go ahead, and by whom?
  - docs/logs/wcp-baseline-breakdown.json (7.4 MB, over the 5 MB limit; its
    gzip fails the scan on email=72 and jwt=4 shapes): strip, replace by a
    body-less summary, or allowlist?
  - Step-21 T3/T4 numbers were recorded with the numeric Host. Amend the
    step-21 report (287/402 -> 286/402 at PL2), or leave it with a pointer
    to this report?
  - Should the engine fail closed on Content-Encoding by its own check
    rather than rely on CRS 920450, or decode gzip/deflate bodies before
    inspection? Today it does neither on its own.
  - The mixed cells and the kill storm show unpaced refusals costing 560 to
    576 CPU-seconds in 300 s. Add a per-address rate limit on refusals, or
    is that out of scope for the engine?
  - Eight attacker addresses still cost 9/300 and 7/301 benign POSTs
    (pool reaches 0). Accept, or raise pool/spares for the shipping config?
  - data/benign-wcp-v0/README.md reproducibility sentence: may it be
    corrected to name the 71cb753 builder (README only, manifest untouched)?
  - Carried from step 21: flip worker mode to default? Keep the two
    cannot-tell telemetry blobs labelled as is?
