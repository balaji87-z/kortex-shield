# Acceptance tests: what "industry standard" means for this project

Each row is a bar taken from a source we read, turned into a test we can run.
Numeric targets are left open on purpose. They are set after the baseline run,
because only the baseline tells us what a number means on our data.

Status values: `not started`, `in progress`, `passing`, `failing`.

| ID | Bar | Source | Test | Pass condition | Status |
|---|---|---|---|---|---|
| A1 | Rule-engine compatibility | CRS engine-options page: Coraza passes 100% of the CRS v4 test suite; ModSecurity v3 fails 2-4% | Run the CRS regression suite against our build | 100% of the suite | not started |
| A2 | Efficacy at independent-test scale | SecureIQLab 2026: 1,608 attack and 1,487 legitimate scenarios, covering OWASP Top 10, API Top 10, L7 DoS, bots | Build our own suite of at least that size, with recorded provenance and held-out attack families | At least 1,600 attack and 1,400 legitimate scenarios; recall and false positive rate reported per family with counts and 95% intervals; targets set after baseline | in progress — attack side: attacks-v0 frozen (1,054 attack samples, 527 distinct payloads × 2 injection points, 4 families, public payload lists with provenance) plus step-14 carrier/encoding expansions frozen (attacks-ct-v0: 320 samples = 40 payloads × 8 carriers; encoding-diff-v0: 192 samples = 16 payloads × 6 encodings × 2 carriers; both derived from attacks-v0 payloads, both derived from attacks-v0 payloads already inside the 527 distinct payloads, so the distinct-payload count is unchanged at 527) — **546 samples short of the 1,600 bar on distinct payloads**; benign side: benign-browse-v0 frozen (214 natural browsing requests), benign-hard-v0 frozen (180 hand-authored hard benign), benign-browse-v1 frozen (774 requests, 60 sessions) and benign-wcp-v0 frozen (20,000 external openappsec-WCP requests, out-of-sample) — the 1,400-legitimate bar is met in count by WCP (20,000), but those requests are third-party browsing replayed against a stub backend, not one app's traffic, and the set is vendor-labelled and audited only at 100 (rule 26), so it is reported separately, never merged (rule 14); benign rates reported separately (rule 14), never merged; no recall/FPR targets set yet |
| A3 | Parser fidelity | WAFFLED (arXiv 2503.10846): 1,207 bypasses across 5 WAFs via multipart, JSON and XML parsing differences | Replay WAFFLED-style body mutations against our proxy in front of each target framework | Zero parsing-discrepancy bypasses on frameworks in scope; the list of frameworks is fixed before testing | not started |
| A4 | PCI DSS 4.0.1 req. 6.4.2 | BDO PCI 4.0 summary | Check that the product sits in front of the app, generates audit logs, and either blocks or raises alerts that are investigated | Audit logs present for every decision; block mode and alert mode both work | not started |
| A5 | Safe rollout | CRS 4 scoring guidance: detection mode for at least a week before blocking | Shadow mode that logs the verdict without enforcing it | Switching modes needs no code change and is itself logged | not started |
| A6 | Latency | Not taken from a source; we set this ourselves | p50 and p99 added latency under load, measured against the no-WAF control | Target set after baseline | not started |
| A7 | Failure behaviour | Not taken from a source; we set this ourselves | Kill the engine; confirm per-site fail-open or fail-closed works as configured | Behaviour matches configuration | not started |
| A8 | Reproducibility | Our own rule | Every reported number can be regenerated from the manifest and one command | One command reproduces each table | in progress — the command chain (runner → docker logs → crs_audit → outcome → report/breakdown) exists and was proven on the smoke run, the 1,054-sample attack runs and the 214/180-sample benign runs; step-12 re-ran all 16 small-dataset parity cells plus the wcp-train TEST PL1 cell (514 = 514, identical id sets) and the full 13,261-row cookie-restored runs from committed scripts with per-run rule-29 proofs; breakdowns in docs/baseline-v0.md…v0.7 regenerate via tools/attack_breakdown.py, tools/benign_breakdown.py and tools/benign_clusters.py; step-13 re-ran both full-scale WCP cells (PL1/PL2, 20,000 samples each) from committed scripts with per-run rule-29 proofs, and the T4 bisect / T6 swap / T7 latency tables regenerate via tools/run_step13_t4_bisect.sh, tools/run_step13_t6.sh and tools/run_step13_t7*.sh |

## Scope decisions to make before testing

- Which of the bot and L7 DoS categories in A2 do we cover? A single proxy node is
  not a global network. We did not find a source describing how those categories
  are scored, so this decision is ours.
- Which web frameworks are in scope for A3.
- Whether to pursue ICSA Labs certification. We could not retrieve its criteria;
  get them from icsalabs.com before deciding.

## Not verified

Gartner evaluation criteria, ICSA Labs criteria, the original SecureIQLab report
(we saw only vendor and distributor summaries that disagree with each other).

## Step-15 engine acceptance tests (rule 37)

| id | behaviour | status |
|----|-----------|--------|
| E1 | conflicting or duplicate Content-Length rejected (400, kortex-decision=framing, not proxied) | passing |
| E2 | Transfer-Encoding with Content-Length rejected (400, framing) | passing |
| E3 | raw NUL in path or query rejected (400, framing) | passing |
| E4 | body over inspected limit rejected 413 (kortex-decision=limit, not passed to engine, event logged) | passing |
| E5 | body exactly at the limit inspected (reaches engine and stub) | passing |
| E6 | time budget expiry returns 503 (kortex-decision=timeout, event logged with sample id) | passing |
| E7 | known SQLi in query blocked at PL1 (403, kortex-decision=block) | passing |
| E8 | benign request passed to the stub backend (200 stub-ok) | passing |
| E9 | /__kortex/config unreachable from non-loopback, JSON config on loopback | passing |

Status recorded at commit time of the tests (go test ./... build failure:
undefined: buildHandler, undefined: loadConfig).

Passing evidence (step-15): `go test -buildvcs=false -count=1 -timeout 90s -v .`
in engine/ -> `ok  kortexshield/engine 0.545s`, 9/9 PASS (E1..E9);
binary verification in docs/logs/step15-t5-verify.txt (403 block with 942100,
413 limit + event, loopback config JSON, audit log parsed by kortex_eval
crs_audit, exit 0). Re-run 2026-11-20 after the gated-listener test-harness
fix: `ok kortexshield/engine 0.288s`, 9/9.

Step-15 T6 evidence (DIAGNOSTIC, docs/logs/step15-t6-analysis.txt): per-sample
blocked-set diff of the engine skeleton vs the Coraza connector on smoke,
attacks-v0, benign-browse-v1, benign-hard-v0 and attacks-ct-v0 at PL1/PL2 —
diffs 1/1/65/16/60/150/23/51/25/4 (engine-only vs ref-only splits in
docs/engine-evidence.md). Scope caveat on E6 (2026-11-20, PROVEN):
docs/logs/step15-t4-skeleton-replay.txt shows the 2,000 ms budget does NOT
interrupt a single-shot body-processing call (481,798-byte body ran
41.8-43.5 s, ended in a normal 403); E6's pass covers budget expiry at phase
boundaries only. The default 131,072-byte inspection cap rejects such bodies
with 413 in ~1-3 ms.

Step-16 T2 acceptance tests (rule 40: committed FAILING before the fix;
failing evidence docs/logs/step16-t2-failing-tests.txt, 8/8 FAIL):

| id | claim | status |
|----|-------|--------|
| E10 | engine matches the connector on the attacks-v0 step-15 T6 JSON diff ids (PL1 65 ids, PL2 16 ids incl. the two former UA-artifact ids; data-driven parity tables in engine/step16_test.go) | failing pre-fix |
| E11 | malformed JSON body denied 400 like the connector (image rule 200002) | failing pre-fix |
| E12 | JSON body with >= 1000 arguments denied 400 like the connector (image rule 200007) | failing pre-fix |
| E13 | text/xml traversal body blocked via the XML processor (image rule 200000 -> 930110), not via mangled ARGS_NAMES rules | failing pre-fix |
| E14 | engine matches the connector on the benign-hard-v0 JSON diff ids (PL1 23, PL2 51) | failing pre-fix |
| E15 | engine passes the benign-browse-v1 PL2 engine-only JSON ids (90) | failing pre-fix |

Excluded from the tables on purpose: the 60+60 benign-browse 920420 ids
(DESIGN C4), the attacks-ct 920420 ids (DESIGN C4), smoke trav-01
(DESIGN front proxy). The attacks-v0 PL2 command-injection-036c522d-q/-login
exclusion was LIFTED after the T2 re-run proved the T6 engine-only blocks
were the missing-User-Agent harness artifact (920320 +2): both ids now sit
in wantAttacksV0PL2 expecting pass, and the parity tests send the same
User-Agent and Host the runner sends on both sides.

Step-16 T2 post-fix status: E10-E15 all PASS; go test 19/19 (E1-E9,
E10 PL1/PL2, E11-E17). The re-run diff table (docs/logs/step16-t2-analysis.txt):
146 differing ids, all DESIGN (144 C4 + 2 front-proxy cells), zero BUG,
zero UNEXPLAINED.

Step-16 T3 acceptance test (rule 40: committed FAILING before the fix;
failing evidence in the commit message run below):

| id | claim | status |
|----|-------|--------|
| E16 | a body whose processing exceeds the time budget is answered 503 kortex-decision=timeout within budget+500ms (481,798-byte wcp body, inspection cap raised to 13,107,200; fixture read from KORTEX_TEST_WCP_BODY, skipped when unset — recorded content is not committed, rule 25) | failing pre-fix: 403 after 44.1 s |

Step-16 T3 acceptance test (rule 40: committed FAILING before the fix;
failing evidence docs/logs/step16-t3-e17-failing.txt):

| id | claim | status |
|----|-------|--------|
| E17 | the abandoned body-processing call owns the transaction: after a 503 timeout the handler's deferred tx.Close() must NOT kill the in-flight call (pre-fix the call "finished" at budget+12 ms with a stale 949110/403 while the unfettered call needs ~42 s, measured 403 at 42.41 s with a 60 s budget) | failing pre-fix; passing after the ownership fix (39324c9) |

Step-17 acceptance tests (rule 40: committed FAILING before the
implementation; failing evidence in commit 460eed7, implementation 559d9b6):

| id | claim | status |
|----|-------|--------|
| E18 | PUT/DELETE/PATCH are rejected 403 kortex-decision=block with 911100 under the default method policy, and pass to the backend when KORTEX_ALLOWED_METHODS includes them | passing |
| E19 | when the in-flight body-processing cap is reached, a further body-bearing request is answered 503 kortex-decision=overload within 50 ms and the decision is logged to the events file | passing |
| E20 | after the abandoned calls finish, new body-bearing requests are inspected again (no overload) | RETIRED as the availability/CPU claim in step-21 in favour of T3g; E20's failure on this host was PROVEN pre-existing (reproduced identically on pre-worker commit 763f8dd, docs/logs/step21-e20preworker.log) and NOT a worker-code regression. T3g (bounded CPU after kill, measures whole process tree and asserts the killed worker PID no longer exists) PASS on go1.25.0, full engine suite ok kortexshield/engine 440.425s. E20 test kept passing (in-process mode still supported/default); the availability/CPU property the system relies on is now T3g |
| E21 | a body-less benign request on a cap-reached engine still returns promptly (<= 500 ms) | passing |

Step-17 status evidence (current host, go 1.25.0): `go test -buildvcs=false
-count=1 -timeout 900s -v .` in engine/ with KORTEX_TEST_WCP_BODY set ->
`ok kortexshield/engine 54.300s`, 23/23 PASS (E1-E21 incl. PL1/PL2
variants), 0 FAIL, 0 SKIP. Without the fixture env the E16/E17/E19/E20/E21
tests skip by design (recorded content is not committed, rule 25).

Step-18 acceptance tests (rule 40: committed FAILING before the
implementation; failing evidence in commit <sha>, implementation <sha>):

| id | claim | status |
|----|-------|--------|
| E22 | a client still streaming a body above the inspected limit receives the full 413 response (status 413 and kortex-decision=limit marker, clean EOF close), not a connection reset (reproduces the step-17 T4 ConnectionResetError ids wcp-1140885081e1 / wcp-f83f7556fc66 / wcp-908ef72be103) | failing pre-fix: read reset after 184 bytes; passing after the bounded-drain fix (e198ead) |
| E23 | (T4) a text/plain body whose SQLi payload spans the '&'-split boundary is blocked like the connector-side carriers (942100 on the raw body) | failing pre-fix: 200 stub-ok |
| E24 | (T4) octet-stream and unknown-content-type bodies with the same split-destroying RCE payloads are inspected as one raw value (932125/932380 PL1; 932240 PL2) | failing pre-fix: 200 stub-ok |
| E25 | (T4) the '&'-split behaviour on urlencoded bodies is unchanged (split-safe payload still blocked via the parsed ARGS targets) | passing pre- and post-fix (regression guard) |
| E26 | (T4 scope) CRS 921150 (CR/LF in argument NAMES) must not fire through the added REQUEST_BODY target: a text/plain body whose split fragments are newline-free but whose raw body carries CRLF must pass (first E26 scenario — a body with no '='/'&' — is blocked even PRE-fix via the split itself and was replaced) | failing pre-scope-fix: 403 with 921150 on REQUEST_BODY; passing after the 921 exclusion (166 updates) |
| E27 | (step-19 T1) every evaluated request leaves a decision event in kortex-events.jsonl — "block" with matched rule ids or "pass" — so a silent engine error can never look like a pass | passing (was written test-first in step-19) |
| E28 | (step-19 T1) optional coraza debug logger via KORTEX_CORAZA_DEBUG_LEVEL/KORTEX_CORAZA_DEBUG_FILE for divergence capture | passing (test-first) |
| E29 | (step-19 T3, rewritten step-20 T2) while the small lane's slots are all held (8 attackers, deterministic KORTEX_TEST_HOLD_BODY_MS hook per rule 48), a probe observes 503 while the lane is full AND a benign SMALL POST is then served (non-503 + backend hit) — size-class lanes make the benign path survive an attacker-large slow-body attack | FAILING BY DESIGN pre-lanes (commit 9f252d7); PASSING after lanes (commit 71d3aec); large-lane run 269/269 benign POSTs served, small-lane residual exposure 6/276 (documented) |
| E30 | (step-20 T1) a duplicate-name request (two same-named `filter` params with DIFFERENT values, wcp-62cd1bd36bf7) gives the SAME outcome on every one of 2000 replays with runtime.GC() between rounds; zero flips required (a flip is a 200 pass-through; 503 timeouts are counted separately and must stay <= N/10 — amended after a load-contaminated run miscounted timeouts as flips, rule 48) | failing pre-fix on coraza v3.7.0: 48/2000 rounds passed (docs/logs/runs/s20-t1-e30/e30-pre-v370.log, worktree 83fbebd); passing after the v3.8.1 bump: blocked=2000 flips=0 timeouts=0 of 2000, 58.6s (docs/logs/step20-gotest.txt) |

Step-21 acceptance tests (rule 40: committed FAILING-BY-DESIGN before the
implementation; failing evidence in commit ba365d5 for E31 and a699174 for
T3a-T3g; implementations e4a2e76 and 5795c34):

| id | claim | status |
|----|-------|--------|
| E31 | GET /__kortex/stats (loopback-only) exposes inflight_small, inflight_large, abandoned_running, kills, overloads, penalised_clients and workers{pool,busy,spares,loading,recycled}, and after the in-flight work drains every counter returns to zero (rule 50: in-flight resources observable) | passing |
| E32 | (step-22) a rule that matches in phase 1 (920350 on a numeric Host) is named in the request's audit entry next to the phase-2 rule (942100), as in the connector's audit log | passing (failing in 5b47a00, docs/logs/step22-e32-failing.log; passing log docs/logs/step22-e32-passing.log) |
| T3a | worker mode decides identically to in-process mode on a small benign body (200) and a small XSS body (403) | passing |
| T3b | at the budget the worker is SIGKILLed, the kill is counted and the slot is released (next request served) | passing |
| T3c | a pre-spawned spare serves the next request after a kill without paying the ~1.5-2 s rule-load in the hot path | passing |
| T3d | recycle-after-N replaces a worker after N jobs and service continues | passing |
| T3e | a per-client in-flight cap: a second body-bearing request from the SAME client while one is in flight gets 503 | passing |
| T3f | after a budget kill the client enters penalty state: further body requests get 503 kortex-decision=overload ("client penalty after kill") until the penalty expires, then 200 | passing |
| T3g | bounded CPU after a kill: the engine process CPU stops growing after the worker is SIGKILLed (the stricter property that replaces E20) | passing |
| T3h | per-client in-flight cap defaults to floor(lane_cap/2) per lane (at least 1), so one client cannot hold a whole lane; large lane cap=2 -> per-client large cap=1, second concurrent large-body request from the same client gets 503 "per-client in-flight cap" | passing |

Step-22 per-client cap follow-up (rule 40: tests committed BEFORE the fix
in 20f3e8a; failing evidence docs/logs/step22-t3i-t3m-failing.log; the fix
is the next commit, full-suite evidence
docs/logs/step22-t3i-t3m-suite-after-fix.log: 42 passing, 5 skipped for
KORTEX_TEST_WCP_BODY unset, 0 failing, macOS arm64 go1.27.4). T3k is a
coverage test for behaviour that already existed, so it passed before the
fix:

| id | claim | status |
|----|-------|--------|
| T3i | an explicit KORTEX_CLIENT_MAX_INFLIGHT is clamped to floor(lane_cap/2) (at least 1) on the large lane: with the override at 4 and large lane cap 2, the second concurrent large-body request from the same client gets 503 "per-client in-flight cap" | passing (failing in 20f3e8a) |
| T3j | the same clamp on the small lane: with the override at 6 and small lane cap 8, four concurrent small-body requests from one client are admitted and the fifth gets 503 "per-client in-flight cap" | passing (failing in 20f3e8a) |
| T3k | with no override the small-lane per-client cap is exactly 4 (floor(8/2)): four concurrent small-body requests from one client are admitted, the fifth gets 503 "per-client in-flight cap" | passing (coverage only, not test-first) |
| T3l | per-client in-flight jobs are counted per lane: a client with one small job in flight may start a large one, a second large one is still refused, and client_inflight_small / client_inflight_large on /__kortex/stats return to zero (rule 50) | passing (failing in 20f3e8a) |
| T3m | /__kortex/config shows worker_mode, the configured client_max_inflight and the effective client_max_inflight_small / client_max_inflight_large (rule 29) | passing (failing in 20f3e8a) |
| T3n | T3g's CPU check counts only the engine parent after the kill: with an unrelated goroutine of the test process spinning (what the wcp-fixture tests E16-E21 leave behind), T3g still passes | passing (failing in bec12db, docs/logs/step22-t3n-failing.log; passing log docs/logs/step22-t3n-passing.log) |
| T3o | canary for T3g (rule 47): the same T3g run with one goroutine of the parent spinning during the CPU window fails on the 150 ms limit | passing (added with the T3n fix) |

E20 retirement note (rule: replacement must be stricter): E20 (step-16,
"after the abandoned calls finish, new body-bearing requests are inspected
again") is RETIRED as the availability/CPU claim in favour of T3g (bounded
CPU after kill, worker mode). The E20 test is kept and still passes —
in-process mode remains supported and default — but the property the
system now relies on under worker mode is T3g. Parity evidence for the
worker mode: acceptance (f) zero-diff on 5 datasets (2520 samples,
docs/logs/runs/s21-t3-parity/) and flip_repro worker PL2 0/2500.

Step-22 run evidence (no new acceptance ids beyond T3h-T3m above; host
changed to macOS arm64, see docs/baseline-v1.7.md):

- Worker-mode parity extended to the two wcp datasets at PL1 and PL2:
  0 status diffs and 0 worst-case-set diffs on 60,000 samples
  (docs/logs/step22-t3-parity.txt). Replays must go to `localhost`: a
  numeric-IP Host adds CRS 920350 (+3) to every request
  (docs/logs/step22-numeric-host.txt).
- T3e/T3f/T3h-T3m behaviour observed under attack in a Linux container
  (docs/logs/step22-t2-cells-summary.txt, docs/logs/runs/s22-t2-penalty-demo/demo.txt).
- Full suite on this host, docs/logs/step22-final-go-test.log:
  42 PASS, 5 SKIP (fixture tests), 0 FAIL,
  `ok kortexshield/engine 48.056s`; docs/logs/step22-final-pytest.log: 181 passed, 4 skipped.
- With the recorded wcp fixture (docs/logs/step22-final-go-test-with-fixture.log):
  45 PASS, 2 FAIL (E20, T3g), exit status 1. E20 also fails alone on this
  host ("abandoned call did not finish within 120s"), so "The E20 test is
  kept and still passes" above does not hold here. T3g passes alone and fails when a
  fixture test ran before it in the same test process (PROVEN for E19,
  docs/logs/step22-t3g-fixture-DIAGNOSTIC.log: alone +125 µs PASS, after
  E19 +1.218 s FAIL): it reads the CPU of the whole test process, which
  then includes the abandoned in-process calls of those tests. T3g's status
  "passing" above is for runs without the fixture on this host. Neither
  test was changed (rule 5); see reports/step-22.md, Questions.
