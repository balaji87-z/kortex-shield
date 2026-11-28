# Acceptance tests: what "industry standard" means for this project

Each row is a bar taken from a source we read, turned into a test we can run.
Numeric targets are left open on purpose. They are set after the baseline run,
because only the baseline tells us what a number means on our data.

Status values: `not started`, `in progress`, `passing`, `failing`.

| ID | Bar | Source | Test | Pass condition | Status |
|---|---|---|---|---|---|
| A1 | Rule-engine compatibility | CRS engine-options page: Coraza passes 100% of the CRS v4 test suite; ModSecurity v3 fails 2-4% | Run the CRS regression suite against our build | 100% of the suite | failing (measured in step 25): CRS v4.25.2 suite, go-ftw 2.1.0, DetectionOnly, PL4, 4,987 tests: 4,862 passed, 125 failed (97.49%; 4,863 / 124 with the CRS project's coraza-overrides); before the step-25 fixes 4,857 / 130. Reference, stock coraza v3.8.1 as Go middleware with response inspection: 4,970 / 17. All 125 classified DESIGN, 0 UNEXPLAINED: 78 need response inspection, which the engine does not have; 19 expect 920420 (no content-type allow-list, C4); 15 are matches of the REQUEST_BODY targets on requests the suite says must not match; 3 are refused by the gate before the rules; 10 are failed by the reference in the same way (Go net/http and coraza behaviour). docs/baseline-v2.0.md, reports/step-25.md |
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
| E33 | (step-22 follow-up) a body sent with a Content-Encoding other than identity is answered 415 kortex-decision=content-encoding by the engine itself, never reaches the backend and writes an event; in blocking and in DetectionOnly mode | passing (failing in 9579672, docs/logs/step22-e33-failing.log; passing log docs/logs/step22-e33-passing.log) |
| E34 | (step-22 follow-up) the E33 refusal is narrow: no header, identity, and a body-less request with the header are not refused by it (DetectionOnly, forwarded) | passing before and after (guards E33's change) |
| E35 | (step-23 T1) every refusal of the framing gate (conflicting Content-Length, duplicate Content-Length, Transfer-Encoding with Content-Length, raw NUL in the target, with or without a sample id) writes exactly one event to kortex-events.jsonl: decision framing, status 400, the gate's reason, the request's sample id | passing (failing in a21491a, docs/logs/step23-e35-failing.log: 5 of 5 cases, 0 framing events; passing log docs/logs/step23-e35-passing.log) |
| E36 | (step-23 T1) canary for E35: a request the gate lets through writes no framing event | passing before and after |
| E37 | (step-23 T2) an unchanged request gets the same status and the same audit rule-id set in every replay: syn-chain (JSON, the 942130 tautology plus a decoy member) and syn-dup (repeated key), 2,000 replays each at PL2, in-process; 503 answers are set aside and capped at 10% | passing with the patched coraza: 2,000 x 403 [942130, 949110] and 2,000 x 403 with one rule-id set (docs/logs/step23-e37-passing.log); failing on stock coraza v3.8.1 in b69492e (docs/logs/step23-e37-failing.log: syn-chain 1,564 x 403 and 436 x 200; syn-dup 2 rule-id sets, 1,701 and 299) |
| E38 | (step-23 T2) the order of the members in a JSON body does not change the decision (syn-chain and syn-chain-rev, 300 replays each) | passing with the patched coraza: 300 x 403 for each order; failing on stock coraza v3.8.1 in b69492e (228 x 403, 72 x 200) |
| E39 | (step-23 T2) a tautology whose key sorts before the decoy's key is decided the same in every replay (300); the outcome is logged, not required to be a block | passing with the patched coraza: 300 x 200, i.e. PASSED every time (the known limit of sorted order, docs/engine-design.md); failing on stock coraza v3.8.1 in b69492e (230 x 200, 70 x 403) |
| E40 | (step-23 T3) a body without Content-Encoding that starts with gzip (1f 8b 08) or zlib (78 01 / 5e / 9c / da) magic writes exactly one log-only event (would_reject, status 0, reason compressed-body-without-content-encoding:gzip or :zlib) and gets the same answer as the same body with its first byte changed (200, forwarded); blocking, DetectionOnly and worker mode | passing (failing in 611508d, docs/logs/step23-e40-failing.log: 15 of 15 cases, no event; passing log docs/logs/step23-e40-passing.log) |
| E41 | (step-23 T3) the E40 event is narrow: text, JSON, magic not at offset 0, partial magic, other zlib-looking pairs, and a body with Content-Encoding: gzip (415 by E33) do not write it | passing before and after |
| E42 | (step-24 T1) a request that Go's net/http server would answer itself without running a handler (33 cases: the 17 of step-23 T5, and missing / duplicate / malformed Host, HTTP version, request line, method, target, header line, header name, 501 header lines, unknown Expect, a refused head carrying an XSS payload) is refused by the engine's gate: 400 `400 kortex-decision=framing`, exactly one framing event with status 400, reason parser:<class> from a fixed word list and the sample id, backend not reached; each case first proves its premise on a bare net/http server | passing (failing in 323ed49, docs/logs/step24-e42-failing.log: 33 of 33 cases, answered 400 / 501 / 505 / 417 / 431 by net/http with no marker and no event; passing log docs/logs/step24-e42-passing.log) |
| E43 | (step-24 T1) guard for E42: 13 well-formed neighbours (Content-Length 5 and 005, chunked, Chunked, valid percent escapes, Expect: 100-continue, HTTP/1.0 without Host, Host with port, empty Host, absolute URI, folded header, 401 header lines) are handed to a handler by bare net/http and are not refused by the gate: forwarded (200 from the stub) or decided by a rule (403), 0 framing events | passing before and after |
| E44 | (step-24 T1) canary for E43 (rule 47): the same well-formed shapes with an XSS payload in the query are blocked 403 by the rules, 0 framing events, backend not reached | passing before and after |
| E45 | (step-24 T1) the parser gate and net/http agree on seeded damage: 20,000 heads made from 5 well-formed ones by 1 to 3 random edits (seed 24); every head that net/http answers 400 or above without running its handler is refused by parserGate and every other head is passed (19,257 compared, 11,890 refused by both, 0 decided differently) | passing since the fix (written with it: it calls parserGate, which did not exist before); it fails when a check is missing, shown by docs/logs/step24-e45-DIAGNOSTIC-gate-without-expect-check.log (421 of 19,257 decided differently with the Expect check switched off) |
| E46 | (step-24 T2) the framing checks see header lines ended by a bare LF: 4 requests (Transfer-Encoding with Content-Length, Content-Length then Transfer-Encoding, duplicate Content-Length; every line or one line ended by LF) are refused 400 `kortex-decision=framing` with one framing event and the usual reason, and do not reach the backend; premises proven per case (the CRLF form is refused, bare net/http runs its handler for the LF form) | passing (failing in 5cd6fc2, docs/logs/step24-e46-e48-failing.log: 4 of 4 forwarded to the backend, 200; passing log docs/logs/step24-e46-e48-passing.log) |
| E47 | (step-24 T2) guard for E46: 3 bare-LF requests without a framing problem are forwarded as before, 0 framing events | passing before and after |
| E48 | (step-24 T2) one connection carries one request: after `OPTIONS *`, `/__kortex/config` or `/__kortex/stats`, a second request on the same connection (one the gate refuses on its own, and a plain GET) is never served: at most 1 response, backend not reached, no pass event | passing (failing in 5cd6fc2, docs/logs/step24-e46-e48-failing.log: 6 of 6, the second request reached the backend; passing log docs/logs/step24-e46-e48-passing.log) |
| E49 | (step-25 T1) with `KORTEX_ERROR_LOG` set, every matched rule that has the `log` action writes one line in the ModSecurity error-log form (`[id "..."]`, `[msg "..."]`) to that file: blocking mode (941100 and 949110 for an XSS query, 403), DetectionOnly (941100, request forwarded 200, query and body), worker mode (body, both modes); a request that matches nothing writes nothing; the path is on `/__kortex/config` (`error_log`) | passing (failing in 80ad1e3, docs/logs/step25-e49-e50-failing.log: 6 of 7 cases, no line, no config key; passing log docs/logs/step25-e49-e50-passing.log) |
| E50 | (step-25 T1) `KORTEX_CRS_TEST_SETUP=on` renders the CRS regression suite's setup: a request with an `X-CRS-Test` header writes exactly one error-log line, rule 999999 with the header value, and no other rule matches it even with an XSS payload (DetectionOnly and blocking); the same payload without the header logs 941100 and no 999999; a 401-character argument matches 920370 and a 400-character one does not (`tx.arg_length=400`); `crs_test_setup` is true on `/__kortex/config` | passing (failing in 80ad1e3, docs/logs/step25-e49-e50-failing.log: 4 of 5 cases; passing log docs/logs/step25-e49-e50-passing.log) |
| E51 | (step-25 T1) guard for E50: with `KORTEX_CRS_TEST_SETUP` unset, `off`, `1`, `true` or `ON`, an XSS query carrying the `X-CRS-Test` header is blocked 403 with 941100 and without 999999 among the matched rules, the backend is not reached, and a 401-character argument passes (the suite's limits are not set) | passing before and after |
| E52 | (step-25 T3, CRS test 920100-16) the rules get the request line as sent: an absolute-form target without a path (`GET http://localhost HTTP/1.1`) matches CRS 920100 and an origin-form target does not; the audit entry carries the protocol of the request (`HTTP/1.0`, `HTTP/1.1`) and the target unchanged | passing (failing in f47d4a6, docs/logs/step25-e52-e55-failing.log: no 920100; protocol recorded as `1.1` for both versions; passing log docs/logs/step25-e52-e55-passing.log) |
| E53 | (step-25 T3, CRS tests 920171-2 and -3) a Transfer-Encoding header is shown to the rules: a GET with `Transfer-Encoding: chunked` matches CRS 920171, a POST does not; in-process and worker mode | passing (failing in f47d4a6, docs/logs/step25-e52-e55-failing.log: no 920171 in either mode; passing log docs/logs/step25-e52-e55-passing.log) |
| E54 | (step-25 T3, CRS test 920280-1) the rules see the Host header the request has: HTTP/1.0 without a Host line matches 920280 and not 920290, an empty Host line matches 920290 and not 920280, a normal Host matches neither; with and without a body, in-process and worker mode | passing (failing in f47d4a6, docs/logs/step25-e52-e55-failing.log: 5 of 10 cases; without a Host line the engine reported an empty one, and in worker mode a request with a body got both 920280 and 920290; passing log docs/logs/step25-e52-e55-passing.log) |
| E55 | (step-25 T3, CRS test 942130-7) CRS 942130 gets no REQUEST_BODY target (165 target updates, 932240 still among them): the tautology `a=42 like 42` in a form body matches 942130 at PL2 as it does in the query string (canary). First written for all 12 chain-starting rules; that form broke E24 PL2, which needs the target on 932240, so it was narrowed to the rule with the shown defect before any fix was committed | passing (failing before the fix, docs/logs/step25-e55-revised-failing.log: no 942130 for the body, 166 updates; first form: docs/logs/step25-e52-e55-failing.log; passing log docs/logs/step25-e52-e55-passing.log) |
| E56 | (step-25 T3) the rules see each header line once: a POST with a body has exactly one Content-Length value in its audit entry, in-process and in worker mode | failing (docs/logs/step25-e56-failing.log: in-process the entry has the value twice; worker mode passes) |
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
| T3p | (step-22 follow-up) a penalised client's body request is refused before any inspection: 503 overload, counted in refused_before_inspection on /__kortex/stats (0 before, 1 after one such request); the killed request and a body-less request from the same client do not count, and the body-less request is served | passing (failing in 41dcb78, docs/logs/step22-t3p-failing.log; passing log docs/logs/step22-t3p-passing.log) |

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
- Follow-up in the same step (reports/step-22.md, F5 to F12), which
  replaces the two bullets above for the engine from 37074bf on: T3g runs
  in its own process (T3n; canary T3o) and E20 waits 480 s (the abandoned
  call takes 260 to 280 s on this host, docs/logs/step22-e20-timing.txt).
  New ids E32, E33, E34, T3p, each failing first. Suites at 37074bf:
  docs/logs/step22-followup-go-test.log 48 PASS, 5 SKIP, 0 FAIL
  (`ok kortexshield/engine 51.195s`);
  docs/logs/step22-followup-go-test-with-fixture.log 53 PASS, 0 SKIP,
  0 FAIL (`ok kortexshield/engine 319.372s`, E20 260.72 s; needs
  `-timeout 900s`); docs/logs/step22-followup-pytest.log 186 passed,
  4 skipped. Parity re-run with this engine: 0 status diffs and 0
  worst-case-set diffs on 60,000 samples
  (docs/logs/step22-t3-parity-after-followup.txt).
- Close-out of step 22 (reports/step-22.md, C1 to C3). Suites at e8ed852:
  docs/logs/step22-closeout-go-test.log 48 PASS, 0 FAIL, 5 SKIP
  (`ok kortexshield/engine 51.879s`);
  docs/logs/step22-closeout-go-test-with-fixture.log 53 PASS, 0 FAIL,
  0 SKIP (`ok kortexshield/engine 322.491s`, E20 262.75 s);
  docs/logs/step22-closeout-pytest.log 186 passed, 4 skipped. No engine
  code and no acceptance id changed. kortex_eval change (not engine code;
  tests first, docs/logs/step22-c2-failing.log -> step22-c2-passing.log):
  the engine's own 413 limit and 415 content-encoding answers are
  classified waf_fail_closed_413 / waf_fail_closed_415 instead of
  waf_pass; Python suite after it 201 passed, 4 skipped
  (docs/logs/step22-closeout-pytest-after-c2.log). flip_repro on coraza
  v3.8.1, in-process, PL2, 5 x 500 rounds: 0 of 2,500 rounds with a flip
  on Host localhost and on 127.0.0.1; DIAGNOSTIC v3.7.0 scratch build on
  this host: 808 and 627 of 2,500 (docs/logs/step22-flip-pl2.txt,
  docs/logs/step22-flip-pl2-DIAGNOSTIC-coraza370.txt).
- Close-out, second part (reports/step-22.md, C5 to C7; no engine code
  and no acceptance id changed). kortex_eval also classifies the engine's
  own 400 framing, 503 timeout and 503 overload answers as fail-closed
  outcomes (tests first, docs/logs/step22-c6-failing.log ->
  step22-c6-passing.log); tools/step21_engine_diff.py counts the five
  fail-closed classes in its worst-case set (docs/logs/step22-c7-failing.log
  -> step22-c7-passing.log; two existing tests changed, named in commit
  1da3128). Python suite after it: 222 passed, 4 skipped
  (docs/logs/step22-closeout-pytest-after-c7.log). Seen, not fixed: the
  framing gate writes no event for its 400 (reports/step-22.md, Questions).

Step-23 run evidence (new ids E35 to E41, each of E35, E37, E38, E39, E40
failing first; E36 and E41 are guards that pass before and after; reports/step-23.md):

- E35/E36: docs/logs/step23-e35-failing.log (5 of 5 refusal cases wrote 0
  events) -> docs/logs/step23-e35-passing.log.
- E37/E38/E39 on stock coraza v3.8.1: docs/logs/step23-e37-failing.log
  (syn-chain 1,564 x 403 and 436 x 200 in 2,000 replays; syn-dup two
  rule-id sets) -> docs/logs/step23-e37-passing.log with the patched copy
  (2,000 x one outcome each; E39 300 x 200, the documented limit). The
  vendored copy is proven against the module cache by
  tools/step23_coraza_vendor.py check (docs/logs/step23-coraza-vendor-check.txt:
  197 of 200 files byte-identical, 2 patched, 1 new).
- E40/E41: docs/logs/step23-e40-failing.log (15 of 15 cases, no event) ->
  docs/logs/step23-e40-passing.log.
- flip_repro on the patched engine, PL2, 5 x 500: 0 of 2,500 rounds with a
  flip on Host localhost and on 127.0.0.1 (docs/logs/step23-flip-pl2.txt);
  DIAGNOSTIC v3.7.0 control 741 and 573 of 2,500.
- In-process against worker mode on benign-wcp-v0 and v1 at PL1 and PL2,
  60,000 pairs: 0 status diffs, 0 worst-case-set diffs with the fail-closed
  classes measured, 0 rule-id set differences (docs/logs/step23-parity.txt).
- Suites at 9754a0d: docs/logs/step23-final-go-test.log 55 PASS, 0 FAIL,
  5 SKIP (`ok kortexshield/engine 62.676s`);
  docs/logs/step23-final-go-test-with-fixture.log 60 PASS, 0 FAIL, 0 SKIP
  (`ok kortexshield/engine 336.432s`, E20 265.18 s);
  docs/logs/step23-final-pytest.log 234 passed, 4 skipped.
- Not an acceptance id, recorded for the next step: Go's HTTP parser inside
  the engine refuses some malformed requests (400 / 501) before the
  engine's handler runs, with no kortex marker and no event (17 of the 61
  cases of the step-23 parsing differential, docs/logs/step23-parsing-diff.txt).

Step-24 run evidence (new ids E42 to E48; E42, E46 and E48 failing first;
E43, E44 and E47 are guards that pass before and after; E45 was written
with the fix because it calls the new function; reports/step-24.md):

- E42/E43/E44: docs/logs/step24-e42-failing.log (33 of 33 refusal cases
  answered 400 / 501 / 505 / 417 / 431 by net/http with no marker and no
  event) -> docs/logs/step24-e42-passing.log.
- E45: 19,257 seeded damaged heads compared, 11,890 refused by net/http and
  by the gate, 0 decided differently (docs/logs/step24-e42-passing.log);
  DIAGNOSTIC with the gate's Expect check switched off: 421 decided
  differently, the test fails
  (docs/logs/step24-e45-DIAGNOSTIC-gate-without-expect-check.log).
- E46/E47/E48: docs/logs/step24-e46-e48-failing.log (E46 4 of 4 forwarded,
  E48 6 of 6 reached the backend) -> docs/logs/step24-e46-e48-passing.log.
  30 repeats of E42 to E44 and E46 to E48 in one process: 180 PASS, 0 FAIL
  (docs/logs/step24-repeat-30x.log).
- The 61 parsing-differential cases on the fixed engine: 0 refused without
  a kortex marker (step 23: 17), 29 framing answers with 29 framing events
  (docs/logs/step24-parsing-diff.txt, step24-parsing-diff-vs-step23.txt).
- Suites at 7316418: docs/logs/step24-final-go-test.log 62 PASS, 0 FAIL,
  5 SKIP (`ok kortexshield/engine 66.028s`);
  docs/logs/step24-final-go-test-with-fixture.log 67 PASS, 0 FAIL, 0 SKIP
  (`ok kortexshield/engine 341.920s`);
  docs/logs/step24-final-pytest.log 242 passed, 4 skipped.

Step-25 run evidence (new ids E49 to E55; E49, E50, E52 to E55 failing
first; E51 is a guard that passes before and after; reports/step-25.md):

- E49/E50/E51: docs/logs/step25-e49-e50-failing.log ->
  docs/logs/step25-e49-e50-passing.log.
- E52 to E55: docs/logs/step25-e52-e55-failing.log (E55 in its first form),
  docs/logs/step25-e55-revised-failing.log ->
  docs/logs/step25-e52-e55-passing.log.
- A1, the CRS v4.25.2 regression suite: docs/logs/s25-ftw.txt (first runs,
  reference, DIAGNOSTIC runs), docs/logs/s25-ftw-fixed.txt (after E52 to
  E55), per-test lists docs/logs/step25-failed-tests.txt and
  docs/logs/step25-failed-probe.txt, run files under
  docs/logs/runs/s25-ftw/ and docs/logs/runs/s25-ftw-fixed/.
- Our own datasets on the step-25 engine against the step-24 runs:
  docs/logs/step25-own-vs-step24.txt (0 status diffs in 5,040 pairs).
