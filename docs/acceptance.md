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
| E20 | after the abandoned calls finish, new body-bearing requests are inspected again (no overload) | passing |
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
