# Step 02 report: request runner, verdict discrimination, audit correlation, 12-request smoke run

## Summary
Runner (`kortex_eval/runner.py`) and audit correlator (`kortex_eval/crs_audit.py`) written, tested (35 tests pass, 19 pre-existing + 16 new), and proven against the live baseline. The block discriminator is "status 403 AND nginx error-page marker in body" — status alone cannot separate CRS blocks from target-own 403s. The 12-sample smoke run shows the plumbing works end to end: runner verdicts and audit-based verdicts agree on all 12 samples; the run also surfaced one CRS false positive (932260 on `/rest/user/whoami`) and one request nginx rejects before CRS ever sees it.

## Task table

| Task | Status | Evidence |
|---|---|---|
| T1 compose env vars + gitignore | done | Raw evidence 1.1 |
| T2 block discriminator | done (used /ftp/lowval.mp4 instead of package.json.bak — reason in doc) | docs/block-discriminator.md, Raw evidence 2.1–2.4 |
| T3 runner + tests | done | Raw evidence 3.1–3.2 |
| T4 crs_audit + audit-rule experiment | done | Raw evidence 4.1–4.3, docs/samples/audit-experiment.txt |
| T5 smoke run + cross-check | done | Raw evidence 5.1–5.4 |
| T6 README/acceptance update | done | commit 0b2… (T6 commit) |

## Raw evidence

### 1.1 compose defaults and overrides
    $ docker compose -f deploy/compose.yml config | grep -E 'published|MODSEC_RULE_ENGINE|PARANOIA'
    (defaults)
      MODSEC_RULE_ENGINE: DetectionOnly
      PARANOIA: "1"
        published: "8081"      (baseline)
        published: "13000"     (target)
    (overrides: TARGET_PORT=14000 BASELINE_PORT=9081 MODSEC_RULE_ENGINE=On PARANOIA=2)
      MODSEC_RULE_ENGINE: 'On'
      PARANOIA: "2"
        published: "9081"
        published: "14000"

    .gitignore now: .venv/ out/ data/external/ __pycache__/ .pytest_cache/ *.pyc

### 2.1 CRS block (XSS via baseline, engine On) — raw capture
    HTTP/1.1 403 Forbidden
    Date: Wed, 18 Nov 2026 09:10:16 GMT
    Content-Type: text/html
    Content-Length: 146
    Connection: keep-alive
    Server: nginx
    Access-Control-Allow-Origin: *
    Access-Control-Max-Age: 3600
    Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
    Access-Control-Allow-Headers: *

    <html><head><title>403 Forbidden</title></head><body>
    <center><h1>403 Forbidden</h1></center><hr><center>nginx</center></body></html>

### 2.2 target-own 403, direct (headers + first 300 body bytes)
    HTTP/1.1 403 Forbidden
    Access-Control-Allow-Origin: *
    X-Content-Type-Options: nosniff
    X-Frame-Options: SAMEORIGIN
    Feature-Policy: payment 'self'
    X-Recruiting: /#/jobs
    Content-Type: text/html; charset=utf-8
    Vary: Accept-Encoding
    (chunked)

    <html><head><meta charset='utf-8'> <title>Error: Only .md and .pdf files are allowed!</title> ...

### 2.3 the SAME path via baseline, engine On — identical target-own 403 passes through
    HTTP/1.1 403 Forbidden
    ... X-Recruiting: /#/jobs ... Content-Type: text/html; charset=utf-8 ...
    <html><head><meta charset='utf-8'> <title>Error: Only .md and .pdf files are allowed!</title> ...

### 2.4 the suggested /ftp/package.json.bak is NOT usable as a target-own 403 via the baseline
Direct: 403 (target). Via baseline, engine On: 403 but CRS-blocked — audit entry shows
rules 920440 ("URL file extension is restricted by policy"), 930130 ("Restricted File
Access Attempt"), 949110 (score 10). The request never reaches the target.
Replacement: /ftp/lowval.mp4 (target-own 403 "Only .md and .pdf files are allowed!",
passes CRS unchanged). Full analysis in docs/block-discriminator.md.

### 2.5 target-own 500 (SQLi direct to target)
    HTTP/1.1 500 Internal Server Error
    ... X-Recruiting: /#/jobs ...
    <title>Error: SQLITE_ERROR: incomplete input</title>

### 2.6 Discriminator decision (full version in docs/block-discriminator.md)
Status alone: NO (both are 403). Rule chosen:
    blocked = (status == --block-status) AND (--block-marker matches body)
defaults: 403 and `<center>nginx</center>` (nginx error-page footer; absent from
Juice Shop pages).

### 3.1 runner CLI as used in T5
    $ .venv/bin/python -m kortex_eval.runner --manifest data/smoke/manifest.jsonl \
        --base-url http://localhost:8081 --out out/smoke-pl1-on
    {"base_url": "http://localhost:8081", "started_utc": "2026-11-18T09:14:14+00:00",
     "ended_utc": "2026-11-18T09:14:14+00:00",
     "git_commit": "a57c9bd18a84051e8d4463fd2b7de251beca90e9",
     "total_samples": 12, "responses_ok": 12, "blocked": 6, "error_count": 0,
     "block_rule": {"block_status": 403, "block_marker": "<center>nginx</center>"}}
    exit=0

### 3.2 pytest after T3/T4 (old + new)
    $ .venv/bin/python -m pytest -q
    ...................................                                      [100%]
    35 passed in 4.60s
(19 pre-existing + 10 runner + 6 crs_audit = 35; no existing test weakened or deleted.)

New-test coverage (tests/test_runner.py, fake HTTP server in a thread, no Docker):
block detected on 403+marker; clean 200 not blocked; target-style 403 without marker
not blocked; timeout recorded as error and excluded from predictions; sample-id header
arrives; raw percent-encoded query reaches the server byte-identical
("GET /rest/products/search?%27%20OR%201%3d1-- HTTP/1.1"); invalid ids refused and
listed with nothing sent; run.json contents; POST body+content-type verbatim;
connection error recorded as error.
tests/test_crs_audit.py runs the parser on the REAL files in docs/samples/.

### 4.1 Header field in the audit JSON (checked on the real samples, not assumed)
    $ python3 -c "... print(t['request'].get('headers'))" over docs/samples/crs-log-{sqli,xss}.txt
    {"Host": "localhost:8081", "User-Agent": "curl/8.5.0", "Accept": "*/*"}
→ `transaction.request.headers` (name→value map) carries the request headers, so
correlation via the `X-Kortex-Sample-Id` header is possible. Task NOT stopped.

### 4.2 Audit-rule experiment (engine On: clean 404 + XSS; DetectionOnly: XSS)
    (engine On)  GET /ftp/definitely-not-real.md  X-Kortex-Sample-Id: exp-404-on   → 404, audit entries: 0
    (engine On)  XSS search                       X-Kortex-Sample-Id: exp-xss-on   → 403, audit entries: 1
    (DetectionOnly) XSS search                    X-Kortex-Sample-Id: exp-xss-donly → 200, audit entries: 1
Controls to isolate the rule:
    (DetectionOnly) /ftp/definitely-not-real.md?q=<script>alert(1)</script>
                                                  X-Kortex-Sample-Id: exp-xss404-donly → 404, audit entries: 1
    (DetectionOnly) GET /rest/product/1/reviews   X-Kortex-Sample-Id: exp-500-donly → 500, audit entries: 1 (0 messages)
Actual rule (documented in docs/samples/audit-experiment.txt and appended to
crs-log-fields.txt): audited iff (≥1 rule matched, regardless of status — even a 200
in DetectionOnly) OR (status matches SecAuditLogRelevantStatus: 4xx except 404, 5xx).
A clean 404 with no rule match fails both and is not audited.
Note: each engine-mode switch recreates the container and resets its log; logs were
captured per mode before switching.

### 4.3 crs_audit CLI on a real capture
    $ .venv/bin/python -m kortex_eval.crs_audit --logs /tmp/exp-on-logs.txt --out /tmp/audit-on.jsonl
    crs_audit: 1 audit entr(ies) -> /tmp/audit-on.jsonl
    {"sample_id": "exp-xss-on", ..., "status": 403, "engine": "Enabled",
     "rules": [{"id": "941100", ...}, ..., {"id": "949110", ...}], "anomaly_score": 20}

### 5.1 Smoke run setup
    $ MODSEC_RULE_ENGINE=On PARANOIA=1 docker compose -f deploy/compose.yml up -d baseline-crs
    $ .venv/bin/python -m kortex_eval.runner --manifest data/smoke/manifest.jsonl \
        --base-url http://localhost:8081 --out out/smoke-pl1-on     # exit=0, 12/12 ok
    $ docker logs deploy-baseline-crs-1 > out/smoke-pl1-on/docker-logs.txt 2>&1
    $ .venv/bin/python -m kortex_eval.crs_audit --logs out/smoke-pl1-on/docker-logs.txt \
        --out out/smoke-pl1-on/audit.jsonl
    crs_audit: 7 audit entr(ies) -> out/smoke-pl1-on/audit.jsonl
    $ .venv/bin/python -m kortex_eval.report --manifest data/smoke/manifest.jsonl \
        --predictions out/smoke-pl1-on/predictions.jsonl --name "CRS PL1 blocking, smoke run (plumbing validation)"
    | Overall attack recall | 5/6 | 83.33% | 43.65% – 96.99% |
    | Recall: path-traversal | 1/2 | 50.00% | 9.45% – 90.55% |
    | Recall: sqli | 2/2 | 100.00% | 34.24% – 100.00% |
    | Recall: xss | 2/2 | 100.00% | 34.24% – 100.00% |
    | False positive rate (benign flagged) | 1/6 | 16.67% | 3.01% – 56.35% |
    (Numbers on 12 hand-written plumbing-validation samples; NOT dataset results.)

### 5.2 Per-sample table (runner × audit cross-check)

| id | label | status | blocked (runner) | audit entry | anomaly score | rule IDs |
|---|---|---|---|---|---|---|
| sqli-01 | attack | 403 | true | yes | 5 | 942100, 949110 |
| sqli-02 | attack | 403 | true | yes | 15 | 942100, 942190, 942360, 949110 |
| xss-01 | attack | 403 | true | yes | 20 | 941100, 941110, 941160, 941390, 949110 |
| xss-02 | attack | 403 | true | yes | 20 | 941100, 941120, 941160, 941390, 949110 |
| trav-01 | attack | 400 | false | no | — | — |
| trav-02 | attack | 403 | true | yes | 30 | 930100, 930110 (x2), 930120, 932160, 949110 |
| home-01 | benign | 200 | false | no | — | — |
| search-01 | benign | 200 | false | no | — | — |
| whoami-01 | benign | 403 | true | yes | 5 | 932260, 949110 |
| js-01 | benign | 200 | false | no | — | — |
| img-01 | benign | 200 | false | no | — | — |
| login-01 | benign | 401 | false | yes (0 rules) | none | — |

### 5.3 Cross-check: runner "blocked" vs "audit anomaly score ≥ threshold (5, PL1)"
Every sample agrees; ZERO disagreements:
- all 5 samples with a score ≥ 5 in the audit log are exactly the 5 the runner blocked;
- trav-01: runner not-blocked, no audit entry (no score) — agree;
- login-01: runner not-blocked (401 ≠ 403), audit entry present with zero rules and no
  score (relevant-status audit of a target 401) — agree;
- home/search/js/img: not blocked, no audit entries — agree.
Label-vs-verdict findings (reported, not hidden):
- whoami-01 (benign) BLOCKED: CRS 932260 "Remote Command Execution: Direct Unix Command
  Execution" fires on the literal string "whoami" in the path /rest/user/whoami;
  score 5 = threshold. A genuine CRS false positive at PL1 on this baseline.
- trav-01 (attack) NOT blocked: nginx itself returns 400 Bad Request (150-byte nginx
  page, Connection: close) for the encoded-dot-segment URI before ModSecurity runs —
  no CRS audit entry at all (confirmed: the same path direct to the target returns 200).
  The WAF never evaluated this request; the runner verdict "not blocked" is correct
  for "the WAF's decision" but the sample needs a different encoding to exercise CRS.

## Deviations from instructions
1. T2: `/ftp/package.json.bak` is a target-own 403 only when sent DIRECTLY; via the
   baseline CRS blocks it first (920440/930130). Used `/ftp/lowval.mp4` as the
   target-own 403, as the step anticipated ("find another target-own 403 and say
   what you used").
2. T4: "a clean request to a non-existent path that returns 404" — Juice Shop v20.4.0
   serves its SPA with 200 for unknown routes. Used `/ftp/definitely-not-real.md`,
   which returns a real 404 on this version.
3. out/ artifacts (responses/predictions/run.json/docker-logs/audit.jsonl) are
   gitignored per the T1 instruction; they are quoted in this report and reproducible
   with the commands above.

## UNVERIFIED items
- None material. All claims above come from captured commands/output. (The exact
  nginx internal reason for the 400 on encoded dot-segments is not verified beyond
  the observable behaviour: 400, 150-byte nginx page, no CRS audit entry.)

## Questions for instructor
1. trav-01: nginx rejects encoded dot-segments before the WAF. For future traversal
   samples, do we keep such samples (they measure "what actually happens on the
   wire") or re-encode them (e.g. %2e%2e%2f without slashes) so CRS actually evaluates
   them? Both are defensible; the dataset step needs a decision.
2. whoami-01: the 932260 false positive on /rest/user/whoami is exactly the kind of
   baseline FP the project wants to measure. Keep the sample as-is in future benign
   sets (it is a real-world FP), or treat /rest/user/whoami as attack-adjacent wording
   and use a different identity endpoint?
3. crs_audit currently reports the inbound score parsed from the 949110 message text.
   For entries with rule matches but no 949110 message (possible at higher paranoia
   configurations?), score stays null. Acceptable, or should the score also be summed
   from individual rule severities?
