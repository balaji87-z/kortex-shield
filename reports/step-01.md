# Step 01 report: bring the baseline testbed up and learn its real behaviour

## Summary
Testbed is up and verified: Juice Shop v20.4.0 behind owasp/modsecurity-crs 4.25.2 (nginx, PL1). 19/19 pytest pass. CRS detects both attacks in DetectionOnly (942100+949110 SQLi; 941100/941110/941160/941390+949110 XSS) and blocks both with 403 in On mode; the benign request is clean in both modes. Host port 3000 was occupied, so the target is published on host port 13000 (deviation, disclosed below).

## Task table

| Task | Status | Evidence |
|---|---|---|
| T1 setup (commit, AGENTS.md/CLAUDE.md, venv+pytest) | done | Raw evidence 1.1–1.3 |
| T2 verify compose.yml against official docs | done | Raw evidence 2.1–2.3, compose.yml comments |
| T3 bring it up, curl target + baseline | partial (target host port changed 3000→13000) | Raw evidence 3.1–3.4 |
| T4 behaviour test, both modes | done | Raw evidence 4.1–4.5 |
| T5 capture log format | done (benign has access log only; see note) | docs/samples/crs-log-*.txt, Raw evidence 5.1 |
| T6 versions | done | Raw evidence 6.1 |

## Raw evidence

### 1.1 git log after T1 commit
    $ git log --oneline -2
    a81b0b0 step-01: T1 commit repo as received (unzip kortex-waf.zip into repo root) + AGENTS.md/CLAUDE.md
    bdade4d Add files via upload

Note: the repo was received as a git clone containing only `kortex-waf.zip`. The
zip's contents were extracted into the repo root (deploy/, docs/, kortex_eval/,
tests/, README.md, pyproject.toml) and committed as "as received".

### 1.2 venv + pytest
    $ python3 -m venv .venv && .venv/bin/pip install -q pytest
    $ .venv/bin/python -m pytest -q
    ...................                                                      [100%]
    19 passed in 0.05s

Expected 19 passed, got 19 passed.

### 1.3 CLAUDE.md
Created with the single line `@AGENTS.md` (this agent is not Claude Code itself,
but the file was created as instructed so any Claude Code session picks up the rules).

### 2.1 Juice Shop verification
Source: https://hub.docker.com/r/bkimminich/juice-shop/tags and
https://hub.docker.com/r/bkimminich/juice-shop (official README: "Run
`docker run --rm -p 3000:3000 bkimminich/juice-shop`", "Browse to http://localhost:3000").
- image name `bkimminich/juice-shop`: confirmed
- specific version tag: `v20.4.0` (latest versioned tag on Docker Hub at time of writing)
- listen port 3000: confirmed
- no backend/paranoia/rule-engine env vars apply (it is the target app)

### 2.2 CRS image verification
Sources:
- https://hub.docker.com/r/owasp/modsecurity-crs/tags (official OWASP image)
- https://github.com/coreruleset/modsecurity-crs-docker#common-env-variables (README)
- https://github.com/coreruleset/modsecurity-crs-docker/blob/main/docker-compose.yaml
- https://github.com/coreruleset/modsecurity-crs-docker/blob/main/src/etc/modsecurity.d/modsecurity.conf
- image name `owasp/modsecurity-crs`: confirmed
- specific version tag: `4.25.2-nginx-lts` (nginx variant; `nginx` alone is a moving tag, replaced by a pinned version)
- `BACKEND`: confirmed — README: "Partial URL for the remote server of the ProxyPass (httpd) and proxy_pass (nginx) directives"
- `PARANOIA`: confirmed — present in upstream docker-compose.yaml ("# Paranoia Level / PARANOIA: 1"); CRS 4 also has `BLOCKING_PARANOIA` (defaults to PARANOIA when unset; container log shows "Configuring 900000 for PARANOIA with blocking_paranoia_level=1")
- `MODSEC_RULE_ENGINE`: confirmed — modsecurity.conf: `SecRuleEngine ${MODSEC_RULE_ENGINE}`
- listen port: confirmed 8080 — README "Server and Port Configuration": `PORT`, default `8080` (nginx). Empirically confirmed: the published mapping `8081:8080` serves traffic.

### 2.3 compose.yml edits
All three VERIFY comments replaced with the source URLs (see deploy/compose.yml).

### 3.1 First `up` failed on host port 3000
    $ docker compose -f deploy/compose.yml up -d
    ...
    Error response from daemon: failed to set up container networking: driver failed programming
    external connectivity on endpoint deploy-target-1 (...): failed to bind host port 0.0.0.0:3000/tcp:
    address already in use

    $ ss -tlnp | grep :3000
    LISTEN 0 511 *:3000 *:* users:(("node /var/labss",pid=6333,fd=20))

An unrelated process (part of this host environment, not ours) holds host port 3000.
Deviation: target published as `13000:3000` (container port unchanged). Flagged in
"Questions for instructor".

### 3.2 Successful up
    $ docker compose -f deploy/compose.yml up -d
    Container deploy-target-1 Started
    Container deploy-baseline-crs-1 Started

### 3.3 docker compose ps
    NAME                    IMAGE                                    SERVICE        STATUS                            PORTS
    deploy-baseline-crs-1   owasp/modsecurity-crs:4.25.2-nginx-lts   baseline-crs   Up 20 seconds (health: starting)   0.0.0.0:8081->8080/tcp
    deploy-target-1         bkimminich/juice-shop:v20.4.0            target         Up 21 seconds                      0.0.0.0:13000->3000/tcp

### 3.4 curls (trimmed to headers)
    $ curl -sS -i http://localhost:13000/          # target directly (host port per deviation)
    HTTP/1.1 200 OK
    Access-Control-Allow-Origin: *
    ... (Content-Length: 9984)

    $ curl -sS -i http://localhost:8081/           # through the baseline
    HTTP/1.1 200 OK
    Date: Wed, 18 Nov 2026 08:52:13 GMT
    ... (same Content-Length: 9984)

### 4.1 Mode A: MODSEC_RULE_ENGINE=DetectionOnly (as shipped), requests via baseline :8081
    $ curl -sS -i http://localhost:8081/
    HTTP/1.1 200 OK
    $ curl -sS -i -G --data-urlencode "q=' OR 1=1--" http://localhost:8081/rest/products/search
    HTTP/1.1 500 Internal Server Error
    $ curl -sS -i -G --data-urlencode "q=<script>alert(1)</script>" http://localhost:8081/rest/products/search
    HTTP/1.1 200 OK

Observed (from audit log, engine field = "DetectionOnly"):
- benign: 200, no CRS messages
- SQLi: 500 — but the SAME request direct to the target also returns 500
  (`curl ... http://localhost:13000/rest/products/search?q=' OR 1=1--` → 500,
  body: "500 Error: SQLITE_ERROR: incomplete input"). The 500 is Juice Shop's own
  behaviour, NOT a WAF block. CRS logged matches: rule 942100 ("SQL Injection Attack
  Detected via libinjection", severity 2) and 949110 ("Inbound Anomaly Score Exceeded
  (Total Score: 5)"). Not blocked (DetectionOnly).
- XSS: 200, CRS logged 941100, 941110, 941160, 941390 and 949110 (Total Score: 20). Not blocked.

### 4.2 Mode switch
    $ sed -i 's/MODSEC_RULE_ENGINE: "DetectionOnly"/MODSEC_RULE_ENGINE: "On"/' deploy/compose.yml
    $ docker compose -f deploy/compose.yml up -d baseline-crs
    Container deploy-baseline-crs-1 Started

### 4.3 Mode B: MODSEC_RULE_ENGINE=On (blocking), same three requests via :8081
    $ curl -sS -i http://localhost:8081/
    HTTP/1.1 200 OK
    $ curl -sS -i -G --data-urlencode "q=' OR 1=1--" http://localhost:8081/rest/products/search
    HTTP/1.1 403 Forbidden
    $ curl -sS -i -G --data-urlencode "q=<script>alert(1)</script>" http://localhost:8081/rest/products/search
    HTTP/1.1 403 Forbidden

Observed: benign 200 / no CRS messages; SQLi 403 (942100 + 949110, score 5); XSS 403
(941100, 941110, 941160, 941390 + 949110, score 20). nginx error log confirms:
"ModSecurity: Access denied with code 403 (phase 2) ... [id "949110"]".

### 4.4 Engine mode confirmation
    $ docker logs deploy-baseline-crs-1 2>&1 | grep -o '"secrules_engine":"[^"]*"' | sort -u
    "secrules_engine":"DetectionOnly"   (mode A run)
    "secrules_engine":"Enabled"         (mode B run; "Enabled" = On)

### 4.5 Rule ID counts in blocking mode
    $ docker logs deploy-baseline-crs-1 --since 2m 2>&1 | grep -oE '"ruleId":"[0-9]+"' | sort | uniq -c
          1 "ruleId":"941100"
          1 "ruleId":"941110"
          1 "ruleId":"941160"
          1 "ruleId":"941390"
          1 "ruleId":"942100"
          2 "ruleId":"949110"

### 4.6 Behaviour table

| Mode | Request | HTTP status | CRS match | Rule IDs |
|---|---|---|---|---|
| DetectionOnly | GET / | 200 | no | — |
| DetectionOnly | SQLi search | 500 (target's own error, same direct) | yes | 942100, 949110 (score 5) |
| DetectionOnly | XSS search | 200 | yes | 941100, 941110, 941160, 941390, 949110 (score 20) |
| On (blocking) | GET / | 200 | no | — |
| On (blocking) | SQLi search | 403 | yes | 942100, 949110 (score 5) |
| On (blocking) | XSS search | 403 | yes | 941100, 941110, 941160, 941390, 949110 (score 20) |

### 5.1 Log location and samples
- Audit log: `MODSEC_AUDIT_LOG=/dev/stdout`, JSON format (`MODSEC_AUDIT_LOG_FORMAT=JSON`),
  readable via `docker logs deploy-baseline-crs-1`. Verified inside the container:
  `MODSEC_AUDIT_LOG=/dev/stdout`, `MODSEC_AUDIT_ENGINE=RelevantOnly`.
- nginx error log (one-line ModSecurity denial summaries) also on stderr → docker logs.
- nginx access log lines also on stdout → docker logs.
- Samples saved: docs/samples/crs-log-benign.txt (access-log line + note), crs-log-sqli.txt
  and crs-log-xss.txt (full audit JSON transactions, blocking mode), crs-log-fields.txt
  (field list, ≤8 lines as required).
- Note: no audit transaction exists for the benign request (RelevantOnly only logs
  4xx/5xx), so its sample is the access-log line. This is observed, not assumed:
  `grep -c '^{"transaction"'` over the full docker logs shows audit entries only for
  the two attack requests.

### 6.1 Versions
    $ docker --version
    Docker version 29.9.2, build a82e528
    $ docker compose version
    Docker Compose version v5.6.1
    $ python3 --version
    Python 3.12.3
    $ docker compose -f deploy/compose.yml images
    deploy-baseline-crs-1   owasp/modsecurity-crs   4.25.2-nginx-lts   linux/amd64   6296ce685cb8   311MB
    deploy-target-1         bkimminich/juice-shop   v20.4.0            linux/amd64   9bbaecc41791   528MB

Pinned images actually used (digests from `docker images --digests`):
- bkimminich/juice-shop:v20.4.0 — sha256:9bbaecc41791f00b002bc65931cc5ff355fbdb941fa72b06558c18dace43197b
- owasp/modsecurity-crs:4.25.2-nginx-lts — sha256:6296ce685cb88ba4012998b935b25dabbd9e0ff326088c1149447102544de661

## Deviations from instructions
1. Target host port: the step says to show `curl http://localhost:3000/`. Host port
   3000 is occupied by an unrelated pre-existing process (pid 6333, `node /var/labss...`).
   The compose mapping was changed to `13000:3000` (container port unchanged) and the
   direct-target curl was run against localhost:13000. Disclosed here and in a comment
   in deploy/compose.yml.
2. compose.yml was left with `MODSEC_RULE_ENGINE: "DetectionOnly"` (the original default)
   after the blocking-mode runs; the mode switch was done by editing the env value and
   `docker compose up -d baseline-crs`, as instructed, then reverted.
3. The repo was received as a zip inside a git clone; the zip contents were extracted
   to the repo root and committed as the "as received" state.

## UNVERIFIED items
- Nothing material. The only doc-vs-reality nuance: the exact default of
  `BLOCKING_PARANOIA` when only `PARANOIA` is set is taken from the container's own
  startup log ("Configuring 900000 for PARANOIA with blocking_paranoia_level=1"),
  which is direct observation of the running image, not a doc quote.

## Questions for instructor
1. Host port 3000 is taken on this machine. Keep `13000:3000` permanently, or should
   the conflicting host process be dealt with / should we parametrise the host port?
2. The SQLi payload `q=' OR 1=1--` makes Juice Shop v20.4.0 return 500
   (SQLITE_ERROR) even without the WAF. For the baseline dataset, do we record the
   target's own 500 as-is, or pick SQLi payloads the target answers normally
   (e.g. `q=' OR '1'='1`)?
3. Should the benign sample requirement be met with the access-log line (current
   choice), or do you want audit entries for 200s too (would require changing
   MODSEC_AUDIT_ENGINE, i.e. touching baseline behaviour)?
