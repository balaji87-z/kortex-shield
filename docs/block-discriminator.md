# Block discriminator: how to tell a WAF block from the target's own error

Evidence collected 2026-11-18, Juice Shop v20.4.0 behind
owasp/modsecurity-crs:4.25.2-nginx-lts, engine On, PARANOIA=1.
Raw captures are reproduced in reports/step-02.md (T2 section).

## The problem

Both of these return HTTP 403, so the status code alone cannot tell them apart:

| Case | Status | Body |
|---|---|---|
| (a) CRS block: XSS search via baseline | 403 | nginx default error page, 146 bytes |
| (b) target-own 403: `/ftp/lowval.mp4` via baseline | 403 | Juice Shop error page ("Only .md and .pdf files are allowed!") |

## Observed differences

| Signal | (a) CRS block | (b) target-own 403 |
|---|---|---|
| Content-Length | `146` (fixed) | absent (chunked) |
| Content-Type | `text/html` (no charset) | `text/html; charset=utf-8` |
| `X-Recruiting` / `Feature-Policy` headers (app headers) | absent | present |
| Body | `<center><h1>403 Forbidden</h1></center><hr><center>nginx</center>` | `<title>Error: Only .md and .pdf files are allowed!</title>` + app styling |

The CRS container's nginx serves its own default error page when ModSecurity
denies the request; the target's response (with its app headers) only appears
when the request was forwarded.

## Rule chosen

    blocked = (status == block_status) AND (block_marker matches response body)

with defaults `--block-status 403` and `--block-marker '<center>nginx</center>'`
for this baseline. The marker is the nginx error-page footer, which the Juice
Shop error pages do not contain. A target-own 403 therefore counts as
NOT blocked; a CRS 403 counts as blocked.

## Notes

- `/ftp/package.json.bak` (the path suggested in the step) is a target-own 403
  when sent directly, but through the baseline CRS blocks it first (rules
  920440 "URL file extension is restricted by policy", 930130 "Restricted File
  Access Attempt", anomaly score 10). It is therefore a CRS block, not a
  target-own 403, when seen through the WAF. `/ftp/lowval.mp4` passes CRS
  unchanged and produces the genuine target-own 403 used here.
- The marker is baseline-specific. For a different engine (e.g. our future
  Coraza proxy) the marker must be re-verified; the CLI exposes it as a flag.

## Outcome `waf_block_outbound` (added step-06 T3, written BEFORE analysis)

A distinct outcome for responses the WAF cut mid-stream while blocking the
OUTBOUND side. Definition (all three must hold; checked only when the runner
row would otherwise be classified `error`):

1. the response errored with an incomplete read or connection reset
   (error string starts with `http_error: IncompleteRead` or contains
   `ConnectionReset` / `RemoteDisconnected`);
2. the sample's audit entry contains rule `959100`
   ("Outbound Anomaly Score Exceeded", RESPONSE-959-BLOCKING-EVALUATION.conf);
3. the inbound score is below the threshold (`inbound_score_from_949110`
   is None or < the run's `--threshold`).

Rationale: in these cases the request reached the engine, the inbound side
did NOT block (score below threshold), but the outbound evaluation blocked
and truncated the response, so the runner could not read a complete response.
This is a WAF block on the outbound side — it must not be counted as a pass,
and it is also not a plain `error` (the cause is identified).

Existing outcomes are unchanged: the check runs only on rows that would
otherwise be `error`, and every other classification path is untouched.

Rule 20 reporting for rates that include this outcome: the **inbound-only**
rate counts `waf_block_outbound` as NOT flagged; the **including-outbound**
rate counts it as flagged. Best case = errors not flagged; worst case =
errors flagged (any remaining `error` rows).

## Coraza (step-10 T8)

Distribution: `ghcr.io/coreruleset/coraza-crs:4.25.2-nginx-lts` (pinned by
digest `sha256:ffefe71585b42daa5ead5653206b086b37090f498e4cde9ed6e4c52f05cc93e7`,
amd64), the coreruleset/coraza-crs-docker nginx variant — chosen because it
is built and shipped by the CRS project itself, bundles CRS 4.25.2 (the same
version as the baseline image), uses the same reverse-proxy shape and the
same env knobs (BACKEND, PARANOIA, BLOCKING_PARANOIA, CORAZA_RULE_ENGINE).
Engine: libcoraza v1.8.0 (Coraza v3 via the nginx connector), from the image
build definition at repo tag 20261011 (image created 2026-10-19).

Block discriminator: **unchanged** — `status == 403` AND body contains
`<center>nginx</center>`. Verified against the running Coraza container: a
blocked request (`/?id=1 AND 1=1`) returns 403 with the standard nginx error
page containing `<hr><center>nginx</center>` (same page as the ModSecurity
baseline, both are the stock nginx 403 page).

Audit log: JSON, one object per line, `{"transaction": {...}, "messages":
[...]}` (messages at TOP level, unlike ModSecurity's nested layout). The
transaction carries the full request headers, so the `X-Kortex-Sample-Id`
header IS present (`transaction.request.headers["x-kortex-sample-id"]`) —
rule IDs are verifiable, not UNVERIFIED. Rule IDs live in
`messages[].error_message` as `[id "942100"]` (extractable by regex);
`producer.rulesets` shows `OWASP_CRS/4.25.2` from inside the container.
Real samples saved BEFORE any parser was written:
docs/samples/coraza-log-benign.txt (200, no messages) and
docs/samples/coraza-log-attack.txt (403, 942100).

## `waf_deny_status` outcome (step-11 T3, defined BEFORE the code change)

Additive outcome class for blocking mode (engine On). A request is
`waf_deny_status` when ALL of:

1. it is NOT blocked by the 403 discriminator (status != 403 or the nginx
   marker is absent — i.e. the existing `waf_block` rule did not fire);
2. its response status is 4xx or 5xx;
3. it has an audit entry containing at least one DENY rule — a rule id
   starting with `2` (200002 "Failed to parse request body", 200007
   "Failed to fully parse request body due to large argument count",
   200003 multipart strict validation, etc. — the image's
   /etc/modsecurity.d/modsecurity.conf body-parser denies, all
   `deny, status:400`);
4. engine mode is blocking (in DetectionOnly these rules log without
   denying, so the class does not apply).

Existing outcomes are unchanged: a request that already classifies as
`waf_block`, `waf_block_outbound`, `error`, `waf_would_block`,
`proxy_reject` or `inconsistent` keeps that class unless it now matches
`waf_deny_status` first (the check runs after the blocked checks and
before the pass/proxy_reject/inconsistent fallthrough). Requests that were
`inconsistent` solely because of a 4xx/5xx status plus a 2xxxxx deny rule
become `waf_deny_status`; everything else stays.

Rule 30: `waf_deny_status` and `inconsistent` counts appear in every rate
table and are included in the worst case.
