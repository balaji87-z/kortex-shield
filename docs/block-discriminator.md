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
