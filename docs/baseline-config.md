# Baseline configurations: crs-default and crs-policy-aligned

Written BEFORE the aligned runs (AGENTS.md rule 17). No frozen dataset is
touched by any of this. No rule-specific exclusions (SecRuleRemoveById,
ctl:ruleRemove*) are used.

## Settings and defaults (from official documentation)

- `tx.allowed_methods` — CRS default `GET HEAD POST OPTIONS`
  (image `crs-setup.conf` line 494; official example file:
  https://github.com/coreruleset/coreruleset/blob/main/crs-setup.conf.example ;
  docker image env `ALLOWED_METHODS`, default documented at
  https://github.com/coreruleset/modsecurity-crs-docker/blob/main/docker-compose.yaml )
- `tx.allowed_request_content_type` — image default
  `|application/x-www-form-urlencoded| |multipart/form-data| |text/xml| |application/xml| |application/soap+xml| |application/json|`
  (image `crs-setup.conf` line 583; the docker image docs list a slightly
  longer default that also includes `multipart/related` and cloudevents types —
  URL above). `text/plain` is NOT in either default, which is why socket.io
  polling POSTs hit rule 920420 (step-04 baseline).
- Both are settable through the image's env vars `ALLOWED_METHODS` and
  `ALLOWED_REQUEST_CONTENT_TYPE` (mapping table in the image:
  `/docker-entrypoint.d/configure-rules.v4.conf`, rules 900200/900220).

## Observed methods and content types in recorded natural traffic

From ALL 214 `data/benign-browse-v0` samples (not only blocked ones):

| method | content-type | samples |
|---|---|---|
| GET | (none) | 135 |
| POST | application/json | 47 |
| POST | text/plain;charset=UTF-8 | 20 (socket.io polling) |
| PUT | application/json | 12 |

## The two configurations

| | crs-default | crs-policy-aligned |
|---|---|---|
| allowed_methods | `GET HEAD POST OPTIONS` (image default) | `GET HEAD POST OPTIONS PUT` |
| allowed_request_content_type | image default (no text/plain) | image default + `\|text/plain\|` |
| everything else | image defaults | image defaults — nothing else changed |

Rationale: the aligned config adds exactly the method and the content type
observed in real recorded browsing traffic (PUT for basket-quantity updates and
review edits; text/plain for socket.io engine.io polling). It is still a
policy decision — it widens what the baseline accepts — and it is documented
here before being run. No exclusions, no threshold changes, no paranoia
changes beyond the PL runs themselves.

## How it is applied

`deploy/compose.yml` passes `ALLOWED_METHODS` and `ALLOWED_REQUEST_CONTENT_TYPE`
through to the container (empty/undefined = image default = crs-default).
The aligned runs set:

    ALLOWED_METHODS='GET HEAD POST OPTIONS PUT'
    ALLOWED_REQUEST_CONTENT_TYPE='|application/x-www-form-urlencoded| |multipart/form-data| |text/xml| |application/xml| |application/soap+xml| |application/json| |text/plain|'

Each run records `--label config=crs-default` or `--label config=crs-policy-aligned`
in `run.json`.

## Default User-Agent option (step-06 T1, added BEFORE any run)

The runner gained `--default-user-agent STRING` (off by default; with the flag
absent, request bytes are unchanged). When set, it adds a `User-Agent` header
only to samples that have none (case-insensitive check); a recorded
User-Agent is never overridden. `run.json` records `default_user_agent`
(null when unset).

Chosen string:

    Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36

Rationale: Chrome 158 is the current stable Chrome (released 2026-11-17) and
this is the exact reduced UA string Chrome 158 sends on Windows, the most
common desktop platform. Sources (checked 2026-11-18):
https://www.clearcotelabs.com/chrome-user-agent and
https://www.whatismybrowser.com/guides/the-latest-user-agent/chrome


## Third config: crs-policy-aligned-v2 (step-08 T2, written BEFORE any run)

What: identical to `crs-policy-aligned` except `DELETE` is added to the
allowed methods:

    ALLOWED_METHODS='GET HEAD POST OPTIONS PUT DELETE'
    ALLOWED_REQUEST_CONTENT_TYPE='|application/x-www-form-urlencoded| |multipart/form-data| |text/xml| |application/xml| |application/soap+xml| |application/json| |text/plain|'

Why: benign-browse-v1 (step-07) shows the real UI issues
`DELETE /api/BasketItems/{id}` when a user removes a basket item (30/30
such requests blocked under crs-policy-aligned at PL1 and PL2, rule 911100
method policy + threshold 949110). Removing a basket item is a normal,
expected user action, so blocking it is a config mismatch, not an attack
signal (AGENTS rule 24 label). No other setting changes.

Configuration documentation URL: the `ALLOWED_METHODS` variable is the CRS
docker image's documented toggle
(https://coreruleset.org/docs/initialize/#environment-variables-in-the-docker-image,
checked 2026-11-18 in step-05 when the first aligned config was
documented).

Label plan (rule 19): results on benign-browse-v0 are IN-SAMPLE-ADJACENT
(the config was derived from v0 traffic plus the v1 DELETE finding, so v0
results test only the DELETE addition's effect on v0 traffic, which
contains no DELETE); results on benign-browse-v1 are IN-SAMPLE for the
DELETE decision (derived from v1). **No out-of-sample estimate exists for
this config yet** — that will require a future recording (v2) the config
has never seen.

## Step-09: audit-log capture change (2026-11-18)

**What:** Mount a `modsecurity-override.conf` setting `SecAuditLog` to a file
inside the container (`/var/log/modsecurity/audit/audit.log`) instead of
`/dev/stdout`, and copy that file out after each run instead of using
`docker logs`.

**Why:** With `SecAuditLog /dev/stdout` (Serial type), large audit entries
(those containing request bodies) exceed pipe-atomic-write limits and
interleave with nginx error-log lines (which also contain raw multi-line
request bodies). This produced unparseable `{"transaction"` lines in
`docker logs` captures (step-05/06/07 captures were smaller-bodied and
unaffected; the WCP corpus with large bodies hit it repeatedly). Writing the
audit log to a dedicated file inside the container eliminates interleaving;
`docker cp` retrieves it cleanly after the run.

**Reference:** https://github.com/coreruleset/modsecurity-crs-docker —
custom configuration via mounting into `/etc/modsecurity.d/`
(`modsecurity-override.conf` is included after `modsecurity.conf` via
`setup.conf`). ModSecurity directive reference:
https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v2.x%29#secauditlog

**Scope:** Capture mechanism only. No CRS rules, no paranoia levels, no
engine settings are changed by this.

**Implementation note (2026-11-18):** bind mounts from this machine's
`/var/labsstorage` volume are read-only inside containers, so mounting the
override file failed. Instead the change is applied at runtime: after the
container starts, `sed` rewrites `SecAuditLog /dev/stdout` to
`SecAuditLog /var/log/modsecurity/audit/audit.log` in
`/etc/modsecurity.d/modsecurity.conf` inside the container and nginx is
reloaded. Same effect, still capture-only.

## Step-10 T6: held-out-host policy config `crs-policy-wcp-train` (documented before running)

- Plan: docs/plan-wcp-heldout.md (preregistered). Host split (seed 0, rule
  fixed there): docs/logs/wcp-heldout-split.json — 1,488 TRAIN hosts
  (9,949 requests) / 1,550 TEST hosts (10,051 requests) of the 19,994-request
  baseline manifest.
- Image defaults, read from inside the container
  (`/etc/modsecurity.d/owasp-crs/crs-setup.conf`): methods
  `GET HEAD POST OPTIONS PUT DELETE` (crs-setup.conf line 494); content types
  `application/json application/x-www-form-urlencoded multipart/form-data
  text/xml application/soap+xml` (line 583).
- TRAIN-observed (frozen manifest, TRAIN hosts only): methods {GET, HEAD,
  POST, PUT, DELETE, PATCH}; 107 distinct non-empty content types.
- `crs-policy-wcp-train` = default UNION TRAIN-observed, never narrower than
  the default: methods `GET HEAD POST OPTIONS PUT DELETE PATCH`; content
  types = the 5 defaults + the 107 TRAIN types = 112 tokens, exactly as
  committed in docs/logs/wcp-heldout-policy.txt (machine-readable:
  docs/logs/wcp-heldout-policy.json).
- Caveat recorded in advance: CRS matches this list as a regex; tokens
  containing regex metacharacters (e.g. `+`, `,`, spaces inside one recorded
  header value) may not behave as literal strings. We pass the raw recorded
  values and measure the result; no token is hand-edited.
- Env vars used: `ALLOWED_METHODS`, `ALLOWED_REQUEST_CONTENT_TYPE` (same
  mechanism as the step-05 aligned configs).

### Revision (still before any wcp-train run): whitespace/comma-free tokens only

The first attempt to start the container with the full 112-token union
failed: nginx exited with `Rules error ... Expecting an action, got:
application/json application/json; charset=UTF-8 ...` — a recorded value
containing a comma (`application/json, application/json`) terminates the
seclang `setvar:'...'` value, and multi-word values cannot survive the
space-separated list mechanism at all. Evidence: failed container log
(reproduced in reports/step-10.md).

Revised definition: `crs-policy-wcp-train` = default UNION **whitespace- and
comma-free** TRAIN-observed content types (21 types) + method PATCH.
86 multi-word recorded types (373 TRAIN requests, e.g.
`application/json; charset=UTF-8`, `multipart/form-data; boundary=...`)
are NOT representable in the CRS mechanism; they stay NOT-allowed and are
blocked by 920420 when they occur. This is a limitation of the CRS config
mechanism, not a tuning choice. Lists: docs/logs/wcp-heldout-policy.json
(includes the full excluded-type list with counts) and
docs/logs/wcp-heldout-policy.txt.
