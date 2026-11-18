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
