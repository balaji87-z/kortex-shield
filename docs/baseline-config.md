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

### Second revision (still before any wcp-train run): single-token types only

A second start attempt with comma-free but semicolon-containing tokens
(`application/json;charset=UTF-8`) also failed: nginx emerg at the same
rule, break point immediately after `charset` — seclang terminates the
`setvar:'...'` value at `;` as well as `,`. Final definition:
`crs-policy-wcp-train` = default UNION the 13 single-token TRAIN-observed
content types (no whitespace, comma or semicolon) + method PATCH.
94 recorded multi-part types (1,578 TRAIN requests) are not representable
in the CRS mechanism; they stay NOT-allowed and are blocked by 920420.
Full excluded list with counts: docs/logs/wcp-heldout-policy.json.

## Step-11 T1: what "default" actually meant (effective-config audit, rule 29)

### The true image default (no env, or empty env)

With `ALLOWED_METHODS`/`ALLOWED_REQUEST_CONTENT_TYPE` unset or empty, the
entrypoint (docker-entrypoint.d/95-configure-rules.sh, `should_set()` =
non-empty test) leaves crs-setup.conf rules 900200/900220 **commented out**
(lines 494/583 of /opt/owasp-crs/crs-setup.conf in the pristine image).
CRS then applies its own fallback defaults from
REQUEST-901-INITIALIZATION.conf (read inside the running container):

- rule 901160 (line 183): `tx.allowed_methods=GET HEAD POST OPTIONS`
  — PUT and DELETE are NOT allowed by the true default;
- rule 901162 (line 193): `tx.allowed_request_content_type=|application/
  x-www-form-urlencoded| |multipart/form-data| |text/xml|
  |application/xml| |application/soap+xml| |application/json|`
  — note the pipe-wrapping (required for the 920420 `@within` match) and
  that `text/plain` is NOT allowed while `application/xml` IS.

Verified live against the running container started with empty env:
POST text/plain -> 403 (920420), POST application/json -> 200, PUT -> 403
(911100). The Coraza image (coraza-crs 4.25.2-nginx-lts) has the identical
structure: 900200/900220 commented (crs-setup.conf lines 494/583), the same
901160/901162 fallbacks, and it DOES honour the two env vars via
/opt/coraza/activate-rules.sh (the README does not list them).

### Per-run conclusions

- Every run labelled `crs-default` (step-05/06 attacks/browse/hard, step-07
  browse-v1, step-09 WCP default, step-10 T6 default, T7 cookie, T8
  Coraza) used the TRUE default policy: compose always passes
  `ALLOWED_METHODS=""`/`ALLOWED_REQUEST_CONTENT_TYPE=""` (verified with
  `env -i docker compose config`), the rules stay commented, and the 901
  fallbacks are active. Evidence beyond config: in the default-run audits
  920420 fires on text/plain but never on application/json, and 911100
  only on PUT/DELETE/PATCH — exactly the fallback policy.
- Rule 29 gap: the step-09 and step-10 run logs did NOT record the
  in-container effective values (the prep scripts printed only
  B/D/P/E). The conclusion above is reconstructed from the rendered
  config of identically-started containers plus audit evidence. From
  step-11 on, every run saves the effective values (rule 29).
- Why step-10 read "PUT DELETE" as the image default: the grep for
  crs-setup.conf lines 494/583 was executed against the container that
  happened to be up at that moment — the last ALIGNED PL2 run
  (ALLOWED_METHODS="GET HEAD POST OPTIONS PUT DELETE") — and its values
  were misattributed to the image default. The v0.5 "image defaults"
  paragraph is wrong and is corrected by a dated note.

### Rendering bug found (affects two run families)

The CRS content-type list must be PIPE-WRAPPED (`|type| |type| ...`):
rule 920420 wraps the observed type as `|type|` and matches it with
`@within` against the tx value (REQUEST-920-PROTOCOL-ENFORCEMENT.conf,
rule 920420 chain). The step-09 `crs-policy-aligned`/`aligned-v2` runs on
WCP and the step-10 `crs-policy-wcp-train` runs passed the list UNWRAPPED
(tools/run_wcp_baselines.sh, tools/run_wcp_heldout.sh), so `@within`
matched NOTHING and 920420 fired on 100% of content-type requests:

- step-09 aligned PL1: 920420 on 2,510/2,510 application/json requests,
  546/546 form-urlencoded, 2,783/2,783 text/plain;
- step-10 wcp-train TEST PL1: 1,264/1,264 json, 338/338 form-urlencoded.

Therefore the step-09 aligned-v2 WCP numbers (32.80%/50.93%) and the
step-10 T6 wcp-train numbers (TEST 31.66%/47.97%, TRAIN 33.95%/53.92%)
measured "block every request that has a Content-Type header", NOT the
intended policies. Dated corrections are in docs/baseline-v0.4.md and
docs/baseline-v0.5.md. The crs-default numbers are unaffected. The
wcp-train runs are re-run in step-11 T2 with the corrected rendering
(documented below before running).

## Step-11 T2: corrected `crs-policy-wcp-train` rendering (documented BEFORE re-running)

Same value set as step-10 (methods `GET HEAD POST OPTIONS PUT DELETE PATCH`;
content types = the 5 defaults + the 13 single-token TRAIN types), rendered
the way CRS requires: every content-type token pipe-wrapped,
`|type| |type| ...` (matching the 901162 fallback format and the 920420
`@within` match). Exact strings committed in
docs/logs/wcp-heldout-policy.txt / .json (`content_types_wrapped`).
Re-runs: TEST and TRAIN, PL1 and PL2, wcp-train only, rule 13 hygiene,
with rule 29 effective-config proof saved into each run's log.

## Step-11 T2 (cont.): true CRS default content-type list

The 901162 fallback (the policy every `crs-default` run actually ran) allows
`application/x-www-form-urlencoded`, `multipart/form-data`, `text/xml`,
`application/xml`, `application/soap+xml`, `application/json` (pipe-wrapped).
`text/plain` is NOT in it. The step-05/08 aligned configs were built from the
image README's example list (which adds `|text/plain|`) — that is why the
aligned CT list contains text/plain. Methods: 901160 fallback is
`GET HEAD POST OPTIONS` (no PUT/DELETE); the aligned configs add PUT
(then DELETE in aligned-v2).

## Step-11 T4: ModSecurity parity runs moved to the stub backend (2026-11-19)

**What:** All step-11 ModSecurity parity/re-run runs set `BACKEND=http://stub-backend:3000`
(compose env, service `baseline-crs`) instead of the default Juice Shop
(`http://target:3000`), so both engines see the same backend. Output dirs are
named `out/modsec-<dataset>-pl<N>-stub`. Rule-29 effective-config proof is
printed per run by `tools/run_modsec_parity.sh`.

**Why:** The step-10 T8 / step-11 T4 Coraza runs all used
`CORAZA_BACKEND=stub-backend:3000`, while the ModSecurity runs being compared
against used the compose default (Juice Shop). Response-dependent rules
(953xxx data-leakage, 959xxx outbound blocking) therefore compared different
response bodies. Evidence: the Coraza benign-wcp-v0 PL1 run shows 1,08x
status-501 responses (stub-backend's "Unsupported method" replies) while the
ModSecurity benign-wcp-v0 PL1 run shows zero (docs/logs/step11-t4-backend-confound.txt).

**Reference:** deploy/compose.yml `BACKEND: "${BACKEND:-http://target:3000}"`
(Step-09 T5 comment); https://github.com/coreruleset/modsecurity-crs-docker#common-env-variables

**Scope:** Backend endpoint only. No CRS rules, paranoia levels, or engine
settings change. The earlier ModSecurity runs (Juice Shop backend) stay
committed as they are; their rates are labelled with their backend.

**Timing note (honesty per rule 17):** the batch launching these runs started
11:08 UTC; this entry was written ~11:15 UTC, before any result from the new
runs was read or reported. The change itself was decided after the 501-status
evidence above, also before reading any new-run result.

## Step-11: keep-alive desync root cause CORRECTED — stub backend, not the runner (2026-11-19)

**Earlier claim in this file's step-11 T4 entry and in
docs/logs/step11-t4-backend-confound.txt section 3** attributed the WCP
keep-alive desync to the runner sending a recorded Content-Length. That was
wrong; the old text is kept above/in that file and corrected here.

**Verified facts (evidence in docs/logs/step11-t4-stub-drain.txt):**
- `kortex_eval/runner.py` already drops any recorded `Content-Length` header
  and always sends `len(body.encode("utf-8","surrogatepass"))`. It never
  emits a mismatched wire framing. No runner change was made.
- The real bug: `tools/stub_backend.py` (BaseHTTPRequestHandler) never read
  request bodies. With HTTP/1.1 keep-alive the unread body stayed in the
  socket and was parsed as the NEXT request line. Reproduced in-process:
  POST with body then GET on one connection -> `501 Unsupported method
  ('{"url":...}GET')`; the 501 page echoes the body, `session_start` inside
  it matches CRS 953110 (ERROR, 4 pts) -> 959100 outbound block (403).
  This explains the Coraza WCP PL1 run's 1,081x501 + 162x502 + 3 outbound
  blocks, and why the small datasets (whose passing traffic rarely reuses a
  poisoned upstream connection) and the Juice-Shop-backed runs (Juice Shop
  drains bodies) showed none of it.
- 653/20,000 WCP manifest samples carry a recorded Content-Length that
  differs from the encoded byte length (488 recorded-too-small, 165
  recorded-too-large). This is a DATASET metadata property, not a wire
  framing bug; the runner neutralises it. Kept on record; no sample changed
  (frozen dataset, rule 10).

**Fix (tools only, not kortex_eval):** `StubHandler._drain_body()` now reads
and discards exactly Content-Length bytes before replying, and closes the
connection on chunked requests. Verified live: POST-with-body then GET on
one connection now returns 200/200 (was 200/501).

**Tests added (97 total, all passing):** runner framing pins
(non-ASCII body CL == byte length; recorded CL larger/smaller is overridden)
and stub keep-alive tests (body-drained next request intact; multi-byte
body next request intact).

**Labelling:** the instructor requested a `runner_cl=fixed` label; since the
runner needed no fix, new runs are labelled `stub_drain=fixed` instead, and
this deviation is reported. Runs made before the fix are labelled by their
output dirs and reported side by side.

## Step-11 T4: request-body limit pinned on both engines (documented before running)

**What:** Both engines are pinned to `SecRequestBodyNoFilesLimit 131072`
(the ModSecurity image's value) for the step-11 parity re-runs. ModSecurity
already runs this value (proven per run by tools/run_modsec_parity.sh rule-29
output). The Coraza image ships 524288
(/opt/coraza/config/coraza.conf); tools/run_coraza_parity.sh now rewrites it
to 131072 in-container before each run and prints the effective value.

**Why:** The 11 Coraza-only 413 responses on benign-wcp-v0 PL1 (bodies
between the two limits) were an image-default difference, not an engine
difference. Rule 28 parity requires identical effective config.

**Reference:** ModSecurity directive
https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v2.x)#secrequestbodynofileslimit
(Coraza implements the same directive; value set in /opt/coraza/config/coraza.conf).

**Scope:** Body-limit value only. If the in-container rewrite + reload does
not take effect (verified by the rule-29 print and a >131072-byte probe),
the Coraza runs keep 524288, the 11 samples stay listed, and no
aligned-config claim is made.

## Step-12: image digests re-pinned (documented BEFORE any step-12 run, 2026-11-20)

Two upstream drift events discovered while starting the step-12 re-runs:

1. **ModSecurity image (`baseline-crs`)**: compose used the floating tag
   `owasp/modsecurity-crs:4.25.2-nginx-lts`. A compose pull on 2026-11-20
   resolved it to a NEW build `sha256:98d448750b86...` (image created
   2026-11-19 14:56:53Z - after all step-11 runs). The step-01/step-11 digest
   `sha256:6296ce685cb8...` is STILL available on Docker Hub and was re-pulled
   by digest. Compose now pins `image@sha256:6296ce68...` so every ModSecurity
   run stays on the image all previous runs used.
2. **Coraza image (`coraza-crs`)**: the step-10/11 pinned digest
   `sha256:ffefe71585b42...` has been DELETED from ghcr.io
   (`docker pull ...@sha256:ffefe715...` -> "not found", 2026-11-20); the old
   image is unobtainable. The tag now resolves to a newer build,
   `sha256:bfbfe70b4445...` (image created 2026-11-13). Compose is re-pinned to
   that digest. Consequences, all verified from inside the new image:
   - CRS is still 4.25.2 (rule files carry `ver:'OWASP_CRS/4.25.2'`; proven
     per run via tx.crs_setup_version=4252).
   - Engine: Go build info in /usr/local/lib/libcoraza.so contains
     `github.com/corazawaf/coraza/v3@v3.7.0` (the old image's engine version
     was never proven in-container; step-10 quoted v1.8.0 from the build def).
   - Image layout changed: rules now at /opt/coraza/owasp-crs/rules/;
     coraza.conf is rendered at runtime from /templates/coraza.conf to
     /opt/coraza/config/coraza.conf (same runtime path as before, so the
     SecRequestBodyNoFilesLimit sed pin in tools/run_coraza_parity.sh still
     applies to the rendered file).
   - The new image HONOURS `DETECTION_PARANOIA` (activate-rules.sh renders
     rule 900001). The old image ignored it and fell back to rule 901125
     (detection = blocking). Step-12 Coraza runs therefore pass
     DETECTION_PARANOIA explicitly and prove tx.detection_paranoia_level
     per run. The step-10/11 Coraza runs relied on the 901125 fallback;
     `docs/logs/coraza-rule29-pl2.txt` line "tx.detection_paranoia_level=1"
     is a grep of the COMMENTED crs-setup example, not the effective value
     (901125 set it to blocking=2; cross-check: the step-11 coraza PL2 run's
     audit contains PL2-tagged rules, which requires detection >= 2).

Comparability caveat (recorded up front): step-12 Coraza-side runs use a
different image build (and engine build) than the step-10/11 Coraza runs.
CRS version equality with the ModSecurity side is proven per run from inside
both containers (rule 28); the engine-version difference is a recorded
deviation, and coraza-vs-step-11 coraza comparisons are labelled accordingly.

## Step-12: Coraza body-limit pin proven INEFFECTIVE (2026-11-20)

The v0.6 claim "SecRequestBodyNoFilesLimit 131072 pinned on Coraza in-container
(sed + nginx -s reload), probe: 200,000-byte body -> 400" is WRONG. The probe
body was invalid JSON, so its 400 was a body-parse deny (rule 200002), not the
size limit. Live proof on the pinned coraza image (bfbfe70b), after the sed
showed 131072 in the rendered file and `nginx -s reload`:

- valid 200,000-byte JSON body -> Coraza 200 (passes), ModSecurity 400
  (200002 "Failed to parse request body").
- valid 120,000-byte JSON body -> 200 on both (control).
- multipart/form-data with one file part, 200,000 bytes -> 200 on both.
- PUT with no content-type, 200,000 bytes -> 403 on both (911100 method
  policy, not a size effect).

Conclusion: `nginx -s reload` does not make the coraza nginx module re-read the
rendered coraza.conf; the running engine keeps the image default 524,288. The
same mechanism applies to the old image, so EVERY Coraza run to date (step-10,
step-11, step-12 small re-runs) ran with effective NoFilesLimit 524,288. For
the small datasets this is non-binding (largest body 1,080 bytes; 0 samples
over 131,072 or 524,288), so the step-12 small-dataset re-runs stand. For
benign-wcp-v0 the 11 samples where Coraza returned 413 and ModSecurity did not
are all > 524,288 bytes (723,995-1,527,423): 10 multipart POSTs (ModSecurity
passes them; file parts count against SecRequestBodyLimit 13,107,200) and 1
no-content-type PUT (ModSecurity blocks 403 on 911100). Evidence:
docs/logs/step12-sizeprobe-*.log, docs/logs/step12-oversize-*.log.
Fix for future runs: pass the limit via the image env (rendered at container
start), not sed+reload. No step-12 run needed it (no dataset body falls between
the limits); recorded here before any future run relies on it.

## Step-12: cookie-restore completeness fix and full re-run (2026-11-20)

The benign-wcp-v0 build stored the dropped cookie under two header spellings:
`cookie` (7,512 frozen rows) and `Cookie` (5,754 frozen rows). The step-10
restore script selected dropped rows with a case-sensitive lookup, so the
step-11 restored-all manifest covered only the 7,511 lowercase rows and
silently skipped 5,750 `Cookie`-spelled rows (rule 12 violation, now fixed).
tools/restore_wcp_cookies.py selection is case-insensitive as of this note;
the rebuilt manifest covers all 13,261 baseline dropped rows and the integrity
check passes (only the cookie value differs from the baseline row). ModSecurity
PL1+PL2 re-runs on the full restore: out/modsec-wcp-cookie-restored-all-pl{1,2}
(rule-29 proofs in out/step12-restored-all.log; fresh container per run). The
frozen dataset was not modified; restored cookie values remain uncommitted.

## Step-13 T1: empty ModSecurity audit in the step-12 smoke runs (2026-11-20)

The step-12 batch1 ModSecurity smoke PL1/PL2 runs captured 0 audit entries
(crs_audit printed "0 audit entr(ies)"; out/modsec-smoke-pl{1,2}-stub/
modsec-audit.log are 0 bytes). All other batch1 ModSecurity runs captured
normally (attacks-v0 944/1,014, browse 183/183, hard 20/78 entries).

PROVEN mechanism (DIAGNOSTIC, docs/logs/step13-t1-crs-setup-lines.txt): after
`nginx -s reload`, requests served by the OLD nginx workers still audit to the
OLD destination (/dev/stdout); only new workers use the redirected audit file.
Diagnostic output: immediately after reload, a 12-request burst produced 6
audit JSON lines in `docker logs` and 0 bytes in the audit file; a request sent
3 s later landed in the file (2,178 bytes). The smoke run's 12 requests
completed within ~1 s of the reload, so every audit entry went to stdout.

Consequences: the `inconsistent` outcome class on those two smoke cells is a
capture artifact (empty audit -> outcome.py cannot confirm the block), NOT an
engine difference. Rule-ID comparisons from the two smoke runs are INVALID;
the other six batch1 ModSecurity runs are unaffected. outcome.py and crs_audit
need no change (they classified empty input correctly); the fix is in the
capture script: tools/run_modsec_parity.sh now waits for the audit file to be
non-empty after a blocked probe before starting the runner (patch committed
with this note, before the re-run). The two smoke cells were re-run with the
fixed script (out/modsec-smoke-pl{1,2}-stub, labels audit_capture=post_reload_wait);
the step-12 T2 smoke numbers are superseded by the re-run.

## Step-13 T4: the Coraza body-limit knob (documented BEFORE any run, rule 17)

### What will be changed and why

The step-12 finding: the sed+reload "pin" of Coraza's
SecRequestBodyNoFilesLimit never took effect; every Coraza run to date ran
with the effective default 524,288 while ModSecurity ran with 131,072.

Root knob found (PROVEN, read from the pinned image bfbfe70b):
- `/templates/coraza.conf` renders `SecRequestBodyNoFilesLimit
  ${CORAZA_REQ_BODY_NOFILES_LIMIT}` and `SecRequestBodyLimit
  ${CORAZA_REQ_BODY_LIMIT}` at container START (template rendering, not a
  reloadable file) — that is why sed+nginx-reload could not change it.
- The image ENV defaults are `CORAZA_REQ_BODY_NOFILES_LIMIT=524288`,
  `CORAZA_REQ_BODY_LIMIT=13107200`, `CORAZA_REQ_BODY_LIMIT_ACTION=Reject`,
  `CORAZA_ARGUMENTS_LIMIT=1000` (docker run --entrypoint env, saved in
  docs/logs/step13-t4-coraza-env.txt). So 524,288 comes from the image ENV
  default — PROVEN, not inferred.

### Intended settings for all step-13 Coraza runs (both engines aligned)

- Coraza: `CORAZA_REQ_BODY_NOFILES_LIMIT=131072` (match ModSecurity's
  modsecurity.conf:8 value), `CORAZA_REQ_BODY_LIMIT=13107200` (already the
  image default; matches ModSecurity SecRequestBodyLimit), limit action
  Reject (default on both).
- ModSecurity: unchanged (SecRequestBodyNoFilesLimit 131072,
  SecRequestBodyLimit 13107200, Reject — proven in-container in step-11/12).
- Mechanism: pass the two vars through deploy/compose.yml environment for the
  coraza-crs service (compose edit committed together with this note, before
  the runs).
- Verification: bisect body size at 1 KB resolution on BOTH engines, PL1,
  stub backend, for valid JSON, urlencoded, and multipart-with-file bodies;
  report status + rule IDs at each threshold. Rule-29 proof lines for every
  run will print the effective limits from inside the container.
- If Coraza cannot match a ModSecurity value, the difference stays a
  documented parameter (no engine code will be written).

### Step-13 T4 addendum: what the bisect actually showed (before any T5 run)

The env knob works mechanically (rendered into the loaded
/opt/coraza/config/coraza.conf: SecRequestBodyNoFilesLimit 131072 — read back
from inside the running container) but the bisect PROVED that this Coraza
build does not enforce it: with the limit set to 131,072, valid JSON,
urlencoded and multipart-with-file bodies of 140,000–1,000,000 bytes all pass
(200); the first 413 appears just above 1,048,576 and its body is the standard
NGINX "413 Request Entity Too Large" HTML page. The Coraza image ships the
STOCK nginx default.conf with NO client_max_body_size directive (nginx default
1 MiB); the ModSecurity image sets client_max_body_size 0 in both location
blocks of its default.conf.template (grep evidence in
docs/logs/step13-t4-nginx-conf.txt).

Consequences, superseding the step-12 wording:
- The step-12 claim "Coraza effective limit always 524,288" is DISPROVEN —
  Coraza (v3.7.0 in this image) enforces neither SecRequestBodyNoFilesLimit
  nor SecRequestBodyLimit on these probe bodies; every observed 413 came from
  the nginx 1 MiB cap. The step-12 sample sizes 723,995–1,527,423 were
  recorded-body lengths; the true encoded sizes are larger (replayed
  wcp-34940e7ffce1 = 1,620,081 bytes), all above 1 MiB.
- The 11 WCP 413 divergences are therefore a PROXY-LAYER difference
  (client_max_body_size 1M vs 0), not a Coraza body-limit behaviour.
- Config change (documented here BEFORE it is run, rule 17): align the proxy
  layer by mounting a one-line nginx include `client_max_body_size 0;` into
  the coraza-crs service (deploy/coraza-nginx-body.conf ->
  /etc/nginx/conf.d/zz-body-size.conf), matching the ModSecurity image's own
  setting. After this, the bisect is repeated to expose Coraza's OWN
  enforcement. If Coraza still does not enforce its configured limits, that
  stays a documented engine difference (no engine code will be written).

### Step-13 T4 addendum 2 (still before the re-bisect / any T5 run)

The first alignment attempt (mounting a one-line include into
/etc/nginx/conf.d/) was INEFFECTIVE: the Coraza image's /etc/nginx/nginx.conf
contains no `include` directives at all — conf.d files are never loaded. The
image renders /etc/nginx/nginx.conf from /templates/nginx.conf at container
start (docker-entrypoint.d/20-envsubst-on-templates.sh). The alignment is
therefore done by mounting a modified copy of that template
(deploy/coraza-nginx.conf.template -> /templates/nginx.conf) with
`client_max_body_size 0;` added to both location blocks; everything else in
the template is byte-identical to the image's. The unused
deploy/coraza-nginx-body.conf attempt is removed.

### Step-13 T4 result (after the re-bisect; all points PROVEN by named experiments)

With the proxy layer aligned (client_max_body_size 0 on both engines):
- Coraza enforces SecRequestBodyLimit 13,107,200 for multipart-with-file
  bodies byte-exactly (13,107,199 -> 200; 13,107,200 -> 413);
  ModSecurity passes at 13,107,200 (boundary differs by one byte).
- Coraza does NOT enforce SecRequestBodyNoFilesLimit at all in this build:
  with the limit configured to 131,072 (read back from the loaded config),
  JSON, urlencoded and text/xml bodies of 140,000–1,000,000 bytes pass.
  ModSecurity enforces 131,072 for the same no-files bodies (400/200002 at
  >= 131,072; bisect log docs/logs/step13-t4-bisect.txt).
- Conclusion: the no-files body-limit difference cannot be removed by
  configuration; it stays a documented engine difference (rule: no engine
  code). The WCP re-runs (T5) therefore use: Coraza with
  CORAZA_REQ_BODY_NOFILES_LIMIT=131072 + client_max_body_size 0 (both
  documented here), ModSecurity unchanged.
- tools/run_coraza_parity.sh: the sed+reload body-limit pin is REMOVED for
  step-13 runs (it never worked and the env var + template mount replace it).

## Step-14 T3: crs-ct-wide config (documented BEFORE the runs, rule 17)

- What: a second config, `crs-ct-wide`, used only by the step-14 attacks-ct-v0
  cells. It activates CRS setup rule 900220 with
  `tx.allowed_request_content_type=|application/x-www-form-urlencoded| |multipart/form-data| |text/xml| |application/xml| |application/soap+xml| |application/json| |text/plain| |application/octet-stream|`
  (the CRS 4.25.2 default list from REQUEST-901-INITIALIZATION lines 192-200,
  plus `|text/plain| |application/octet-stream|`). `crs-default` leaves the
  env unset, so the CRS default list applies (rule 901370-style default).
- Why: the step-14 task asks whether a content-type policy change moves
  detection blocks, not just policy blocks. text/plain and
  application/octet-stream are the two carriers CRS blocks by default
  (rule 920420).
- How: ModSecurity image — env `ALLOWED_REQUEST_CONTENT_TYPE` (native
  entrypoint support, configure-rules.v4.conf line 16). Coraza image — same
  env, native support in /opt/coraza/activate-rules.sh line 43; the env was
  not passed through in deploy/compose.yml before, so the passthrough was
  added (deploy/compose.yml, coraza service, step-14 comment).
- Mechanism proof per run: the rule-29 line in each run's log prints
  `env_CT=[...]` from inside the container, plus the effective crs-setup
  grep of rule 900220 where activated.
- Reference: https://coreruleset.org/docs/prepare/#environment-variables and
  the in-image scripts quoted above.

## Step-22: engine default actions for all phases (documented BEFORE the run, rule 17)

- What: the engine's generated configuration (engine/config.go) gains
  `SecDefaultAction "phase:N,log,auditlog,pass"` for N = 1 to 5, before the
  rule Include. These are lines 98-102 of the connector image's
  /opt/coraza/config/crs-setup.conf (read from the running container
  2026-11-27 with `grep -n ^SecDefaultAction`).
- Why: the engine set no SecDefaultAction, so only phase 2 had coraza's
  built-in default (log, auditlog). CRS rules that match in phase 1 (920350
  numeric Host, 920450 restricted header, 920320 missing User-Agent, ...)
  scored and appeared on the block page, but were missing from the audit
  entry, while the connector's audit log has them (step-22 report, T5:
  920450 message on 15 of 15 connector cells, 0 of 15 engine cells). Test
  E32 (failing in 5b47a00).
- Expected effect: audit entries and the rule-id sets derived from them
  gain phase-1 rule ids. No status may change: the disruptive action stays
  with CRS 949110 (deny) and `pass` is the default in every phase already.
  Checked after the change by replaying benign-wcp-v1 at PL1 and PL2 and
  comparing statuses per id with the step-22 parity run.
- Reference: https://coraza.io/docs/seclang/directives/#secdefaultaction

## Step-25: CRS regression-suite configuration (documented BEFORE the run, rule 17)

- What: two engine switches, both off by default, used only by the runs of
  the CRS regression suite (docs/plan-step25-crs-regression.md).
  1. `KORTEX_ERROR_LOG=<path>`: one line per matched rule that has the
     `log` action, in the ModSecurity error-log form produced by coraza's
     `MatchedRule.ErrorLog()`. No rule and no decision changes.
  2. `KORTEX_CRS_TEST_SETUP=on`: three directives before the rule Include:
     - `SecAction "id:900005,phase:1,nolog,pass,setvar:tx.crs_validate_utf8_encoding=1,setvar:tx.arg_name_length=100,setvar:tx.arg_length=400,setvar:tx.total_arg_length=64000,setvar:tx.max_num_args=255,setvar:tx.max_file_size=64100,setvar:tx.combined_file_sizes=65535"`
       (rule 900005 of the suite's README, without its three `ctl` /
       paranoia actions: mode and paranoia come from `KORTEX_RULE_ENGINE`,
       `KORTEX_BLOCKING_PARANOIA`, `KORTEX_DETECTION_PARANOIA`);
     - `SecAction "id:900511,phase:1,pass,nolog,setvar:tx.crs_xml_attr_inspect=1"`
       (the CRS `tests/docker-compose.yml` at v4.25.2);
     - `SecRule REQUEST_HEADERS:X-CRS-Test "@rx ^.*$" "id:999999,phase:1,pass,t:none,log,msg:'X-CRS-Test %{MATCHED_VAR}',ctl:ruleRemoveById=1-999999"`
       (the suite's log marker; text from coraza v3.8.1
       `testing/coreruleset/coreruleset_test.go`).
- Run settings of the suite, through the existing variables:
  `KORTEX_RULE_ENGINE=DetectionOnly`, `KORTEX_BLOCKING_PARANOIA=4`,
  `KORTEX_DETECTION_PARANOIA=4`. Limits, budget, lanes, allowed methods,
  900220 and the REQUEST_BODY targets: as in baseline v1.9.
- Why: the suite's runner (go-ftw) reads the WAF's log between two marker
  requests to see which rules matched; the suite is written for
  DetectionOnly at paranoia level 4 with these limits
  (`tests/regression/README.md`). The engine had no log go-ftw can read for
  a request that is forwarded.
- Rule 17 and `ctl:ruleRemoveById`: rule 999999 removes every rule for a
  request that carries the `X-CRS-Test` header. It is a harness rule of the
  suite, rendered only with the switch on. No baseline, parity or dataset
  run sets the switch, and the switch is printed on `/__kortex/config`
  (`crs_test_setup`), so its absence is provable per run (rule 29). With the
  switch on the engine must not face anything but the test runner: any
  client can then switch the rules off with one header.
- Expected effect: none on any run that does not set the two variables.
- References: https://github.com/coreruleset/coreruleset/blob/v4.25.2/tests/regression/README.md ,
  https://github.com/coreruleset/coreruleset/blob/v4.25.2/tests/docker-compose.yml ,
  https://github.com/corazawaf/coraza/blob/v3.8.1/testing/coreruleset/coreruleset_test.go ,
  https://github.com/coreruleset/go-ftw/pull/133 (marker rule),
  https://coraza.io/docs/seclang/actions/#ctl

## Step-26: runs of attacks-v1 (documented BEFORE the runs, rule 17)

- What: no configuration is changed. The runs of docs/plan-attacks-v1.md
  use settings that exist:
  1. Reach check, before the freeze: the engine in-process with
     `KORTEX_RULE_ENGINE=DetectionOnly`, `KORTEX_BLOCKING_PARANOIA=1`,
     `KORTEX_DETECTION_PARANOIA=1`, otherwise as in baseline v2.0. The run
     script passes the mode through `ENGINE_RULE_MODE` (tools/step22_lib.sh;
     default `On`, as before).
  2. Engine runs after the freeze: baseline v2.0 as it is (blocking, PL1 and
     PL2, in-process and worker; `KORTEX_ERROR_LOG` and
     `KORTEX_CRS_TEST_SETUP` unset).
  3. Baseline images of deploy/compose.yml with their default configuration
     and the stub backend, as in the step-22 follow-up
     (tools/run_step22_modsec_connector.sh): ModSecurity
     `MODSEC_RULE_ENGINE=On`, Coraza connector `CORAZA_RULE_ENGINE=On`,
     `PARANOIA` = `BLOCKING_PARANOIA` = `DETECTION_PARANOIA` = 1 or 2. The
     ModSecurity audit log is redirected to a file and nginx reloaded (the
     capture-only change of step 9 and step 13), with 20 control requests
     before and after the samples (rule 36).
  4. DIAGNOSTIC (rule 34): the engine built in a scratch copy without the
     REQUEST_BODY target updates (the one-line change of the step-25
     DIAGNOSTIC), PL1 and PL2. It gives no baseline number.
- Why: first measurement of recall on attack payloads that no engine
  setting was chosen with.
- No rule exclusion and no setting is changed in response to a result of
  these runs (rule 17).

## Step-27: head time limit as a setting (documented BEFORE the run, rule 17)

- What: `KORTEX_HEAD_TIMEOUT_MS` (default 30000): how long the gate waits
  for the end of a request head. The value was a constant of 30 s; the
  default keeps it. Printed on `/__kortex/config` as `head_timeout_ms` and
  on the startup line.
- Why: the gate now answers and logs a head that does not end in time
  (docs/engine-design.md, step 27), and a test of that must not wait 30 s
  (rule 48: a failing-by-design test must fail deterministically).
- No run of this step sets it; no rule or limit changes.
- Reference: https://pkg.go.dev/net/http#Server (ReadHeaderTimeout, the
  equivalent net/http setting).

## Step-27: cap on connections waiting in the gate (documented BEFORE the run, rule 17)

- What: `KORTEX_MAX_PENDING_HEADS` (default 256): how many accepted
  connections may be waiting for the end of their request head at once. A
  connection over the cap is answered `503 kortex-decision=overload`
  (event `overload`, reason `pending-heads`). Printed on `/__kortex/config`
  as `max_pending_heads`; the current count is `pending_heads` on
  `/__kortex/stats`.
- Why: the gate now reads heads concurrently instead of one at a time
  inside the accept loop (docs/engine-design.md, step 27, E61), and the
  waiting connections need a bound.
- Expected effect on the dataset runs: none. The runner sends one request
  at a time, so at most one head is waiting.
- No rule or inspection limit changes.
