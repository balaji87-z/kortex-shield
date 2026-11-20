# Plan: attacks-ct-v0 — attack-side carrier set (preregistration)

Date: 2026-11-20 (step-14, task T2). Status: plan committed BEFORE the
manifest is built and BEFORE any run (rules 10, 22). After results are seen
the manifest and this plan are not edited; any change creates a new version.

## Purpose

Measure how ModSecurity and Coraza (CRS 4.25.2) detect the same attack
payloads delivered through different request carriers, under the default
content-type policy and under a widened policy. This is an attack-side
complement to the benign-wcp-v0 baselines.

## Payloads (fixed by id, frozen)

40 payloads from the frozen attacks-v0 manifest, 10 per family, chosen by
seeded sample: `random.Random(0)` over the alphabetically sorted list of
distinct payloads (a payload = one SecLists/PayloadsAllTheThings source line;
attacks-v0 stores each payload as a `-q`/`-login` pair, the first occurrence
in file order is taken). Selection script: tools/build_attacks_ct_v0.py.
The 40 ids (source commit/line in attacks-v0 manifest):

- sqli: sqli-0933fb66, sqli-6e47f23b, sqli-8c187a93, sqli-a2035700,
  sqli-bd5671f5, sqli-bde4f6b2, sqli-c6072953, sqli-daa646a8, sqli-e0ed04bd,
  sqli-eb3ff328 (source: SecLists quick-SQLi.txt, commit 6b19c2f5)
- xss: xss-369d0b75, xss-545d1ff8, xss-56083d09, xss-784791cd, xss-84f65a00,
  xss-8f5b4e90, xss-9d9144c5, xss-e0e52a03, xss-eb4cfe84, xss-ffb57ed3
  (source: SecLists XSS-Cheat-Sheet-PortSwigger.txt, commit 6b19c2f5)
- path-traversal: path-traversal-1ec1b09a, path-traversal-2aa7f02e,
  path-traversal-556a4824, path-traversal-921f3d78, path-traversal-9a36aadc,
  path-traversal-a605a9c3, path-traversal-c5d7df2b, path-traversal-d0149f94,
  path-traversal-f51c297b, path-traversal-f8eebd5c (source:
  PayloadsAllTheThings Traversal.txt, commit 08ea40e7)
- command-injection: command-injection-029d9cca, command-injection-05bbe7a8,
  command-injection-1b8cf3ce, command-injection-227cb8a4,
  command-injection-77c3ff65, command-injection-b810e30e,
  command-injection-cfb6b9f0, command-injection-dc2932d5,
  command-injection-ecb32a80, command-injection-f48aa068 (source:
  PayloadsAllTheThings command_exec.txt, commit 08ea40e7)

Payload text is taken from the `-q` sample of each pair: the URL-decoded value
of `q=` in the query string. Payload lengths 3–292 characters, none contain
newlines. Payloads come from public payload lists (rule 11: "attack" means
"listed in this source", not "verified exploitable").

## Carriers (8 per payload, 320 samples total)

Path `/` for every sample. `P` = raw payload text, `U(P)` = its
percent-encoding (RFC 3986 unreserved characters kept). Sample id =
`actv0-<carrier>-<payload id without -q suffix>`.

1. `query` — GET `/`?q=U(P)`, no body.
2. `urlencoded` — POST, body `q=U(P)`, Content-Type
   `application/x-www-form-urlencoded`.
3. `json` — POST, body `{"q":"P"}` with JSON escaping, Content-Type
   `application/json`.
4. `multipart` — POST, multipart/form-data with boundary
   `----kortexboundary`, one form field `q` = P (raw), valid
   Content-Disposition and closing boundary.
5. `text-plain` — POST, body = P (raw), Content-Type `text/plain`.
6. `octet-stream` — POST, body = P (raw bytes), Content-Type
   `application/octet-stream`.
7. `unknown-ct` — POST, body = P (raw), Content-Type
   `application/x-kortex-probe-unknown` (a type absent from every allowlist).
8. `no-ct` — POST, body = P (raw), no Content-Type header.

Method: GET for `query`, POST for all body carriers. Backend: the neutral
stub (stub-backend:3000), so every non-200 is attributable to the WAF.

Example (payload `admin" or "1"="1"#`, id sqli-6e47f23b):

- query: `GET /?q=admin%22%20or%20%221%22%3D%221%22%23`
- urlencoded: POST body `q=admin%22%20or%20%221%22%3D%221%22%23`
- json: POST body `{"q":"admin\" or \"1\"=\"1\"#"}`

## Configs (documented before running, rule 17)

- `crs-default` — image defaults, `ALLOWED_REQUEST_CONTENT_TYPE` unset.
- `crs-ct-wide` — default policy plus `text/plain` and
  `application/octet-stream`, set through the CRS mechanism
  (`tx.allowed_request_content_type` in crs-setup.conf) via the images'
  `ALLOWED_REQUEST_CONTENT_TYPE` env: value
  `|application/x-www-form-urlencoded| |multipart/form-data| |text/xml| |application/xml| |application/soap+xml| |application/json| |text/plain| |application/octet-stream|`
  (the CRS default list plus the two types). The rendered value
  `tx.allowed_request_content_type=...` is printed from inside each running
  container before the run (rule 29) and saved with the run log.

Engines: ModSecurity (8081) and Coraza (8082). Paranoia levels 1 and 2
(BLOCKING_PARANOIA = DETECTION_PARANOIA = PL). Rule 13: fresh container per
run, one audit log per run, `--workers 1`. Rule 36: per run, a seeded control
request known to match a rule (GET `/?q=%27%20OR%201%3D1--`, matches 942100)
is sent 20 times before and 20 times after the main run; the audit log must
contain 20 + 20 control entries — counts are printed per run and reported.

Runs: 2 configs × 2 engines × 2 PL = 8 cells × 320 samples = 2,560 requests
plus 8 × 40 = 320 control requests.

## Analysis (stated before running)

Per cell (carrier × config × engine × PL): blocked count of 40 and the audit
rule IDs. Blocks are split into (a) blocks whose only rule is 920420 (policy)
and (b) blocks with at least one detection rule. Reported:

- per carrier, per config, per engine, per PL: blocked count of 40 and rule
  IDs;
- carriers where one engine blocked fewer than the other;
- carriers where the detection-rule block count drops from crs-default to
  crs-ct-wide;
- every payload id detected under one carrier and not under another on the
  same engine.

No rates across carriers (rule 35): the carriers differ structurally, so only
counts of 40 are reported. No interpretation, no verdict (decision 0002).

## Freeze

The manifest (320 rows, kortex_eval manifest format) is built by
tools/build_attacks_ct_v0.py into data/attacks-ct-v0/manifest.jsonl and
frozen: its SHA-256 is written to data/attacks-ct-v0/MANIFEST.sha256 right
after the build. After results are seen the manifest is never edited
(rule 10); a change would create a new version folder.
