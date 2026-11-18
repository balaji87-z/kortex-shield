# benign-browse-v1 — natural browsing traffic from the real Juice Shop UI (frozen)

Frozen 2026-11-18 (step-07). Manifest SHA-256:
`950a683bf776ef637691514f1dab809fddd2de757bacdff3dc9cb1f30af3b085`
(over `manifest.jsonl`, raw bytes). After this file was written, no sample
may be added, removed or edited (AGENTS rule 10); any change creates a new
version folder.

## What it is

774 unique benign requests produced by **60 scripted Playwright sessions**
driving the real OWASP Juice Shop v20.4.0 UI, recorded through the TARGET
directly (port 13000, no WAF in the path). Session indices 1000–1059
(preregistered in `docs/plan-benign-v1.md`, committed before recording):
30 anonymous (even indices), 30 registered (odd indices), each seeded by
its index. Flows: v0 flows (home/products, product dialogs, catalog-derived
searches, register/login, basket add, basket/profile pages, product review)
plus the v1 flows — review edit (`PUT /rest/products/1/reviews`), basket
quantity change (`PUT /api/BasketItems/:id`, also recorded in its
double-slash spelling `//api/BasketItems/:id` as sent by the app), basket
item removal (`DELETE //api/BasketItems/:id`), and log out / log in again.
Theme switch is not drivable (no UI control in v20.4.0); language switch
was dropped before recording (menu items never render under Playwright —
see the deviation note in `docs/plan-benign-v1.md`).

## Files

- `manifest.jsonl` — the 774 samples (identical bytes to `candidates.jsonl`).
- `sessions.jsonl` — one row per sample id: `{"id": ..., "sessions": [...]}`
  listing EVERY session index that produced that content hash. Dedupe
  collapses identical requests; this file preserves the session dimension.
- `annotations.jsonl` — `{"id", "endpoint"}` per sample (normalized endpoint
  from `kortex_eval.endpoints`).
- `MANIFEST.sha256` — SHA-256 of `manifest.jsonl`.

## Dedupe

Key: SHA-256 over `(method, path, query, content_type, body)` — same as v0.
Recorded headers are kept on the sample but are NOT part of the hash.
Consequence: identical requests made twice within one session (e.g. a
second login POST after logout) collapse into one sample and are visible
only through `sessions.jsonl` at the session level, not as request counts.

## Counts

- 774 unique samples after dedupe (raw captured-request count lost with the
  recorder's log file — recorded as a deviation in `reports/step-07.md`;
  the first recording attempt produced 7970 raw → 879 unique, the final
  recording's raw count is UNVERIFIED).
- 68 distinct normalized endpoints.
- Reach check (DetectionOnly, PL1, fresh container, rule 13): 774/774
  reachable; 0 `proxy_reject`, 0 `inconsistent`, 0 `error` → nothing
  quarantined, nothing excluded. 184 samples `waf_would_block` under
  DetectionOnly are reported in `reports/step-07.md` (they are kept — a
  detection-rule hit on benign traffic is a finding, not an exclusion).

## Label meaning

All samples are labelled `benign` / family `benign` because they were
produced by driving the real UI with realistic user actions. Per the
standing rules this means "produced by the recorded benign flow", not
"verified impossible to block for legitimate reasons"; the per-endpoint
blocking results in the baseline docs are the check on that.
