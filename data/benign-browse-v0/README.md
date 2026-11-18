# benign-browse-v0 — recorded natural browsing traffic (frozen)

- **Source**: `playwright-<version>:tools/record_benign.py@<git commit>` — Playwright
  driving the REAL Juice Shop UI at `http://localhost:13000/` (recorded through the
  target directly, no WAF in the path).
- **Sessions**: 20 (10 anonymous: home, 5 product dialogs, 10 catalog-derived searches;
  10 registered: deterministic register/login, browse, 2 basket adds, basket, profile,
  1 product review from a hand-written list of 20 plain sentences).
- **Capture**: every browser request (method, raw path, raw query, headers, raw body,
  content-type). Recorded headers kept except `Host`, `Content-Length`, `Connection`,
  `Accept-Encoding`; the runner adds `X-Kortex-Sample-Id` (overrides any recorded
  header of the same name).
- **Dedupe**: by content hash over (method, path, query, content-type, body).
  Recorded headers are NOT part of the hash: two requests with identical
  method/path/query/content-type/body but different headers collapse to one
  sample, keeping the first-seen headers. Captured 1374 requests →
  **214 unique samples**.
- **Reach check** (rule 13: fresh container, DetectionOnly, PARANOIA=1, workers 1):
  214/214 reachable, 0 probes, 0 quarantine, 0 excluded.
- **Frozen**: `manifest.jsonl` SHA-256 `20fe88df3152c43dd8312fe16e835a6de432e01f14dd5e191f0933ca1d4de8b1`.
  Never edit after seeing blocking-mode results (AGENTS.md rule 10).
- **Files**: `manifest.jsonl`, `MANIFEST.sha256`, `annotations.jsonl` (endpoint per
  sample from `kortex_eval.endpoints`), `candidates.jsonl` (pre-freeze, kept for
  provenance), `probes.jsonl` / `quarantine.jsonl` (empty).

## Environment findings recorded during capture

1. **UI search is client-side in Juice Shop v20.4.0.** Typing a term in the search box
   (or navigating to `#/search?q=<term>`) filters the already-fetched product list in
   the browser; the SPA sends only one `GET /rest/products/search?q=` (empty q) when
   the search page loads. Per-term search requests therefore do NOT appear on the
   wire and are absent from this corpus. Verified by request-event logging during
   scripted searches.
2. All 20 sessions ran in ONE browser context, so browser caching collapsed repeated
   identical requests (assets, repeated API calls) into single samples — the dedupe
   numbers below the session level are dominated by this.
3. Real-traffic quirks preserved: `GET /rest/basket/NaN` (transient app behavior),
   `socket.io` polling (73 samples), static assets.

## Known limitation

The sample mix is asset-heavy (static JS/CSS/images, socket.io polling). Endpoint
diversity is real but per-endpoint counts are small; treat per-endpoint FP rates as
indicative only.
