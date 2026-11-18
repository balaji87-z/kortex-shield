# Preregistration: benign-browse-v1 (step-07, T3)

Written and committed BEFORE any v1 recording or run (AGENTS rule 22).
No v0 dataset is edited.

## Sources and procedure

- Same source as v0: `tools/record_benign.py` drives the real Juice Shop UI
  with Playwright, recording through the TARGET directly (port 13000, no WAF
  in the path), so blocks cannot alter what is recorded. Every request the
  browser makes is captured (method, raw path, raw query, headers, raw body,
  content-type).
- 60 sessions, each seeded by its index. Indices start at **1000** (v0 used
  0–19), so v1 users, review sentences and sampled product indices differ
  from v0 even where flows are identical.
- Even indices = anonymous sessions, odd indices = registered sessions
  (30 each), same split rule as v0.
- Both the welcome banner AND the fruit-cookie banner ("Me want it!") are
  dismissed at session start; the cookie banner was found to intercept
  clicks on the register page during the step-07 probe.

## Flows

Kept from v0 (same selectors, per session):

1. open home, wait for products;
2. 5 product dialogs (anonymous);
3. 10 searches using terms derived from the rendered product names
   (anonymous);
4. register a deterministic seeded user, log in (registered);
5. add 2 products to the basket (registered);
6. open the basket and the profile pages (registered);
7. post one product review from the hand-written sentence list
   (registered).

Added in v1 (registered sessions; all verified drivable by the step-07
probe on Juice Shop v20.4.0):

8. **product-review edit** — post a review, then click the `Edit Review`
   button on the just-posted review and save an edited sentence (drives
   `PUT /rest/user/reviews` style traffic plus the edit-dialog requests);
9. **basket quantity change** — on the basket page click the row's
   `fa-plus-square` button once (drives `PUT /api/BasketItems/:id`);
10. **basket item removal** — click the row's `fa-trash-alt` button
    (drives `DELETE /api/BasketItems/:id`);
11. **language switch** — open the navbar `Language selection menu` and
    pick a second language, then switch back (drives `GET /assets/i18n/*`
    and re-rendered pages);
12. **log out and back in** — open the account menu, log out, then log in
    again with the same seeded credentials (drives logout + a second login
    POST in the same session).

Not drivable, listed with reason:

- **theme switch** — Juice Shop v20.4.0 ships no theme toggle in its UI;
  the step-07 probe enumerated all `button[aria-label]` controls on the
  home page and found no theme control. No synthetic API calls are made to
  substitute for it (the recorder only keeps what the real UI sends).

## Dedupe and the session dimension

- Dedupe key is unchanged from v0: SHA-256 over
  `(method, path, query, content_type, body)`. Recorded headers are kept on
  the sample but are NOT part of the hash (dataset README).
- Dedupe must not erase the session dimension: the recorder additionally
  writes **`sessions.jsonl`**, one row per sample id, mapping
  `{"id": <sample id>, "sessions": [list of session indices that produced
  this content hash, sorted]}`. The sample row itself keeps only the first
  occurrence's request fields, exactly as v0 did.

## Counts

- Target: 60 sessions → expect roughly 3× v0's raw request volume
  (v0: 20 sessions → 1374 captured requests → 214 unique samples). No
  numeric sample target is set; the actual counts are reported after the
  run, before freezing.

## Saturation measurement (T5, preregistered)

For v1 sessions **in recording order**, report cumulative distinct requests
and cumulative distinct endpoints after 5, 10, 20, 30, 40, 50 and 60
sessions, and the same after 5, 10 and 20 sessions for v0. Present as a
table (tabulate; no image). State whether growth has flattened (the
increment between the last two checkpoints is small relative to the total)
and what that implies for reaching the 1,400-distinct-legitimate-requests
bar of `docs/acceptance.md` A2 by scripted sessions alone.

## Freeze procedure (T4)

1. record 60 sessions → `candidates.jsonl` + per-session reports;
2. dedupe → samples + `sessions.jsonl`;
3. reach check in DetectionOnly PL1 (rule 13: container force-recreated,
   one run per log capture, `--workers 1`); filter ONLY on
   `proxy_reject`, `inconsistent`, `error` — a sample flagged by detection
   rules in DetectionOnly is NOT removed (it is a true-positive finding
   against the corpus, to be reported, not silently dropped);
4. freeze: `MANIFEST.sha256`, dataset README (sources, counts, dedupe
   fields, sessions.jsonl description), `annotations.jsonl` (endpoint per
   sample).
