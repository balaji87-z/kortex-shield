# benign-hard-v0 — hand-authored hard benign inputs (frozen)

- **Source**: `hand-authored-hard-benign@<git commit>` — 90 hand-written legitimate
  values in attack-adjacent categories (SQL/shell/HTML words inside natural-language
  searches, apostrophes/unicode names, special-character passwords, URLs and emails
  in text, long review sentences, code-like text).
- **Injection points**: same two as the attack corpus —
  `GET /rest/products/search?q=<quoted>` and `POST /rest/user/login` with the value
  in `email` (even indices) or `password` (odd indices). 180 samples.
- **Reach check** (rule 13: fresh container, DetectionOnly, PARANOIA=1, workers 1):
  180/180 reachable, 0 probes, 0 quarantine, 0 excluded.
- **Frozen**: `manifest.jsonl` SHA-256 `65bdfc69022c5b02...` (full value in
  `MANIFEST.sha256`). Never edit after seeing blocking-mode results (rule 10).
- **Files**: `manifest.jsonl`, `MANIFEST.sha256`, `annotations.jsonl` (endpoint per
  sample), `candidates.jsonl` (pre-freeze), `probes.jsonl` / `quarantine.jsonl` (empty).

## ⚠️ This set OVERSTATES the false positive rate on natural traffic

Every value was chosen because it looks attack-adjacent. A CRS false-positive rate
measured on this set is an UPPER BOUND for natural traffic and is NOT comparable to
the rate on `benign-browse-v0`. **Never merge or average the two rates** (AGENTS.md
rule 14). Report both separately, always with this caveat.
