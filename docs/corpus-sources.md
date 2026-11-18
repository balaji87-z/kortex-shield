# Corpus sources

Recorded per standing rule 10-12 and step-03 T3. Cloned with `git clone --depth 1`
into `data/external/` (gitignored); the commit SHA below is what was actually used.

| Repo | URL | Commit SHA | License (from its LICENSE file) |
|---|---|---|---|
| SecLists | https://github.com/danielmiessler/SecLists | `6b19c2f5088c45b5dadb4d8918d2ab4f7efb03a9` | MIT (LICENSE: "MIT License, Copyright (c) 2018 Daniel Miessler") |
| PayloadsAllTheThings | https://github.com/swisskyrepo/PayloadsAllTheThings | `08ea40e77db3f42ef8f20c65196f3936a19b6c86` | MIT (LICENSE: "MIT License, Copyright (c) 2019 Swissky") |

Clones verified:
    $ git -C data/external/SecLists rev-parse HEAD
    6b19c2f5088c45b5dadb4d8918d2ab4f7efb03a9
    $ git -C data/external/PayloadsAllTheThings rev-parse HEAD
    08ea40e77db3f42ef8f20c65196f3936a19b6c86

## openappsec WAF Comparison Project legitimate set (added step-09, T3)

- Project repo: https://github.com/openappsec/waf-comparison-project
  cloned `--depth 50` into `data/external/waf-comparison-project` (gitignored).
  Commit SHA used: `8ec8263eebba76816601f7c7052f8ffb83e31312`
  (2026-02-11 "Merge pull request #10 from Tal-Gav/wcp_2026_update").
- Licence: Apache License 2.0 (`LICENSE` file in the repo). Permits use and
  redistribution with attribution; the dataset itself is fetched separately
  (see below), so what we commit is a fetch script plus the SHA-256 of the
  downloaded archive, not the data.
- Legitimate dataset URL (from `config.py`, `LEGITIMATE_URL_PATH`):
  https://downloads.openappsec.io/waf-comparison-project/legitimate.zip
  - downloaded 2026-11-18; SHA-256 of the zip:
    `58faee18c54229759287a574f6f8cb1e3b951fa135e403ea9a679d2b18efd778`
    (1,203,983,791 bytes; server `content-length` matched after a resumed
    download; first attempt truncated at 792,576,000 bytes and was discarded).
- Malicious dataset (same project, `malicious.zip` +
  openappsec/mgm-web-attack-payloads): NOT used in step-09 (plan-benign-wcp-v0).

### How the repo defines the sets (from its README at that commit)

- Legitimate: "1,040,242 different HTTP requests from 185 real-web sites in
  12 categories. Each dataset was recorded by browsing to real-world websites
  and conducting various operations in the site (for example, sign-up,
  selecting products and placing in a cart, etc.) ensuring the presence of
  100% legitimate requests."
- Label assignment method: everything in the legitimate zip is labelled
  legitimate because it was produced by scripted browsing of real sites
  (vendor-asserted; no per-request labelling evidence is published). This is
  the "listed under this label in this source" meaning of rule 11.
- Discrepancy noted: the repo README says 185 sites / 12 categories, but the
  zip contains 692 JSON files and the requests carry 10,455 distinct `host`
  header values (includes third-party hosts: CDNs, analytics, ads). We treat
  the 692 files as the site strata and report host counts as measured.

### Format and fields (measured, streaming over the zip, no full extraction)

- 692 files `Legitimate/browsing_*.json`, each a JSON array of request
  objects, 37–8,311 requests per file (median 1,290).
- Every request object has exactly 4 fields: `method`, `url` (path + query,
  no scheme/host), `headers` (object, original casing preserved), `data`
  (string body, "" when absent).
- Header/body presence: all 1,040,242 have `headers`; 240,554 have a
  non-empty `data` (1,661,808,469 body bytes total).
- Methods: GET 741,100; POST 295,304; PUT 2,014; HEAD 1,311; DELETE 457;
  PATCH 56.
- Distinct `host` header values: 10,455. Top: www.facebook.com 21,183;
  www.google.com 18,195; www.forever21.com 12,687; www.google-analytics.com
  12,100; googleads.g.doubleclick.net 8,540.
- Credential-bearing requests (header-name census over the full set):
  `Authorization`/`Proxy-Authorization` header present in 35,738 requests;
  `Cookie` header present in 715,322 requests. Deeper value-level scanning
  (emails, API keys in query/body) is done on the built sample only
  (plan-benign-wcp-v0) and reported there (rule 25: type and count only).

### Replayability check (T3 STOP condition)

- Headers: present for every request → replayable.
- Bodies: present for every request that had one (`data` field) → replayable.
- Licence: Apache 2.0, no restriction on replaying for testing; we commit
  only derived sample data + fetch script + SHA, which the licence allows
  with attribution.
- → T4–T6 NOT blocked.
