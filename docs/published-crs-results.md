# Published CRS evaluation numbers (research notes, step-08 T4)

Research only — nothing was run or downloaded for this document. Compiled
2026-11-18 via web search. Every number below is quoted from the source
text shown in the search results; anything I could not read directly in the
source is marked **UNVERIFIED** (I only saw abstracts/snippets for several
papers). Numbers are NOT averaged across sources (per instructions); each
row stands alone. "Read directly" = the figure appeared verbatim in the
page text I saw.

## Sources with concrete numbers

### 1. MSc dissertation repo: ModSecurity CRS 3.3.8, PL1 vs PL2

- URL: https://github.com/Bill-Benson/Modsecurity-crs-paranoia-evaluation
- Date: created 2026-04-25 (submitted as MSc dissertation, Wrexham
  University, April 2026)
- CRS version: 3.3.8 (ModSecurity v3.0.14 + nginx, docker image
  `owasp/modsecurity-crs:n...` — exact tag truncated in the snippet:
  UNVERIFIED)
- Paranoia levels: PL1 (inbound threshold 5) vs PL2 (inbound threshold 3)
- Dataset: 700 requests per configuration — 200 malicious (100 SQLi + 100
  XSS across 5 subcategories each) and 500 benign (SQL-keyword,
  scripting-keyword, special-chars, neutral), i.e. hand-designed benign
  traffic, not natural browsing
- Numbers (read directly): TPR 97.0% at both PLs; FPR 1.0% (PL1) → 2.0%
  (PL2); precision 97.5% → 95.1%; F1 97.2% → 96.0%; MCC 0.9614 → 0.9444.
  Key claim: no PL2-tagged rule fired in either configuration; every
  difference came from threshold arithmetic ("threshold-not-rules" effect).
- Attack/benign definition: attack = curated SQLi/XSS payload lists;
  benign = deliberately designed requests containing SQL/scripting
  keywords and special characters.
- Comparability to our setup: partial. Same engine family (ModSecurity +
  CRS docker image), same PL1/PL2 axis and threshold semantics. Not
  comparable on traffic: their benign set is synthetic keyword traffic,
  ours is recorded real-UI sessions; their attack set is 200 curated
  payloads vs our 1,054-sample corpus. Their "PL2 = threshold only"
  finding mirrors our step-05 discovery (BLOCKING_PARANOIA quirk) but with
  a different root cause (their config used threshold 3 at PL2).

### 2. Indonesian journal: ModSecurity + CRS on OWASP Juice Shop

- URL: https://j-ptiik.ub.ac.id/index.php/j-ptiik/article/download/16627/7293
  (Jurnal Pengembangan Teknologi Informasi dan Ilmu Komputer, Vol. 10
  No. 6, Juni 2026 — volume/year as printed; UNVERIFIED beyond the page)
- Date: June 2026 (as printed)
- CRS version: not visible in the abstract — UNVERIFIED
- Paranoia levels: PL1–PL4
- Dataset: modern SQL Injection attacks against OWASP Juice Shop in Docker
- Numbers (read directly from the abstract): Detection Rate 98.82% (PL1),
  99.98% (PL2), 99.99% (PL3), 99.99% (PL4); False Positive Rate 25.93%
  (PL1), 57.43% (PL2), 66.96% (PL3), 100% (PL4)
- Attack/benign definition: attack = "modern" SQLi (encoding, obfuscation,
  comment injection, bypasses); benign = not visible in the abstract —
  UNVERIFIED (an FPR of 100% at PL4 suggests the benign set consists of
  requests that all trip CRS at PL4, but that is inference, not a stated
  fact)
- Comparability: the TARGET is the same (Juice Shop on Docker), which makes
  the FP numbers interesting against ours (crs-default 15.89% on v0
  natural at PL1). But their benign definition is unknown and their attack
  set is SQLi-only, so the comparison is suggestive, not controlled.

### 3. wafplanet.com blog: AI agent tuning CRS regexes

- URL: https://wafplanet.com/blog/autoresearch-crs-regex/
- Date: 2026-03-16
- CRS version: CRS nightly (their words) on nginx, PL1
- Dataset: 4,595 requests — 95 malicious payloads derived from a CVE
  database (chosen to hit known CRS blind spots) + 4,500 legitimate
  requests from the openappsec/waf-comparison-project (real captured
  browsing sessions from 692 websites)
- Numbers (read directly): baseline balanced accuracy 0.630, TPR 55.8%,
  FPR 29.7% (1,338 FPs); after 20 rule-editing experiments: balanced
  accuracy 0.976, TPR 100%, FPR 4.8% (218 FPs)
- Attack/benign definition: attack = CVE-derived payloads targeting CRS
  gaps; benign = real captured browsing sessions from 692 websites
  (e-commerce, travel, gaming, food delivery, social media)
- Comparability: the benign half is the closest published analogue to our
  natural-browsing corpora (real browser sessions against real sites).
  Their baseline FPR 29.7% at PL1 with default-ish CRS is in the same
  range as our crs-default numbers (15.89% v0 / 23.77% v1). Their attack
  set is adversarially chosen against CRS gaps, so their TPR is not
  comparable to our recall.

### 4. Anuvarshini et al., Computers & Security (2025)

- URL: https://doi.org/10.1016/j.cose.2025.104714
- Date: published 2025-10-20
- CRS version: not visible in the abstract — UNVERIFIED
- Paranoia level: not visible — UNVERIFIED
- Dataset: "controlled test environment" — details not visible — UNVERIFIED
- Numbers (read directly from the abstract): baseline detection precision
  60.54%, improved to 97.46% by adding 146 custom rules, "with no increase
  in false positives"
- Attack/benign definition: not visible in the abstract — UNVERIFIED
- Comparability: cannot be judged from the abstract alone.

### 5. AutoEx (Reyes Narváez et al., Electronics, MDPI)

- URL: https://www.mdpi.com/2079-9292/15/9/1877
- Date: published 2026-04-29
- CRS version: not visible — UNVERIFIED
- Paranoia levels: "multiple CRS paranoia levels" (unspecified)
- Dataset: controlled traffic scenarios (details not in abstract)
- Numbers (read directly from the abstract): FP rates decrease "from 100%
  to mean residual values between 32% and 46%" with simple input datasets,
  "below 2%" with representative datasets; detection effectiveness 100%
  ("all intentionally introduced attack payloads correctly identified and
  blocked")
- Attack/benign definition: attack = intentionally introduced payloads;
  benign = "traces of legitimate traffic" (generation method not visible —
  UNVERIFIED)
- Comparability: their 100% pre-tuning FP rate implies a benign set that
  CRS flags wholesale — very different from natural browsing; not
  comparable without the full paper.

### 6. CRS GitHub issue #1016 (2018): CRS 2.2.9 on CSIC 2010 / ECML-PKDD

- URL: https://github.com/SpiderLabs/owasp-modsecurity-crs/issues/1016
- Date: 2018-02 (thread; last update 2020-02)
- CRS version: 2.2.9 (stated in the comment)
- Paranoia level: not applicable/mentioned (CRS 2.x era)
- Dataset: CSIC 2010 and ECML/PKDD 2007 (see T5 doc for dataset details)
- Numbers (read directly from the comment by rodrigo-martinez):
  | dataset | precision | recall | FPR | FNR |
  |---|---|---|---|---|
  | ECML/PKDD 2007 | 0.7 | 0.93 | 57.21% | 7.03% |
  | CSIC 2010 | 0.5 | 0.343 | 23.93% | 65.68% |
- Attack/benign definition: the datasets' own labels; the commenter notes
  CSIC labels misspelled-parameter requests as "anomalous" although they
  are not attacks.
- Comparability: old CRS (2.2.9), old engines; useful mainly as evidence
  that dataset label quality drives WAF metrics, not as a CRS 4.x
  baseline.

## Sources with no numbers visible (all UNVERIFIED — abstract only)

- Reyes Narváez et al., "Evaluation Framework for False Positives in
  Open-Source WAFs Based on OWASP CRS Paranoia Levels", Eng. Proc. 2025,
  https://doi.org/10.3390/engproc2025115001 (2025-11-15). Framework for FP
  measurement across PL1–PL4 with controlled legitimate traffic; no
  figures visible in the abstract.
- Curipallo Martínez et al., "Web Application Protection Optimization
  Through Coraza WAF...", Eng. Proc. 2025,
  https://www.mdpi.com/2673-4591/115/1/17 (2025-11-15). Coraza WAF + CRS
  4.15.0 behind Envoy/Caddy, FP measured per PL2–PL4; exact FP values not
  visible in the snippet. Relevant to the future Coraza engine decision
  (same rule set version family as ours).
- Scano et al., "ModSec-Learn", arXiv:2406.13547 (v1 2024-06-19, v2
  2026-09-29), https://arxiv.org/pdf/2406.13547 — argues CRS's manual
  scoring is suboptimal; releases https://github.com/pralab/modsec-learn
  and https://github.com/pralab/http-traffic-dataset. Baseline CRS numbers
  not visible in the snippet.
- Floris et al., "ModSec-AdvLearn", arXiv:2308.04964,
  https://arxiv.org/html/2308.04964v4 — SQLi focus; claims +30% detection
  at negligible FP vs CRS manual configs; per-config numbers not visible.
- Riverol et al., "Capturing the security expert knowledge...",
  https://arxiv.org/html/2407.18445 (2024) — vanilla CRS baseline improved
  upon; numbers not visible.

## The CRS project's own position (qualitative, read directly)

- https://coreruleset.org/docs/2-how-crs-works/2-3-false-positives-and-tuning/
  : "Paranoia level 1 is designed to cause few, ideally zero, false
  positives; higher paranoia levels are increasingly likely to cause false
  positives." FPs are expected to be tuned away with rule exclusions.
- https://coreruleset.org/docs/2-how-crs-works/2-2-paranoia_levels/ :
  PL1 "baseline security with minimal need to tune away false positives";
  PL2 "expect to encounter false positives" (off-the-shelf online shop);
  PL3 "online banking level security with lots of false positives"; PL4
  "be prepared to face a large number of false positives".
- The project publishes per-rule regression tests (go-ftw) but no
  published aggregate FP/detection benchmark was found in its
  documentation — UNVERIFIED whether one exists elsewhere.

## Comparability summary (no averaging)

| source | traffic kind | PL | comparable to our setup? |
|---|---|---|---|
| Bill-Benson 2026 | synthetic keyword benign; curated payloads | 1, 2 | partial: same engine/image family, different traffic |
| j-ptiik 2026 | Juice Shop target; SQLi attacks | 1–4 | partial: same target app, unknown benign definition |
| wafplanet 2026 | real browsing sessions (692 sites) + CVE payloads | 1 | closest on benign traffic; attack set not comparable |
| Anuvarshini 2025 | controlled environment (details unseen) | ? | cannot judge |
| AutoEx 2026 | controlled scenarios | 1–4? | cannot judge (benign generation unseen) |
| CRS issue #1016 | CSIC/ECML datasets | n/a (CRS 2.x) | no: old CRS, dataset labels questioned |
| CRS docs | — | 1–4 | qualitative expectations only, no numbers |

What this means for our engine decision (context only, no conclusion
drawn here): independent measurements disagree by tens of percentage
points on both axes, driven mostly by how benign traffic is defined —
which is the same lever our own v0/v1 in-sample vs out-of-sample gap
(0.93% → 4.39%) exposed. Any published number is only as comparable as
its benign-traffic definition.
