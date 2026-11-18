# External benign HTTP dataset candidates (research notes, step-08 T5)

Research only — nothing was downloaded or ingested (per step instructions).
Compiled 2026-11-18 via web search. "Licence as stated on the source" means
I quote what the page I saw says; where no licence statement was visible I
say so. Everything I could not read directly in a source page is marked
UNVERIFIED.

## 1. HTTP DATASET CSIC 2010

- URL: original page http://isi.csic.es/dataset/ is dead; archived copy
  https://web.archive.org/web/20130924222653/iec.csic.es/dataset (read
  directly); mirror PDF https://petescully.co.uk/wp-content/uploads/2018/04/http_dataset_csic_2010.pdf
- What: HTTP requests to an e-commerce web application (shopping cart,
  registration) developed at CSIC; labelled normal/anomalous. 36,000
  normal requests (training) + 36,000 normal (test) + 25,000+ anomalous.
- How generated: automatically — real parameter values drawn from two
  databases (normal/anomalous values); anomalous requests include static
  attacks (hidden/nonexistent resources, config files, session-id URL
  rewrite) and dynamic attacks (SQLi, CRLF, XSS, buffer overflow,
  parameter tampering...); anomalous traffic partly generated with Paros
  (now OWASP ZAP) and w3af (per the msudol dataset collection README).
- Licence: no licence statement visible on the archived CSIC page —
  UNVERIFIED. Kaggle reuploads state "Data files © Original Authors"
  (https://www.kaggle.com/datasets/ispangler/csic-2010-web-application-attacks).
- Size: ~72k normal + 25k anomalous requests; CSV conversions ~29.5 MB
  (Kaggle) or ~99 MB raw packet form (petescully.co.uk conversion).
- Known criticisms (read directly where noted):
  - CRS maintainer thread (GitHub SpiderLabs issue #1016, 2018): requests
    with misspelled parameter NAMES are labelled anomalous although they
    are not attacks; measured CRS 2.2.9 recall on it was only 0.343.
  - The msudol collection README: "we do not know how real attacks and
    anomalous traffic distribute in this dataset".
  - Age: generated 2009–2010 against a Spanish e-commerce app; HTTP/1.1,
    single old user agent (Konqueror 3.5 in the Kaggle CSV preview).
- Could it serve as our benign corpus? Partly. The 72k "normal" requests
  are machine-generated forms traffic for one application — much larger
  than our 774-sample v1, and it covers a real app's endpoint structure.
  But it is not natural browsing (no asset loads, no socket.io, no SPA
  behaviour), the application is not ours (Juice Shop), and the label
  quality of the anomalous half is questioned. Usable as an additional
  benign stress set, not as a replacement for recorded sessions.

## 2. ECML/PKDD 2007 Challenge dataset

- URL: described in https://github.com/msudol/Web-Application-Attack-Datasets/blob/master/OriginalDataSets/README.md
  (read directly); original challenge page lirmm.fr link may be dead —
  UNVERIFIED
- What: 35,006 normal + 15,110 attack requests, whole requests (headers +
  body), seven attack types.
- How generated: real recorded traffic, then sanitized — every URL,
  parameter name and value renamed to random strings (except attack
  payloads).
- Licence: not visible — UNVERIFIED.
- Known criticisms: the sanitization itself (same msudol README and the
  CRS issue #1016 comment): parameter names/values are random strings, so
  the "normal" traffic no longer resembles any real application's
  traffic.
- Could it serve as a benign corpus? No for WAF FP testing in our setup:
  randomized parameter names make CRS rule matches behave unlike any real
  deployment. Mentioned here because it is one of only two public sets
  with full requests.

## 3. openappsec/waf-comparison-project (WCP)

- URL: https://github.com/openappsec/waf-comparison-project (read
  directly); docs https://docs.openappsec.io/references/waf-comparison-project
- What: 1,040,242 legitimate HTTP requests from 692 real websites in 14
  categories (e-commerce, travel, information, social media, search
  engines, food, videos, file uploads/downloads...) + 73,924 malicious
  payloads; ships as a Docker tool that replays them against a WAF and
  produces a PDF report (TPR / TNR / balanced accuracy).
- How generated: real captured browsing sessions per website (the
  categories CSV lists per-site request counts, e.g. browsing_yahoo
  13,785, browsing_mako 20,770).
- Licence: Apache License 2.0 (stated on the GitHub repo — read directly).
- Known criticisms: none found in this search — UNVERIFIED whether any
  published critique exists. Self-published by openappsec (a WAF vendor),
  so it is not vendor-neutral in origin, though the datasets themselves
  are plain request lists.
- Could it serve as a benign corpus? The strongest candidate found: real
  browsing sessions at scale, permissive licence, whole requests. It is
  what the wafplanet.net blog used as its benign half (FPR 29.7% baseline
  at PL1). Caveats for us: traffic is against 692 different sites, not
  Juice Shop, so endpoint-specific FPs (whoami 932260) cannot occur; and
  replaying 1M requests needs infrastructure decisions (rule 13 hygiene,
  runtime). Would complement, not replace, our recorded Juice Shop
  sessions.

## 4. Biblio-US17 (Universidad de Sevilla)

- URL: https://dtstc.ugr.es/neus-cslab/recursos/ds-biblio/ (read directly;
  Spanish). DOI 10.12795/11441/148254.
- What: 47,902,323 HTTP requests (access_log + ssl_access_log) from the
  real public web server of the University of Sevilla library over 6
  months, semi-automatically labelled (legitimate / attacks / erroneous)
  starting from several SIDS classifications.
- How generated: captured from real operation (Apache traces), not
  synthetic; privacy-reduced to method + URI + response status only
  (timestamps, IPs removed; sensitive URI parts replaced).
- Licence: not visible on the page I saw — UNVERIFIED (it is a DOI-registered
  dataset, so terms live at the DOI landing page, which I did not open).
- Known criticisms: none found — UNVERIFIED.
- Could it serve as a benign corpus? Not for request-level WAF replay:
  no headers and no bodies (URI + method + status only), so it cannot be
  sent through CRS the way our samples can. Useful only for URI-level
  statistics or as evidence about real-world URI distributions.

## 5. pralab/http-traffic-dataset (ModSec-Learn companion)

- URL: https://github.com/pralab/http-traffic-dataset (named in the
  ModSec-Learn abstract, https://arxiv.org/pdf/2406.13547 — I did not open
  the repo itself)
- What: the dataset used to train/evaluate ModSec-Learn — traffic with CRS
  rule activations as features (details UNVERIFIED: I only saw the
  abstract's mention).
- Licence: UNVERIFIED (not seen).
- Known criticisms: none found — UNVERIFIED.
- Could it serve as a benign corpus? Unknown without inspecting the repo;
  flagged as a follow-up candidate only.

## 6. WebRequests aggregation (redata.uy)

- URL: https://redata.anii.org.uy/dataset.xhtml?persistentId=doi%3A10.60895%2Fredata%2FRWUUSV
  (read directly)
- What: URI-only collection merged from Malicious-URLs, PKDD and CSIC 2010
  (goodqueries.txt / badqueries.txt etc.), tokenized to TF-IDF vectors.
- Licence: CC BY 4.0 (stated on the page).
- Could it serve as a benign corpus? No: URI strings only, no
  method/headers/body, and it is a derived aggregation of the sets above.

## Summary judgement (per source, not averaged)

- Best candidates for a future benign corpus: **WCP legitimate set**
  (real browsing, permissive licence, whole requests) and **CSIC 2010
  normal split** (large, machine-generated forms traffic, label caveats).
- Not usable for request replay: Biblio-US17 (no headers/bodies),
  WebRequests (URI only), ECML/PKDD (randomized parameters).
- Nothing was downloaded; any future use needs a preregistered plan
  (rule 22) covering licence verification (several are UNVERIFIED),
  replay procedure, and how these sets relate to the frozen v0/v1
  datasets.
