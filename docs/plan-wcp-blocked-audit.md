# Plan: WCP blocked-side label audit (step-10 T5, preregistered)

Written 2026-11-18 BEFORE reading any sampled request. Nothing below has run.

## Question

Are the WCP requests that CRS blocks with at least one detection rule
actually benign, or does the vendor-labelled "legitimate" set contain
attack-like traffic? (The build-time audit of 100 looked at the whole
sample; this one looks specifically at the blocked side.)

## Procedure (fixed before looking)

1. Population: default-config runs on benign-wcp-v0
   (`out/benign-wcp-v0-pl1-default-ua`, `out/benign-wcp-v0-pl2-default-ua`),
   blocked samples (`outcome == "waf_block"`) whose audit entry contains at
   least one detection-class rule (classes per docs/rule-classes.md:
   930/931/932/933/934/941/942/943/944xxx; threshold rules 949110/959100/950100
   excluded from the class check).
2. Samples: `random.Random(0).sample(sorted(ids), 100)` from default PL1,
   and `random.Random(0).sample(sorted(ids), 50)` from default PL2
   (independent draws; overlap allowed).
3. Each sampled request is read manually: method, path, query (as needed),
   content type, body excerpt, host, and the rule IDs with messages that
   fired. Classification per request, one of:
   - `ordinary benign` — normal browsing/telemetry traffic; the detection
     rule is a false positive on ordinary content;
   - `plausibly malicious` — the request content itself looks like an attack
     payload (would not be out of place in an attack corpus);
   - `cannot tell` — encoded/opaque content (binary, compressed, encrypted
     telemetry) that cannot be judged by reading.
4. Reporting: counts per class, the id and rule IDs for every sampled
   request (in reports/step-10.md). NO credential, key, token or email
   VALUES are quoted (rule 25) — only ids and rule ids.
5. This is an audit of 100 and 50, not a proof (rule 26). The frozen dataset
   is not changed by the result (rule 10); no sample is excluded.
