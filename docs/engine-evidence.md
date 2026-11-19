# Engine evidence (step-11, rule 28)

Every claim below was read from inside the running container during a run or
probe on 2026-11-19. Raw proofs live in the run logs (out/step11-parity-batch3.log)
and docs/logs/.

## Versions

| | ModSecurity | Coraza |
|---|---|---|
| Image | owasp/modsecurity-crs:4.25.2-nginx-lts@sha256:6296ce685cb88ba4012998b935b25dabbd9e0ff326088c1149447102544de661 | ghcr.io/coreruleset/coraza-crs:4.25.2-nginx-lts@sha256:ffefe71585b42daa5ead5653206b086b37090f498e4cde9ed6e4c52f05cc93e7 |
| Engine | libmodsecurity3 3.0.17, ModSecurity-nginx v1.0.4 (nginx notice line at start) | no version string found in the container (UNVERIFIED); CRS 4.25.2 proven via tx.crs_setup_version=4252 |
| Ruleset | OWASP_CRS/4.25.2 (audit entries) | OWASP_CRS/4.25.2 (audit entries, tx.crs_setup_version=4252) |

## Effective config (rule 29), read from inside each container

| setting | ModSecurity | Coraza |
|---|---|---|
| SecRuleEngine / rule engine | On (modsecurity.conf) | On (CORAZA_RULE_ENGINE) |
| blocking paranoia | tx.blocking_paranoia_level=1 or 2 (pinned per run) | =1 or =2 (crs-setup.conf) |
| detection paranoia | tx.detection_paranoia_level pinned = blocking | defaults to blocking via 901125 (image ignores DETECTION_PARANOIA env) |
| SecRequestBodyNoFilesLimit | 131072 (image default, unchanged) | 131072 after in-container pin (ships 524288; sed + nginx -s reload; probe: 200,000-byte body -> 400) |
| SecRequestBodyLimit | 13107200 | 13107200 |
| SecRequestBodyLimitAction | Reject | (same behaviour observed) |
| SecResponseBodyAccess | on (modsecurity.conf:14) | on (coraza.conf:9) |
| SecResponseBodyMimeType | text/plain text/html text/xml | text/plain text/html text/xml |
| outbound threshold | tx.outbound_anomaly_score_threshold=4 (crs-setup.conf:343) | same default (959100 fired at Total Score 4) |
| audit | JSON format, RelevantStatus "^(?:5|4(?!04))" (only 4xx/5xx logged) | logs all transactions (incl. 200s) |

## Parity results (fixed harness, same stub backend, frozen benign-wcp-v0)

- Blocked-set diff (discriminator): PL1 6 only-modsec / 7 only-coraza;
  PL2 6 only-modsec / 8 only-coraza. Most are the 400-vs-403 status asymmetry
  (body-parser deny vs inbound 403 block on the same oversized/unparseable
  bodies), plus 1 timeout and 1 oversized-body 413.
- Rule-presence: large and real. Examples (only-coraza, PL2): 931130 612,
  942200 2,385, 942370 2,331, 942340 2,120, 932200 1,095; (PL1): 932370 303,
  921150 379, 942550 296, 920270 273, 932130 225. Only-coraza was verified
  against the raw ModSecurity audit for a spot-checked sample (rule absent
  there), so it is not an extraction artifact. Interpretation: Coraza's regex
  engine matches additional CRS rules; the extra matches rarely change the
  block outcome (threshold arithmetic absorbs them). Reported per rule 28 as
  per-sample differences; no totals-only claims.
- The reverse direction also exists but is small (e.g. 942430 only-modsec 233
  at PL2).
- 920260 differential probes: 30 probes, 0 disagreements (PL1, default).
- Coraza parity caveat: PARANOIA env is a no-op on the Coraza image;
  DETECTION_PARANOIA defaults to BLOCKING via rule 901125 - PL2 parity holds
  because blocking paranoia is genuinely 2 (proven from crs-setup.conf).
