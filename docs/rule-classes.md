# Rule classes: policy/protocol vs detection (written BEFORE the T3 analysis)

Source of the mapping: the rule files inside the running image
`owasp/modsecurity-crs:4.25.2-nginx-lts`, directory
`/etc/modsecurity.d/owasp-crs/rules/` (listed 2026-11-18, container at
PARANOIA=2/BLOCKING_PARANOIA=2).

## Classification rule (fixed before looking at any run data)

- **policy/protocol** = rules from the method-enforcement and
  protocol-enforcement files:
  - `REQUEST-911-METHOD-ENFORCEMENT.conf` (IDs 911xxx)
  - `REQUEST-920-PROTOCOL-ENFORCEMENT.conf` (IDs 920xxx)
- **detection** = rules from the attack-detection files (LFI/RFI/RCE/PHP/
  NodeJS/XSS/SQLi/session-fixation/Java):
  - `REQUEST-930-APPLICATION-ATTACK-LFI.conf` (930xxx)
  - `REQUEST-931-APPLICATION-ATTACK-RFI.conf` (931xxx)
  - `REQUEST-932-APPLICATION-ATTACK-RCE.conf` (932xxx)
  - `REQUEST-933-APPLICATION-ATTACK-PHP.conf` (933xxx)
  - `REQUEST-934-APPLICATION-ATTACK-GENERIC.conf` (934xxx; contains the
    NodeJS attack rules — there is no separate NodeJS file in CRS 4.25.2)
  - `REQUEST-941-APPLICATION-ATTACK-XSS.conf` (941xxx)
  - `REQUEST-942-APPLICATION-ATTACK-SQLI.conf` (942xxx)
  - `REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf` (943xxx)
  - `REQUEST-944-APPLICATION-ATTACK-JAVA.conf` (944xxx)

## Where the threshold rules fit

- `949110` lives in `REQUEST-949-BLOCKING-EVALUATION.conf`; `959100` in
  `RESPONSE-959-BLOCKING-EVALUATION.conf`; `950100` ("The Application Returned
  a 500-Level Status Code") in `RESPONSE-950-DATA-LEAKAGES.conf` area of the
  outbound evaluation. These are **threshold/evaluation rules, not policy and
  not detection**: they decide blocking from the score accumulated by other
  rules. A blocked request classified below by the NON-threshold rules it
  matched.

## Files that fit NEITHER class (stated explicitly)

- `REQUEST-901-INITIALIZATION.conf` (901xxx) — TX variable initialisation.
- `REQUEST-905-COMMON-EXCEPTIONS.conf`, `REQUEST-999-COMMON-EXCEPTIONS-AFTER.conf`
  (905xxx/999xxx) — known-benign pattern exceptions.
- `REQUEST-913-SCANNER-DETECTION.conf` (913xxx) — scanner user-agent
  detection; not method/protocol policy, not one of the listed attack files.
- `REQUEST-921-PROTOCOL-ATTACK.conf` (921xxx) — protocol *attacks* (request
  smuggling, CRLF); the name suggests protocol but the instructor's policy
  class names only the enforcement files (911/920), so 921 is UNCLASSIFIED
  here, not silently merged into either class.
- `REQUEST-922-MULTIPART-ATTACK.conf` (922xxx) — multipart parser attacks;
  UNCLASSIFIED (same reasoning as 921).
- `RESPONSE-950/951/952/953/954/956-DATA-LEAKAGES*.conf`,
  `RESPONSE-955-WEB-SHELLS.conf` (950xxx–956xxx) — outbound response
  inspection; UNCLASSIFIED (neither request policy nor the listed request
  detection files).
- `RESPONSE-980-CORRELATION.conf` (980xxx) — reporting/correlation only.

## Per-request classification used in the analysis (fixed here, before analysis)

For each blocked request, take the non-threshold rule IDs it matched in the
audit (threshold rules 949110/950100/959100 excluded):

- **policy-only**: ≥1 policy rule (911/920), 0 detection rules.
- **detection-only**: ≥1 detection rule (930/931/932/933/934/941/942/943/944),
  0 policy rules.
- **both**: ≥1 policy AND ≥1 detection rule.
- **neither**: only threshold rules or rules from the UNCLASSIFIED files
  above. Reported as its own row, not folded into the other three.
