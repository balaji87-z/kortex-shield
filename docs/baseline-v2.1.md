# Baseline v2.1 (step-26, 2026-11-28)

Host and tools are those of baseline v2.0 (macOS 27.0 arm64, Apple M6,
go1.27.4, Python 3.15.2, pytest 9.2.0). Docker was used in this step for
the two baseline images: client 29.10.1, server 29.5.2 linux/arm64 (colima).
The engine is the engine of baseline v2.0: no file under engine/ changed
(binary sha256 761ef5ad...702792fb, engine code of 497d585), coraza v3.8.1
with the step-23 patch, CRS 4.25.2. kortex_eval is unchanged. New in this
step: attacks-v1, the first attack dataset that no engine setting was
chosen with. Raw outputs and deviations: reports/step-26.md.

Images (rule 7), ruleset proven inside each container (rule 28):

| WAF | image | ruleset inside |
|---|---|---|
| ModSecurity | owasp/modsecurity-crs:4.25.2-nginx-lts@sha256:6296ce68...44de661, linux/arm64 | OWASP_CRS/4.25.2, /etc/modsecurity.d/owasp-crs/rules |
| Coraza connector | ghcr.io/coreruleset/coraza-crs:4.25.2-nginx-lts@sha256:bfbfe70b...1c28f4a6, linux/arm64 | OWASP_CRS/4.25.2, /opt/coraza/owasp-crs/rules; libcoraza built from coraza v3.7.0 with `-tags=coraza.rule.no_regex_multiline` |
| engine | built from this repository | engine/crs, CRS 4.25.2 (engine/RULES.sha256) |

## attacks-v1

Frozen, manifest sha256 7a82a516...6723066. Source: PayloadsAllTheThings at
08ea40e (MIT), 48 files. "attack" means "listed under this family in this
source", not "verified exploitable" (rule 11). Each payload is sent twice:
as the query argument of a search and as a JSON string of a login.

| family | kind | distinct payloads | requests |
|---|---|---|---|
| sqli | seen family, unseen files | 300 | 600 |
| xss | seen family, unseen files | 300 | 600 |
| path-traversal | seen family, unseen files | 200 | 400 |
| command-injection | seen family, unseen files | 71 | 142 |
| lfi | new family | 200 | 400 |
| xxe | new family | 101 | 202 |
| ssti | new family | 107 | 214 |
| nosql | new family | 26 | 52 |
| ldap | new family | 30 | 60 |
| total | | 1,335 | 2,670 |

Excluded to named files: 96 payloads of attacks-v0, 74 listed by an earlier
family, 3 unsendable. Reach check before the freeze (engine, DetectionOnly,
PL1): all 2,670 judged by the rules, none quarantined. With attacks-v0:
1,862 distinct payloads, 3,724 requests (A2 asks for 1,600 attack
scenarios).

## Held-out recall

Denominator: all 2,670 requests. Best case counts only `waf_block`
(headline, rule 21); worst case counts every outcome that is not a pass.
In every run of this step the two are equal: no error, deny_status,
inconsistent or fail-closed outcome (rule 30: 0 of each). HELD-OUT for every
engine setting. Intervals are 95% Wilson intervals; requests are not
independent (two per payload), so the per-payload column is the one to
read.

| WAF | PL | waf_block | recall, requests | per payload (blocked at both points) |
|---|---|---|---|---|
| engine, in-process and worker | 1 | 2,214 | 2,214/2,670 = 82.92% (81.45 to 84.30) | 1,107/1,335 = 82.92% (80.81 to 84.84) |
| Coraza connector image | 1 | 2,214 | 82.92% (81.45 to 84.30) | 1,107/1,335 (80.81 to 84.84) |
| ModSecurity image | 1 | 2,210 | 2,210/2,670 = 82.77% (81.29 to 84.16) | 1,105/1,335 = 82.77% (80.65 to 84.70) |
| engine, in-process and worker | 2 | 2,444 | 2,444/2,670 = 91.54% (90.42 to 92.53) | 1,222/1,335 = 91.54% (89.92 to 92.91) |
| Coraza connector image | 2 | 2,444 | 91.54% (90.42 to 92.53) | 1,222/1,335 (89.92 to 92.91) |
| ModSecurity image | 2 | 2,444 | 91.54% (90.42 to 92.53) | 1,222/1,335 (89.92 to 92.91) |

For comparison, the IN-SAMPLE numbers of attacks-v0 on the same engine
(baseline v2.0): 90.51% at PL1, 97.15% at PL2.

Every payload is blocked at both injection points or at neither, on all
three WAFs and at both levels (0 payloads blocked at one point only). So
the 2,670 requests carry the information of 1,335.

Engine, per family (requests; the same at both injection points):

| family | kind | PL1 blocked | PL1 recall (95% Wilson) | PL2 blocked | PL2 recall (95% Wilson) |
|---|---|---|---|---|---|
| sqli | seen | 488/600 | 81.33% (78.02 to 84.25) | 578/600 | 96.33% (94.51 to 97.57) |
| xss | seen | 556/600 | 92.67% (90.30 to 94.49) | 576/600 | 96.00% (94.12 to 97.30) |
| path-traversal | seen | 346/400 | 86.50% (82.80 to 89.50) | 364/400 | 91.00% (87.79 to 93.43) |
| command-injection | seen | 98/142 | 69.01% (60.99 to 76.04) | 110/142 | 77.46% (69.92 to 83.56) |
| lfi | new | 330/400 | 82.50% (78.47 to 85.91) | 356/400 | 89.00% (85.55 to 91.70) |
| xxe | new | 186/202 | 92.08% (87.52 to 95.07) | 190/202 | 94.06% (89.90 to 96.57) |
| ssti | new | 158/214 | 73.83% (67.56 to 79.26) | 206/214 | 96.26% (92.80 to 98.09) |
| nosql | new | 44/52 | 84.62% (72.48 to 91.99) | 50/52 | 96.15% (87.02 to 98.94) |
| ldap | new | 8/60 | 13.33% (6.91 to 24.17) | 14/60 | 23.33% (14.44 to 35.44) |
| seen families | | 1,488/1,742 | 85.42% (83.68 to 87.00) | 1,628/1,742 | 93.46% (92.20 to 94.52) |
| new families | | 726/928 | 78.23% (75.46 to 80.77) | 816/928 | 87.93% (85.68 to 89.87) |

- ldap is the weak family on all three WAFs (8 of 60 at PL1, 14 of 60 at
  PL2): CRS 4.25.2 has one LDAP rule (921200). command-injection and ssti
  are next at PL1.
- Rule 18 (ids in 20% or more of the audit entries), engine: PL1 949110
  (2,214 of 2,214), 941100 (620), 941390 (500), 941160 (482); PL2 949110
  (2,444), 942520 (756), 941100 (620), 942430 (606), 941390 (500), 942370
  (492), 941320 (490). All are detection rules of the families or the
  blocking rule; none is a harness artifact (no rule matches on the
  request shape itself).
- The requests not blocked, by id: docs/logs/step26-not-blocked-ids.txt
  (engine PL1 456, PL2 226).

## Engine against the baselines, per sample id (rules 28, 32)

| comparison | PL | status diffs | worst-case-set diffs | rule-id-set diffs |
|---|---|---|---|---|
| engine in-process against worker | 1, 2 | 0 | 0 | 0 |
| engine against Coraza connector | 1 | 0 | 0 | 0 |
| engine against Coraza connector | 2 | 0 | 0 | 4 |
| engine against ModSecurity | 1 | 8 | 8 (6 only the engine blocks, 2 only ModSecurity) | 32 |
| engine against ModSecurity | 2 | 0 | 0 | 90 |

- Engine against the connector, PL2, 4 requests (two command-injection
  payloads at both points): the engine logs 942330, the connector does not.
  PROVEN cause: the connector image is built with
  `coraza.rule.no_regex_multiline`; the engine built with that tag gives
  the connector's result on 100 of 100 sends
  (docs/logs/step26-DIAGNOSTIC-942330.txt). DESIGN, documented in
  docs/engine-design.md after the run.
- Engine against ModSecurity: the same per-sample differences exist between
  the connector image and ModSecurity (apart from the 4 above), so they
  come with coraza, not with the engine's own code (DESIGN, decision 0004;
  measured by the connector column). PL1: 3 lfi payloads are blocked only
  by the engine and the connector (930120), 1 xss payload only by
  ModSecurity (941100). Rule ids, PL2: only the engine 930120 on 8
  requests; only ModSecurity 920230 on 50, 920260 on 18, 941100 on 6,
  942131 on 6, 942430 on 2. Why each rule differs between coraza and
  ModSecurity is not established here (HYPOTHESIS: decoding and
  libinjection differences).
- ModSecurity runs, rule 36: 20 of 20 control requests in the audit before
  and 20 of 20 after the samples, at both levels.

## The REQUEST_BODY targets on this dataset (DIAGNOSTIC)

The engine built without the REQUEST_BODY target updates gives the same
result as the engine on attacks-v1: 0 status, 0 worst-case-set and 0
rule-id-set differences at PL1 and PL2. The same DIAGNOSTIC binary blocks 6
requests fewer than the engine on attacks-ct-v0 at PL1 (286 against 292;
text/plain, octet-stream and unknown content types), so the build does
differ where the targets apply. The targets add nothing here because both
carriers of attacks-v1 (a query argument, a JSON body) are parsed into
arguments. attacks-v1 therefore says nothing for or against the step-18
choice.

## Unchanged

Every number of baseline v2.0 (the CRS suite, attacks-v0, attacks-ct-v0,
encoding-diff-v0, the benign sets, wcp): not re-run, the engine is the same
binary.

## Not measured in this step

The benign side of A2; the new families through carriers that fit them (an
XML body for xxe, for example); other sources than PayloadsAllTheThings;
the engine with `coraza.rule.no_regex_multiline` on any other dataset;
timing.
