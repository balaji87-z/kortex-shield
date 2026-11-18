# Acceptance tests: what "industry standard" means for this project

Each row is a bar taken from a source we read, turned into a test we can run.
Numeric targets are left open on purpose. They are set after the baseline run,
because only the baseline tells us what a number means on our data.

Status values: `not started`, `in progress`, `passing`, `failing`.

| ID | Bar | Source | Test | Pass condition | Status |
|---|---|---|---|---|---|
| A1 | Rule-engine compatibility | CRS engine-options page: Coraza passes 100% of the CRS v4 test suite; ModSecurity v3 fails 2-4% | Run the CRS regression suite against our build | 100% of the suite | not started |
| A2 | Efficacy at independent-test scale | SecureIQLab 2026: 1,608 attack and 1,487 legitimate scenarios, covering OWASP Top 10, API Top 10, L7 DoS, bots | Build our own suite of at least that size, with recorded provenance and held-out attack families | At least 1,600 attack and 1,400 legitimate scenarios; recall and false positive rate reported per family with counts and 95% intervals; targets set after baseline | in progress — attack side: attacks-v0 frozen (1,054 attack samples, 527 distinct payloads × 2 injection points, 4 families, public payload lists with provenance) — **546 samples short of the 1,600 bar**; benign side: benign-browse-v0 frozen (214 natural browsing requests) and benign-hard-v0 frozen (180 hand-authored hard benign) — **1,006 legitimate scenarios short of the 1,400 bar**; benign rates reported separately (rule 14), never merged; no recall/FPR targets set yet |
| A3 | Parser fidelity | WAFFLED (arXiv 2503.10846): 1,207 bypasses across 5 WAFs via multipart, JSON and XML parsing differences | Replay WAFFLED-style body mutations against our proxy in front of each target framework | Zero parsing-discrepancy bypasses on frameworks in scope; the list of frameworks is fixed before testing | not started |
| A4 | PCI DSS 4.0.1 req. 6.4.2 | BDO PCI 4.0 summary | Check that the product sits in front of the app, generates audit logs, and either blocks or raises alerts that are investigated | Audit logs present for every decision; block mode and alert mode both work | not started |
| A5 | Safe rollout | CRS 4 scoring guidance: detection mode for at least a week before blocking | Shadow mode that logs the verdict without enforcing it | Switching modes needs no code change and is itself logged | not started |
| A6 | Latency | Not taken from a source; we set this ourselves | p50 and p99 added latency under load, measured against the no-WAF control | Target set after baseline | not started |
| A7 | Failure behaviour | Not taken from a source; we set this ourselves | Kill the engine; confirm per-site fail-open or fail-closed works as configured | Behaviour matches configuration | not started |
| A8 | Reproducibility | Our own rule | Every reported number can be regenerated from the manifest and one command | One command reproduces each table | in progress — the command chain (runner → docker logs → crs_audit → outcome → report/breakdown) exists and was proven on the smoke run, the 1,054-sample attack runs and the 214/180-sample benign runs; breakdowns in docs/baseline-v0.md regenerate via tools/attack_breakdown.py and tools/benign_breakdown.py |

## Scope decisions to make before testing

- Which of the bot and L7 DoS categories in A2 do we cover? A single proxy node is
  not a global network. We did not find a source describing how those categories
  are scored, so this decision is ours.
- Which web frameworks are in scope for A3.
- Whether to pursue ICSA Labs certification. We could not retrieve its criteria;
  get them from icsalabs.com before deciding.

## Not verified

Gartner evaluation criteria, ICSA Labs criteria, the original SecureIQLab report
(we saw only vendor and distributor summaries that disagree with each other).
