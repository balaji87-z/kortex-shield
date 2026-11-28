# Step-24 T4 plan: our own datasets on the step-24 engine (written BEFORE the runs)

Why: step 23 changed how rules match (patched coraza, sorted key order) and
step 24 changed the gate. Step 23 measured only the two external benign
datasets with the patched engine; the attack datasets were NOT MEASURED. The
last engine runs of our own datasets are from step 21, on stock coraza
v3.8.1 and with requests sent to 127.0.0.1, which adds CRS 920350 (numeric
Host, +3) to every request. No run of these datasets with Host localhost
exists for the engine.

## Datasets (frozen, unchanged; hashes checked by the script before any run)

| dataset | requests | label | sha256 of manifest.jsonl |
|---|---|---|---|
| attacks-v0 | 1,054 | attack | 5b6a844d...d4fa8540 |
| attacks-ct-v0 | 320 | attack | 69d0447c...5f923251 |
| encoding-diff-v0 | 192 | attack | ff00384d...6ea27e5c |
| benign-browse-v1 | 774 | benign, natural (recorded browsing) | 950a683b...0af3b085 |
| benign-hard-v0 | 180 | benign, hard (attack-looking but harmless) | 65bdfc69...3a01d78b |

"attack" means "listed under this family in the public source", not
"verified exploitable" (rule 11). Natural and hard benign inputs are never
merged into one rate (rule 14).

## Runs

Engine: built from HEAD by the script, coraza v3.8.1 with the step-23 patch,
CRS 4.25.2. Config: that of the step-22/23 runs (blocking, limits 13,107,200
/ 131,072, budget 2,000 ms, lanes 8 / 2, threshold 65,536); nothing in
docs/baseline-config.md changes (rule 17). One engine process and one audit
log per run, runner `--workers 1`, requests to `http://localhost:PORT`,
effective config per run in the log (rules 13, 29).

1. Main: 5 datasets x PL1, PL2 x in-process, worker = 20 runs.
2. DIAGNOSTIC stock coraza: the same commit built in a scratch copy with
   the `replace` dropped (stock coraza v3.8.1 from the module cache),
   in-process, 5 datasets x PL1, PL2 = 10 runs. Purpose: per-sample effect
   of the patch on these datasets. Stock coraza is not repeatable (step 22),
   so a sample that differs is replayed 20 times on each build before it is
   called an effect of the patch.
3. DIAGNOSTIC numeric Host: the patched engine, in-process, PL1, requests to
   `http://127.0.0.1:PORT`, 5 runs. Purpose: to tie any difference from the
   step-21 numbers to the Host header and not to the engine.

DIAGNOSTIC runs give no baseline and no parity number (rule 34).

## What is reported

- Per run: requests, distinct payloads (attack: family + payload hash in the
  id) or distinct endpoints (benign: method + path) (rule 15); outcome
  counts; errors, deny_status, inconsistent and fail-closed answers by count
  (rule 30).
- Attack datasets: recall, best case (headline, rule 21: only `waf_block`
  counts) and worst case (errors, deny_status, inconsistent and fail-closed
  answers also count), denominator all requests; per family.
  attacks-v0 and attacks-ct-v0 are IN-SAMPLE for the REQUEST_BODY target
  choice of step 18 (rules 19, 45) and are labelled so. encoding-diff-v0 is
  a set of chosen encodings of chosen payloads: counts only, no rate
  (rule 35).
- Benign datasets: blocks as potential false positives (rule 46), best and
  worst case, headline worst case, natural and hard apart. benign-browse-v1
  and benign-hard-v0 informed no engine setting (held-out).
- Rule 18: rule ids in 20% or more of a run's audit entries.
- Parity (rule 32), per sample id: status, worst-case set, rule-id set;
  in-process against worker; patched against stock (DIAGNOSTIC).
- Durable files per run under docs/logs/runs/s24-own/ (rule 42):
  responses.jsonl, outcomes.jsonl, run.json, body-less audit index.

## Not in this plan

ModSecurity and the connector image, timing, and the external benign
datasets (re-run separately with the step-23 script as a check that the
gate change refuses none of them).
