# Baseline v0.7 (step-12, 2026-11-20)

Supersedes v0.6 (kept in docs/baseline-v0.6.md; superseded text is not repeated
here). This version closes evidence gaps left by step-11: image drift, config
proofs, forensics on the status-400 and timeout tails, and a corrected
cookie-restoration run. No frozen dataset changed and no kortex_eval behaviour
changed (97 tests pass).

## What changed vs v0.6

1. **Image drift found and re-pinned.** The floating ModSecurity tag pulled a
   new build (created 2026-11-19 14:56Z, after every step-11 run); the old
   digest is still pullable, so `deploy/compose.yml` now pins both engines by
   digest: modsec `sha256:6296ce68…` (kept) and coraza re-pinned to
   `sha256:bfbfe70b…` (the old coraza digest `ffefe715…` was deleted from
   ghcr and can no longer be pulled). CRS is 4.25.2 on both new images; the
   Coraza engine is proven `github.com/corazawaf/coraza/v3@v3.7.0` from the Go
   build info inside `libcoraza.so`. Documented in docs/baseline-config.md
   BEFORE any step-12 run (rule 17).
2. **The new Coraza image honours `DETECTION_PARANOIA`.** The old image
   ignored it (detection fell back to blocking via rule 901125). Step-12
   Coraza runs prove detection paranoia explicitly from inside the container
   (D=1 at PL1, D=2 at PL2; docs/logs/step12-rule29-table.txt). Comparability
   caveat: step-11 Coraza runs ran on the old image where D was never reported
   and fell back to B; step-12 small-dataset re-runs (below) remove that doubt
   for the small datasets.
3. **The Coraza request-body-limit pin never took effect — corrected.** v0.6
   claimed `SecRequestBodyNoFilesLimit 131072` was pinned in-container on
   Coraza ("probe: 200,000-byte body -> 400"). That probe body was invalid
   JSON, so the 400 was a body-parse deny (200002), not the size limit. Live
   proof on the new image: after the sed + `nginx -s reload`, a VALID
   200,000-byte JSON body passes Coraza with 200 while ModSecurity rejects the
   same body with 400 (200002) — the running Coraza keeps the image default
   524,288 (docs/logs/step12-sizeprobe-*.log). The same mechanism applies to
   the old image, so **every Coraza run to date ran with an effective
   NoFilesLimit of 524,288**, not 131,072. Consequence: the 11 WCP samples
   where Coraza returned 413 and ModSecurity did not are all bodies of
   723,995–1,527,423 bytes (> 524,288): 10 multipart/form-data POSTs
   (ModSecurity counts file parts against SecRequestBodyLimit 13,107,200, not
   the no-files limit, and passes them) and 1 no-content-type PUT (ModSecurity
   blocks it on method policy 911100, 403, while Coraza rejects 413). This is
   a config-parity violation on the body-limit axis, not an engine
   disagreement; it is listed per sample in docs/logs/step12-t3-wcp-deepdive.txt.
   For all four small datasets the pin was non-binding (largest body 1,080
   bytes), so the step-12 small-dataset re-runs are unaffected.
4. **Small-dataset engine parity re-proven after the stub-drain fix.** Every
   step-11 small-dataset parity log predated commit 37bc833 (the stub-drain
   fix), so all 16 cells were re-run on the digest-pinned images with rule-29
   proofs (out/step12-batch1.log). Result: **0 only-modsec and 0 only-coraza
   blocked-set differences in all 8 dataset x PL cells** (smoke 6/6,
   attacks-v0 954/954 PL1 and 1,024/1,024 PL2, benign-browse-v1 184/184,
   benign-hard-v0 22/22 PL1 and 78/78 PL2); worst-case sets (rule 32) also
   identical in every cell (docs/logs/step12-t2-parity-small.txt). ModSecurity
   shows some `inconsistent` outcomes where Coraza shows `waf_block` on the
   same samples; the blocked sets still match.
5. **wcp-train runs accepted with caveat (T7).** The step-12 re-run of the
   wcp-train TEST PL1 cell reproduced the step-11 run exactly: 514 blocked in
   both, identical id sets (symmetric difference 0), identical
   predictions.jsonl. The other three step-11 wcp-train cells are accepted on
   that basis, with the caveat that they ran on the pre-fix harness and the
   old Coraza image.
6. **Status-400 forensics (17 samples, all ModSecurity deny-status 400).**
   200002 = "Failed to parse request body" (modsecurity.conf template line 49);
   200007 = "Failed to fully parse request body due to large argument count"
   (SecArgumentsLimit >= 1000). Classes: 10 replay_artifact (all carry
   `Content-Encoding: gzip`; the runner sends the header verbatim with the
   DECOMPRESSED body, so the engine's decoder fails; recorded CL != sent bytes
   for all 10), 2 malformed_original (invalid JSON in the source itself, CL
   matches), 5 unknown (valid JSON with 1,160–4,373 members hitting the
   200007 limit). No binary/non-UTF-8 bodies and no lone surrogates among the
   17 (docs/logs/step12-status400-forensics.txt).
7. **Timeout forensics (T6).** The 8 Coraza PL1 timeout samples replayed 5x
   each on both engines with a 60 s timeout: 7 of 8 are fast on BOTH engines
   (medians 5–81 ms) — the step-11 timeouts were transient, not sample
   properties. 1 of 8 (wcp-80a49c991b2d, POST text/plain 477,231 bytes) is
   engine-specific: ModSecurity 403 in ~23 ms, Coraza 403 in ~46 s on all 5
   repeats (docs/logs/step12-t6-replay-*.jsonl). The 1 ModSecurity error
   sample (wcp-6b0bf5e43122) is a runner-side latin-1 encoding failure that
   fails identically on both engines before any request is sent.
8. **Matched-shape probes (T3).** 20 synthetic probes built from the
   only-Coraza match shapes (documented in tools/probe_matched_shapes.py
   before sending), sent to both engines at PL1: **0 block disagreements**;
   one rule-logging difference (920260 logged by ModSecurity only, both 200).
   The probes did NOT reproduce the recorded-traffic divergence: the WCP
   divergence needs the exact recorded binary argument-name byte sequences,
   not just the shapes (docs/logs/step12-t3-probes-*.jsonl). Per rule 4, no
   engine is called correct.
9. **Cookie restoration was incomplete — fixed and re-run (T5).** The dataset
   stores the dropped cookie under two header spellings: `cookie` (7,512 rows
   in the frozen manifest) and `Cookie` (5,754 rows). The step-10 restore
   script selected with a case-sensitive lookup, so the step-11 "restored-all"
   run covered only the 7,511 lowercase rows and silently skipped 5,750
   `Cookie`-spelled rows. The selection is now case-insensitive; the full
   restore covers all 13,261 baseline dropped rows (integrity check: only the
   cookie value differs); ModSecurity PL1+PL2 re-runs with rule-29 proofs and
   fresh containers (out/step12-restored-all.log). Nothing in the frozen
   dataset was modified; restored cookie values stay uncommitted (rule 25).
10. **Denominator reconciliation.** benign-wcp-v0 was built as 20,000 rows;
    1 sample (wcp-6b0bf5e43122, non-latin-1 header) is in the quarantine file,
    so the baseline manifest has 19,994 rows (13,261 cookie-dropped + 6,733
    cookie-absent). The step-11 parity runs replayed the full frozen 20,000-row
    manifest (the quarantined sample errors client-side on both engines). All
    rates below state which denominator they use.

## Headline numbers

Small datasets (step-12 re-runs, both engines, digest-pinned images):

| dataset | PL | blocked modsec | blocked coraza | diff |
|---|---|---|---|---|
| smoke | 1/2 | 6 / 6 | 6 / 6 | 0 |
| attacks-v0 | 1 | 954/1054 | 954/1054 | 0 |
| attacks-v0 | 2 | 1024/1054 | 1024/1054 | 0 |
| benign-browse-v1 | 1/2 | 184/774 | 184/774 | 0 |
| benign-hard-v0 | 1 | 22/180 | 22/180 | 0 |
| benign-hard-v0 | 2 | 78/180 | 78/180 | 0 |

benign-wcp-v0 (frozen 20,000-row manifest, step-11 runs accepted per item 5):
ModSecurity PL1 3,823/19,999 = 19.12% (worst 19.11%+1 error), PL2 8,949/19,999
= 44.75%; Coraza PL1 3,824/19,991 = 19.13% (worst 19.12% with 9 errors), PL2
8,951/19,997 = 44.76%. Worst-case sets (rule 32) differ by 1 only-modsec and
17 only-coraza samples at PL1 (10 of the 17 are the >524,288-byte 413 bodies
explained in item 3); see docs/logs/step12-t3-wcp-deepdive.txt for per-sample
status/outcome/rules.

Cookie strata (ModSecurity, baseline-manifest denominators, rule 14 — never
merged; worst case = waf_block + waf_deny_status + inconsistent + error):

| stratum | run | PL1 | PL2 |
|---|---|---|---|
| dropped (13,261) | cookie = "[DROPPED]" (full-run) | 2,682/13,261 = 20.22% | 6,111/13,261 = 46.08% |
| dropped (13,261) | real cookie restored | 5,362/13,261 = 40.43% | 10,809/13,261 = 81.51% |
| dropped (2,000 seeded) | cookie = "[DROPPED]" (dropped-run) | 436/2,000 = 21.80% | 838/2,000 = 41.90% |
| absent (6,733) | no cookie (full-run) | 1,205/6,733 = 17.90% | 2,903/6,733 = 43.12% |

Restoring the real cookie roughly doubles the flagged rate on the dropped
stratum (PL1 40.43% vs 20.22%; PL2 81.51% vs 46.08%). The v0.6 restored rates
(54.44% / 92.48%) were computed on the 7,511-row lowercase-cookie subset and
are superseded by these full-stratum numbers; the subset is not a random
sample of the stratum, so the two must not be compared as if equivalent.
Top sole-rule attributions in the restored run (949110 excluded): PL1
932270 (1,614), 920420 (1,416), 942550 (321); PL2 920420 (419), 931130 (419),
942200 (337). Full per-host tables: docs/logs/step12-t5-cookie-strata.txt.

## What v0.7 does NOT claim

- The default config's allowed content-type list comes from the CRS 901160/
  901162 fallback (6 types), not from the runner's 18-type env list: the
  rendered config ignores the env (proven per run by tools/check_default_
  signature.py: 920420 never fires on fallback-allowed types, 911100 still
  fires on PUT/DELETE/PATCH). **Widening the content-type list to the env's
  18 types would remove a defence** (920420 would stop firing on the 12 extra
  types) **and attacks-v0 cannot measure that cost**: every attacks-v0 body
  uses a content type the fallback already allows, so a widened list would
  show no recall change on attacks-v0 while real traffic with the widened
  types would lose the 920420 check. Any widening experiment needs attack
  samples in the newly allowed types first.
- No engine is called correct anywhere: the 400-vs-403 asymmetries, the 413
  bodies and the probe results are listed per sample, not judged (rule 4).
- Coraza version for the OLD image (step-11 runs) remains UNVERIFIED (image
  no longer pullable); the new image is proven v3.7.0.
