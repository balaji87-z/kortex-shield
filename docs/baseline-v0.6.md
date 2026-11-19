# Baseline v0.6 (step-11, 2026-11-19)

Supersedes v0.5 (kept below in docs/baseline-v0.5.md; superseded text is not
repeated here). Changes are harness corrections and the completed engine-parity
work; no frozen dataset changed and no kortex_eval behaviour changed.

## What changed vs v0.5

1. Harness bug fixed (tools only): tools/stub_backend.py never read request
   bodies, so on HTTP/1.1 keep-alive connections a request body was parsed as
   the next request line (reproduced live: 200 then 501
   `Unsupported method ('{"url":...}GET')`). Fixed with `_drain_body()`.
   Evidence: docs/logs/step11-t4-stub-drain.txt.
2. The runner was exonerated: kortex_eval/runner.py always sends
   `Content-Length = len(body.encode("utf-8","surrogatepass"))` and drops any
   recorded Content-Length header. The 653/20,000 benign-wcp-v0 samples with a
   recorded-CL-vs-encoded-bytes mismatch are a dataset metadata property and
   never reach the wire. Framing is pinned by 3 new tests
   (tests/test_runner.py) and keep-alive integrity by 2 new stub tests; 97
   tests pass.
3. Request-body limit pinned on both engines:
   SecRequestBodyNoFilesLimit 131072 (the ModSecurity image's value). Coraza
   ships 524288 and is rewritten in-container before each run
   (tools/run_coraza_parity.sh), proven per run by the rule-29 print and a
   behavioural probe (200,000-byte body -> 400 after the pin).
4. Engine parity re-established on the same backend (stub-backend:3000):
   ModSecurity WCP PL1/PL2 and Coraza WCP PL1/PL2 re-run with the fixed
   harness. Per-sample blocked-set diffs: PL1 6 only-modsec / 7 only-coraza,
   PL2 6 only-modsec / 8 only-coraza - mostly 400-vs-403 status asymmetry
   (waf_deny_status vs discriminator block), not engine disagreement
   (docs/logs/t4-parity-wcp-fixed.txt).
   Rule-presence differences are large and real (e.g. PL2 942200
   only-coraza 2,385; PL1 932370 only-coraza 303): Coraza matches additional
   CRS rules ModSecurity does not (spot-check verified against the raw modsec
   audit, not a parser artifact). They rarely change the blocking outcome:
   PL2 blocked sets differ by 14 of 20,000 samples.
5. T5 (920260 differential probes, 30 probes, PL1 default, both engines):
   zero disagreements (docs/logs/t5-probe-modsec-pl1.txt,
   docs/logs/t5-probe-coraza-pl1.txt).
6. T6 (cookie sensitivity, fixed harness, ModSecurity/stub): same 7,511 rows,
   dropped 22.14% (PL1) / 41.66% (PL2) vs restored 54.44% / 92.48% (rates =
   blocked incl. deny-status; best = worst here, 0 non-block non-pass rows).
   Top restored-only rule: 932270 (425) at PL1; PL2 adds 942200 (1,784),
   942340 (1,590), 942370 (1,536), 932271 (1,069), 932270 (854). Confirms the
   v0.5 cookie-sensitivity finding and extends it to PL2.
7. waf_deny_status totals (rule 30): fixed-harness runs - coraza 60/60 (PL1/PL2),
   modsec 64/64; all 17 step-10 status-400 samples still return 400
   (verified by id); 10 of the 17 are among the 653 recorded-CL-mismatched
   samples (metadata-only property).
8. T5 probe results and the side-by-side table:
   docs/logs/step11-side-by-side.txt.

## Headline numbers (benign-wcp-v0, default config, frozen manifest)

- ModSecurity PL1: 3,823 / 19,999 = 19.12% (worst case 19.11% with the 1
  error flagged); PL2: 8,949 / 19,999 = 44.75%.
- Coraza PL1: 3,824 / 19,991 = 19.13% (worst case 19.12% with 9 errors
  flagged); PL2: 8,951 / 19,997 = 44.76% (worst case 44.76%).
- The two engines agree on the blocking outcome for 19,987/20,000 (PL1) and
  19,986/20,000 (PL2) samples.
- In-sample label: the default config was NOT derived from this dataset;
  rates are out-of-sample for the default. The wcp-train policy numbers in
  v0.5 remain in-sample (TRAIN hosts) and its TEST-side numbers held-out;
  those runs used the leaky stub and are re-quantified only where stated
  (T2 correction in reports/step-11.md).
