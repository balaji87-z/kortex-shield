#!/bin/bash
# Step-12 T2 + T7 batch (launched BEFORE any result was read; rule 17 note in
# reports/step-12.md). All small-dataset parity logs predate the stub-drain fix
# commit 37bc833 (2026-11-19 12:47 UTC): coraza small runs 01:54-05:36, modsec
# small stub runs 11:08-11:11 (leaky stub - the fix landed 12:42:30). Re-run
# every small dataset on BOTH engines at PL1 and PL2 with rule-29 proof.
# Then step-12 T7: one wcp-train cell (TEST PL1) on the fixed stub.
# Old run dirs were backed up to out/backup-step11-small/ and
# out/backup-step11-wcp-heldout-test-wcp-train-pl1 before this batch started.
set -u
cd "$(dirname "$0")/.."
echo "=== step12 batch1 start $(date -u +%FT%TZ)"

tools/run_coraza_parity.sh \
  smoke:data/smoke/manifest.jsonl:1 \
  smoke:data/smoke/manifest.jsonl:2 \
  attacks-v0:data/attacks-v0/manifest.jsonl:1 \
  attacks-v0:data/attacks-v0/manifest.jsonl:2 \
  benign-browse-v1:data/benign-browse-v1/manifest.jsonl:1 \
  benign-browse-v1:data/benign-browse-v1/manifest.jsonl:2 \
  benign-hard-v0:data/benign-hard-v0/manifest.jsonl:1 \
  benign-hard-v0:data/benign-hard-v0/manifest.jsonl:2

tools/run_modsec_parity.sh \
  smoke:data/smoke/manifest.jsonl:1 \
  smoke:data/smoke/manifest.jsonl:2 \
  attacks-v0:data/attacks-v0/manifest.jsonl:1 \
  attacks-v0:data/attacks-v0/manifest.jsonl:2 \
  benign-browse-v1:data/benign-browse-v1/manifest.jsonl:1 \
  benign-browse-v1:data/benign-browse-v1/manifest.jsonl:2 \
  benign-hard-v0:data/benign-hard-v0/manifest.jsonl:1 \
  benign-hard-v0:data/benign-hard-v0/manifest.jsonl:2

# Step-12 T7: wcp-train TEST PL1 on the fixed stub (rule 13 hygiene + rule 29
# proof are inside tools/run_wcp_heldout.sh).
tools/run_wcp_heldout.sh test:wcp-train:1

echo "=== step12 batch1 end $(date -u +%FT%TZ)"
