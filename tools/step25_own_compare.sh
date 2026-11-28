#!/bin/bash
# Step-25: our own datasets on the step-25 engine against the step-24 runs,
# per sample id (rule 32): status and worst-case set, then rule-id sets.
# Usage: bash tools/step25_own_compare.sh > docs/logs/step25-own-vs-step24.txt
set -u
cd "$(dirname "$0")/.."
PY=.venv/bin/python
A=docs/logs/runs/s24-own
B=docs/logs/runs/s25-own
echo "# step-25: own datasets on the step-25 engine against the step-24 runs, per sample id (rule 32)"
echo "# $(date -u +%FT%TZ) git $(git rev-parse HEAD)"
runs=()
for ds in attacks-v0 attacks-ct-v0 encoding-diff-v0 benign-browse-v1 benign-hard-v0; do
  for pl in 1 2; do
    for mode in inprocess worker; do
      r="$ds-$mode-pl$pl"
      runs+=("$r")
      echo "== $ds PL$pl $mode (a=step-24 b=step-25):"
      echo "# $PY tools/step21_engine_diff.py $A/$r $B/$r"
      $PY tools/step21_engine_diff.py "$A/$r" "$B/$r"
    done
  done
done
echo
echo "# rule-id sets per sample, step-24 runs (a) against step-25 runs (b)"
echo "# $PY tools/step25_ruleid_diff.py $A $B <20 runs>"
$PY tools/step25_ruleid_diff.py "$A" "$B" "${runs[@]}"
