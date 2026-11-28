#!/bin/bash
# Step-25: our own datasets on the step-25 engine against the step-24 runs,
# per sample id (rule 32): status and worst-case set, then rule-id sets.
# Usage: bash tools/step25_own_compare.sh > docs/logs/step25-own-vs-step24.txt
# Later steps: OWN_A=docs/logs/runs/s25-own OWN_A_NAME=step-25
#   OWN_B=docs/logs/runs/s27-own OWN_B_NAME=step-27 bash tools/step25_own_compare.sh
set -u
cd "$(dirname "$0")/.."
PY=.venv/bin/python
A=${OWN_A:-docs/logs/runs/s24-own}
B=${OWN_B:-docs/logs/runs/s25-own}
AN=${OWN_A_NAME:-step-24}
BN=${OWN_B_NAME:-step-25}
echo "# $BN: own datasets on the $BN engine against the $AN runs, per sample id (rule 32)"
echo "# $(date -u +%FT%TZ) git $(git rev-parse HEAD)"
runs=()
for ds in attacks-v0 attacks-ct-v0 encoding-diff-v0 benign-browse-v1 benign-hard-v0; do
  for pl in 1 2; do
    for mode in inprocess worker; do
      r="$ds-$mode-pl$pl"
      runs+=("$r")
      echo "== $ds PL$pl $mode (a=$AN b=$BN):"
      echo "# $PY tools/step21_engine_diff.py $A/$r $B/$r"
      $PY tools/step21_engine_diff.py "$A/$r" "$B/$r"
    done
  done
done
echo
echo "# rule-id sets per sample, $AN runs (a) against $BN runs (b)"
echo "# $PY tools/step25_ruleid_diff.py $A $B <20 runs>"
$PY tools/step25_ruleid_diff.py "$A" "$B" "${runs[@]}"
