#!/bin/bash
# Step-27 T2: encoding-diff-v0, the Python client's runs against the
# raw-socket runner's runs of the same engine, per sample id (rule 32):
# status and worst-case set, then rule-id sets.
# Usage: bash tools/step27_raw_compare.sh > docs/logs/step27-raw-vs-python-client.txt
set -u
cd "$(dirname "$0")/.."
PY=.venv/bin/python
A=docs/logs/runs/s27-own
B=docs/logs/runs/s27-raw
echo "# step-27 T2: encoding-diff-v0, the Python client's runs (a, step-27 engine, $A) against the raw-socket runner's runs (b, $B), per sample id"
echo "# $(date -u +%FT%TZ) git $(git rev-parse HEAD)"
LINKS=$(mktemp -d)
runs=()
for pl in 1 2; do
  for mode in inprocess worker; do
    r=encoding-diff-v0-$mode-pl$pl
    runs+=("$r")
    ln -s "$PWD/$B/encoding-diff-v0-raw-$mode-pl$pl" "$LINKS/$r"
    echo "== encoding-diff-v0 PL$pl $mode (a=Python client b=raw runner):"
    echo "# $PY tools/step21_engine_diff.py $A/$r $B/encoding-diff-v0-raw-$mode-pl$pl"
    $PY tools/step21_engine_diff.py "$A/$r" "$B/encoding-diff-v0-raw-$mode-pl$pl"
  done
done
echo
echo "# rule-id sets per sample, Python client (a) against raw runner (b)"
$PY tools/step25_ruleid_diff.py "$A" "$LINKS" "${runs[@]}"
rm -rf "$LINKS"
