#!/bin/bash
# Step-26: the tables and per-sample comparisons of the attacks-v1 runs.
# Usage: bash tools/step26_summary.sh > docs/logs/step26-summary.txt
#        (also writes docs/logs/step26-not-blocked-ids.txt)
set -u
cd "$(dirname "$0")/.."
PY=.venv/bin/python
E=docs/logs/runs/s26-engine
B=docs/logs/runs/s26-baseline
D=DIAGNOSTIC-no-body-targets
echo "# step-26: attacks-v1 (held-out for every engine setting), tables"
echo "# $(date -u +%FT%TZ) git $(git rev-parse HEAD)"
echo "# \"attack\" means \"listed under this family in this source\", not \"verified exploitable\" (rule 11)"
: > docs/logs/step26-not-blocked-ids.txt
for pl in 1 2; do
  echo
  echo "== PL$pl: rates and counts per run"
  $PY tools/step26_summary.py --missed-out out/step26-missed-pl$pl.txt \
    engine-inprocess-pl$pl=$E/attacks-v1-inprocess-pl$pl engine-worker-pl$pl=$E/attacks-v1-worker-pl$pl \
    modsecurity-pl$pl=$B/attacks-v1-modsec-pl$pl coraza-connector-pl$pl=$B/attacks-v1-coraza-pl$pl \
    $D-pl$pl=$E/attacks-v1-inprocess-pl$pl-$D | grep -v '^ids of the requests'
  cat out/step26-missed-pl$pl.txt >> docs/logs/step26-not-blocked-ids.txt
done
for pl in 1 2; do
  echo
  echo "== PL$pl: per sample id (rule 32: status, worst-case set, rule-id sets)"
  $PY tools/step26_summary.py compare engine-inprocess=$E/attacks-v1-inprocess-pl$pl engine-worker=$E/attacks-v1-worker-pl$pl
  $PY tools/step26_summary.py compare engine=$E/attacks-v1-inprocess-pl$pl modsecurity=$B/attacks-v1-modsec-pl$pl
  $PY tools/step26_summary.py compare engine=$E/attacks-v1-inprocess-pl$pl coraza-connector=$B/attacks-v1-coraza-pl$pl
  $PY tools/step26_summary.py compare modsecurity=$B/attacks-v1-modsec-pl$pl coraza-connector=$B/attacks-v1-coraza-pl$pl
  $PY tools/step26_summary.py compare engine=$E/attacks-v1-inprocess-pl$pl $D=$E/attacks-v1-inprocess-pl$pl-$D
done
