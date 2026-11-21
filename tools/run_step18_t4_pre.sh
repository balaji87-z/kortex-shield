#!/bin/bash
# Step-18 T4 PRE-side re-run (script bug fix): the first pass lost the PRE
# runs to a binary-name typo (/tmp/kortex-engine-pre vs -prefix); the POST
# runs of that pass are valid and kept. This re-runs ONLY the PRE side
# (engine built from commit 1964793, pre-REQUEST_BODY-fix) for the four
# small datasets at PL1+PL2. Same config/UA/marker contract as
# tools/run_step18_t4.sh; evidence appended to the same run log.
set -u
cd "$(cd "$(dirname "$0")/.." && pwd)"
RUN=docs/logs/step18-t4-runs.txt

UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36"
DSS="attacks-ct-v0 attacks-v0 benign-browse-v1 benign-hard-v0"

echo "== load average at start (PRE re-run): $(uptime)" >> $RUN
if ! curl -s -o /dev/null --max-time 2 http://127.0.0.1:13000/; then
  (cd /tmp && nohup python3 -m http.server 13000 >/tmp/kx18-stub-13000.log 2>&1 &)
  sleep 1
fi
export PATH=$PATH:$HOME/go/bin
git worktree prune; git worktree add -f /tmp/kortex-prefix 1964793 >> $RUN 2>&1 || true
(cd /tmp/kortex-prefix/engine && go build -buildvcs=false -o /tmp/kortex-engine-prefix .) || { echo "PRE BUILD FAILED" >> $RUN; exit 1; }
echo "== PRE engine binary: $(md5sum /tmp/kortex-engine-prefix) (1964793, pre-REQUEST_BODY-fix)" >> $RUN

start_engine() { # $1=pl
  local pl=$1
  rm -f /tmp/kx18t4-events-pre-$pl.jsonl /tmp/kx18t4-audit-pre-$pl.log
  KORTEX_BACKEND_URL=http://127.0.0.1:13000 \
  KORTEX_RULES_DIR="$PWD/engine/crs" \
  KORTEX_RULE_ENGINE=On \
  KORTEX_BLOCKING_PARANOIA=$pl KORTEX_DETECTION_PARANOIA=$pl \
  KORTEX_MAX_BODY_BYTES=13107200 KORTEX_MAX_INSPECTED_BYTES=131072 \
  KORTEX_ENGINE_TIME_BUDGET_MS=2000 \
  KORTEX_LISTEN_ADDR=127.0.0.1:8090 \
  KORTEX_EVENTS_FILE=/tmp/kx18t4-events-pre-$pl.jsonl \
  KORTEX_AUDIT_LOG=/tmp/kx18t4-audit-pre-$pl.log \
  /tmp/kortex-engine-prefix > /tmp/kx18t4-engine-pre-$pl.log 2>&1 &
  EPID=$!
  for i in $(seq 1 20); do sleep 1; curl -s -o /dev/null --max-time 3 http://127.0.0.1:8090/ && break; done
  echo "== engine effective config (pre PL$pl):" >> $RUN
  cat /tmp/kx18t4-engine-pre-$pl.log >> $RUN
  echo "== /__kortex/config:" >> $RUN
  curl -s http://127.0.0.1:8090/__kortex/config >> $RUN
  echo >> $RUN
}
stop_engine() { kill $EPID 2>/dev/null; wait $EPID 2>/dev/null; }

for PL in 1 2; do
  start_engine $PL
  for DS in $DSS; do
    echo "== run engine $DS pre pl$PL $(date -u +%FT%TZ)" >> $RUN
    .venv/bin/python -m kortex_eval.runner --manifest data/$DS/manifest.jsonl \
      --base-url http://localhost:8090 --out out/s18-t4-engine-$DS-pre-pl$PL \
      --timeout 30 --workers 1 --block-status 403 \
      --block-marker 'kortex-decision=block' \
      --default-user-agent "$UA" >> $RUN 2>&1
    cp /tmp/kx18t4-audit-pre-$PL.log out/s18-t4-engine-$DS-pre-pl$PL/engine-audit-full.log
    cp /tmp/kx18t4-events-pre-$PL.jsonl out/s18-t4-engine-$DS-pre-pl$PL/kortex-events-full.jsonl 2>/dev/null || true
    .venv/bin/python -m kortex_eval.crs_audit --logs out/s18-t4-engine-$DS-pre-pl$PL/engine-audit-full.log \
      --out out/s18-t4-engine-$DS-pre-pl$PL/audit.jsonl >> $RUN 2>&1
    .venv/bin/python -m kortex_eval.outcome --responses out/s18-t4-engine-$DS-pre-pl$PL/responses.jsonl \
      --audit out/s18-t4-engine-$DS-pre-pl$PL/audit.jsonl \
      --out out/s18-t4-engine-$DS-pre-pl$PL/outcomes.jsonl --engine-mode blocking >> $RUN 2>&1
    tools/preserve_run.sh out/s18-t4-engine-$DS-pre-pl$PL
  done
  stop_engine
done
echo "== load average at end (PRE re-run): $(uptime)" >> $RUN
echo PRE-REDONE >> $RUN
git worktree remove --force /tmp/kortex-prefix >> $RUN 2>&1 || true
