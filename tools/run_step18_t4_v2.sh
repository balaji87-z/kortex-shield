#!/bin/bash
# Step-18 T4 re-run AFTER the 921 scope fix (commit 02bac43, 166 updates):
# POST side only for the four small datasets (PL1+PL2) and benign-wcp-v0
# (PL1+PL2). The PRE side is unaffected (the pre engine never had the
# additions). Out dirs are suffixed -v2; the first-pass post dirs are kept
# for the audit trail. Same config/UA/marker contract as tools/run_step18_t4.sh.
set -u
cd "$(cd "$(dirname "$0")/.." && pwd)"
RUN=docs/logs/step18-t4-runs.txt

UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36"
DSS="attacks-ct-v0 attacks-v0 benign-browse-v1 benign-hard-v0"

echo "== load average at start (v2 re-run): $(uptime)" >> $RUN
if ! curl -s -o /dev/null --max-time 2 http://127.0.0.1:13000/; then
  (cd /tmp && nohup python3 -m http.server 13000 >/tmp/kx18-stub-13000.log 2>&1 &)
  sleep 1
fi
export PATH=$PATH:$HOME/go/bin
(cd engine && go build -buildvcs=false -o /tmp/kortex-engine-v2 .) || { echo "V2 BUILD FAILED" >> $RUN; exit 1; }
echo "== V2 engine binary: $(md5sum /tmp/kortex-engine-v2) (02bac43, 921 excluded, 166 updates)" >> $RUN

start_engine() { # $1=pl
  local pl=$1
  rm -f /tmp/kx18t4-events-v2-$pl.jsonl /tmp/kx18t4-audit-v2-$pl.log
  KORTEX_BACKEND_URL=http://127.0.0.1:13000 \
  KORTEX_RULES_DIR="$PWD/engine/crs" \
  KORTEX_RULE_ENGINE=On \
  KORTEX_BLOCKING_PARANOIA=$pl KORTEX_DETECTION_PARANOIA=$pl \
  KORTEX_MAX_BODY_BYTES=13107200 KORTEX_MAX_INSPECTED_BYTES=131072 \
  KORTEX_ENGINE_TIME_BUDGET_MS=2000 \
  KORTEX_LISTEN_ADDR=127.0.0.1:8090 \
  KORTEX_EVENTS_FILE=/tmp/kx18t4-events-v2-$pl.jsonl \
  KORTEX_AUDIT_LOG=/tmp/kx18t4-audit-v2-$pl.log \
  /tmp/kortex-engine-v2 > /tmp/kx18t4-engine-v2-$pl.log 2>&1 &
  EPID=$!
  for i in $(seq 1 20); do sleep 1; curl -s -o /dev/null --max-time 3 http://127.0.0.1:8090/ && break; done
  echo "== engine effective config (v2 PL$pl):" >> $RUN
  cat /tmp/kx18t4-engine-v2-$pl.log >> $RUN
  echo "== /__kortex/config:" >> $RUN
  curl -s http://127.0.0.1:8090/__kortex/config >> $RUN
  echo >> $RUN
}
stop_engine() { kill $EPID 2>/dev/null; wait $EPID 2>/dev/null; }

run_ds() { # $1=ds $2=pl
  local ds=$1 pl=$2
  echo "== run engine $ds v2 pl$pl $(date -u +%FT%TZ)" >> $RUN
  .venv/bin/python -m kortex_eval.runner --manifest data/$ds/manifest.jsonl \
    --base-url http://localhost:8090 --out out/s18-t4-engine-$ds-v2-pl$pl \
    --timeout 30 --workers 1 --block-status 403 \
    --block-marker 'kortex-decision=block' \
    --default-user-agent "$UA" >> $RUN 2>&1
  cp /tmp/kx18t4-audit-v2-$pl.log out/s18-t4-engine-$ds-v2-pl$pl/engine-audit-full.log
  cp /tmp/kx18t4-events-v2-$pl.jsonl out/s18-t4-engine-$ds-v2-pl$pl/kortex-events-full.jsonl 2>/dev/null || true
  .venv/bin/python -m kortex_eval.crs_audit --logs out/s18-t4-engine-$ds-v2-pl$pl/engine-audit-full.log \
    --out out/s18-t4-engine-$ds-v2-pl$pl/audit.jsonl >> $RUN 2>&1
  .venv/bin/python -m kortex_eval.outcome --responses out/s18-t4-engine-$ds-v2-pl$pl/responses.jsonl \
    --audit out/s18-t4-engine-$ds-v2-pl$pl/audit.jsonl \
    --out out/s18-t4-engine-$ds-v2-pl$pl/outcomes.jsonl --engine-mode blocking >> $RUN 2>&1
  tools/preserve_run.sh out/s18-t4-engine-$ds-v2-pl$pl
}

for PL in 1 2; do
  start_engine $PL
  for DS in $DSS; do run_ds $DS $PL; done
  stop_engine
done
for PL in 1 2; do
  start_engine $PL
  run_ds benign-wcp-v0 $PL
  stop_engine
done
echo "== load average at end (v2 re-run): $(uptime)" >> $RUN
echo V2-DONE >> $RUN
