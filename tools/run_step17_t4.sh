#!/bin/bash
# Step-17 T4: run benign-wcp-v0 (20,000 samples) through the engine at PL1
# and PL2 (DIAGNOSTIC vs the step-13 connector reference - the engine is not
# a baseline; see rule 34). Stub backend, rules 13/29/36 (workers 1, config
# proof, frozen manifest), same UA contract as tools/run_step16_t2.sh.
# Reference: out/coraza-benign-wcp-v0-pl{1,2}-default (step-13, same UA).
set -u
cd "$(cd "$(dirname "$0")/.." && pwd)"
RUN=docs/logs/step17-t4-runs.txt
mkdir -p out
: > $RUN

UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36"

echo "== load average at start: $(uptime)" >> $RUN
if ! curl -s -o /dev/null --max-time 2 http://127.0.0.1:13000/; then
  (cd /tmp && nohup python3 -m http.server 13000 >/tmp/kx17-stub-13000.log 2>&1 &)
  sleep 1
fi

for PL in 1 2; do
  rm -f /tmp/kx17t4-events-$PL.jsonl /tmp/kx17t4-audit-$PL.log
  KORTEX_BACKEND_URL=http://127.0.0.1:13000 \
  KORTEX_RULES_DIR="$PWD/engine/crs" \
  KORTEX_RULE_ENGINE=On \
  KORTEX_BLOCKING_PARANOIA=$PL KORTEX_DETECTION_PARANOIA=$PL \
  KORTEX_MAX_BODY_BYTES=13107200 KORTEX_MAX_INSPECTED_BYTES=131072 \
  KORTEX_ENGINE_TIME_BUDGET_MS=2000 \
  KORTEX_LISTEN_ADDR=127.0.0.1:8090 \
  KORTEX_EVENTS_FILE=/tmp/kx17t4-events-$PL.jsonl \
  KORTEX_AUDIT_LOG=/tmp/kx17t4-audit-$PL.log \
  /tmp/kortex-engine > /tmp/kx17t4-engine-$PL.log 2>&1 &
  EPID=$!
  for i in $(seq 1 20); do sleep 1; curl -s -o /dev/null --max-time 3 http://127.0.0.1:8090/ && break; done
  echo "== engine effective config (PL$PL):" >> $RUN
  cat /tmp/kx17t4-engine-$PL.log >> $RUN
  echo "== /__kortex/config:" >> $RUN
  curl -s http://127.0.0.1:8090/__kortex/config >> $RUN
  echo >> $RUN
  echo "== run engine benign-wcp-v0 pl$PL $(date -u +%FT%TZ)" >> $RUN
  .venv/bin/python -m kortex_eval.runner --manifest data/benign-wcp-v0/manifest.jsonl \
    --base-url http://localhost:8090 --out out/s17-t4-engine-benign-wcp-v0-pl$PL \
    --timeout 30 --workers 1 --block-status 403 \
    --block-marker 'kortex-decision=block' \
    --default-user-agent "$UA" >> $RUN 2>&1
  cp /tmp/kx17t4-audit-$PL.log out/s17-t4-engine-benign-wcp-v0-pl$PL/engine-audit-full.log
  cp /tmp/kx17t4-events-$PL.jsonl out/s17-t4-engine-benign-wcp-v0-pl$PL/kortex-events-full.jsonl 2>/dev/null || true
  .venv/bin/python -m kortex_eval.crs_audit --logs out/s17-t4-engine-benign-wcp-v0-pl$PL/engine-audit-full.log \
    --out out/s17-t4-engine-benign-wcp-v0-pl$PL/audit.jsonl >> $RUN 2>&1
  .venv/bin/python -m kortex_eval.outcome --responses out/s17-t4-engine-benign-wcp-v0-pl$PL/responses.jsonl \
    --audit out/s17-t4-engine-benign-wcp-v0-pl$PL/audit.jsonl \
    --out out/s17-t4-engine-benign-wcp-v0-pl$PL/outcomes.jsonl --engine-mode blocking >> $RUN 2>&1
  kill $EPID 2>/dev/null; wait $EPID 2>/dev/null
done
echo "== load average at end: $(uptime)" >> $RUN
echo ALL-DONE >> $RUN
# Rule 42 (step-18): durable evidence copy before the next task starts.
tools/preserve_run.sh out/s17-t4-engine-benign-wcp-v0-pl1 out/s17-t4-engine-benign-wcp-v0-pl2
