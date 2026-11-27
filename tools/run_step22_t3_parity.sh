#!/bin/bash
# Step-22 T3: decision parity in-process vs worker mode on benign-wcp-v0
# and benign-wcp-v1, PL1 and PL2. tools/step21_engine_diff.py compares, per
# sample id, the status and the worst-case set (blocked + deny_status +
# inconsistent + error; a sample with no status counts as error) and lists
# the differing ids (rule 32/39). It does not print rule ids.
# Diff tool note: deny_status and inconsistent are compared only when both run directories already have an outcomes.jsonl; otherwise the tool prints NOT MEASURED.
# This script does not produce outcomes.jsonl.
set -u
cd "$(dirname "$0")/.."
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36"
OUT=docs/logs/runs/s22-t3-parity
mkdir -p $OUT
: > docs/logs/step22-t3-parity.txt

ps aux | grep stub200 | grep -v grep | awk '{print $2}' | while read p; do kill -9 $p 2>/dev/null; done; sleep 1
setsid nohup python3 /tmp/stub200.py >/tmp/stub200.log 2>&1 &
sleep 1
curl -s -o /dev/null -X POST --max-time 2 http://127.0.0.1:13000/ || { echo "BACKEND NO RESPONDE"; exit 1; }

run_engine() { # $1=mode $2=port $3=pl
  local mode=$1 port=$2 pl=$3
  local extra=""
  [ "$mode" = worker ] && extra="KORTEX_WORKER_MODE=on KORTEX_WORKER_POOL=3 KORTEX_WORKER_SPARES=1"
  env KORTEX_BACKEND_URL=http://127.0.0.1:13000 KORTEX_RULES_DIR=$PWD/engine/crs \
    KORTEX_RULE_ENGINE=On KORTEX_BLOCKING_PARANOIA=$pl KORTEX_DETECTION_PARANOIA=$pl \
    KORTEX_MAX_BODY_BYTES=13107200 KORTEX_MAX_INSPECTED_BYTES=131072 \
    KORTEX_MAX_INFLIGHT_BODY=8 KORTEX_MAX_INFLIGHT_BODY_LARGE=2 KORTEX_BODY_LANE_THRESHOLD=65536 \
    KORTEX_ENGINE_TIME_BUDGET_MS=2000 KORTEX_LISTEN_ADDR=127.0.0.1:$port \
    KORTEX_EVENTS_FILE=/tmp/kx-s22t3-ev-$mode-pl$pl.jsonl KORTEX_AUDIT_LOG=/tmp/kx-s22t3-aud-$mode-pl$pl.log \
    $extra /tmp/kortex-engine > $OUT/engine-$mode-pl$pl.log 2>&1 &
  for i in $(seq 1 60); do curl -s -o /dev/null --max-time 1 http://127.0.0.1:$port/ && return 0; sleep 0.5; done
  echo "engine $mode pl$pl no levanto" && return 1
}

kill_engines() {
  ps aux | grep kortex-engine | grep -v grep | awk '{print $2}' | while read p; do kill -9 $p 2>/dev/null; done
  sleep 1
}

for PL in 1 2; do
  for DS in benign-wcp-v0 benign-wcp-v1; do
    for MODE in inprocess worker; do
      PORT=8097; [ "$MODE" = worker ] && PORT=8098
      kill_engines
      run_engine $MODE $PORT $PL || continue
      echo "== $DS [$MODE] PL$PL rule29: $(curl -s http://127.0.0.1:$PORT/__kortex/config)" | tee -a docs/logs/step22-t3-parity.txt
      .venv/bin/python -m kortex_eval.runner --manifest data/$DS/manifest.jsonl \
        --base-url http://127.0.0.1:$PORT --out $OUT/$DS-$MODE-pl$PL --timeout 15 --workers 1 \
        --default-user-agent "$UA" --label engine=kortex --label mode=$MODE --label paranoia=$PL \
        > $OUT/$DS-$MODE-pl$PL.runner.log 2>&1 || echo "runner nonzero (sample errors); continuing"
      # durable audit copy per run
      cp /tmp/kx-s22t3-aud-$MODE-pl$PL.log $OUT/$DS-$MODE-pl$PL/audit.log 2>/dev/null || true
      kill_engines
    done
    echo "== diff $DS PL$PL:" | tee -a docs/logs/step22-t3-parity.txt
    .venv/bin/python tools/step21_engine_diff.py $OUT/$DS-inprocess-pl$PL $OUT/$DS-worker-pl$PL \
      2>&1 | tee -a docs/logs/step22-t3-parity.txt
  done
done
echo S22-T3-PARITY-DONE
