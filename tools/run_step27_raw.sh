#!/bin/bash
# Step-27 T2: encoding-diff-v0 sent with the raw-socket runner
# (tools/raw_runner.py), all 192 requests, including the 10 the Python client
# refuses to build. Engine in-process and worker, PL1 and PL2; one engine
# process and one audit log per run (rule 13); effective config per run
# (rule 29). Durable files: docs/logs/runs/s27-raw/<run>/ (rule 42).
# Usage: [STUB_PORT=13004] run_step27_raw.sh
set -u
cd "$(dirname "$0")/.."
. tools/step22_lib.sh
DS=encoding-diff-v0
MAN=data/$DS/manifest.jsonl
DUR=docs/logs/runs/s27-raw
LOG=docs/logs/step27-raw-runner.txt
mkdir -p out $DUR; : > $LOG
echo "# Step-27 T2: $DS through the raw-socket runner, engine in-process and worker, PL1 and PL2" | tee -a $LOG
echo "== $(date -u +%FT%TZ), $(sw_vers -productName) $(sw_vers -productVersion) $(uname -srm), $(go version), $($PY --version), load at start: $(uptime | sed 's/.*load/load/')" | tee -a $LOG
echo "== git $(git rev-parse HEAD), tracked paths changed under engine/: $(git status --porcelain engine | wc -l | tr -d ' ')" | tee -a $LOG
echo "== manifest $MAN sha256 $(sha256_of $MAN) (frozen: $(awk '{print $1}' data/$DS/MANIFEST.sha256)), $(wc -l < $MAN | tr -d ' ') requests" | tee -a $LOG
if curl -s -o /dev/null --max-time 2 http://127.0.0.1:$STUB_PORT/; then echo "port $STUB_PORT already answers" | tee -a $LOG; exit 1; fi
build_engine $LOG || exit 1
start_stub || exit 1
for PL in 1 2; do
  for MODE in inprocess worker; do
    PORT=8097; [ "$MODE" = worker ] && PORT=8098
    NAME=$DS-raw-$MODE-pl$PL
    rm -rf out/s27-raw-$NAME
    start_engine s27-$NAME $MODE $PORT $PL 2000 out/s27-$NAME.engine.log || { echo "engine did not start for $NAME" | tee -a $LOG; continue; }
    config_proof "$NAME" $PORT $LOG
    $PY tools/raw_runner.py --manifest $MAN --base-url $BASE:$PORT --out out/s27-raw-$NAME --timeout 15 \
      --block-status 403 --block-marker 'kortex-decision=block' --default-user-agent "$UA" \
      --label engine=kortex --label mode=$MODE --label paranoia=$PL --label step27=raw 2>&1 | sed "s|^|== $NAME raw runner: |" | tee -a $LOG
    echo "== $NAME stats after run: $(curl -s http://127.0.0.1:$PORT/__kortex/stats)" >> $LOG
    stop_engine
    echo "== $NAME kortex_eval.crs_audit and kortex_eval.outcome output:" >> $LOG
    finish_run out/s27-raw-$NAME $DUR/$NAME $LOG
    $PY tools/step23_events_index.py "$ENGINE_EVENTS" $DUR/$NAME/events.index.jsonl | sed "s|^|== $NAME events: |" | tee -a $LOG
  done
done
stop_stub
echo "== load at end: $(uptime | sed 's/.*load/load/')" | tee -a $LOG
echo S27-RAW-DONE | tee -a $LOG
