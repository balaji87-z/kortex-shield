#!/bin/bash
# Step-24 T4: our own five datasets on the step-24 engine (plan:
# docs/plan-step24-own-datasets.md). One engine process and one audit log per
# run (rule 13), runner --workers 1, effective config per run in the log
# (rule 29). Raw audit logs stay under out/; durable files per run under
# docs/logs/runs/s24-own/ (rule 42).
#
# Usage: [STUB_PORT=13004] run_step24_datasets.sh main|stock|numeric-host
#   main          patched engine, PL1 and PL2, in-process and worker (20 runs)
#   stock         DIAGNOSTIC: the same commit built against stock coraza
#                 v3.8.1 (replace dropped in a scratch copy), in-process,
#                 PL1 and PL2 (10 runs)
#   numeric-host  DIAGNOSTIC: patched engine, in-process, PL1, requests to
#                 http://127.0.0.1 instead of http://localhost (5 runs)
set -u
cd "$(dirname "$0")/.."
. tools/step22_lib.sh
WHAT=${1:-main}
DATASETS="attacks-v0 attacks-ct-v0 encoding-diff-v0 benign-browse-v1 benign-hard-v0"
DUR=docs/logs/runs/s24-own
case $WHAT in
  main)         LOG=docs/logs/step24-own-datasets.txt; PLS="1 2"; MODES="inprocess worker"; SUFFIX=""; TITLE="patched engine" ;;
  stock)        LOG=docs/logs/step24-own-datasets-DIAGNOSTIC-stock-coraza.txt; PLS="1 2"; MODES="inprocess"; SUFFIX="-DIAGNOSTIC-stock"; TITLE="DIAGNOSTIC stock coraza v3.8.1" ;;
  numeric-host) LOG=docs/logs/step24-own-datasets-DIAGNOSTIC-numeric-host.txt; PLS="1"; MODES="inprocess"; SUFFIX="-DIAGNOSTIC-numeric-host"; TITLE="DIAGNOSTIC numeric Host (127.0.0.1)"; BASE=http://127.0.0.1 ;;
  *) echo "usage: run_step24_datasets.sh main|stock|numeric-host"; exit 2 ;;
esac
mkdir -p out $DUR
: > $LOG
echo "# Step-24 T4: own datasets, $TITLE" | tee -a $LOG
echo "== $(date -u +%FT%TZ), $(sw_vers -productName) $(sw_vers -productVersion) $(uname -srm), $(go version), $($PY --version), load at start: $(uptime | sed 's/.*load/load/')" | tee -a $LOG
echo "== git $(git rev-parse HEAD), tracked paths changed in the working tree: $(git status --porcelain -uno | wc -l | tr -d ' ')" | tee -a $LOG
for DS in $DATASETS; do
  WANT=$(awk '{print $1}' data/$DS/MANIFEST.sha256)
  GOT=$(sha256_of data/$DS/manifest.jsonl)
  echo "== manifest data/$DS/manifest.jsonl sha256 $GOT (frozen: $WANT), $(wc -l < data/$DS/manifest.jsonl | tr -d ' ') requests" | tee -a $LOG
  [ "$GOT" = "$WANT" ] || { echo "MANIFEST HASH MISMATCH, stopping" | tee -a $LOG; exit 1; }
done
if curl -s -o /dev/null --max-time 2 http://127.0.0.1:$STUB_PORT/; then
  echo "port $STUB_PORT already answers; set STUB_PORT to a free port" | tee -a $LOG; exit 1
fi
if [ "$WHAT" = stock ]; then
  SCR=out/DIAGNOSTIC-engine-stock-coraza
  rm -rf $SCR && mkdir -p $SCR && (cd engine && tar cf - --exclude engine --exclude '*.log' .) | (cd $SCR && tar xf -)
  rm -rf $SCR/third_party
  (cd $SCR && go mod edit -dropreplace github.com/corazawaf/coraza/v3 \
    && go build -buildvcs=false -o ../kortex-engine-DIAGNOSTIC-stock-coraza .) || { echo "SCRATCH BUILD FAILED" | tee -a $LOG; exit 1; }
  ENGINE_BIN=out/kortex-engine-DIAGNOSTIC-stock-coraza
  echo "== DIAGNOSTIC scratch engine coraza module: $(cd $SCR && go list -m github.com/corazawaf/coraza/v3)" | tee -a $LOG
  echo "== DIAGNOSTIC scratch engine sha256 $(sha256_of $ENGINE_BIN); files that differ from engine/ other than go.mod, go.sum and third_party: $(diff -rq --exclude=go.mod --exclude=go.sum --exclude=third_party --exclude=engine --exclude='*.log' engine $SCR | wc -l | tr -d ' '); diff of go.mod against engine/go.mod:" | tee -a $LOG
  diff engine/go.mod $SCR/go.mod | tee -a $LOG
else
  echo "== coraza module of engine/: $(cd engine && go list -m github.com/corazawaf/coraza/v3)" | tee -a $LOG
  $PY tools/step23_coraza_vendor.py check | tail -1 | tee -a $LOG
  build_engine $LOG || exit 1
fi
start_stub || exit 1

for PL in $PLS; do
  for DS in $DATASETS; do
    for MODE in $MODES; do
      PORT=8097; [ "$MODE" = worker ] && PORT=8098
      NAME=$DS-$MODE-pl$PL$SUFFIX
      start_engine s24-$NAME $MODE $PORT $PL 2000 out/s24-$NAME.engine.log || { echo "engine did not start for $NAME" | tee -a $LOG; continue; }
      config_proof "$NAME" $PORT $LOG
      $PY -m kortex_eval.runner --manifest data/$DS/manifest.jsonl \
        --base-url $BASE:$PORT --out out/s24-own-$NAME --timeout 15 --workers 1 \
        --block-status 403 --block-marker 'kortex-decision=block' \
        --default-user-agent "$UA" --label engine=kortex --label mode=$MODE --label paranoia=$PL --label step24=$WHAT \
        > out/s24-own-$NAME.runner.log 2>&1 || echo "runner nonzero for $NAME (sample errors); continuing" >> $LOG
      echo "== $NAME stats after run: $(curl -s http://127.0.0.1:$PORT/__kortex/stats)" >> $LOG
      stop_engine
      echo "== $NAME kortex_eval.crs_audit and kortex_eval.outcome output:" >> $LOG
      finish_run out/s24-own-$NAME $DUR/$NAME $LOG
      $PY tools/step23_events_index.py "$ENGINE_EVENTS" $DUR/$NAME/events.index.jsonl | sed "s|^|== $NAME events: |" | tee -a $LOG
    done
    if [ "$WHAT" = main ]; then
      echo "== diff $DS PL$PL (a=inprocess b=worker):" | tee -a $LOG
      $PY tools/step21_engine_diff.py $DUR/$DS-inprocess-pl$PL $DUR/$DS-worker-pl$PL 2>&1 | tee -a $LOG
    fi
  done
done
stop_stub
echo "== load at end: $(uptime | sed 's/.*load/load/')" | tee -a $LOG
echo "S24-OWN-$WHAT-DONE" | tee -a $LOG
