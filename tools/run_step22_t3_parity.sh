#!/bin/bash
# Step-22 T3: decision parity in-process vs worker mode on benign-wcp-v0
# and benign-wcp-v1, PL1 and PL2. tools/step21_engine_diff.py compares, per
# sample id, the status and the worst-case set (blocked + deny_status +
# inconsistent + error; a sample with no status counts as error) and lists
# the differing ids (rule 32/39). It does not print rule ids.
# Each run gets its own engine process (rule 13) and its effective config in
# the log (rule 29). outcomes.jsonl is produced for every run, so deny_status
# and inconsistent are measured. Raw audit logs stay under out/ (rule 51);
# docs/logs/runs/s22-t3-parity/ holds responses, outcomes, run.json and a
# body-less audit index per run.
set -u
cd "$(dirname "$0")/.."
. tools/step22_lib.sh
# T3_TAG: suffix for a later re-run (other engine commit), so the first recording is kept
TAG=${T3_TAG:-}
DUR=docs/logs/runs/s22-t3-parity$TAG
LOG=docs/logs/step22-t3-parity$TAG.txt
mkdir -p out $DUR
: > $LOG
echo "# Step-22 T3: in-process vs worker parity on the wcp datasets" >> $LOG
echo "== host: $(uname -srm); $(python3 --version); load at start: $(uptime | sed 's/.*load/load/')" >> $LOG
for DS in benign-wcp-v0 benign-wcp-v1; do
  echo "== $DS manifest sha256 $(sha256_of data/$DS/manifest.jsonl) (frozen: $(cat data/$DS/MANIFEST.sha256))" >> $LOG
done
build_engine $LOG || exit 1
start_stub || exit 1

for PL in 1 2; do
  for DS in benign-wcp-v0 benign-wcp-v1; do
    for MODE in inprocess worker; do
      PORT=8097; [ "$MODE" = worker ] && PORT=8098
      NAME=$DS-$MODE-pl$PL
      start_engine t3$TAG-$NAME $MODE $PORT $PL 2000 $DUR/engine-$NAME.log || continue
      config_proof "$NAME" $PORT $LOG
      $PY -m kortex_eval.runner --manifest data/$DS/manifest.jsonl \
        --base-url $BASE:$PORT --out out/s22-t3$TAG-$NAME --timeout 15 --workers 1 \
        --block-status 403 --block-marker 'kortex-decision=block' \
        --default-user-agent "$UA" --label engine=kortex --label mode=$MODE --label paranoia=$PL \
        > $DUR/$NAME.runner.log 2>&1 || echo "runner nonzero for $NAME (sample errors); continuing" >> $LOG
      echo "== $NAME stats after run: $(curl -s http://127.0.0.1:$PORT/__kortex/stats)" >> $LOG
      stop_engine
      finish_run out/s22-t3$TAG-$NAME $DUR/$NAME $LOG
    done
    echo "== diff $DS PL$PL (a=inprocess b=worker):" | tee -a $LOG
    $PY tools/step21_engine_diff.py out/s22-t3$TAG-$DS-inprocess-pl$PL out/s22-t3$TAG-$DS-worker-pl$PL 2>&1 | tee -a $LOG
  done
done
stop_stub
echo "== load at end: $(uptime | sed 's/.*load/load/')" >> $LOG
echo S22-T3-PARITY-DONE
