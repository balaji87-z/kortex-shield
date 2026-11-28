#!/bin/bash
# Step-23 T2/T3/T4: in-process and worker-mode runs of benign-wcp-v0 and
# benign-wcp-v1 at PL1 and PL2 (8 runs) with the step-23 engine (patched
# coraza, framing events, compressed-body event). One engine process and one
# audit log per run (rule 13), runner --workers 1, requests to "localhost",
# effective config per run in the log (rule 29).
#
# What it reports:
#   - per pair, tools/step21_engine_diff.py: status diffs and the worst-case
#     set with the fail-closed classes (responses.jsonl carries
#     engine_decision in both modes)
#   - tools/step22_t3_summary.py: rate table, rule-18 list, rule-id set
#     differences in-process vs worker
#   - per run, the count of compressed-body events (E40) and of framing
#     events (E35), from the engine events file
#   - tools/step23_parity_vs_c2.py: per sample against the step-22 C2 runs
#     (stock coraza, in-process)
# Durable files per run under docs/logs/runs/s23-parity/: responses.jsonl,
# outcomes.jsonl, run.json, audit.index.jsonl (body-less), and
# events.index.jsonl (sample id, decision, status, reason of every event
# that is not a pass or a block). Raw audit logs stay under out/ (rule 51).
#
# Usage: [STUB_PORT=13004] [WCP_DATA_DIR=dir] run_step23_parity.sh
set -u
cd "$(dirname "$0")/.."
. tools/step22_lib.sh
DATA=${WCP_DATA_DIR:-data}
DUR=docs/logs/runs/s23-parity
LOG=docs/logs/step23-parity.txt
mkdir -p out $DUR
: > $LOG
echo "# Step-23: in-process and worker-mode runs of the wcp datasets, PL1 and PL2" | tee -a $LOG
echo "== $(date -u +%FT%TZ), $(sw_vers -productName) $(sw_vers -productVersion) $(uname -srm), $(go version), $($PY --version), load at start: $(uptime | sed 's/.*load/load/')" | tee -a $LOG
echo "== git $(git rev-parse HEAD), tracked paths changed in the working tree: $(git status --porcelain -uno | wc -l | tr -d ' ')" | tee -a $LOG
echo "== coraza module of engine/: $(cd engine && go list -m github.com/corazawaf/coraza/v3)" | tee -a $LOG
$PY tools/step23_coraza_vendor.py check | tail -1 | tee -a $LOG
for DS in benign-wcp-v0 benign-wcp-v1; do
  WANT=$(awk '{print $1}' data/$DS/MANIFEST.sha256)
  GOT=$(sha256_of "$DATA/$DS/manifest.jsonl")
  echo "== manifest $DATA/$DS/manifest.jsonl sha256 $GOT (frozen: $WANT)" | tee -a $LOG
  [ "$GOT" = "$WANT" ] || { echo "MANIFEST HASH MISMATCH, stopping" | tee -a $LOG; exit 1; }
done
if curl -s -o /dev/null --max-time 2 http://127.0.0.1:$STUB_PORT/; then
  echo "port $STUB_PORT already answers; set STUB_PORT to a free port" | tee -a $LOG; exit 1
fi
build_engine $LOG || exit 1
start_stub || exit 1

for PL in 1 2; do
  for DS in benign-wcp-v0 benign-wcp-v1; do
    for MODE in inprocess worker; do
      PORT=8097; [ "$MODE" = worker ] && PORT=8098
      NAME=$DS-$MODE-pl$PL
      start_engine s23-$NAME $MODE $PORT $PL 2000 out/s23-$NAME.engine.log || { echo "engine did not start for $NAME" | tee -a $LOG; continue; }
      config_proof "$NAME" $PORT $LOG
      $PY -m kortex_eval.runner --manifest "$DATA/$DS/manifest.jsonl" \
        --base-url $BASE:$PORT --out out/s23-parity-$NAME --timeout 15 --workers 1 \
        --block-status 403 --block-marker 'kortex-decision=block' \
        --default-user-agent "$UA" --label engine=kortex --label mode=$MODE --label paranoia=$PL --label coraza=v3.8.1-kortex \
        > out/s23-parity-$NAME.runner.log 2>&1 || echo "runner nonzero for $NAME (sample errors); continuing" >> $LOG
      echo "== $NAME stats after run: $(curl -s http://127.0.0.1:$PORT/__kortex/stats)" >> $LOG
      stop_engine
      echo "== $NAME kortex_eval.crs_audit and kortex_eval.outcome output:" >> $LOG
      finish_run out/s23-parity-$NAME $DUR/$NAME $LOG
      $PY tools/step23_events_index.py "$ENGINE_EVENTS" $DUR/$NAME/events.index.jsonl | sed "s|^|== $NAME events: |" | tee -a $LOG
    done
    echo "== diff $DS PL$PL (a=inprocess b=worker):" | tee -a $LOG
    $PY tools/step21_engine_diff.py $DUR/$DS-inprocess-pl$PL $DUR/$DS-worker-pl$PL 2>&1 | tee -a $LOG
  done
done
stop_stub
echo "== load at end: $(uptime | sed 's/.*load/load/')" | tee -a $LOG
$PY tools/step22_t3_summary.py $DUR 2>&1 | tee -a $LOG
$PY tools/step23_parity_vs_c2.py docs/logs/runs/s22-c2-outcomes $DUR 2>&1 | tee -a $LOG
echo "S23-PARITY-DONE" | tee -a $LOG
