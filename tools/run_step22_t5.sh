#!/bin/bash
# Step-22 T5 driver (engine side): padding matrix extension (k=8, 32,
# 120000 B; PL1 and PL2), Content-Encoding / Transfer-Encoding probes
# (PL1) and the DIAGNOSTIC compressed-body cells (PL1). One engine process per run (rule 13), effective config saved per
# run (rule 29). The connector side needs Docker and is not run here.
# Durable copies: docs/logs/runs/s22-t5/ (result rows, config, body-less
# audit index); summary: docs/logs/step22-t5.txt.
set -u
cd "$(dirname "$0")/.."
. tools/step22_lib.sh
DUR=docs/logs/runs/s22-t5
LOG=docs/logs/step22-t5.txt
mkdir -p out $DUR
: > $LOG
echo "# Step-22 T5 (engine side only; connector NOT MEASURED: no Docker on this host)" >> $LOG
echo "== host: $(uname -srm); $(python3 --version); load at start: $(uptime | sed 's/.*load/load/')" >> $LOG
build_engine $LOG || exit 1
start_stub || exit 1

run_one() { # <name> <pl> <kind padding|encoding>
  local name=$1 pl=$2 kind=$3
  start_engine t5-$name inprocess 8099 $pl 2000 $DUR/engine-$name.log || return 1
  config_proof "$name" 8099 $LOG
  if [ "$kind" = diag ]; then
    $PY tools/run_step22_t5_encoding_diag.py --engine $BASE:8099 --out $DUR/$name.jsonl > out/s22-t5-$name.stdout 2>> $LOG
    kind=encoding
  elif [ "$kind" = padding ]; then
    $PY tools/run_step22_t5_padding.py --engine $BASE:8099 --pl $pl --out $DUR/$name.jsonl > out/s22-t5-$name.stdout 2>> $LOG
  else
    $PY tools/run_step22_t5_encoding.py --engine $BASE:8099 --out $DUR/$name.jsonl > out/s22-t5-$name.stdout 2>> $LOG
  fi
  stop_engine
  $PY tools/step22_body_index.py $ENGINE_AUDIT $DUR/$name.audit.index.jsonl >> $LOG
  $PY tools/step22_t5_summarise.py $kind $DUR/$name.jsonl "$name" $DUR/$name.audit.index.jsonl >> $LOG
}

run_one padding-pl1 1 padding
run_one padding-pl2 2 padding
run_one encoding-pl1 1 encoding
echo "# DIAGNOSTIC (rule 34): compressed-body inspection cells F/G/H, never a baseline number" >> $LOG
run_one DIAGNOSTIC-encoding-pl1 1 diag
stop_stub
echo "== load at end: $(uptime | sed 's/.*load/load/')" >> $LOG
echo S22-T5-DONE
