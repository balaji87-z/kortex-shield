#!/bin/bash
# Step-19 T1: discriminating experiments for the pass-through flip.
# Conditions: (d) default, (a) GOGC=off, (b) GOGC=1, (c) GOMAXPROCS=1.
# 5 repeats x 500 rounds each, same binary, PL2 (flips observed at PL2).
# Each repeat = fresh engine process. Artifacts under docs/logs/runs/s19-flip-<cond>-<rep>/.
set -u
cd "$(dirname "$0")/.."
BIN=${BIN:-/tmp/kortex-engine-v2}
ROUNDS=${ROUNDS:-500}
PORT=8097
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36"
OUT=docs/logs/step19-t1-flip-experiments.txt
mkdir -p docs/logs/runs

run_once() {  # $1=cond-name $2=rep $3=extra env "K=V K=V"
  local cond=$1 rep=$2 envs=$3
  local ev=/tmp/kx-flip-ev.jsonl aud=/tmp/kx-flip-audit.log
  rm -f $ev $aud
  # shellcheck disable=SC2086
  env $envs KORTEX_BACKEND_URL=http://127.0.0.1:13000 \
    KORTEX_RULES_DIR=$PWD/engine/crs KORTEX_RULE_ENGINE=On \
    KORTEX_BLOCKING_PARANOIA=2 KORTEX_DETECTION_PARANOIA=2 \
    KORTEX_MAX_BODY_BYTES=13107200 KORTEX_MAX_INSPECTED_BYTES=131072 \
    KORTEX_ENGINE_TIME_BUDGET_MS=2000 KORTEX_LISTEN_ADDR=127.0.0.1:$PORT \
    KORTEX_EVENTS_FILE=$ev KORTEX_AUDIT_LOG=$aud \
    $BIN >/tmp/kx-flip-$cond-$rep.log 2>&1 &
  local pid=$!
  sleep 1.5
  local rundir=docs/logs/runs/s19-flip-$cond-$rep
  mkdir -p $rundir
  .venv/bin/python tools/flip_repro.py --base-url http://127.0.0.1:$PORT \
    --rounds $ROUNDS --out $rundir/rounds.jsonl > $rundir/summary.txt 2>&1
  local rc=$?
  kill $pid 2>/dev/null; wait $pid 2>/dev/null
  local line
  line=$(grep "flip_rounds" $rundir/summary.txt | tail -1)
  echo "cond=$cond rep=$rep rc=$rc :: $line" | tee -a $OUT
  cp /tmp/kx-flip-$cond-$rep.log $rundir/engine.log 2>/dev/null
  cp $ev $rundir/events.jsonl 2>/dev/null
}

: > $OUT
echo "== T1 flip experiments: $(date -u +%FT%TZ) binary=$BIN rounds=$ROUNDS ==" | tee -a $OUT
for cond in d a b c; do
  for rep in 1 2 3 4 5; do
    case $cond in
      d) envs="";;
      a) envs="GOGC=off";;
      b) envs="GOGC=1";;
      c) envs="GOMAXPROCS=1";;
    esac
    run_once $cond $rep "$envs"
  done
done
echo "FLIP-EXPERIMENTS-DONE" | tee -a $OUT
