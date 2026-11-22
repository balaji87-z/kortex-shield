#!/bin/bash
# Step-20 T3: inspection time vs body size. 3 cuerpos text/plain
# (pathologia=WCP real, prosa benigna, adversarial denso en keywords)
# x 4 tamanos x engine pre/post x PL1/PL2 x 3 reps. budget=120000ms.
# Los bloques se anotan (status 403 = bloqueado, no tiempo de inspeccion util).
set -u
cd "$(dirname "$0")/.."
OUT=docs/logs/step20-t3-cost.txt
PORT=8106
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36"
: > $OUT
echo "== T3 cost: $(date -u +%FT%TZ) budget=120000ms secuencial, host post-reboot (ver regla 43) ==" | tee -a $OUT
run_engine() { # $1=pre|post $2=pl $3=rep
  local which=$1 pl=$2 rep=$3 bin ev
  if [ "$which" = pre ]; then bin=/tmp/kortex-engine-prefix; else bin=/tmp/kortex-engine-lanes; fi
  ev=/tmp/kx-t3-ev-$which-$pl-$rep.jsonl; rm -f $ev
  KORTEX_BACKEND_URL=http://127.0.0.1:13000 KORTEX_RULES_DIR=$PWD/engine/crs \
    KORTEX_RULE_ENGINE=On KORTEX_BLOCKING_PARANOIA=$pl KORTEX_DETECTION_PARANOIA=$pl \
    KORTEX_MAX_BODY_BYTES=13107200 KORTEX_MAX_INSPECTED_BYTES=131072 \
    KORTEX_ENGINE_TIME_BUDGET_MS=120000 KORTEX_LISTEN_ADDR=127.0.0.1:$PORT \
    KORTEX_EVENTS_FILE=$ev KORTEX_AUDIT_LOG=/tmp/kx-t3-aud-$which-$pl-$rep.log \
    $bin >/tmp/kx-t3-eng-$which-$pl-$rep.log 2>&1 &
  local EP=$!
  for i in $(seq 1 60); do curl -s -o /dev/null --max-time 1 http://127.0.0.1:$PORT/ && break; sleep 0.5; done
  local cfg
  cfg=$(curl -s http://127.0.0.1:$PORT/__kortex/config)
  echo "rule29[$which pl=$pl rep=$rep]: $(echo $cfg | grep -o 'request_body_target_updates=[0-9]*\|"blocking_paranoia":[0-9]*' | tr '\n' ' ')" | tee -a $OUT
  for kind in patho prose adv; do
    for size in 16384 32768 65536 131072; do
      local t
      t=$(curl -s -o /dev/null -w "%{http_code} %{time_total}" -X POST \
        -H "Content-Type: text/plain" -H "X-Kortex-Sample-Id: t3-$which-$pl-$rep-$kind-$size" \
        -H "User-Agent: $UA" --data-binary @/tmp/kx-t3bodies/$kind-$size.bin http://127.0.0.1:$PORT/)
      local la
      la=$(uptime | grep -o "load average.*")
      echo "$which pl=$pl rep=$rep $kind size=$size -> $t load=[$la]" | tee -a $OUT
    done
  done
  kill $EP 2>/dev/null; wait $EP 2>/dev/null
  local rundir=docs/logs/runs/s20-t3-$which-pl$pl-rep$rep
  mkdir -p $rundir; cp $ev $rundir/events.jsonl 2>/dev/null
  cp /tmp/kx-t3-eng-$which-$pl-$rep.log $rundir/engine.log 2>/dev/null
}
for pl in 1 2; do
  for rep in 1 2 3; do
    run_engine pre $pl $rep
    run_engine post $pl $rep
  done
done
echo T3-COST-DONE
