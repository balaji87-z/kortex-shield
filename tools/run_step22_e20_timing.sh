#!/bin/bash
# Step-22 follow-up: how long does the abandoned in-process call of E20 take
# on this host? TestE20OverloadRecovery waits 120 s for the event
# "abandoned-body-processing-finished" and fails here. This sends the same
# request (the recorded wcp fixture body, text/plain, to "/") to an engine
# process with E20's settings and waits for that event, up to MAX_WAIT_S.
# The fixture is not committed (rules 25, 51): set KORTEX_TEST_WCP_BODY.
# Usage: run_step22_e20_timing.sh [repeats]     (default 3)
#   E20_ENGINE_BIN=<binary> E20_ENGINE_NOTE=<text> times a scratch build instead (DIAGNOSTIC)
# Log: docs/logs/step22-e20-timing.txt (appends one block per call)
set -u
cd "$(dirname "$0")/.."
. tools/step22_lib.sh
STUB_PORT=13002   # own stub: the compose "target" service publishes 13000 while containers are up
FIX=${KORTEX_TEST_WCP_BODY:-out/step14-t5/wcp-80a49c991b2d.body}
REPEATS=${1:-3}
MAX_WAIT_S=${MAX_WAIT_S:-1800}
LOG=docs/logs/step22-e20-timing.txt
[ -f "$FIX" ] || { echo "fixture $FIX missing"; exit 1; }
mkdir -p out
{
  echo "# Step-22: duration of E20's abandoned in-process call (fixture $(wc -c < $FIX | tr -d ' ') bytes, sha256 $(sha256_of $FIX); not committed)"
  echo "== host: $(uname -srm); $(go version); $(sysctl -n hw.ncpu 2>/dev/null || nproc) cpus; $(date -u +%FT%TZ)"
} >> $LOG
if [ -n "${E20_ENGINE_BIN:-}" ]; then
  # DIAGNOSTIC (rule 34): a scratch build, e.g. out/kortex-engine-DIAGNOSTIC-coraza370 from tools/run_step22_t3_diag.sh
  ENGINE_BIN=$E20_ENGINE_BIN
  echo "== DIAGNOSTIC engine binary $ENGINE_BIN sha256 $(sha256_of $ENGINE_BIN) (${E20_ENGINE_NOTE:-scratch build})" >> $LOG
else
  build_engine $LOG || exit 1
fi
start_stub || exit 1
for rep in $(seq 1 $REPEATS); do
  EV=out/s22-e20-timing-$rep.events.jsonl
  rm -f $EV out/s22-e20-timing-$rep.audit.log
  env KORTEX_BACKEND_URL=http://127.0.0.1:$STUB_PORT KORTEX_RULES_DIR=$PWD/engine/crs \
    KORTEX_RULE_ENGINE=On KORTEX_BLOCKING_PARANOIA=1 KORTEX_DETECTION_PARANOIA=1 \
    KORTEX_MAX_BODY_BYTES=13107200 KORTEX_MAX_INSPECTED_BYTES=13107200 \
    KORTEX_MAX_INFLIGHT_BODY=1 KORTEX_BODY_LANE_THRESHOLD=13107200 \
    KORTEX_ENGINE_TIME_BUDGET_MS=200 KORTEX_LISTEN_ADDR=127.0.0.1:8097 \
    KORTEX_EVENTS_FILE=$PWD/$EV KORTEX_AUDIT_LOG=$PWD/out/s22-e20-timing-$rep.audit.log \
    $ENGINE_BIN > out/s22-e20-timing-$rep.engine.log 2>&1 &
  ENGINE_PID=$!
  for i in $(seq 1 120); do curl -s -o /dev/null --max-time 1 http://127.0.0.1:8097/ && break; sleep 0.5; done
  [ $rep = 1 ] && config_proof "e20-timing" 8097 $LOG
  load0=$(uptime | sed 's/.*load/load/')
  t0=$(date +%s)
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 -H 'Content-Type: text/plain' -H "X-Kortex-Sample-Id: e20-timing-$rep" \
    --data-binary @$FIX http://localhost:8097/)
  finished=no
  while [ $(( $(date +%s) - t0 )) -lt $MAX_WAIT_S ]; do
    grep -q abandoned-body-processing-finished $EV 2>/dev/null && { finished=yes; break; }
    sleep 1
  done
  t1=$(date +%s)
  cpu=$(ps -o time= -p $ENGINE_PID | tr -d ' ')
  after=$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 -H 'Content-Type: application/json' -H "X-Kortex-Sample-Id: e20-timing-$rep-after" \
    -d '{}' http://localhost:8097/rest/user/login)
  {
    echo "== repeat $rep: occupier answered $code; abandoned call finished=$finished after $((t1 - t0)) s wall (1 s polling; limit $MAX_WAIT_S s); engine process CPU time $cpu; next body-bearing request -> $after"
    echo "   $load0 (start); $(uptime | sed 's/.*load/load/') (end)"
    echo "   event rows (sample id, decision, status, elapsed_ms, reason only):"
    $PY -c "
import json,sys
for l in open('$EV'):
    e=json.loads(l); print('    ', {k:e.get(k) for k in ('ts','sample_id','decision','status','elapsed_ms','reason')})"
  } >> $LOG
  stop_engine
done
stop_stub
echo S22-E20-TIMING-DONE
