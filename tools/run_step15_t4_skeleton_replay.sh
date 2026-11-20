#!/bin/bash
# Step-15 T4 follow-up (DIAGNOSTIC): replay the pathology sample
# wcp-80a49c991b2d (481,798-byte text/plain body) against the engine skeleton,
# 3 reps, engine time budget 2000 ms, per docs/logs/step15-t4-scaling.txt plan.
# Two configs:
#   A) default max_inspected_bytes=131072 -> body is above the inspection cap,
#      so the expected decision is 413 kortex-decision=limit before the engine;
#   B) KORTEX_MAX_INSPECTED_BYTES=13107200 -> the engine actually processes the
#      body, so the elapsed time is the engine's own CRS processing time.
# Rule 34: DIAGNOSTIC, never a baseline or parity number.
set -u
cd /home/Kavinharish/kortexshield
RUN=docs/logs/step15-t4-skeleton-replay.txt
BODY=out/step14-t5/wcp-80a49c991b2d.body
: > $RUN
echo "== step-15 T4 pathology replay vs skeleton (DIAGNOSTIC) $(date -u +%FT%TZ)" >> $RUN
echo "body bytes: $(wc -c < $BODY)" >> $RUN
echo "load_avg_start: $(cat /proc/loadavg)" >> $RUN

start_engine() { # $1 = label, extra env via KORTEX_ vars already set by caller
  rm -f /tmp/kx-events-replay.jsonl /tmp/kx-audit-replay.log
  KORTEX_BACKEND_URL=http://127.0.0.1:13000 \
  KORTEX_RULES_DIR=/home/Kavinharish/kortexshield/engine/crs \
  KORTEX_RULE_ENGINE=On \
  KORTEX_BLOCKING_PARANOIA=1 KORTEX_DETECTION_PARANOIA=1 \
  KORTEX_MAX_BODY_BYTES=13107200 \
  KORTEX_ENGINE_TIME_BUDGET_MS=2000 \
  KORTEX_LISTEN_ADDR=127.0.0.1:8091 \
  KORTEX_EVENTS_FILE=/tmp/kx-events-replay.jsonl \
  KORTEX_AUDIT_LOG=/tmp/kx-audit-replay.log \
  env ${KORTEX_MAX_INSPECTED_BYTES_OVERRIDE:+KORTEX_MAX_INSPECTED_BYTES=$KORTEX_MAX_INSPECTED_BYTES_OVERRIDE} \
  /tmp/kortex-engine > /tmp/kx-engine-replay.log 2>&1 &
  EPID=$!
  for i in $(seq 1 20); do sleep 1; curl -s -o /dev/null --max-time 3 http://127.0.0.1:8091/ && break; done
  grep effective /tmp/kx-engine-replay.log >> $RUN
}

stop_engine() { kill $EPID 2>/dev/null || true; wait $EPID 2>/dev/null || true; }

replay() { # $1 = label
  echo "-- $1" >> $RUN
  for i in 1 2 3; do
    curl -s -o /tmp/kx-replay-body.out -w "status=%{http_code} time_total_s=%{time_total}\n" \
      --max-time 120 -X POST -H 'Content-Type: text/plain' --data-binary @$BODY \
      http://127.0.0.1:8091/ >> $RUN
  done
  head -c 120 /tmp/kx-replay-body.out >> $RUN; echo >> $RUN
}

echo "== config A: default max_inspected_bytes=131072" >> $RUN
start_engine
replay "pathology text/plain 481798B default-inspection-cap"
stop_engine

echo "== config B: KORTEX_MAX_INSPECTED_BYTES=13107200 (engine processes body)" >> $RUN
KORTEX_MAX_INSPECTED_BYTES_OVERRIDE=13107200 start_engine
replay "pathology text/plain 481798B full-inspection"
stop_engine

echo "load_avg_end: $(cat /proc/loadavg)" >> $RUN
echo ALL-DONE >> $RUN
