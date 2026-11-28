#!/bin/bash
# Step-22 shared helpers for the engine runs (T3, T4, T5). Sourced, not run.
# Works on macOS and Linux: no setsid, no /proc, no /tmp evidence (rule 23).
# Raw engine audit logs hold request bodies, so they stay under gitignored
# out/; only body-less indexes are copied to docs/logs/runs (rule 51).
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36"
ENGINE_BIN=out/kortex-engine
# Requests go to "localhost", never to a numeric address: CRS 920350 (Host
# header is a numeric IP address, +3) would otherwise match every request and
# turn any single warning-level match into a block.
BASE=http://localhost
# 13000 is also the host port of the compose "target" service: while those
# containers are up, set STUB_PORT to another port or the engine's backend
# would be Juice Shop, not the stub.
STUB_PORT=${STUB_PORT:-13000}
PY=.venv/bin/python

sha256_of() { if command -v sha256sum >/dev/null; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }

build_engine() { # prints binary hash + commit to $1
  mkdir -p out
  (cd engine && go build -buildvcs=false -o ../$ENGINE_BIN .) || { echo "ENGINE BUILD FAILED"; return 1; }
  echo "== engine binary sha256 $(sha256_of $ENGINE_BIN) built from $(git rev-parse HEAD) with $(go version)" | tee -a "$1"
}

start_stub() {
  if curl -s -o /dev/null --max-time 2 http://127.0.0.1:$STUB_PORT/; then return 0; fi
  nohup python3 tools/stub_backend.py $STUB_PORT > out/stub-$STUB_PORT.log 2>&1 &
  STUB_PID=$!
  for i in $(seq 1 20); do curl -s -o /dev/null --max-time 1 http://127.0.0.1:$STUB_PORT/ && return 0; sleep 0.5; done
  echo "STUB BACKEND DID NOT START"; return 1
}

stop_stub() { [ -n "${STUB_PID:-}" ] && kill $STUB_PID 2>/dev/null; }

# start_engine <tag> <mode inprocess|worker> <port> <pl> <budget_ms> <engine-log>
# Audit and events files: out/s22-<tag>.audit.log / out/s22-<tag>.events.jsonl
start_engine() {
  local tag=$1 mode=$2 port=$3 pl=$4 budget=$5 elog=$6 extra=""
  [ "$mode" = worker ] && extra="KORTEX_WORKER_MODE=on KORTEX_WORKER_POOL=3 KORTEX_WORKER_SPARES=1"
  ENGINE_AUDIT=out/s22-$tag.audit.log
  ENGINE_EVENTS=out/s22-$tag.events.jsonl
  rm -f $ENGINE_AUDIT $ENGINE_EVENTS
  env KORTEX_BACKEND_URL=http://127.0.0.1:$STUB_PORT KORTEX_RULES_DIR=$PWD/engine/crs \
    KORTEX_RULE_ENGINE=On KORTEX_BLOCKING_PARANOIA=$pl KORTEX_DETECTION_PARANOIA=$pl \
    KORTEX_MAX_BODY_BYTES=13107200 KORTEX_MAX_INSPECTED_BYTES=131072 \
    KORTEX_MAX_INFLIGHT_BODY=8 KORTEX_MAX_INFLIGHT_BODY_LARGE=2 KORTEX_BODY_LANE_THRESHOLD=65536 \
    KORTEX_ENGINE_TIME_BUDGET_MS=$budget KORTEX_LISTEN_ADDR=127.0.0.1:$port \
    KORTEX_EVENTS_FILE=$PWD/$ENGINE_EVENTS KORTEX_AUDIT_LOG=$PWD/$ENGINE_AUDIT \
    $extra $ENGINE_BIN > "$elog" 2>&1 &
  ENGINE_PID=$!
  for i in $(seq 1 120); do curl -s -o /dev/null --max-time 1 http://127.0.0.1:$port/ && return 0; sleep 0.5; done
  echo "engine $tag did not start"; return 1
}

stop_engine() {
  [ -n "${ENGINE_PID:-}" ] || return 0
  local kids
  kids=$(pgrep -P $ENGINE_PID)  # worker children, before the parent goes
  kill $ENGINE_PID 2>/dev/null
  wait $ENGINE_PID 2>/dev/null
  [ -n "$kids" ] && kill -9 $kids 2>/dev/null
  ENGINE_PID=""
  sleep 1
}

# rule 29: effective config from the running engine, into the run log
config_proof() { # <label> <port> <log>
  echo "== $1 rule29 $(date -u +%FT%TZ) load: $(uptime | sed 's/.*load/load/'): $(curl -s http://127.0.0.1:$2/__kortex/config)" | tee -a "$3"
}

# After a runner run: parse the audit log, classify outcomes, and keep the
# durable body-less evidence (rule 42 as limited by rule 51): responses.jsonl,
# outcomes.jsonl, run.json and a body-less audit index. The parsed audit.jsonl
# quotes matched request data, so it stays under out/ only.
# finish_run <out-run-dir> <durable-dir> <log>
finish_run() {
  local run=$1 dur=$2 log=$3 f
  cp $ENGINE_AUDIT $run/engine-audit-full.log 2>/dev/null || : > $run/engine-audit-full.log
  $PY -m kortex_eval.crs_audit --logs $run/engine-audit-full.log --out $run/audit.jsonl >> "$log" 2>&1 \
    || echo "crs_audit exit $? for $run (rule 13)" | tee -a "$log"
  $PY -m kortex_eval.outcome --responses $run/responses.jsonl --audit $run/audit.jsonl \
    --out $run/outcomes.jsonl --engine-mode blocking >> "$log" 2>&1
  mkdir -p $dur
  $PY tools/step22_body_index.py $run/engine-audit-full.log $dur/audit.index.jsonl >> "$log" 2>&1
  for f in responses.jsonl outcomes.jsonl run.json audit.index.jsonl; do
    [ "$f" = audit.index.jsonl ] || cp $run/$f $dur/$f
    if [ "$(wc -c < $dur/$f)" -gt 5242880 ]; then gzip -9 -f $dur/$f; fi
  done
}
