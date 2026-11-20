#!/usr/bin/env bash
# Step-13 T7 (DIAGNOSTIC, rule 34): latency pathology characterisation for
# wcp-80a49c991b2d (477,231-byte text/plain POST; ModSecurity ~23 ms, Coraza
# ~46 s in step-12 T6). Truncate the body at 1/4/16/64/128/256/477 KB, 3
# replays each, 60 s timeout, both engines, PL1, stub backend. Then replay the
# 20 largest-body WCP samples once each on both engines. Results to
# docs/logs/step13-t7-*.txt. Never used for baseline numbers.
set -u
cd "$(dirname "$0")/.."

bring_coraza() {
  docker compose -f deploy/compose.yml down > /dev/null 2>&1 || true
  for try in 1 2 3; do
    CORAZA_RULE_ENGINE=On CORAZA_BACKEND=stub-backend:3000 PARANOIA=1 BLOCKING_PARANOIA=1 DETECTION_PARANOIA=1 \
      CORAZA_REQ_BODY_NOFILES_LIMIT=131072 CORAZA_REQ_BODY_LIMIT=13107200 \
      docker compose -f deploy/compose.yml --profile coraza up -d --force-recreate stub-backend coraza-crs > /dev/null
    sleep 8
    curl -s -o /dev/null --max-time 5 http://localhost:8082/ && return 0
  done
  return 1
}

bring_modsec() {
  docker compose -f deploy/compose.yml down > /dev/null 2>&1 || true
  for try in 1 2 3; do
    MODSEC_RULE_ENGINE=On PARANOIA=1 BLOCKING_PARANOIA=1 DETECTION_PARANOIA=1 BACKEND=http://stub-backend:3000 \
      docker compose -f deploy/compose.yml up -d --force-recreate stub-backend baseline-crs > /dev/null
    sleep 8
    curl -s -o /dev/null --max-time 5 http://localhost:8081/ && return 0
  done
  return 1
}

# $1=engine port, $2=label, $3=sizes file
truncate_replay() {
  .venv/bin/python tools/t7_truncate_replay.py "$1" "$2" "$3"
}

SIZES=/tmp/t7-sizes.txt
printf '%s\n' 1024 4096 16384 65536 131072 262144 477231 > "$SIZES"

echo "== coraza truncation series $(date -u +%FT%TZ)"
bring_coraza || exit 1
truncate_replay 8082 coraza "$SIZES" > docs/logs/step13-t7-truncate-coraza.txt

echo "== modsec truncation series $(date -u +%FT%TZ)"
bring_modsec || exit 1
truncate_replay 8081 modsec "$SIZES" > docs/logs/step13-t7-truncate-modsec.txt

echo "== 20 largest-body samples, both engines"
bring_coraza || exit 1
.venv/bin/python tools/t7_largest_replay.py 8082 coraza > docs/logs/step13-t7-largest-coraza.txt
bring_modsec || exit 1
.venv/bin/python tools/t7_largest_replay.py 8081 modsec > docs/logs/step13-t7-largest-modsec.txt
echo T7 SERIES DONE
