#!/bin/bash
# Step-12 T6: replay the 9 problem samples (8 coraza PL1 timeouts + 1 modsec
# encoding error) 5x each on BOTH engines, 60s timeout. Fresh container per
# engine (rule 13). Results: docs/logs/step12-t6-replay-<engine>.jsonl
set -e
cd "$(dirname "$0")/.."
echo "== t6 replay start $(date -u +%FT%TZ)"

docker compose -f deploy/compose.yml down > /dev/null 2>&1 || true
MODSEC_RULE_ENGINE=On PARANOIA=1 BLOCKING_PARANOIA=1 DETECTION_PARANOIA=1 \
  BACKEND=http://stub-backend:3000 \
  docker compose -f deploy/compose.yml up -d --force-recreate stub-backend baseline-crs > /dev/null
sleep 8
.venv/bin/python tools/replay_timeouts.py localhost 8081 modsec docs/logs/step12-t6-replay-modsec.jsonl

docker compose -f deploy/compose.yml down > /dev/null 2>&1 || true
MODSEC_RULE_ENGINE=On PARANOIA=1 BLOCKING_PARANOIA=1 DETECTION_PARANOIA=1 \
  CORAZA_RULE_ENGINE=On CORAZA_BACKEND=stub-backend:3000 \
  docker compose -f deploy/compose.yml --profile coraza up -d --force-recreate stub-backend coraza-crs > /dev/null
sleep 8
.venv/bin/python tools/replay_timeouts.py localhost 8082 coraza docs/logs/step12-t6-replay-coraza.jsonl
echo "== t6 replay end $(date -u +%FT%TZ)"
