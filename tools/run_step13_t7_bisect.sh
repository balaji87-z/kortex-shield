#!/usr/bin/env bash
# Step-13 T7 (DIAGNOSTIC): identify the dominant Coraza rule behind the
# quadratic latency on wcp-80a49c991b2d by disabling rule IDs one at a time
# (or the passed set) in a SCRATCH container via /opt/coraza/overrides.
# Usage: run_step13_t7_bisect.sh "941100" ["932120 932380 ..."]
# Each invocation: start scratch coraza with the given rules removed, replay
# the sample once, print elapsed+status. Never used for baseline numbers.
set -u
cd "$(dirname "$0")/.."
REMOVE="$1"
cat > /tmp/t7-override.conf <<EOF
# step-13 T7 DIAGNOSTIC scratch override (removed: $REMOVE)
SecRuleRemoveById $REMOVE
EOF
cat > /tmp/t7-compose-override.yml <<'EOF'
services:
  coraza-crs:
    volumes:
      - /tmp/t7-override.conf:/opt/coraza/overrides/zz-t7.conf:ro
EOF
docker compose -f deploy/compose.yml -f /tmp/t7-compose-override.yml down > /dev/null 2>&1 || true
for try in 1 2 3; do
  CORAZA_RULE_ENGINE=On CORAZA_BACKEND=stub-backend:3000 PARANOIA=1 BLOCKING_PARANOIA=1 DETECTION_PARANOIA=1 \
    CORAZA_REQ_BODY_NOFILES_LIMIT=131072 CORAZA_REQ_BODY_LIMIT=13107200 \
    docker compose -f deploy/compose.yml -f /tmp/t7-compose-override.yml --profile coraza up -d --force-recreate stub-backend coraza-crs > /dev/null
  sleep 8
  curl -s -o /dev/null --max-time 5 http://localhost:8082/ && break
done
# prove the removal is live in the running container
docker exec deploy-coraza-crs-1 sh -c "grep -h 'SecRuleRemoveById' /opt/coraza/overrides/zz-t7.conf; grep -c \"id:'$REMOVE'\" /opt/coraza/config/coraza-rules.conf 2>/dev/null || true" >&2
.venv/bin/python tools/t7_truncate_replay.py 8082 "removed[$REMOVE]" /dev/stdin <<'EOF'
477231
EOF
