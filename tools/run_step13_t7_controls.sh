#!/usr/bin/env bash
# Step-13 T7 (DIAGNOSTIC): isolate the Coraza quadratic latency.
# Controls: (a) allowed-CT urlencoded body of the same size (parsed fast?),
# (b) text/plain with SecRequestBodyAccess Off (body not read),
# (c) text/plain with SecRuleEngine DetectionOnly (rules run, no block).
set -u
cd "$(dirname "$0")/.."
measure() { # $1=label
  .venv/bin/python tools/t7_truncate_replay.py 8082 "$1" /dev/stdin <<'EOF'
477231
EOF
}

echo "== control A: urlencoded allowed CT, same size"
.venv/bin/python - 8082 <<'PYEOF' 2>&1
import http.client, time
body = ("a=" + "a"*477230).encode()
for _ in range(3):
    c = http.client.HTTPConnection("localhost", 8082, timeout=90)
    t0 = time.monotonic()
    c.request("POST", "/", body=body, headers={"Content-Type": "application/x-www-form-urlencoded"})
    r = c.getresponse(); r.read()
    print(f"urlencoded-control: {round((time.monotonic()-t0)*1000)}ms {r.status}")
    c.close()
PYEOF

echo "== control B: SecRequestBodyAccess Off (scratch container)"
docker compose -f deploy/compose.yml down > /dev/null 2>&1 || true
cat > /tmp/t7-body-off.conf <<'EOF'
SecRequestBodyAccess Off
EOF
cat > /tmp/t7-compose-override.yml <<'EOF'
services:
  coraza-crs:
    volumes:
      - /tmp/t7-body-off.conf:/opt/coraza/overrides/zz-t7.conf:ro
EOF
for try in 1 2 3; do
  CORAZA_RULE_ENGINE=On CORAZA_BACKEND=stub-backend:3000 PARANOIA=1 BLOCKING_PARANOIA=1 DETECTION_PARANOIA=1 \
    CORAZA_REQ_BODY_NOFILES_LIMIT=131072 CORAZA_REQ_BODY_LIMIT=13107200 \
    docker compose -f deploy/compose.yml -f /tmp/t7-compose-override.yml --profile coraza up -d --force-recreate stub-backend coraza-crs > /dev/null
  sleep 8
  curl -s -o /dev/null --max-time 5 http://localhost:8082/ && break
done
docker exec deploy-coraza-crs-1 grep -h "RequestBodyAccess" /opt/coraza/overrides/zz-t7.conf >&2
measure "bodyaccess-off"

echo "== control C: DetectionOnly (rules run, no block)"
docker compose -f deploy/compose.yml down > /dev/null 2>&1 || true
for try in 1 2 3; do
  CORAZA_RULE_ENGINE=DetectionOnly CORAZA_BACKEND=stub-backend:3000 PARANOIA=1 BLOCKING_PARANOIA=1 DETECTION_PARANOIA=1 \
    CORAZA_REQ_BODY_NOFILES_LIMIT=131072 CORAZA_REQ_BODY_LIMIT=13107200 \
    docker compose -f deploy/compose.yml --profile coraza up -d --force-recreate stub-backend coraza-crs > /dev/null
  sleep 8
  curl -s -o /dev/null --max-time 5 http://localhost:8082/ && break
done
docker exec deploy-coraza-crs-1 grep -h "^SecRuleEngine" /opt/coraza/config/coraza.conf >&2
measure "detection-only"
echo "T7 CONTROLS DONE"
