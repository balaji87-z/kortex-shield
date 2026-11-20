#!/bin/bash
# Step-12 T4: oversize-body probes on both engines + in-container config facts.
# Bodies: 120,000 and 200,000 bytes of valid JSON ({"k0":0,"k1":0,...} sized to
# the exact byte length by padding the last value), POST application/json.
# Also prints: coraza nginx client_max_body_size, effective coraza.conf limits,
# and the modsec effective limits (rule 29 context for the 400-vs-413 question).
set -e
cd "$(dirname "$0")/.."
echo "== oversize probe start $(date -u +%FT%TZ)"

body() {  # $1 = target byte size -> valid JSON of exactly that many bytes
  .venv/bin/python - "$1" <<'PYEOF'
import sys
n = int(sys.argv[1])
base = b'{"k0":'
pad = n - len(base) - 1
body = base + b'0' * pad + b'}'
assert len(body) == n, (len(body), n)
import kortex_eval  # noqa: F401 (ensure venv)
sys.stdout.buffer.write(body)
PYEOF
}

# --- ModSecurity (port 8081) ---
docker compose -f deploy/compose.yml down > /dev/null 2>&1 || true
MODSEC_RULE_ENGINE=On PARANOIA=1 BLOCKING_PARANOIA=1 DETECTION_PARANOIA=1 \
  BACKEND=http://stub-backend:3000 \
  docker compose -f deploy/compose.yml up -d --force-recreate stub-backend baseline-crs > /dev/null
sleep 8
docker exec deploy-baseline-crs-1 sed -i 's|SecAuditLog /dev/stdout|SecAuditLog /var/log/modsecurity/audit/audit.log|' /etc/modsecurity.d/modsecurity.conf
docker exec deploy-baseline-crs-1 nginx -s reload
sleep 2
echo "--- modsec effective limits (in-container)"
docker exec deploy-baseline-crs-1 grep -n "SecRequestBodyLimit\|SecRequestBodyNoFilesLimit\|SecRequestBodyLimitAction" /etc/modsecurity.d/modsecurity.conf
for size in 120000 200000; do
  body $size > /tmp/oversize.json
  code=$(.venv/bin/python - "$size" <<'PYEOF'
import sys, http.client
body = open("/tmp/oversize.json", "rb").read()
c = http.client.HTTPConnection("localhost", 8081, timeout=30)
c.request("POST", "/oversize-probe", body=body,
          headers={"Content-Type": "application/json", "Content-Length": str(len(body)),
                   "User-Agent": "probe", "Accept-Encoding": "identity"})
r = c.getresponse(); r.read()
print(r.status)
PYEOF
  )
  echo "modsec $size-byte body -> $code"
done
docker cp deploy-baseline-crs-1:/var/log/modsecurity/audit/audit.log docs/logs/step12-oversize-modsec-audit.log
.venv/bin/python -m kortex_eval.crs_audit --logs docs/logs/step12-oversize-modsec-audit.log --out docs/logs/step12-oversize-modsec-audit.jsonl

# --- Coraza (port 8082) ---
docker compose -f deploy/compose.yml down > /dev/null 2>&1 || true
MODSEC_RULE_ENGINE=On PARANOIA=1 BLOCKING_PARANOIA=1 DETECTION_PARANOIA=1 \
  CORAZA_RULE_ENGINE=On CORAZA_BACKEND=stub-backend:3000 \
  docker compose -f deploy/compose.yml --profile coraza up -d --force-recreate stub-backend coraza-crs > /dev/null
sleep 8
echo "--- coraza nginx client_max_body_size (in-container)"
docker exec deploy-coraza-crs-1 grep -rn "client_max_body_size" /etc/nginx/ 2>/dev/null || echo "(not set -> nginx default 1m)"
docker exec deploy-coraza-crs-1 sed -i 's/SecRequestBodyNoFilesLimit 524288/SecRequestBodyNoFilesLimit 131072/' /opt/coraza/config/coraza.conf
docker exec deploy-coraza-crs-1 nginx -s reload
sleep 2
echo "--- coraza effective limits (in-container, after pin)"
docker exec deploy-coraza-crs-1 grep -n "SecRequestBodyLimit\|SecRequestBodyNoFilesLimit\|SecRequestBodyLimitAction" /opt/coraza/config/coraza.conf
for size in 120000 200000; do
  body $size > /tmp/oversize.json
  code=$(.venv/bin/python - "$size" <<'PYEOF'
import sys, http.client
body = open("/tmp/oversize.json", "rb").read()
c = http.client.HTTPConnection("localhost", 8082, timeout=30)
c.request("POST", "/oversize-probe", body=body,
          headers={"Content-Type": "application/json", "Content-Length": str(len(body)),
                   "User-Agent": "probe", "Accept-Encoding": "identity"})
r = c.getresponse(); r.read()
print(r.status)
PYEOF
  )
  echo "coraza $size-byte body -> $code"
done
docker cp deploy-coraza-crs-1:/var/log/coraza/audit/audit.log docs/logs/step12-oversize-coraza-audit.log
.venv/bin/python tools/coraza_audit.py --logs docs/logs/step12-oversize-coraza-audit.log --out docs/logs/step12-oversize-coraza-audit.jsonl
echo "== oversize probe end $(date -u +%FT%TZ)"
