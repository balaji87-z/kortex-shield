#!/bin/bash
# Step-12 T3: run the 20 matched-shape probes against BOTH engines at PL1
# (default config). One fresh container pair per engine (rule 13 hygiene).
# Audit logs captured per engine; results in docs/logs/step12-t3-probes-*.
set -e
cd "$(dirname "$0")/.."
echo "== probe run start $(date -u +%FT%TZ)"

# --- ModSecurity (port 8081) ---
docker compose -f deploy/compose.yml down > /dev/null 2>&1 || true
MODSEC_RULE_ENGINE=On PARANOIA=1 BLOCKING_PARANOIA=1 DETECTION_PARANOIA=1 \
  BACKEND=http://stub-backend:3000 \
  docker compose -f deploy/compose.yml up -d --force-recreate stub-backend baseline-crs > /dev/null
sleep 8
docker exec deploy-baseline-crs-1 sed -i 's|SecAuditLog /dev/stdout|SecAuditLog /var/log/modsecurity/audit/audit.log|' /etc/modsecurity.d/modsecurity.conf
docker exec deploy-baseline-crs-1 nginx -s reload
sleep 2
.venv/bin/python tools/probe_matched_shapes.py localhost 8081 modsec docs/logs/step12-t3-probes
docker cp deploy-baseline-crs-1:/var/log/modsecurity/audit/audit.log docs/logs/step12-t3-probes-modsec-audit.log
.venv/bin/python -m kortex_eval.crs_audit --logs docs/logs/step12-t3-probes-modsec-audit.log --out docs/logs/step12-t3-probes-modsec-audit.jsonl
.venv/bin/python tools/probe_rule_extract.py docs/logs/step12-t3-probes-modsec-audit.jsonl docs/logs/step12-t3-probes-modsec-rules.jsonl
echo "== modsec probe pass done"

# --- Coraza (port 8082) ---
docker compose -f deploy/compose.yml down > /dev/null 2>&1 || true
MODSEC_RULE_ENGINE=On PARANOIA=1 BLOCKING_PARANOIA=1 DETECTION_PARANOIA=1 \
  CORAZA_RULE_ENGINE=On CORAZA_BACKEND=stub-backend:3000 \
  docker compose -f deploy/compose.yml --profile coraza up -d --force-recreate stub-backend coraza-crs > /dev/null
sleep 8
docker exec deploy-coraza-crs-1 sed -i 's/SecRequestBodyNoFilesLimit 524288/SecRequestBodyNoFilesLimit 131072/' /opt/coraza/config/coraza.conf
docker exec deploy-coraza-crs-1 nginx -s reload
sleep 2
.venv/bin/python tools/probe_matched_shapes.py localhost 8082 coraza docs/logs/step12-t3-probes
docker cp deploy-coraza-crs-1:/var/log/coraza/audit/audit.log docs/logs/step12-t3-probes-coraza-audit.log
.venv/bin/python tools/coraza_audit.py --logs docs/logs/step12-t3-probes-coraza-audit.log --out docs/logs/step12-t3-probes-coraza-audit.jsonl
.venv/bin/python tools/probe_rule_extract.py docs/logs/step12-t3-probes-coraza-audit.jsonl docs/logs/step12-t3-probes-coraza-rules.jsonl
echo "== coraza probe pass done"
echo "== probe run end $(date -u +%FT%TZ)"
