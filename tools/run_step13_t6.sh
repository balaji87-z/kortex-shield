#!/usr/bin/env bash
# Step-13 T6 (DIAGNOSTIC, docs/decisions/0003-step13-t6-hypothesis.md):
# content-type swap test. 100 body-bearing samples from the step-11/12
# only-Coraza-rule set, as-recorded vs Content-Type rewritten to
# application/x-www-form-urlencoded, both engines, PL1, stub backend.
# Scratch manifests live in out/ and are never committed.
set -u
cd "$(dirname "$0")/.."
mkdir -p out/step13-t6

# 1. pick 100 samples: have a body, matched a Coraza-only rule in the PL1 run
.venv/bin/python tools/pick_t6_samples.py > out/step13-t6/picked.txt

# 2. build the two manifests (scratch)
.venv/bin/python tools/build_t6_manifests.py

# 3. run both engines on both variants (PL1, stub backend)
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36"
for variant in recorded urlenc; do
  # ModSecurity
  docker compose -f deploy/compose.yml down > /dev/null 2>&1 || true
  for try in 1 2 3; do
    MODSEC_RULE_ENGINE=On PARANOIA=1 BLOCKING_PARANOIA=1 DETECTION_PARANOIA=1 BACKEND=http://stub-backend:3000 \
      docker compose -f deploy/compose.yml up -d --force-recreate stub-backend baseline-crs > /dev/null
    sleep 8
    curl -s -o /dev/null --max-time 5 http://localhost:8081/ && break
  done
  docker exec deploy-baseline-crs-1 sed -i 's|SecAuditLog /dev/stdout|SecAuditLog /var/log/modsecurity/audit/audit.log|' /etc/modsecurity.d/modsecurity.conf
  docker exec deploy-baseline-crs-1 nginx -s reload
  audit_ok=0
  for i in 1 2 3 4 5 6 7 8 9 10; do
    sleep 1
    curl -s -o /dev/null "http://localhost:8081/?audit-warmup-blocked=%27%20OR%201%3d1--"
    docker exec deploy-baseline-crs-1 sh -c '[ -s /var/log/modsecurity/audit/audit.log ]' && audit_ok=1 && break
  done
  [ "$audit_ok" = 1 ] || { echo "AUDIT CAPTURE FAILED ($variant modsec)"; exit 1; }
  .venv/bin/python -m kortex_eval.runner --manifest out/step13-t6/manifest-$variant.jsonl \
    --base-url http://localhost:8081 --out out/step13-t6/modsec-$variant --timeout 30 --workers 1 \
    --default-user-agent "$UA" --label t6=diag --label engine=modsec --label variant=$variant
  docker cp deploy-baseline-crs-1:/var/log/modsecurity/audit/audit.log out/step13-t6/modsec-$variant/modsec-audit.log
  .venv/bin/python -m kortex_eval.crs_audit --logs out/step13-t6/modsec-$variant/modsec-audit.log --out out/step13-t6/modsec-$variant/audit.jsonl
  .venv/bin/python -m kortex_eval.outcome --responses out/step13-t6/modsec-$variant/responses.jsonl \
    --audit out/step13-t6/modsec-$variant/audit.jsonl --out out/step13-t6/modsec-$variant/outcomes.jsonl --engine-mode blocking

  # Coraza
  docker compose -f deploy/compose.yml down > /dev/null 2>&1 || true
  for try in 1 2 3; do
    CORAZA_RULE_ENGINE=On CORAZA_BACKEND=stub-backend:3000 PARANOIA=1 BLOCKING_PARANOIA=1 DETECTION_PARANOIA=1 \
      CORAZA_REQ_BODY_NOFILES_LIMIT=131072 CORAZA_REQ_BODY_LIMIT=13107200 \
      docker compose -f deploy/compose.yml --profile coraza up -d --force-recreate stub-backend coraza-crs > /dev/null
    sleep 8
    curl -s -o /dev/null --max-time 5 http://localhost:8082/ && break
  done
  .venv/bin/python -m kortex_eval.runner --manifest out/step13-t6/manifest-$variant.jsonl \
    --base-url http://localhost:8082 --out out/step13-t6/coraza-$variant --timeout 30 --workers 1 \
    --default-user-agent "$UA" --label t6=diag --label engine=coraza --label variant=$variant
  docker cp deploy-coraza-crs-1:/var/log/coraza/audit/audit.log out/step13-t6/coraza-$variant/coraza-audit.log
  .venv/bin/python tools/coraza_audit.py --logs out/step13-t6/coraza-$variant/coraza-audit.log --out out/step13-t6/coraza-$variant/audit.jsonl
  .venv/bin/python -m kortex_eval.outcome --responses out/step13-t6/coraza-$variant/responses.jsonl \
    --audit out/step13-t6/coraza-$variant/audit.jsonl --out out/step13-t6/coraza-$variant/outcomes.jsonl --engine-mode blocking
done
echo T6 RUNS DONE
