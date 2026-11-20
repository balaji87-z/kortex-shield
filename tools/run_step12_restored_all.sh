#!/bin/bash
# Step-12 T5: FULL cookie-restored re-run (ModSecurity, PL1+PL2) after the
# case-sensitivity fix in tools/restore_wcp_cookies.py. The step-11 restored
# run covered only 7,511 of 13,261 cookie-dropped rows ("cookie"-spelled only;
# the "Cookie"-spelled rows were skipped). This re-run covers all 13,261.
# Rule 13: fresh container per run. Rule 29: effective-config proof printed
# from inside the container before each run.
set -e
cd "$(dirname "$0")/.."
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36"
echo "== step12 restored-all re-run start $(date -u +%FT%TZ)"

for PL in 1 2; do
  docker compose -f deploy/compose.yml down > /dev/null 2>&1 || true
  MODSEC_RULE_ENGINE=On PARANOIA=$PL BLOCKING_PARANOIA=$PL DETECTION_PARANOIA=$PL \
    BACKEND=http://stub-backend:3000 \
    docker compose -f deploy/compose.yml up -d --force-recreate stub-backend baseline-crs > /dev/null
  sleep 8
  echo "rule29: engine=$(docker exec deploy-baseline-crs-1 grep -m1 '^SecRuleEngine' /etc/modsecurity.d/modsecurity.conf | tr -d '\r') B=$(docker exec deploy-baseline-crs-1 grep -m1 'setvar:tx.blocking_paranoia_level=' /etc/modsecurity.d/modsecurity.conf | grep -oP '(?<=@eq )\d' | head -1) D=$(docker exec deploy-baseline-crs-1 grep -m1 'setvar:tx.detection_paranoia_level=' /etc/modsecurity.d/modsecurity.conf | grep -oP '(?<=@eq )\d' | head -1) P=$PL BACKEND=http://stub-backend:3000"
  docker exec deploy-baseline-crs-1 sed -i 's|SecAuditLog /dev/stdout|SecAuditLog /var/log/modsecurity/audit/audit.log|' /etc/modsecurity.d/modsecurity.conf
  docker exec deploy-baseline-crs-1 nginx -s reload
  sleep 2
  .venv/bin/python -m kortex_eval.runner --manifest out/wcp-cookie-restored-all/manifest.jsonl \
    --base-url http://localhost:8081 --out out/modsec-wcp-cookie-restored-all-pl$PL --timeout 15 --workers 1 \
    --default-user-agent "$UA" --label variant=restored-all --label paranoia=$PL
  docker cp deploy-baseline-crs-1:/var/log/modsecurity/audit/audit.log out/modsec-wcp-cookie-restored-all-pl$PL/modsec-audit.log
  .venv/bin/python -m kortex_eval.crs_audit --logs out/modsec-wcp-cookie-restored-all-pl$PL/modsec-audit.log \
    --out out/modsec-wcp-cookie-restored-all-pl$PL/audit.jsonl
  .venv/bin/python -m kortex_eval.outcome --responses out/modsec-wcp-cookie-restored-all-pl$PL/responses.jsonl \
    --audit out/modsec-wcp-cookie-restored-all-pl$PL/audit.jsonl \
    --out out/modsec-wcp-cookie-restored-all-pl$PL/outcomes.jsonl --engine-mode blocking
  echo "=== done restored-all PL$PL"
done
echo ALL RESTORED-ALL RUNS DONE
