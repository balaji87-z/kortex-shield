#!/bin/bash
# Step-10 T7: cookie sensitivity runs (4 runs, rule 13 hygiene).
set -e
cd "$(dirname "$0")/.."
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36"

prep_container() {  # $1=pl
  docker compose -f deploy/compose.yml down > /dev/null 2>&1 || true
  MODSEC_RULE_ENGINE=On PARANOIA=$1 BLOCKING_PARANOIA=$1 DETECTION_PARANOIA=$1 \
    BACKEND=http://stub-backend:3000 \
    docker compose -f deploy/compose.yml up -d --force-recreate stub-backend baseline-crs > /dev/null
  sleep 8
  docker exec deploy-baseline-crs-1 sed -i 's|SecAuditLog /dev/stdout|SecAuditLog /var/log/modsecurity/audit/audit.log|' /etc/modsecurity.d/modsecurity.conf
  docker exec deploy-baseline-crs-1 nginx -s reload
  sleep 2
}

run_one() {  # $1=variant $2=pl
  prep_container "$2"
  curl -s -o /dev/null -w "pre-run probe: %{http_code}\n" http://localhost:8081/
  .venv/bin/python -m kortex_eval.runner --manifest out/wcp-cookie-$1/manifest.jsonl \
    --base-url http://localhost:8081 --out out/wcp-cookie-$1-pl$2 --timeout 15 --workers 1 \
    --default-user-agent "$UA" --label variant=$1 --label paranoia=$2
  docker cp deploy-baseline-crs-1:/var/log/modsecurity/audit/audit.log out/wcp-cookie-$1-pl$2/modsec-audit.log
  .venv/bin/python -m kortex_eval.crs_audit --logs out/wcp-cookie-$1-pl$2/modsec-audit.log --out out/wcp-cookie-$1-pl$2/audit.jsonl
  .venv/bin/python -m kortex_eval.outcome --responses out/wcp-cookie-$1-pl$2/responses.jsonl \
    --audit out/wcp-cookie-$1-pl$2/audit.jsonl --out out/wcp-cookie-$1-pl$2/outcomes.jsonl --engine-mode blocking
  echo "=== done $1 PL$2"
}

run_one restored 1
run_one restored 2
run_one dropped 1
run_one dropped 2
echo ALL COOKIE RUNS DONE
