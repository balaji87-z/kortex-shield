#!/bin/bash
# Step-09 baseline runs for benign-wcp-v0 against the stub backend.
# Applies the audit-log-to-file change (docs/baseline-config.md) per run,
# then runs the runner + audit + outcome pipeline (rule 13 hygiene).
set -e
cd "$(dirname "$0")/.."
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36"
MANIFEST=out/benign-wcp-v0-baseline-manifest.jsonl

prep_container() {  # $1=cfg $2=pl
  if [ "$1" = default ]; then AM=""; CT=""; else AM="GET HEAD POST OPTIONS PUT DELETE"; CT="application/json application/x-www-form-urlencoded multipart/form-data text/xml application/soap+xml"; fi
  docker compose -f deploy/compose.yml down > /dev/null 2>&1 || true
  MODSEC_RULE_ENGINE=On PARANOIA=$2 BLOCKING_PARANOIA=$2 DETECTION_PARANOIA=$2 \
    BACKEND=http://stub-backend:3000 ALLOWED_METHODS="$AM" ALLOWED_REQUEST_CONTENT_TYPE="$CT" \
    docker compose -f deploy/compose.yml up -d --force-recreate stub-backend baseline-crs > /dev/null
  sleep 8
  docker exec deploy-baseline-crs-1 sed -i 's|SecAuditLog /dev/stdout|SecAuditLog /var/log/modsecurity/audit/audit.log|' /etc/modsecurity.d/modsecurity.conf
  docker exec deploy-baseline-crs-1 nginx -s reload
  sleep 2
  docker exec deploy-baseline-crs-1 bash -c 'echo "B=$BLOCKING_PARANOIA D=$DETECTION_PARANOIA P=$PARANOIA E=$MODSEC_RULE_ENGINE"; grep "^SecAuditLog " /etc/modsecurity.d/modsecurity.conf'
}

run_one() {  # $1=cfg $2=pl
  prep_container "$1" "$2"
  curl -s -o /dev/null -w "pre-run probe: %{http_code}\n" http://localhost:8081/
  .venv/bin/python -m kortex_eval.runner --manifest $MANIFEST --base-url http://localhost:8081 \
    --out out/benign-wcp-v0-pl$2-$1-ua --timeout 15 --workers 1 \
    --default-user-agent "$UA" --label config=$1 --label paranoia=$2
  docker cp deploy-baseline-crs-1:/var/log/modsecurity/audit/audit.log out/benign-wcp-v0-pl$2-$1-ua/modsec-audit.log
  .venv/bin/python -m kortex_eval.crs_audit --logs out/benign-wcp-v0-pl$2-$1-ua/modsec-audit.log --out out/benign-wcp-v0-pl$2-$1-ua/audit.jsonl
  .venv/bin/python -m kortex_eval.outcome --responses out/benign-wcp-v0-pl$2-$1-ua/responses.jsonl --audit out/benign-wcp-v0-pl$2-$1-ua/audit.jsonl --out out/benign-wcp-v0-pl$2-$1-ua/outcomes.jsonl --engine-mode blocking
  echo "=== done $1 PL$2"
}

run_one default 1
run_one default 2
run_one aligned 1
run_one aligned 2
echo ALL RUNS DONE
