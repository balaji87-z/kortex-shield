#!/bin/bash
# Step-10 T6: held-out-host runs (8 blocking runs, rule 13 hygiene).
# configs: default | wcp-train (crs-policy-wcp-train, docs/baseline-config.md)
# sides:   test | train (docs/logs/wcp-heldout-split.json)
set -e
cd "$(dirname "$0")/.."
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36"
POLICY=$(grep '^ALLOWED_METHODS=' docs/logs/wcp-heldout-policy.txt | cut -d= -f2-)
POLICY_CT=$(grep '^ALLOWED_REQUEST_CONTENT_TYPE=' docs/logs/wcp-heldout-policy.txt | cut -d= -f2-)

prep_container() {  # $1=cfg $2=pl
  if [ "$1" = default ]; then AM=""; CT=""; else AM="$POLICY"; CT="$POLICY_CT"; fi
  docker compose -f deploy/compose.yml down > /dev/null 2>&1 || true
  MODSEC_RULE_ENGINE=On PARANOIA=$2 BLOCKING_PARANOIA=$2 DETECTION_PARANOIA=$2 \
    BACKEND=http://stub-backend:3000 ALLOWED_METHODS="$AM" ALLOWED_REQUEST_CONTENT_TYPE="$CT" \
    docker compose -f deploy/compose.yml up -d --force-recreate stub-backend baseline-crs > /dev/null
  sleep 8
  docker exec deploy-baseline-crs-1 sed -i 's|SecAuditLog /dev/stdout|SecAuditLog /var/log/modsecurity/audit/audit.log|' /etc/modsecurity.d/modsecurity.conf
  docker exec deploy-baseline-crs-1 nginx -s reload
  sleep 2
  docker exec deploy-baseline-crs-1 bash -c 'echo "rule29: engine=$MODSEC_RULE_ENGINE B=$BLOCKING_PARANOIA D=$DETECTION_PARANOIA P=$PARANOIA env_AM=[$ALLOWED_METHODS] env_CT=[$ALLOWED_REQUEST_CONTENT_TYPE]"; grep -n "setvar:'"'"'tx.allowed_methods=" /etc/modsecurity.d/owasp-crs/crs-setup.conf | head -1; grep -n "setvar:'"'"'tx.allowed_request_content_type=" /etc/modsecurity.d/owasp-crs/crs-setup.conf | head -1; grep -n "id:901160" -A7 /etc/modsecurity.d/owasp-crs/rules/REQUEST-901-INITIALIZATION.conf | grep setvar; grep -n "id:901162" -A7 /etc/modsecurity.d/owasp-crs/rules/REQUEST-901-INITIALIZATION.conf | grep setvar' 
}

run_one() {  # $1=side $2=cfg $3=pl
  prep_container "$2" "$3"
  curl -s -o /dev/null -w "pre-run probe: %{http_code}\n" http://localhost:8081/
  .venv/bin/python -m kortex_eval.runner --manifest out/wcp-heldout-$1-manifest.jsonl \
    --base-url http://localhost:8081 --out out/wcp-heldout-$1-$2-pl$3 --timeout 15 --workers 1 \
    --default-user-agent "$UA" --label side=$1 --label config=$2 --label paranoia=$3
  docker cp deploy-baseline-crs-1:/var/log/modsecurity/audit/audit.log out/wcp-heldout-$1-$2-pl$3/modsec-audit.log
  .venv/bin/python -m kortex_eval.crs_audit --logs out/wcp-heldout-$1-$2-pl$3/modsec-audit.log --out out/wcp-heldout-$1-$2-pl$3/audit.jsonl
  .venv/bin/python -m kortex_eval.outcome --responses out/wcp-heldout-$1-$2-pl$3/responses.jsonl \
    --audit out/wcp-heldout-$1-$2-pl$3/audit.jsonl --out out/wcp-heldout-$1-$2-pl$3/outcomes.jsonl --engine-mode blocking
  echo "=== done $1 $2 PL$3"
}

SPECS="test:default:1 test:default:2 test:wcp-train:1 test:wcp-train:2 train:default:1 train:default:2 train:wcp-train:1 train:wcp-train:2"
if [ $# -gt 0 ]; then SPECS="$@"; fi
for spec in $SPECS; do
  IFS=: read -r side cfg pl <<EOF
$spec
EOF
  run_one $side $cfg $pl
done
echo ALL HELDOUT RUNS DONE
