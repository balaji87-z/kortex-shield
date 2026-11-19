#!/bin/bash
# Step-11 T2 probes: which content types / methods get 920420/911100 under each config.
set -e
cd "$(dirname "$0")/.."
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36"
POLICY=$(grep '^ALLOWED_METHODS=' docs/logs/wcp-heldout-policy.txt | cut -d= -f2-)
POLICY_CT=$(grep '^ALLOWED_REQUEST_CONTENT_TYPE=' docs/logs/wcp-heldout-policy.txt | cut -d= -f2-)
probe() {
  case "$2" in
    application/json) B='{}';;
    application/xml|text/xml) B='<a/>';;
    "") B="";;
    *) B="x=1";;
  esac
  echo "--- $1 ${2:-<no-ct>} (config=$CFG PL1)"
  curl -s -o /dev/null -w "status=%{http_code}\n" -X "$1" ${2:+-H "Content-Type: $2"} ${2:+--data-binary "$B"} http://localhost:8081/probe
}
run_cfg() {
  docker compose -f deploy/compose.yml down >/dev/null 2>&1 || true
  if [ "$1" = wcp-train ]; then AM="$POLICY"; CT="$POLICY_CT"; else AM=""; CT=""; fi
  MODSEC_RULE_ENGINE=On PARANOIA=1 BLOCKING_PARANOIA=1 DETECTION_PARANOIA=1 \
    BACKEND=http://stub-backend:3000 ALLOWED_METHODS="$AM" ALLOWED_REQUEST_CONTENT_TYPE="$CT" \
    docker compose -f deploy/compose.yml up -d --force-recreate stub-backend baseline-crs >/dev/null
  sleep 8
  docker exec deploy-baseline-crs-1 sed -i 's|SecAuditLog /dev/stdout|SecAuditLog /var/log/modsecurity/audit/audit.log|' /etc/modsecurity.d/modsecurity.conf
  docker exec deploy-baseline-crs-1 nginx -s reload; sleep 2
  for spec in "POST application/json" "POST text/plain" "POST application/x-protobuf" "POST application/xml" "PUT " "PATCH " "DELETE " "POST application/csp-report"; do
    CFG="$1" probe $spec
  done
  docker cp deploy-baseline-crs-1:/var/log/modsecurity/audit/audit.log out/probe-$1-audit.log
  .venv/bin/python -m kortex_eval.crs_audit --logs out/probe-$1-audit.log --out out/probe-$1-audit.jsonl
  echo "rules per probe (cfg=$1):"
  python3 - <<PYEOF
import json
for e in [json.loads(l) for l in open("out/probe-$1-audit.jsonl")]:
    ids=sorted({str(r["id"]) for r in e["rules"]})
    print(" ", e["method"], e["uri"], "->", ids)
PYEOF
}
run_cfg wcp-train
run_cfg default
