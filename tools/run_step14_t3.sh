#!/bin/bash
# Step-14 T3: run the frozen attacks-ct-v0 manifest (320 samples) through
# 8 cells: {crs-default, crs-ct-wide} x {modsec, coraza} x {PL1, PL2}.
# Rule 13: fresh container per run. Rule 36: 20 control requests before and
# 20 after each run; audit entries for them are counted and printed.
# Usage: run_step14_t3.sh
set -u
cd "$(dirname "$0")/.."
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36"
MAN=data/attacks-ct-v0/manifest.jsonl
CT_DEFAULT=""
CT_WIDE='|application/x-www-form-urlencoded| |multipart/form-data| |text/xml| |application/xml| |application/soap+xml| |application/json| |text/plain| |application/octet-stream|'

# rule-36 control: known to match 942100 (libinjection SQLi) -> 403 + audit entry
ctrl() { # $1 port
  for i in $(seq 1 20); do
    curl -s -o /dev/null --max-time 10 "http://localhost:$1/?audit-ctl=%27%20OR%201%3D1--"
  done
}

count_ctl_modsec() { # $1 marker text of audit file
  docker exec deploy-baseline-crs-1 sh -c "grep -c 'audit-ctl' /var/log/modsecurity/audit/audit.log" 2>/dev/null || echo 0
}
count_ctl_coraza() {
  docker exec deploy-coraza-crs-1 sh -c "grep -c 'audit-ctl' /var/log/coraza/audit/audit.log" 2>/dev/null || echo 0
}

run_modsec() { # $1 pl  $2 ct  $3 tag
  docker compose -f deploy/compose.yml down > /dev/null 2>&1 || true
  for try in 1 2 3; do
    MODSEC_RULE_ENGINE=On PARANOIA=$1 BLOCKING_PARANOIA=$1 DETECTION_PARANOIA=$1 \
      BACKEND=http://stub-backend:3000 ALLOWED_REQUEST_CONTENT_TYPE="$2" \
      docker compose -f deploy/compose.yml up -d --force-recreate stub-backend baseline-crs > /dev/null
    sleep 10
    curl -s -o /dev/null --max-time 5 http://localhost:8081/ && break
  done
  docker exec deploy-baseline-crs-1 sed -i 's|SecAuditLog /dev/stdout|SecAuditLog /var/log/modsecurity/audit/audit.log|' /etc/modsecurity.d/modsecurity.conf
  docker exec deploy-baseline-crs-1 nginx -s reload
  audit_ok=0
  for i in 1 2 3 4 5 6 7 8 9 10; do
    sleep 1
    curl -s -o /dev/null "http://localhost:8081/?audit-warmup-blocked=%27%20OR%201%3D1--"
    docker exec deploy-baseline-crs-1 sh -c '[ -s /var/log/modsecurity/audit/audit.log ]' && audit_ok=1 && break
  done
  [ "$audit_ok" = 1 ] || { echo "AUDIT CAPTURE FAILED (modsec pl$1 $3)"; exit 1; }
  docker exec deploy-baseline-crs-1 bash -c 'echo "rule29-modsec: E=$MODSEC_RULE_ENGINE B=$BLOCKING_PARANOIA P=$PARANOIA D=$DETECTION_PARANOIA env_CT=[$ALLOWED_REQUEST_CONTENT_TYPE]"; grep -E "^SecRuleEngine" /etc/modsecurity.d/modsecurity.conf; grep -A7 "id:900000" /etc/modsecurity.d/owasp-crs/crs-setup.conf | grep -o "tx.blocking_paranoia_level=[0-9]*"; grep -A7 "id:900001" /etc/modsecurity.d/owasp-crs/crs-setup.conf | grep -o "tx.detection_paranoia_level=[0-9]*"; grep -o "tx.allowed_request_content_type=[^ ]*" /etc/modsecurity.d/owasp-crs/crs-setup.conf | head -1; grep -o "tx.crs_setup_version=[0-9]*" /etc/modsecurity.d/owasp-crs/crs-setup.conf'
  ctrl 8081; before=$(count_ctl_modsec)
  echo "rule36: control-before entries: $before (expect 20)"
  .venv/bin/python -m kortex_eval.runner --manifest "$MAN" --base-url http://localhost:8081 \
    --out "out/t14-attacks-ct-$3-pl$1" --timeout 30 --workers 1 \
    --default-user-agent "$UA" --label engine=modsec --label config=$3 --label paranoia=$1 \
    || echo "runner exited non-zero (sample errors); continuing"
  ctrl 8081; after=$(count_ctl_modsec)
  echo "rule36: control-after total entries: $after (expect 40; before=$before)"
  docker cp deploy-baseline-crs-1:/var/log/modsecurity/audit/audit.log "out/t14-attacks-ct-$3-pl$1/modsec-audit.log"
  .venv/bin/python -m kortex_eval.crs_audit --logs "out/t14-attacks-ct-$3-pl$1/modsec-audit.log" --out "out/t14-attacks-ct-$3-pl$1/audit.jsonl"
  .venv/bin/python -m kortex_eval.outcome --responses "out/t14-attacks-ct-$3-pl$1/responses.jsonl" \
    --audit "out/t14-attacks-ct-$3-pl$1/audit.jsonl" --out "out/t14-attacks-ct-$3-pl$1/outcomes.jsonl" --engine-mode blocking
}

run_coraza() { # $1 pl  $2 ct  $3 tag
  docker compose -f deploy/compose.yml down > /dev/null 2>&1 || true
  for try in 1 2 3; do
    CORAZA_RULE_ENGINE=On CORAZA_BACKEND=stub-backend:3000 PARANOIA=$1 BLOCKING_PARANOIA=$1 DETECTION_PARANOIA=$1 \
      CORAZA_REQ_BODY_NOFILES_LIMIT=131072 CORAZA_REQ_BODY_LIMIT=13107200 ALLOWED_REQUEST_CONTENT_TYPE="$2" \
      docker compose -f deploy/compose.yml --profile coraza up -d --force-recreate stub-backend coraza-crs > /dev/null
    sleep 10
    curl -s -o /dev/null --max-time 5 http://localhost:8082/ && break
  done
  docker exec deploy-coraza-crs-1 bash -c 'echo "rule29-coraza: E=$CORAZA_RULE_ENGINE B=$BLOCKING_PARANOIA P=$PARANOIA D=$DETECTION_PARANOIA env_CT=[$ALLOWED_REQUEST_CONTENT_TYPE] env_body=[nofiles=$CORAZA_REQ_BODY_NOFILES_LIMIT total=$CORAZA_REQ_BODY_LIMIT]"; grep -A8 "id:900000" /opt/coraza/config/crs-setup.conf | grep -o "tx.blocking_paranoia_level=[0-9]*"; grep -A8 "id:900001" /opt/coraza/config/crs-setup.conf | grep -o "tx.detection_paranoia_level=[0-9]*"; grep -o "tx.allowed_request_content_type=[^ ]*" /opt/coraza/config/crs-setup.conf | head -1; grep -o "tx.crs_setup_version=[0-9]*" /opt/coraza/config/crs-setup.conf; grep -n "SecRequestBodyLimit\|SecRequestBodyNoFilesLimit" /opt/coraza/config/coraza.conf | head -2; grep -c "client_max_body_size 0" /etc/nginx/nginx.conf'
  ctrl 8082; before=$(count_ctl_coraza)
  echo "rule36: control-before entries: $before (expect 20)"
  .venv/bin/python -m kortex_eval.runner --manifest "$MAN" --base-url http://localhost:8082 \
    --out "out/t14-attacks-ct-$3-pl$1" --timeout 30 --workers 1 \
    --default-user-agent "$UA" --label engine=coraza --label config=$3 --label paranoia=$1 \
    || echo "runner exited non-zero (sample errors); continuing"
  ctrl 8082; after=$(count_ctl_coraza)
  echo "rule36: control-after total entries: $after (expect 40; before=$before)"
  docker cp deploy-coraza-crs-1:/var/log/coraza/audit/audit.log "out/t14-attacks-ct-$3-pl$1/coraza-audit.log"
  .venv/bin/python tools/coraza_audit.py --logs "out/t14-attacks-ct-$3-pl$1/coraza-audit.log" --out "out/t14-attacks-ct-$3-pl$1/audit.jsonl"
  .venv/bin/python -m kortex_eval.outcome --responses "out/t14-attacks-ct-$3-pl$1/responses.jsonl" \
    --audit "out/t14-attacks-ct-$3-pl$1/audit.jsonl" --out "out/t14-attacks-ct-$3-pl$1/outcomes.jsonl" --engine-mode blocking
}

case "$1" in
  modsec-default-pl1) run_modsec 1 "$CT_DEFAULT" default ;;
  modsec-default-pl2) run_modsec 2 "$CT_DEFAULT" default ;;
  modsec-wide-pl1)    run_modsec 1 "$CT_WIDE" ct-wide ;;
  modsec-wide-pl2)    run_modsec 2 "$CT_WIDE" ct-wide ;;
  coraza-default-pl1) run_coraza 1 "$CT_DEFAULT" default ;;
  coraza-default-pl2) run_coraza 2 "$CT_DEFAULT" default ;;
  coraza-wide-pl1)    run_coraza 1 "$CT_WIDE" ct-wide ;;
  coraza-wide-pl2)    run_coraza 2 "$CT_WIDE" ct-wide ;;
  *) echo "unknown cell: $1"; exit 1 ;;
esac
echo "=== done $1"
