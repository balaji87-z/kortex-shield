#!/bin/bash
# Step-11 T4/T6: ModSecurity runs against the SAME stub backend the Coraza
# parity runs use. The step-09/10 ModSecurity runs went to Juice Shop
# (compose BACKEND default) while every Coraza run went to stub-backend, so
# response-dependent rules (953xxx/959xxx outbound) were compared across
# different backends. Rule 28 requires the same backend on both engines.
# One audit log per run, container force-recreated before each run (rule 13),
# audit capture via in-container file + docker cp (docs/baseline-config.md,
# step-09 section; capture-only change applied per run after start).
set -e
cd "$(dirname "$0")/.."
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36"

run_one() {  # $1=dataset name $2=manifest $3=paranoia level
  docker compose -f deploy/compose.yml down > /dev/null 2>&1 || true
  for try in 1 2 3; do
    MODSEC_RULE_ENGINE=On PARANOIA=$3 BLOCKING_PARANOIA=$3 DETECTION_PARANOIA=$3 \
      BACKEND=http://stub-backend:3000 \
      docker compose -f deploy/compose.yml up -d --force-recreate stub-backend baseline-crs > /dev/null
    sleep 8
    if curl -s -o /dev/null --max-time 5 http://localhost:8081/; then break; fi
    echo "baseline container not answering (try $try) - retrying"
  done
  # rule 29: effective config proof, read from inside the running container
  docker exec deploy-baseline-crs-1 bash -c 'echo "rule29-modsec: E=$MODSEC_RULE_ENGINE B=$BLOCKING_PARANOIA P=$PARANOIA D=$DETECTION_PARANOIA BACKEND=$BACKEND env_CT=[$ALLOWED_REQUEST_CONTENT_TYPE] env_M=[$ALLOWED_METHODS]"; grep -E "^SecRuleEngine" /etc/modsecurity.d/modsecurity.conf; grep -A7 "id:900000" /etc/modsecurity.d/owasp-crs/crs-setup.conf | grep -o "tx.paranoia_level=[0-9]*\|tx.blocking_paranoia_level=[0-9]*"; grep -A7 "id:900001" /etc/modsecurity.d/owasp-crs/crs-setup.conf | grep -o "tx.executing_paranoia_level=[0-9]*\|tx.detection_paranoia_level=[0-9]*"; grep -o "tx.crs_setup_version=[0-9]*" /etc/modsecurity.d/owasp-crs/crs-setup.conf; grep -n "^SecRequestBodyLimit\|^SecRequestBodyNoFilesLimit" /etc/modsecurity.d/modsecurity.conf; grep -n "^SecResponseBodyAccess\|^SecResponseBodyMimeType" /etc/modsecurity.d/modsecurity.conf'
  # capture-only change (documented docs/baseline-config.md step-09): audit to file
  docker exec deploy-baseline-crs-1 sed -i 's|SecAuditLog /dev/stdout|SecAuditLog /var/log/modsecurity/audit/audit.log|' /etc/modsecurity.d/modsecurity.conf
  docker exec deploy-baseline-crs-1 nginx -s reload
  curl -s -o /dev/null -w "pre-run probe: %{http_code}\n" http://localhost:8081/
  .venv/bin/python -m kortex_eval.runner --manifest "$2" --base-url http://localhost:8081 \
    --out "out/modsec-$1-pl$3-stub" --timeout 15 --workers 1 \
    --default-user-agent "$UA" --label engine=modsec --label backend=stub --label paranoia=$3 \
    --label stub_drain=fixed --label body_limit=131072 \
    || echo "runner exited non-zero (sample errors); continuing audit processing"
  docker cp deploy-baseline-crs-1:/var/log/modsecurity/audit/audit.log "out/modsec-$1-pl$3-stub/modsec-audit.log"
  .venv/bin/python -m kortex_eval.crs_audit --logs "out/modsec-$1-pl$3-stub/modsec-audit.log" --out "out/modsec-$1-pl$3-stub/audit.jsonl"
  .venv/bin/python -m kortex_eval.outcome --responses "out/modsec-$1-pl$3-stub/responses.jsonl" \
    --audit "out/modsec-$1-pl$3-stub/audit.jsonl" --out "out/modsec-$1-pl$3-stub/outcomes.jsonl" --engine-mode blocking
  echo "=== done modsec $1 pl$3"
}

if [ $# -eq 0 ]; then
  run_one smoke data/smoke/manifest.jsonl 1
  run_one attacks-v0 data/attacks-v0/manifest.jsonl 1
  run_one benign-browse-v1 data/benign-browse-v1/manifest.jsonl 1
  run_one benign-hard-v0 data/benign-hard-v0/manifest.jsonl 1
else
  for spec in "$@"; do IFS=: read -r name man pl <<< "$spec"; run_one "$name" "$man" "$pl"; done
fi
echo ALL MODSEC RUNS DONE
