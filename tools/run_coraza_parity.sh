#!/bin/bash
# Step-10 T8 / step-11 T4: Coraza parity runs (rule 13 hygiene: fresh
# container per run). Backend: stub-backend:3000 - the same backend the
# ModSecurity parity runs use (see docs/baseline-config.md step-11 T4 entry;
# the original step-10 comment about BACKEND=target was wrong for these
# runs). One audit log per run, captured via docker cp.
# Step-11: SecRequestBodyNoFilesLimit pinned to 131072 (ModSecurity image's
# value) in-container before each run; effective value printed per run.
set -e
cd "$(dirname "$0")/.."
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36"

# Step-11 T4: parameterized; args are "name:manifest:pl" triples (default config).
run_one() {  # $1=dataset name $2=manifest $3=paranoia level
  docker compose -f deploy/compose.yml down > /dev/null 2>&1 || true
    for try in 1 2 3; do
      MODSEC_RULE_ENGINE=On PARANOIA=$3 BLOCKING_PARANOIA=$3 DETECTION_PARANOIA=$3 \
        CORAZA_RULE_ENGINE=On CORAZA_BACKEND=stub-backend:3000 \
        docker compose -f deploy/compose.yml --profile coraza up -d --force-recreate stub-backend coraza-crs > /dev/null
      sleep 8
      if curl -s -o /dev/null --max-time 5 http://localhost:8082/; then break; fi
      echo "coraza container not answering (try $try) - retrying"
    done
  # Step-13 T4: the sed+reload body-limit pin is removed (it never took
  # effect; the limits now come from CORAZA_REQ_BODY_* env rendered at start,
  # and the nginx client_max_body_size alignment ships in compose). The
  # rule-29 line below still prints the effective limits from the loaded
  # config.
  docker exec deploy-coraza-crs-1 sh -c 'echo "rule29-coraza: E=$CORAZA_RULE_ENGINE B=$BLOCKING_PARANOIA P=$PARANOIA D=$DETECTION_PARANOIA env_CT=[$ALLOWED_REQUEST_CONTENT_TYPE] env_body=[nofiles=$CORAZA_REQ_BODY_NOFILES_LIMIT total=$CORAZA_REQ_BODY_LIMIT]"; grep -A8 "id:900000" /opt/coraza/config/crs-setup.conf | grep -o "tx.paranoia_level=[0-9]*\|tx.blocking_paranoia_level=[0-9]*"; grep -A8 "id:900001" /opt/coraza/config/crs-setup.conf | grep -o "tx.executing_paranoia_level=[0-9]*\|tx.detection_paranoia_level=[0-9]*"; grep -o "tx.crs_setup_version=[0-9]*" /opt/coraza/config/crs-setup.conf; grep -n "SecRequestBodyLimit\|SecRequestBodyNoFilesLimit" /opt/coraza/config/coraza.conf | head -2; grep -c "client_max_body_size 0" /etc/nginx/nginx.conf'
  curl -s -o /dev/null -w "pre-run probe: %{http_code}\n" http://localhost:8082/
  .venv/bin/python -m kortex_eval.runner --manifest "$2" --base-url http://localhost:8082 \
    --out "out/coraza-$1-pl$3-default" --timeout 15 --workers 1 \
    --default-user-agent "$UA" --label engine=coraza --label paranoia=$3 \
    --label stub_drain=fixed --label body_limit=131072 \
    || echo "runner exited non-zero (sample errors); continuing audit processing"
  docker cp deploy-coraza-crs-1:/var/log/coraza/audit/audit.log "out/coraza-$1-pl$3-default/coraza-audit.log"
  .venv/bin/python tools/coraza_audit.py --logs "out/coraza-$1-pl$3-default/coraza-audit.log" --out "out/coraza-$1-pl$3-default/audit.jsonl"
  .venv/bin/python -m kortex_eval.outcome --responses "out/coraza-$1-pl$3-default/responses.jsonl" \
    --audit "out/coraza-$1-pl$3-default/audit.jsonl" --out "out/coraza-$1-pl$3-default/outcomes.jsonl" --engine-mode blocking
  echo "=== done coraza $1 pl$3"
  # Rule 42 (step-18): durable evidence copy before the next task starts.
  tools/preserve_run.sh "out/coraza-$1-pl$3-default"
}

if [ $# -eq 0 ]; then
  run_one smoke data/smoke/manifest.jsonl 1
  run_one attacks-v0 data/attacks-v0/manifest.jsonl 1
  run_one benign-browse-v1 data/benign-browse-v1/manifest.jsonl 1
  run_one benign-hard-v0 data/benign-hard-v0/manifest.jsonl 1
else
  for spec in "$@"; do IFS=: read -r name man pl <<< "$spec"; run_one "$name" "$man" "$pl"; done
fi
echo ALL CORAZA RUNS DONE
