#!/bin/bash
# Step-22 T5, connector side: the same padding matrix (PL1, PL2), encoding
# probes (PL1) and DIAGNOSTIC compressed-body cells (PL1) as
# tools/run_step22_t5.sh, sent to the pinned Coraza connector image
# (deploy/compose.yml, profile coraza) in front of the stub backend.
# Fresh containers per run (rule 13); image digest, ruleset version and
# effective levels printed from inside the container per run (rules 7, 28, 29).
# Durable copies: docs/logs/runs/s22-t5-connector/; log: docs/logs/step22-t5-connector.txt
set -u
cd "$(dirname "$0")/.."
. tools/step22_lib.sh
DUR=docs/logs/runs/s22-t5-connector
LOG=docs/logs/step22-t5-connector.txt
C=deploy-coraza-crs-1
mkdir -p out $DUR
: > $LOG
echo "# Step-22 T5 connector side (ghcr.io/coreruleset/coraza-crs, pinned digest in deploy/compose.yml)" >> $LOG
echo "== host: $(uname -srm); docker server $(docker version --format '{{.Server.Version}} {{.Server.Os}}/{{.Server.Arch}}'); load at start: $(uptime | sed 's/.*load/load/')" >> $LOG

run_one() { # <name> <pl> <kind padding|encoding|diag>
  local name=$1 pl=$2 kind=$3 up=0
  docker compose -f deploy/compose.yml --profile coraza down > /dev/null 2>&1 || true
  for try in 1 2 3; do
    MODSEC_RULE_ENGINE=On PARANOIA=$pl BLOCKING_PARANOIA=$pl DETECTION_PARANOIA=$pl \
      CORAZA_RULE_ENGINE=On CORAZA_BACKEND=stub-backend:3000 \
      docker compose -f deploy/compose.yml --profile coraza up -d --force-recreate stub-backend coraza-crs > /dev/null 2>&1
    for i in $(seq 1 30); do curl -s -o /dev/null --max-time 3 http://localhost:8082/ && { up=1; break; }; sleep 1; done
    [ $up = 1 ] && break
    echo "connector not answering (try $try)" >> $LOG
  done
  [ $up = 1 ] || { echo "== $name: CONNECTOR DID NOT START, run skipped" | tee -a $LOG; return 1; }
  {
    echo "== $name rule29/28 $(date -u +%FT%TZ)"
    echo "   image: $(docker inspect --format '{{.Config.Image}} id {{.Image}}' $C) platform $(docker image inspect --format '{{.Os}}/{{.Architecture}}' $(docker inspect --format '{{.Image}}' $C))"
    docker exec $C sh -c 'echo "   env: E=$CORAZA_RULE_ENGINE B=$BLOCKING_PARANOIA P=$PARANOIA D=$DETECTION_PARANOIA CT=[$ALLOWED_REQUEST_CONTENT_TYPE] body=[nofiles=$CORAZA_REQ_BODY_NOFILES_LIMIT total=$CORAZA_REQ_BODY_LIMIT]"; echo "   crs-setup: $(grep -A8 "id:900000" /opt/coraza/config/crs-setup.conf | grep -o "tx.blocking_paranoia_level=[0-9]*") $(grep -A8 "id:900001" /opt/coraza/config/crs-setup.conf | grep -o "tx.detection_paranoia_level=[0-9]*") $(grep -o "tx.crs_setup_version=[0-9]*" /opt/coraza/config/crs-setup.conf)"; echo "   ruleset: $(grep -m1 -o "ver:.OWASP_CRS/[0-9.]*" /opt/coraza/owasp-crs/rules/REQUEST-901-INITIALIZATION.conf) in /opt/coraza/owasp-crs/rules ($(ls /opt/coraza/owasp-crs/rules/*.conf | wc -l) .conf files)"'
  } >> $LOG 2>&1
  case $kind in
    padding)  $PY tools/run_step22_t5_padding.py --engine http://localhost:8082 --pl $pl --out $DUR/$name.jsonl > out/s22-t5c-$name.stdout 2>> $LOG ;;
    encoding) $PY tools/run_step22_t5_encoding.py --engine http://localhost:8082 --out $DUR/$name.jsonl > out/s22-t5c-$name.stdout 2>> $LOG ;;
    diag)     $PY tools/run_step22_t5_encoding_diag.py --engine http://localhost:8082 --out $DUR/$name.jsonl > out/s22-t5c-$name.stdout 2>> $LOG ;;
  esac
  docker cp $C:/var/log/coraza/audit/audit.log out/s22-t5c-$name.audit.log >> $LOG 2>&1
  $PY tools/step22_body_index.py out/s22-t5c-$name.audit.log $DUR/$name.audit.index.jsonl >> $LOG
  [ "$kind" = padding ] || kind=encoding
  $PY tools/step22_t5_summarise.py $kind $DUR/$name.jsonl "connector $name" $DUR/$name.audit.index.jsonl >> $LOG
}

run_one padding-pl1 1 padding
run_one padding-pl2 2 padding
run_one encoding-pl1 1 encoding
echo "# DIAGNOSTIC (rule 34): compressed-body inspection cells F/G/H, never a baseline number" >> $LOG
run_one DIAGNOSTIC-encoding-pl1 1 diag
docker compose -f deploy/compose.yml --profile coraza down > /dev/null 2>&1
echo "== load at end: $(uptime | sed 's/.*load/load/')" >> $LOG
echo S22-T5-CONNECTOR-DONE
