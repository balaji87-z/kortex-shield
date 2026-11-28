#!/bin/bash
# Step-22 T5b DIAGNOSTIC (rule 34): cell G (tools/run_step22_t5_cellg.py) at
# PL1 and PL2, on the engine (in-process, as tools/run_step22_t5.sh) or on the
# pinned Coraza connector image (as tools/run_step22_t5_connector.sh). One
# engine process / fresh container per run (rule 13), effective config per run
# (rule 29). Never a baseline number.
# Usage: run_step22_t5_cellg.sh engine|connector
# Evidence: docs/logs/runs/s22-t5-cellg/, log docs/logs/step22-t5-cellg-<side>-DIAGNOSTIC.txt
set -u
cd "$(dirname "$0")/.."
. tools/step22_lib.sh
STUB_PORT=13003   # own stub: the compose "target" service publishes 13000 while containers are up
SIDE=${1:?engine or connector}
# CELLG_TAG: suffix for a later re-run, so the first recording is kept
DUR=docs/logs/runs/s22-t5-cellg${CELLG_TAG:-}
LOG=docs/logs/step22-t5-cellg-$SIDE${CELLG_TAG:-}-DIAGNOSTIC.txt
C=deploy-coraza-crs-1
mkdir -p out $DUR
: > $LOG
echo "# Step-22 T5b DIAGNOSTIC cell G, $SIDE side (rule 34: never a baseline or parity number)" >> $LOG

summarise() { # <name> <audit-log> <label>
  $PY tools/step22_body_index.py $2 $DUR/$1.audit.index.jsonl >> $LOG
  $PY tools/step22_t5_summarise.py encoding $DUR/$1.jsonl "$3" $DUR/$1.audit.index.jsonl >> $LOG
}

if [ "$SIDE" = engine ]; then
  echo "== host: $(uname -srm); $(python3 --version); load at start: $(uptime | sed 's/.*load/load/')" >> $LOG
  build_engine $LOG || exit 1
  start_stub || exit 1
  for pl in 1 2; do
    name=DIAGNOSTIC-cellg-engine-pl$pl
    start_engine t5g-pl$pl inprocess 8099 $pl 2000 $DUR/engine-$name.log || exit 1
    config_proof "$name" 8099 $LOG
    $PY tools/run_step22_t5_cellg.py --engine $BASE:8099 --tag e-pl$pl --out $DUR/$name.jsonl > out/s22-t5g-$name.stdout 2>> $LOG
    stop_engine
    summarise $name $ENGINE_AUDIT "$name"
  done
  stop_stub
else
  echo "== host: $(uname -srm); docker server $(docker version --format '{{.Server.Version}} {{.Server.Os}}/{{.Server.Arch}}'); load at start: $(uptime | sed 's/.*load/load/')" >> $LOG
  for pl in 1 2; do
    name=DIAGNOSTIC-cellg-connector-pl$pl
    up=0
    docker compose -f deploy/compose.yml --profile coraza down > /dev/null 2>&1 || true
    for try in 1 2 3; do
      MODSEC_RULE_ENGINE=On PARANOIA=$pl BLOCKING_PARANOIA=$pl DETECTION_PARANOIA=$pl \
        CORAZA_RULE_ENGINE=On CORAZA_BACKEND=stub-backend:3000 \
        docker compose -f deploy/compose.yml --profile coraza up -d --force-recreate stub-backend coraza-crs > /dev/null 2>&1
      for i in $(seq 1 30); do curl -s -o /dev/null --max-time 3 http://localhost:8082/ && { up=1; break; }; sleep 1; done
      [ $up = 1 ] && break
    done
    [ $up = 1 ] || { echo "== $name: CONNECTOR DID NOT START, run skipped" | tee -a $LOG; continue; }
    {
      echo "== $name rule29/28 $(date -u +%FT%TZ)"
      echo "   image: $(docker inspect --format '{{.Config.Image}} id {{.Image}}' $C) platform $(docker image inspect --format '{{.Os}}/{{.Architecture}}' $(docker inspect --format '{{.Image}}' $C))"
      docker exec $C sh -c 'echo "   env: E=$CORAZA_RULE_ENGINE B=$BLOCKING_PARANOIA P=$PARANOIA D=$DETECTION_PARANOIA CT=[$ALLOWED_REQUEST_CONTENT_TYPE] body=[nofiles=$CORAZA_REQ_BODY_NOFILES_LIMIT total=$CORAZA_REQ_BODY_LIMIT]"; echo "   crs-setup: $(grep -A8 "id:900000" /opt/coraza/config/crs-setup.conf | grep -o "tx.blocking_paranoia_level=[0-9]*") $(grep -A8 "id:900001" /opt/coraza/config/crs-setup.conf | grep -o "tx.detection_paranoia_level=[0-9]*") $(grep -o "tx.crs_setup_version=[0-9]*" /opt/coraza/config/crs-setup.conf)"; echo "   ruleset: $(grep -m1 -o "ver:.OWASP_CRS/[0-9.]*" /opt/coraza/owasp-crs/rules/REQUEST-901-INITIALIZATION.conf) in /opt/coraza/owasp-crs/rules ($(ls /opt/coraza/owasp-crs/rules/*.conf | wc -l) .conf files)"'
    } >> $LOG 2>&1
    $PY tools/run_step22_t5_cellg.py --engine http://localhost:8082 --tag c-pl$pl --out $DUR/$name.jsonl > out/s22-t5g-$name.stdout 2>> $LOG
    docker cp $C:/var/log/coraza/audit/audit.log out/s22-t5g-$name.audit.log >> $LOG 2>&1
    summarise $name out/s22-t5g-$name.audit.log "$name"
  done
  docker compose -f deploy/compose.yml --profile coraza down > /dev/null 2>&1
fi
echo "== load at end: $(uptime | sed 's/.*load/load/')" >> $LOG
echo S22-T5-CELLG-DONE
