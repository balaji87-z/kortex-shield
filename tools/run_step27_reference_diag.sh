#!/bin/bash
# Step-27 DIAGNOSTIC (rule 34): the XML attribute case and the raw overlong
# path of the parsing differential against the two pinned reference images
# (ModSecurity and the Coraza connector, CRS v4.25.2, blocking, PL1, stub
# backend), to say whether the engine differs from the reference on them
# (rule 39). No baseline or parity number comes from this run.
# Usage: run_step27_reference_diag.sh   (needs docker)
set -u
cd "$(dirname "$0")/.."
PY=.venv/bin/python
LOG=docs/logs/step27-DIAGNOSTIC-reference.txt
: > $LOG
echo "# Step-27 DIAGNOSTIC: xml-attr and ovl-path-raw against the pinned reference images, blocking, PL1" | tee -a $LOG
echo "== $(date -u +%FT%TZ), $(sw_vers -productName) $(sw_vers -productVersion) $(uname -srm), git $(git rev-parse HEAD)" | tee -a $LOG
echo "== docker client $(docker version --format '{{.Client.Version}}') server $(docker version --format '{{.Server.Version}} {{.Server.Os}}/{{.Server.Arch}}')" | tee -a $LOG
inside='
f=$(find / -name REQUEST-901-INITIALIZATION.conf -not -path "/proc/*" 2>/dev/null | head -1)
d=$(dirname "$(dirname "$f")")
echo "   rules file: $f"
echo "   version string: $(grep -m1 -o "ver:.OWASP_CRS/[0-9.]*" "$f")"
echo "   rule 901181 in it: $(grep -c "id:901181" "$f")"
echo "   lines that set tx.crs_xml_attr_inspect, outside the rules directory:"
grep -rn "crs_xml_attr_inspect" /etc /opt 2>/dev/null | grep -v "/rules/" | grep -v "^\s*#" | grep -v ":[0-9]*:\s*#" | sed "s/^/      /" | head -10
echo "   (end of list)"
'
run_one() { # <modsec|coraza>
  local eng=$1 port c up=0 i
  docker compose -f deploy/compose.yml --profile coraza down > /dev/null 2>&1 || true
  if [ $eng = modsec ]; then
    port=8081; c=deploy-baseline-crs-1
    MODSEC_RULE_ENGINE=On PARANOIA=1 BLOCKING_PARANOIA=1 DETECTION_PARANOIA=1 BACKEND=http://stub-backend:3000 \
      docker compose -f deploy/compose.yml up -d --force-recreate stub-backend baseline-crs > /dev/null 2>&1
  else
    port=8082; c=deploy-coraza-crs-1
    MODSEC_RULE_ENGINE=On PARANOIA=1 BLOCKING_PARANOIA=1 DETECTION_PARANOIA=1 CORAZA_RULE_ENGINE=On CORAZA_BACKEND=stub-backend:3000 \
      docker compose -f deploy/compose.yml --profile coraza up -d --force-recreate stub-backend coraza-crs > /dev/null 2>&1
  fi
  for i in $(seq 1 40); do curl -s -o /dev/null --max-time 3 http://localhost:$port/ && { up=1; break; }; sleep 1; done
  [ $up = 1 ] || { echo "== $eng: CONTAINER DID NOT START" | tee -a $LOG; return 1; }
  {
    echo "== $eng-DIAGNOSTIC $(date -u +%FT%TZ)"
    echo "   image: $(docker inspect --format '{{.Config.Image}} id {{.Image}}' $c)"
    docker exec $c sh -c 'echo "   env: MODSEC_RULE_ENGINE=$MODSEC_RULE_ENGINE CORAZA_RULE_ENGINE=$CORAZA_RULE_ENGINE BLOCKING_PARANOIA=$BLOCKING_PARANOIA PARANOIA=$PARANOIA DETECTION_PARANOIA=$DETECTION_PARANOIA BACKEND=$BACKEND"'
    docker exec $c sh -c "$inside"
    echo "   control (a query the image must block): GET /?control=' OR 1=1-- -> $(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://localhost:$port/?control=%27%20OR%201%3d1--")"
    echo "   control (a plain request the image must pass): GET /hello -> $(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://localhost:$port/hello")"
    $PY tools/step27_reference_probe.py $port $eng
    sleep 2
    echo "   rule ids per case, from the image's audit log (ids below 900000 and the CRS bookkeeping rules left out):"
    if [ $eng = modsec ]; then docker logs $c 2>&1; else docker exec $c cat /var/log/coraza/audit/audit.log 2>/dev/null; fi \
      | $PY tools/step27_reference_probe.py --audit-ids
  } 2>&1 | tee -a $LOG
}
run_one modsec
run_one coraza
docker compose -f deploy/compose.yml --profile coraza down > /dev/null 2>&1 || true
echo "S27-REFERENCE-DIAG-DONE" | tee -a $LOG
