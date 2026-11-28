#!/bin/bash
# Step-26: runs of attacks-v1 (docs/plan-attacks-v1.md, docs/baseline-config.md
# step 26). One engine process or container and one audit capture per run
# (rule 13), runner --workers 1, effective config per run in the log (rule 29).
# Requests go to "localhost". Raw audit logs stay under out/; durable files
# per run under docs/logs/runs/s26-*/ (rule 42).
#
# Usage: [STUB_PORT=13004] run_step26_attacks_v1.sh reach|engine|diag|baseline
#   reach     BEFORE the freeze: every candidate once, engine in-process,
#             DetectionOnly, PL1 (who was judged by the rules, who was not)
#   engine    frozen manifest, blocking, PL1 and PL2, in-process and worker
#   diag      DIAGNOSTIC: the engine without the REQUEST_BODY target updates
#             (scratch build), in-process, PL1 and PL2
#   baseline  the ModSecurity and the Coraza connector image of
#             deploy/compose.yml, stub backend, PL1 and PL2 (needs docker)
set -u
cd "$(dirname "$0")/.."
. tools/step22_lib.sh
WHAT=${1:-}
DS=attacks-v1
head_lines() {
  echo "== $(date -u +%FT%TZ), $(sw_vers -productName) $(sw_vers -productVersion) $(uname -srm), $(go version), $($PY --version), load at start: $(uptime | sed 's/.*load/load/')" | tee -a $LOG
  echo "== git $(git rev-parse HEAD), tracked paths changed in the working tree: $(git status --porcelain -uno | wc -l | tr -d ' '), under engine/: $(git status --porcelain engine | wc -l | tr -d ' ')" | tee -a $LOG
}
frozen_manifest() {
  MAN=data/$DS/manifest.jsonl
  local want got
  want=$(awk '{print $1}' data/$DS/MANIFEST.sha256)
  got=$(sha256_of $MAN)
  echo "== manifest $MAN sha256 $got (frozen: $want), $(wc -l < $MAN | tr -d ' ') requests" | tee -a $LOG
  [ "$got" = "$want" ] || { echo "MANIFEST HASH MISMATCH, stopping" | tee -a $LOG; exit 1; }
}
free_stub_port() {
  if curl -s -o /dev/null --max-time 2 http://127.0.0.1:$STUB_PORT/; then
    echo "port $STUB_PORT already answers; set STUB_PORT to a free port" | tee -a $LOG; exit 1
  fi
}
# engine_run <name> <mode> <pl> <manifest> <durable dir> <outcome mode blocking|detection>
engine_run() {
  local NAME=$1 MODE=$2 PL=$3 M=$4 DUR=$5 OM=$6 PORT=8097 run=out/s26-$1
  [ "$MODE" = worker ] && PORT=8098
  rm -rf $run
  start_engine s26-$NAME $MODE $PORT $PL 2000 out/s26-$NAME.engine.log || { echo "engine did not start for $NAME" | tee -a $LOG; return 1; }
  config_proof "$NAME" $PORT $LOG
  $PY -m kortex_eval.runner --manifest $M --base-url $BASE:$PORT --out $run --timeout 15 --workers 1 \
    --block-status 403 --block-marker 'kortex-decision=block' \
    --default-user-agent "$UA" --label engine=kortex --label mode=$MODE --label paranoia=$PL --label step26=$WHAT \
    > out/s26-$NAME.runner.log 2>&1 || echo "runner nonzero for $NAME (sample errors); continuing" >> $LOG
  echo "== $NAME stats after run: $(curl -s http://127.0.0.1:$PORT/__kortex/stats)" >> $LOG
  stop_engine
  echo "== $NAME kortex_eval.crs_audit and kortex_eval.outcome ($OM) output:" >> $LOG
  if [ "$OM" = blocking ]; then
    finish_run $run $DUR/$NAME $LOG
  else
    cp $ENGINE_AUDIT $run/engine-audit-full.log 2>/dev/null || : > $run/engine-audit-full.log
    $PY -m kortex_eval.crs_audit --logs $run/engine-audit-full.log --out $run/audit.jsonl >> $LOG 2>&1 \
      || echo "crs_audit exit $? for $run (rule 13)" | tee -a $LOG
    $PY -m kortex_eval.outcome --responses $run/responses.jsonl --audit $run/audit.jsonl \
      --out $run/outcomes.jsonl --engine-mode detection >> $LOG 2>&1
    mkdir -p $DUR/$NAME
    $PY tools/step22_body_index.py $run/engine-audit-full.log $DUR/$NAME/audit.index.jsonl >> $LOG 2>&1
    cp $run/responses.jsonl $run/outcomes.jsonl $run/run.json $DUR/$NAME/
  fi
  $PY tools/step23_events_index.py "$ENGINE_EVENTS" $DUR/$NAME/events.index.jsonl | sed "s|^|== $NAME events: |" | tee -a $LOG
}

case $WHAT in
reach)
  LOG=docs/logs/step26-reach.txt; DUR=docs/logs/runs/s26-reach; mkdir -p out $DUR; : > $LOG
  echo "# Step-26: reach check of the attacks-v1 candidates (before the freeze): engine in-process, DetectionOnly, PL1" | tee -a $LOG
  head_lines
  [ -f data/$DS/MANIFEST.sha256 ] && { echo "data/$DS is frozen already; the reach check runs before the freeze" | tee -a $LOG; exit 1; }
  CAND=data/$DS/candidates.jsonl
  echo "== candidates $CAND sha256 $(sha256_of $CAND), $(wc -l < $CAND | tr -d ' ') requests" | tee -a $LOG
  free_stub_port
  build_engine $LOG || exit 1
  start_stub || exit 1
  ENGINE_RULE_MODE=DetectionOnly engine_run $DS-reach-detection-pl1 inprocess 1 $CAND $DUR detection
  stop_stub
  $PY - $DUR/$DS-reach-detection-pl1 <<'PYEOF' | tee -a $LOG
import collections, json, sys
d = sys.argv[1]
out = collections.Counter(json.loads(l)["outcome"] for l in open(f"{d}/outcomes.jsonl"))
st = collections.Counter(json.loads(l).get("status") for l in open(f"{d}/responses.jsonl"))
err = collections.Counter(json.loads(l).get("error_class") for l in open(f"{d}/responses.jsonl") if json.loads(l).get("error"))
print(f"== reach outcomes: {dict(sorted(out.items()))}; statuses {dict(sorted(st.items(), key=lambda kv: str(kv[0])))}; client errors by class {dict(err)}")
PYEOF
  ;;
engine)
  LOG=docs/logs/step26-engine.txt; DUR=docs/logs/runs/s26-engine; mkdir -p out $DUR; : > $LOG
  echo "# Step-26: attacks-v1 on the engine, blocking, PL1 and PL2, in-process and worker" | tee -a $LOG
  head_lines; frozen_manifest; free_stub_port
  echo "== coraza module of engine/: $(cd engine && go list -m github.com/corazawaf/coraza/v3)" | tee -a $LOG
  build_engine $LOG || exit 1
  start_stub || exit 1
  for PL in 1 2; do
    for MODE in inprocess worker; do engine_run $DS-$MODE-pl$PL $MODE $PL $MAN $DUR blocking; done
    echo "== diff $DS PL$PL (a=inprocess b=worker):" | tee -a $LOG
    $PY tools/step21_engine_diff.py $DUR/$DS-inprocess-pl$PL $DUR/$DS-worker-pl$PL 2>&1 | tee -a $LOG
  done
  stop_stub
  ;;
diag)
  LOG=docs/logs/step26-DIAGNOSTIC-no-body-targets.txt; DUR=docs/logs/runs/s26-engine; mkdir -p out $DUR; : > $LOG
  echo "# Step-26 DIAGNOSTIC: attacks-v1 on the engine built without the REQUEST_BODY target updates, in-process, PL1 and PL2" | tee -a $LOG
  head_lines; frozen_manifest; free_stub_port
  SCR=out/DIAGNOSTIC-engine-no-body-targets
  rm -rf $SCR && mkdir -p $SCR && (cd engine && tar cf - --exclude engine --exclude '*.log' .) | (cd $SCR && tar xf -)
  python3 - $SCR/config.go <<'PYEOF' || { echo "SCRATCH EDIT FAILED" | tee -a $LOG; exit 1; }
import sys
s = open(sys.argv[1]).read()
old = "return base + renderBodyTargetUpdates(bodyTargets), nil"
assert s.count(old) == 1, s.count(old)
open(sys.argv[1], "w").write(s.replace(old, "return base, nil"))
PYEOF
  (cd $SCR && go build -buildvcs=false -o ../kortex-engine-DIAGNOSTIC-no-body-targets .) || { echo "SCRATCH BUILD FAILED" | tee -a $LOG; exit 1; }
  ENGINE_BIN=out/kortex-engine-DIAGNOSTIC-no-body-targets
  echo "== DIAGNOSTIC scratch engine sha256 $(sha256_of $ENGINE_BIN); files that differ from engine/: $(diff -rq --exclude=engine --exclude='*.log' engine $SCR | wc -l | tr -d ' '); diff of config.go against engine/config.go:" | tee -a $LOG
  diff engine/config.go $SCR/config.go | tee -a $LOG
  start_stub || exit 1
  for PL in 1 2; do
    engine_run $DS-inprocess-pl$PL-DIAGNOSTIC-no-body-targets inprocess $PL $MAN $DUR blocking
    echo "== diff $DS PL$PL (a=engine b=DIAGNOSTIC without the REQUEST_BODY targets):" | tee -a $LOG
    $PY tools/step21_engine_diff.py $DUR/$DS-inprocess-pl$PL $DUR/$DS-inprocess-pl$PL-DIAGNOSTIC-no-body-targets 2>&1 | tee -a $LOG
  done
  stop_stub
  ;;
baseline)
  LOG=docs/logs/step26-baseline.txt; DUR=docs/logs/runs/s26-baseline; mkdir -p out $DUR; : > $LOG
  echo "# Step-26: attacks-v1 on the ModSecurity image and the Coraza connector image, PL1 and PL2 (default config, stub backend)" | tee -a $LOG
  head_lines; frozen_manifest
  echo "== docker client $(docker version --format '{{.Client.Version}}') server $(docker version --format '{{.Server.Version}} {{.Server.Os}}/{{.Server.Arch}} kernel {{.Server.KernelVersion}}')" | tee -a $LOG
  control() { # <port> <tag> : 20 requests that match 942100 (libinjection SQLi)
    local i
    for i in $(seq -w 1 20); do
      curl -s -o /dev/null --max-time 10 -A "$UA" -H "X-Kortex-Sample-Id: ctl-$2-$i" \
        "http://localhost:$1/?control=%27%20OR%201%3d1--"
    done
  }
  run_one() { # <engine modsec|coraza> <pl>
    local eng=$1 pl=$2 name=$DS-$1-pl$2 port c up=0 run try i
    run=out/s26-$name
    rm -rf $run
    docker compose -f deploy/compose.yml --profile coraza down > /dev/null 2>&1 || true
    if [ $eng = modsec ]; then port=8081; c=deploy-baseline-crs-1; else port=8082; c=deploy-coraza-crs-1; fi
    for try in 1 2 3; do
      if [ $eng = modsec ]; then
        MODSEC_RULE_ENGINE=On PARANOIA=$pl BLOCKING_PARANOIA=$pl DETECTION_PARANOIA=$pl BACKEND=http://stub-backend:3000 \
          docker compose -f deploy/compose.yml up -d --force-recreate stub-backend baseline-crs > /dev/null 2>&1
      else
        MODSEC_RULE_ENGINE=On PARANOIA=$pl BLOCKING_PARANOIA=$pl DETECTION_PARANOIA=$pl \
          CORAZA_RULE_ENGINE=On CORAZA_BACKEND=stub-backend:3000 \
          docker compose -f deploy/compose.yml --profile coraza up -d --force-recreate stub-backend coraza-crs > /dev/null 2>&1
      fi
      for i in $(seq 1 30); do curl -s -o /dev/null --max-time 3 http://localhost:$port/ && { up=1; break; }; sleep 1; done
      [ $up = 1 ] && break
      echo "$eng not answering (try $try)" >> $LOG
    done
    [ $up = 1 ] || { echo "== $name: CONTAINER DID NOT START, run skipped" | tee -a $LOG; return 1; }
    {
      echo "== $name rule29/28 $(date -u +%FT%TZ) load: $(uptime | sed 's/.*load/load/')"
      echo "   image: $(docker inspect --format '{{.Config.Image}} id {{.Image}}' $c) platform $(docker image inspect --format '{{.Os}}/{{.Architecture}}' $(docker inspect --format '{{.Image}}' $c)) repo digests $(docker image inspect --format '{{join .RepoDigests " "}}' $(docker inspect --format '{{.Image}}' $c))"
      if [ $eng = modsec ]; then
        docker exec $c bash -c 'echo "   env: E=$MODSEC_RULE_ENGINE B=$BLOCKING_PARANOIA P=$PARANOIA D=$DETECTION_PARANOIA BACKEND=$BACKEND CT=[$ALLOWED_REQUEST_CONTENT_TYPE] M=[$ALLOWED_METHODS]"; echo "   conf: $(grep -E "^SecRuleEngine" /etc/modsecurity.d/modsecurity.conf) $(grep -E "^SecRequestBodyLimit |^SecRequestBodyNoFilesLimit " /etc/modsecurity.d/modsecurity.conf | tr "\n" " ")"; echo "   crs-setup: $(grep -A7 "id:900000" /etc/modsecurity.d/owasp-crs/crs-setup.conf | grep -o "tx.blocking_paranoia_level=[0-9]*") $(grep -A7 "id:900001" /etc/modsecurity.d/owasp-crs/crs-setup.conf | grep -o "tx.detection_paranoia_level=[0-9]*") $(grep -o "tx.crs_setup_version=[0-9]*" /etc/modsecurity.d/owasp-crs/crs-setup.conf)"; echo "   ruleset: $(grep -m1 -o "ver:.OWASP_CRS/[0-9.]*" /etc/modsecurity.d/owasp-crs/rules/REQUEST-901-INITIALIZATION.conf) in /etc/modsecurity.d/owasp-crs/rules ($(ls /etc/modsecurity.d/owasp-crs/rules/*.conf | wc -l) .conf files)"'
        # capture-only change (docs/baseline-config.md, step-09 and step-13): audit to a file, then wait for it
        docker exec $c sed -i 's|SecAuditLog /dev/stdout|SecAuditLog /var/log/modsecurity/audit/audit.log|' /etc/modsecurity.d/modsecurity.conf
        docker exec $c nginx -s reload
        local ok=0
        for i in $(seq 1 15); do
          sleep 1
          curl -s -o /dev/null "http://localhost:$port/?audit-warmup-blocked=%27%20OR%201%3d1--"
          docker exec $c sh -c '[ -s /var/log/modsecurity/audit/audit.log ]' && { ok=1; break; }
        done
        [ $ok = 1 ] || { echo "== $name: AUDIT CAPTURE FAILED (file empty after 15 warm-up probes), run skipped"; return 1; }
        sleep 3   # old nginx workers (stdout audit) drain
      else
        docker exec $c sh -c 'echo "   env: E=$CORAZA_RULE_ENGINE B=$BLOCKING_PARANOIA P=$PARANOIA D=$DETECTION_PARANOIA CT=[$ALLOWED_REQUEST_CONTENT_TYPE] body=[nofiles=$CORAZA_REQ_BODY_NOFILES_LIMIT total=$CORAZA_REQ_BODY_LIMIT]"; echo "   crs-setup: $(grep -A8 "id:900000" /opt/coraza/config/crs-setup.conf | grep -o "tx.blocking_paranoia_level=[0-9]*") $(grep -A8 "id:900001" /opt/coraza/config/crs-setup.conf | grep -o "tx.detection_paranoia_level=[0-9]*") $(grep -o "tx.crs_setup_version=[0-9]*" /opt/coraza/config/crs-setup.conf)"; echo "   ruleset: $(grep -m1 -o "ver:.OWASP_CRS/[0-9.]*" /opt/coraza/owasp-crs/rules/REQUEST-901-INITIALIZATION.conf) in /opt/coraza/owasp-crs/rules ($(ls /opt/coraza/owasp-crs/rules/*.conf | wc -l) .conf files)"'
      fi
    } >> $LOG 2>&1
    control $port pre
    $PY -m kortex_eval.runner --manifest $MAN --base-url http://localhost:$port \
      --out $run --timeout 15 --workers 1 --default-user-agent "$UA" \
      --label engine=$eng --label backend=stub --label paranoia=$pl --label step=26 \
      > out/s26-$name.runner.log 2>&1 || echo "   runner exited non-zero for $name (sample errors)" >> $LOG
    control $port post
    sleep 2
    if [ $eng = modsec ]; then
      docker cp $c:/var/log/modsecurity/audit/audit.log $run/raw-audit.log >> $LOG 2>&1
      $PY -m kortex_eval.crs_audit --logs $run/raw-audit.log --out $run/audit.jsonl >> $LOG 2>&1 || echo "   crs_audit exit $? for $name (rule 13)" | tee -a $LOG
    else
      docker cp $c:/var/log/coraza/audit/audit.log $run/raw-audit.log >> $LOG 2>&1
      $PY tools/coraza_audit.py --logs $run/raw-audit.log --out $run/audit.jsonl >> $LOG 2>&1 || echo "   coraza_audit exit $? for $name (rule 13)" | tee -a $LOG
    fi
    $PY -m kortex_eval.outcome --responses $run/responses.jsonl --audit $run/audit.jsonl \
      --out $run/outcomes.jsonl --engine-mode blocking >> $LOG 2>&1
    mkdir -p $DUR/$name
    $PY tools/step22_audit_jsonl_index.py $run/audit.jsonl $DUR/$name/audit.index.jsonl >> $LOG 2>&1
    cp $run/responses.jsonl $run/outcomes.jsonl $run/run.json $DUR/$name/
    $PY - $DUR/$name/audit.index.jsonl "$name" >> $LOG <<'PYEOF'
import json, sys, collections
rows = [json.loads(l) for l in open(sys.argv[1])]
ctl = collections.Counter()
for r in rows:
    sid = r.get("sample_id") or ""
    if sid.startswith("ctl-"):
        ctl[sid.split("-")[1]] += 1
samples = sum(1 for r in rows if (r.get("sample_id") or "").startswith("v1-"))
print(f"   rule36 {sys.argv[2]}: control entries in the audit: pre {ctl['pre']}/20, post {ctl['post']}/20; "
      f"audit entries {len(rows)} ({samples} with a v1 sample id, {sum(1 for r in rows if not r.get('sample_id'))} without a sample id)")
PYEOF
    $PY - $run "$name" >> $LOG <<'PYEOF'
import json, sys, collections
run, name = sys.argv[1], sys.argv[2]
out = collections.Counter(json.loads(l)["outcome"] for l in open(f"{run}/outcomes.jsonl"))
st = collections.Counter(json.loads(l).get("status") for l in open(f"{run}/responses.jsonl"))
n = sum(out.values())
print(f"   result {name}: n={n} outcomes={dict(sorted(out.items()))}")
print(f"   result {name}: status counts={dict(sorted(st.items(), key=lambda kv: str(kv[0])))}")
PYEOF
    echo "== $name done $(date -u +%FT%TZ) load: $(uptime | sed 's/.*load/load/')" | tee -a $LOG
  }
  for pl in 1 2; do
    run_one modsec $pl
    run_one coraza $pl
  done
  docker compose -f deploy/compose.yml --profile coraza down > /dev/null 2>&1
  ;;
*) echo "usage: run_step26_attacks_v1.sh reach|engine|diag|baseline"; exit 2 ;;
esac
echo "== load at end: $(uptime | sed 's/.*load/load/')" | tee -a $LOG
echo "S26-$WHAT-DONE" | tee -a $LOG
