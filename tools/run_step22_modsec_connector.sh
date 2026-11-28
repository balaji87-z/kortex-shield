#!/bin/bash
# Step-22 follow-up: the ModSecurity image vs the Coraza connector image on
# benign-wcp-v0 at PL1 and PL2 (the step-13 T5 comparison, not re-run since).
# Same stub backend, same manifest, default config, runner --workers 1, one
# fresh container and one audit capture per run (rule 13). Per run: image
# digest and platform, ruleset version read inside the container (rules 7,
# 28), effective levels (rule 29). The ModSecurity audit capture is an
# edit-and-reload change, so 20 control requests known to match a rule are
# sent before and 20 after the sample set and counted in the audit (rule 36).
# Requests go to "localhost" (numeric Host would add CRS 920350).
# Evidence: docs/logs/runs/s22-modsec-connector/<run>/ holds responses.jsonl,
# outcomes.jsonl, run.json and a body-less audit index; the raw and parsed
# audit logs quote request data and stay under gitignored out/ (rule 51).
# Usage: run_step22_modsec_connector.sh [dataset]   (default benign-wcp-v0)
set -u
cd "$(dirname "$0")/.."
. tools/step22_lib.sh
DS=${1:-benign-wcp-v0}
MAN=data/$DS/manifest.jsonl
DUR=docs/logs/runs/s22-modsec-connector
LOG=docs/logs/step22-modsec-connector.txt
# any other dataset is a script check only: nothing goes to docs/
if [ "$DS" != benign-wcp-v0 ]; then DUR=out/s22-mc-check-$DS; LOG=out/s22-mc-check-$DS.txt; fi
mkdir -p out $DUR
: > $LOG
{
  echo "# Step-22: ModSecurity image vs Coraza connector image on $DS, PL1 and PL2 (default config, stub backend)"
  echo "== host: $(uname -srm); docker client $(docker version --format '{{.Client.Version}}') server $(docker version --format '{{.Server.Version}} {{.Server.Os}}/{{.Server.Arch}} kernel {{.Server.KernelVersion}}'); load at start: $(uptime | sed 's/.*load/load/')"
  echo "== manifest $MAN sha256 $(sha256_of $MAN) ($(wc -l < $MAN | tr -d ' ') samples)"
} | tee -a $LOG

control() { # <port> <tag> : 20 requests that match 942100 (libinjection SQLi)
  local i
  for i in $(seq -w 1 20); do
    curl -s -o /dev/null --max-time 10 -A "$UA" -H "X-Kortex-Sample-Id: ctl-$2-$i" \
      "http://localhost:$1/?control=%27%20OR%201%3d1--"
  done
}

run_one() { # <engine modsec|coraza> <pl>
  local eng=$1 pl=$2 name=$1-$DS-pl$2 port c up=0 run
  run=out/s22-mc-$name
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
    echo "   image: $(docker inspect --format '{{.Config.Image}} id {{.Image}}' $c) platform $(docker image inspect --format '{{.Os}}/{{.Architecture}}' $(docker inspect --format '{{.Image}}' $c))"
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
    --label engine=$eng --label backend=stub --label paranoia=$pl --label step=22 \
    > out/s22-mc-$name.runner.log 2>&1 || echo "   runner exited non-zero for $name (sample errors)" >> $LOG
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
  for f in responses.jsonl outcomes.jsonl run.json; do
    cp $run/$f $DUR/$name/$f
    if [ "$(wc -c < $DUR/$name/$f)" -gt 5242880 ]; then gzip -9 -f $DUR/$name/$f; fi
  done
  $PY - $DUR/$name/audit.index.jsonl "$name" >> $LOG <<'PYEOF'
import json, sys, collections
rows = [json.loads(l) for l in open(sys.argv[1])]
ctl = collections.Counter()
for r in rows:
    sid = r.get("sample_id") or ""
    if sid.startswith("ctl-"):
        ctl[sid.split("-")[1]] += 1
samples = sum(1 for r in rows if (r.get("sample_id") or "").startswith("wcp-"))
print(f"   rule36 {sys.argv[2]}: control entries in the audit: pre {ctl['pre']}/20, post {ctl['post']}/20; "
      f"audit entries {len(rows)} ({samples} with a wcp sample id, {sum(1 for r in rows if not r.get('sample_id'))} without a sample id)")
PYEOF
  $PY - $run "$name" >> $LOG <<'PYEOF'
import json, sys, collections
run, name = sys.argv[1], sys.argv[2]
out = collections.Counter(json.loads(l)["outcome"] for l in open(f"{run}/outcomes.jsonl"))
st = collections.Counter(json.loads(l).get("status") for l in open(f"{run}/responses.jsonl"))
n = sum(out.values())
blocked = out["waf_block"]
worst = n - out["waf_pass"]
print(f"   result {name}: n={n} outcomes={dict(sorted(out.items()))}")
print(f"   result {name}: status counts={dict(sorted(st.items(), key=lambda kv: str(kv[0])))}")
print(f"   result {name}: blocked-only {blocked}/{n} = {blocked/n:.2%}; worst case (every outcome except waf_pass, errors flagged) {worst}/{n} = {worst/n:.2%}")
PYEOF
  echo "== $name done $(date -u +%FT%TZ) load: $(uptime | sed 's/.*load/load/')" | tee -a $LOG
}

for pl in 1 2; do
  run_one modsec $pl
  run_one coraza $pl
  echo "== per-sample diff $DS PL$pl (tools/coraza_parity_diff.py out/s22-mc-modsec-$DS-pl$pl out/s22-mc-coraza-$DS-pl$pl)" >> $LOG
  $PY tools/coraza_parity_diff.py out/s22-mc-modsec-$DS-pl$pl out/s22-mc-coraza-$DS-pl$pl >> $LOG 2>&1
done
docker compose -f deploy/compose.yml --profile coraza down > /dev/null 2>&1
echo "== load at end: $(uptime | sed 's/.*load/load/')" | tee -a $LOG
echo S22-MODSEC-CONNECTOR-DONE
