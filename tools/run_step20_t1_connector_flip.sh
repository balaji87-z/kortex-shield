#!/bin/bash
# Step-20 T1 (rule 44 discriminator): does the coraza CONNECTOR (pinned image,
# coraza v3.7.0 inside) share the duplicate-arg flip defect? Run flip_repro
# 5x500 at PL2 against the connector (port 8082). The preregistered dup-args
# shapes duplicate IDENTICAL values and cannot exercise the different-values
# cache collision; flip_repro's two samples carry same-name DIFFERENT-value
# `filter` args, which is the defect trigger.
set -u
cd "$(dirname "$0")/.."
RUNDIR=docs/logs/runs/s20-t1-flip-connector-pl2
mkdir -p "$RUNDIR"
PL=2
echo "== connector flip PL$PL $(date -u +%FT%TZ) load=[$(uptime | grep -o 'load average.*')]"
docker compose -f deploy/compose.yml down --remove-orphans >/dev/null 2>&1 || true
docker rm -f deploy-coraza-crs-1 deploy-stub-backend-1 deploy-target-1 >/dev/null 2>&1 || true
MODSEC_RULE_ENGINE=On PARANOIA=$PL BLOCKING_PARANOIA=$PL DETECTION_PARANOIA=$PL \
  CORAZA_RULE_ENGINE=On CORAZA_BACKEND=stub-backend:3000 \
  docker compose -f deploy/compose.yml --profile coraza up -d --no-deps --force-recreate stub-backend coraza-crs >"$RUNDIR/compose-up.log" 2>&1
ok=0
for i in $(seq 1 24); do sleep 5; if curl -s -o /dev/null --max-time 5 http://localhost:8082/; then ok=1; break; fi; done
[ $ok -eq 1 ] || { echo "CORAZA NOT UP (120s)" | tee "$RUNDIR/rule29.txt"; exit 1; }
{
  echo "== rule29 connector PL$PL:"
  docker exec deploy-coraza-crs-1 sh -c 'echo "E=$CORAZA_RULE_ENGINE B=$BLOCKING_PARANOIA P=$PARANOIA D=$DETECTION_PARANOIA"'
  docker exec deploy-coraza-crs-1 sh -c 'grep -o "tx.crs_setup_version=[0-9]*" /opt/coraza/config/crs-setup.conf'
  echo "== coraza library version inside the container (rule 28):"
  docker exec deploy-coraza-crs-1 sh -c 'grep -ao "github.com/corazawaf/coraza/v3@v[0-9.]*" /usr/local/lib/libcoraza.so 2>/dev/null | head -1 || strings /usr/local/lib/libcoraza.so 2>/dev/null | grep -o "coraza/v3@v[0-9.]*" | head -1'
  echo "== image digest:"
  docker inspect --format '{{.Image}}' deploy-coraza-crs-1
  docker image inspect --format '{{index .RepoDigests 0}}' ghcr.io/coreruleset/coraza-crs:4.25.2-nginx-lts 2>/dev/null
} | tee "$RUNDIR/rule29.txt"
for R in 1 2 3 4 5; do
  .venv/bin/python tools/flip_repro.py --base-url http://127.0.0.1:8082 --rounds 500 \
    --out "$RUNDIR/rounds-pl2-r$R.jsonl" 2>/dev/null | tail -1
done
echo "load_end=[$(uptime | grep -o 'load average.*')]"
docker compose -f deploy/compose.yml down --remove-orphans >/dev/null 2>&1 || true
echo "CONNECTOR-FLIP-DONE"
