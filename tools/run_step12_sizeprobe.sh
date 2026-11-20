#!/bin/bash
# Step-12 T4 (second pass): isolate the request-body SIZE limit from body
# PARSING. Four probes per engine, all with VALID bodies:
#   V1  POST application/json, valid JSON, 120,000 bytes  (< 131072)
#   V2  POST application/json, valid JSON, 200,000 bytes  (> 131072)
#   V3  POST multipart/form-data with one FILE part, 200,000 bytes total
#   V4  PUT with NO content-type, 200,000 bytes body
# Expected mechanism under test: SecRequestBodyNoFilesLimit applies to V1/V2
# on both engines; V3/V4 exercise the paths where ModSecurity passed the
# 723KB-1.5MB samples that Coraza rejected with 413 (the 11 divergent WCP
# samples). Status + rule IDs recorded per engine.
set -e
cd "$(dirname "$0")/.."

probe() {  # $1 port  $2 label  $3 kind
  .venv/bin/python - "$1" "$2" "$3" <<'PYEOF'
import io, json, sys, http.client
port, label, kind = int(sys.argv[1]), sys.argv[2], sys.argv[3]

def valid_json(n):
    # {"k":"aaa...a"} of exactly n bytes
    s = b'{"k":"'
    return s + b'a' * (n - len(s) - 2) + b'"}'

if kind == "V1":
    body, ct = valid_json(120000), "application/json"
elif kind == "V2":
    body, ct = valid_json(200000), "application/json"
elif kind == "V3":
    boundary = "----kortexprobe"
    part_head = (f"--{boundary}\r\n"
                 f'Content-Disposition: form-data; name="f"; filename="f.bin"\r\n'
                 f"Content-Type: application/octet-stream\r\n\r\n").encode()
    tail = f"\r\n--{boundary}--\r\n".encode()
    total = 200000
    filelen = total - len(part_head) - len(tail)
    body = part_head + b"B" * filelen + tail
    assert len(body) == total, len(body)
    ct = f"multipart/form-data; boundary={boundary}"
else:  # V4
    body, ct = b"P" * 200000, None

headers = {"User-Agent": "probe", "Accept-Encoding": "identity",
           "Content-Length": str(len(body))}
if ct:
    headers["Content-Type"] = ct
method = "PUT" if kind == "V4" else "POST"
c = http.client.HTTPConnection("localhost", port, timeout=30)
c.request(method, "/size-probe-" + kind, body=body, headers=headers)
r = c.getresponse(); r.read()
print(f"{label} {kind} ({method}, ct={ct or 'NONE'}, {len(body)} bytes) -> {r.status}")
PYEOF
}

run_engine() {  # $1 = modsec | coraza
  if [ "$1" = modsec ]; then
    docker compose -f deploy/compose.yml down > /dev/null 2>&1 || true
    MODSEC_RULE_ENGINE=On PARANOIA=1 BLOCKING_PARANOIA=1 DETECTION_PARANOIA=1 \
      BACKEND=http://stub-backend:3000 \
      docker compose -f deploy/compose.yml up -d --force-recreate stub-backend baseline-crs > /dev/null
    sleep 8
    docker exec deploy-baseline-crs-1 sed -i 's|SecAuditLog /dev/stdout|SecAuditLog /var/log/modsecurity/audit/audit.log|' /etc/modsecurity.d/modsecurity.conf
    docker exec deploy-baseline-crs-1 nginx -s reload
    sleep 2
    for k in V1 V2 V3 V4; do probe 8081 modsec $k; done
    docker cp deploy-baseline-crs-1:/var/log/modsecurity/audit/audit.log docs/logs/step12-sizeprobe-modsec-audit.log
    .venv/bin/python -m kortex_eval.crs_audit --logs docs/logs/step12-sizeprobe-modsec-audit.log --out docs/logs/step12-sizeprobe-modsec-audit.jsonl
  else
    docker compose -f deploy/compose.yml down > /dev/null 2>&1 || true
    MODSEC_RULE_ENGINE=On PARANOIA=1 BLOCKING_PARANOIA=1 DETECTION_PARANOIA=1 \
      CORAZA_RULE_ENGINE=On CORAZA_BACKEND=stub-backend:3000 \
      docker compose -f deploy/compose.yml --profile coraza up -d --force-recreate stub-backend coraza-crs > /dev/null
    sleep 8
    docker exec deploy-coraza-crs-1 sed -i 's/SecRequestBodyNoFilesLimit 524288/SecRequestBodyNoFilesLimit 131072/' /opt/coraza/config/coraza.conf
    docker exec deploy-coraza-crs-1 nginx -s reload
    sleep 2
    for k in V1 V2 V3 V4; do probe 8082 coraza $k; done
    docker cp deploy-coraza-crs-1:/var/log/coraza/audit/audit.log docs/logs/step12-sizeprobe-coraza-audit.log
    .venv/bin/python tools/coraza_audit.py --logs docs/logs/step12-sizeprobe-coraza-audit.log --out docs/logs/step12-sizeprobe-coraza-audit.jsonl
  fi
}
run_engine modsec
run_engine coraza
echo "== size probes done"
