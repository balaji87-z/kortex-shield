#!/usr/bin/env bash
# Step-13 T4 (DIAGNOSTIC-labelled bisect; never used for baseline numbers):
# find the effective SecRequestBodyNoFilesLimit of BOTH engines at 1 KB
# resolution, PL1, stub backend, for valid JSON, urlencoded, and
# multipart-with-file bodies. Reports status + rule IDs at each threshold.
set -u
cd "$(dirname "$0")/.."
OUT=docs/logs/step13-t4-bisect.txt
: > "$OUT"

bring_up () { # $1=engine
  docker compose -f deploy/compose.yml down > /dev/null 2>&1 || true
  if [ "$1" = modsec ]; then
    MODSEC_RULE_ENGINE=On PARANOIA=1 BLOCKING_PARANOIA=1 DETECTION_PARANOIA=1 \
      BACKEND=http://stub-backend:3000 \
      docker compose -f deploy/compose.yml up -d --force-recreate stub-backend baseline-crs > /dev/null
    sleep 8
    PORT=8081
    docker exec deploy-baseline-crs-1 bash -c 'grep -n "^SecRequestBodyLimit\|^SecRequestBodyNoFilesLimit" /etc/modsecurity.d/modsecurity.conf' >> "$OUT"
  else
    CORAZA_BACKEND=stub-backend:3000 PARANOIA=1 BLOCKING_PARANOIA=1 DETECTION_PARANOIA=1 \
      CORAZA_REQ_BODY_NOFILES_LIMIT=131072 CORAZA_REQ_BODY_LIMIT=13107200 \
      docker compose -f deploy/compose.yml --profile coraza up -d --force-recreate stub-backend coraza-crs > /dev/null
    sleep 8
    for try in 1 2 3; do
      if curl -s -o /dev/null --max-time 5 http://localhost:8082/; then break; fi
      echo "coraza not answering (try $try) - recreating" >> "$OUT"
      CORAZA_BACKEND=stub-backend:3000 PARANOIA=1 BLOCKING_PARANOIA=1 DETECTION_PARANOIA=1 \
        CORAZA_REQ_BODY_NOFILES_LIMIT=131072 CORAZA_REQ_BODY_LIMIT=13107200 \
        docker compose -f deploy/compose.yml --profile coraza up -d --force-recreate coraza-crs > /dev/null
      sleep 8
    done
    PORT=8082
    docker exec deploy-coraza-crs-1 sh -c 'env | grep -E "CORAZA_REQ_BODY|CORAZA_ARGUMENTS" | sort; grep -n "NoFilesLimit\|RequestBodyLimit " /templates/coraza.conf' >> "$OUT"
  fi
  curl -s -o /dev/null --max-time 5 "http://localhost:$PORT/" || echo "container not answering" >> "$OUT"
}

probe () { # $1=port $2=kind $3=bytes  -> prints "kind bytes status rules"
  local port=$1 kind=$2 n=$3 resp rules=""
  if [ "$kind" = json ]; then
    body=$(python3 -c "print('{\"k\":\"' + 'a'*$n + '\"}')")
    ct="application/json"
  elif [ "$kind" = urlenc ]; then
    body=$(python3 -c "print('a=' + 'a'*$n)")
    ct="application/x-www-form-urlencoded"
  else # multipart with a file part
    body=$(python3 - "$n" <<'PYEOF'
import sys
n=int(sys.argv[1])
b=b"--X\r\nContent-Disposition: form-data; name=\"f\"; filename=\"f.txt\"\r\nContent-Type: text/plain\r\n\r\n" + b"a"*n + b"\r\n--X--\r\n"
import sys as s; s.stdout.buffer.write(b)
PYEOF
)
    resp=$(curl -s -o /dev/null -w "%{http_code}" -X POST -F "f=@-;filename=f.txt" "http://localhost:$port/" <<< "")
    return
  fi
  resp=$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "Content-Type: $ct" --data-binary "$body" "http://localhost:$port/")
  echo "$kind $n $resp"
}

# Simplify: use python for all three kinds so multipart works byte-exact.
send () { # $1=port $2=kind $3=n -> "status"
  .venv/bin/python - "$1" "$2" "$3" <<'PYEOF'
import http.client, sys
port, kind, n = int(sys.argv[1]), sys.argv[2], int(sys.argv[3])
if kind == "json":
    body = ('{"k":"' + "a"*n + '"}').encode(); ct = "application/json"
elif kind == "urlenc":
    body = ("a=" + "a"*n).encode(); ct = "application/x-www-form-urlencoded"
else:
    body = (b"--X\r\nContent-Disposition: form-data; name=\"f\"; filename=\"f.txt\"\r\n"
            b"Content-Type: text/plain\r\n\r\n" + b"a"*n + b"\r\n--X--\r\n")
    ct = "multipart/form-data; boundary=X"
c = http.client.HTTPConnection("localhost", port, timeout=30)
c.request("POST", "/", body=body, headers={"Content-Type": ct})
r = c.getresponse(); r.read()
print(r.status)
c.close()
PYEOF
}

for eng in modsec coraza; do
  echo "=== engine $eng $(date -u +%FT%TZ)" >> "$OUT"
  bring_up "$eng"
  if [ "$eng" = modsec ]; then PORT=8081; else PORT=8082; fi
  for kind in json urlenc multipart; do
    prev=""
    for n in 128500 128999 129000 129999 130000 130999 131000 131001 131072 131073 132000 140000; do
      st=$(send "$PORT" "$kind" "$n")
      echo "$eng $kind $n -> $st" >> "$OUT"
    done
  done
done
echo "=== bisect done $(date -u +%FT%TZ)" >> "$OUT"
cat "$OUT"
