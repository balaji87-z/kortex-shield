#!/bin/bash
# Step-22 T1 pre-push gate (rule 51): fail on oversized staged files and on
# credential-shaped content in staged paths. Run manually or from a hook:
#   tools/prepush_scan.sh            # scan everything staged for the next commit
#   tools/prepush_scan.sh --range A..B  # scan every commit in a range (pre-push)
set -euo pipefail
MAX_BYTES=$((100 * 1024 * 1024))   # GitHub hard limit
WARN_BYTES=$((1 * 1024 * 1024))    # anything over 1 MB deserves a look

fail=0
note() { echo "prepush: $*"; }
deny() { echo "prepush: FAIL: $*" >&2; fail=1; }

scan_text() { # file -> credential-shape scan, counts only
    local f="$1"
    python3 - "$f" <<'PY'
import re, sys, gzip, io
path = sys.argv[1]
op = gzip.open if path.endswith(".gz") else open
pats = {
    "jwt": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"),
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    "mapbox_token": re.compile(r"\b(pk|sk)\.(ey|access)[A-Za-z0-9._-]{20,}"),
    "private_key_block": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "slack_token": re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    "bearer_header": re.compile(r"[Aa]uthorization['\"]?\s*[:=]\s*['\"]?Bearer\s+[A-Za-z0-9._-]{20,}"),
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
}
counts = {k: 0 for k in pats}
with op(path, "rt", errors="replace") as fh:
    for line in fh:
        for k, rx in pats.items():
            if rx.search(line):
                counts[k] += 1
hits = {k: v for k, v in counts.items() if v}
if hits:
    print("CRED_SHAPES " + path + " " + ",".join(f"{k}={v}" for k, v in sorted(hits.items())))
PY
}

mode="${1:-staged}"
if [ "$mode" = "--range" ]; then
    range="${2:?usage: prepush_scan.sh --range A..B}"
    # 1) size gate over every blob in the range
    while read -r size path; do
        if [ "$size" -gt "$MAX_BYTES" ]; then
            deny "blob over GitHub limit: $path ($size bytes)"
        elif [ "$size" -gt "$WARN_BYTES" ]; then
            note "large blob: $path ($size bytes)"
        fi
    done < <(git rev-list --objects "$range" | git cat-file --batch-check='%(objecttype) %(objectsize) %(rest)' | awk '$1=="blob"{print $2, $3}')
    # 2) credential scan over every non-binary blob text in the range
    tmpscan=$(mktemp)
    trap 'rm -f "$tmpscan"' EXIT
    while read -r sha path; do
        case "$path" in
            *.png|*.jpg|*.bin|*.zip|*.pdf) continue ;;
        esac
        git cat-file blob "$sha" > "$tmpscan"
        hits=$(scan_text "$tmpscan" || true)
        [ -n "$hits" ] && deny "${hits/CRED_SHAPES \/tmp\/*/CRED_SHAPES $path}"
    done < <(git rev-list --objects "$range" | git cat-file --batch-check='%(objecttype) %(objectname) %(rest)' | awk '$1=="blob"{print $2, $3}')
else
    # staged mode: what will go into the next commit
    while read -r path; do
        [ -f "$path" ] || continue
        size=$(stat -c%s "$path")
        if [ "$size" -gt "$MAX_BYTES" ]; then
            deny "staged file over GitHub limit: $path ($size bytes)"
        elif [ "$size" -gt "$WARN_BYTES" ]; then
            note "large staged file: $path ($size bytes)"
        fi
        case "$path" in
            *.png|*.jpg|*.bin|*.zip|*.pdf) continue ;;
        esac
        hits=$(scan_text "$path")
        [ -n "$hits" ] && deny "$hits"
    done < <(git diff --cached --name-only; git ls-files -o --exclude-standard)
fi

if [ "$fail" -ne 0 ]; then
    echo "prepush: BLOCKED (fix the findings above; counts only, values never printed)" >&2
    exit 1
fi
echo "prepush: OK"
