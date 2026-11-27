#!/bin/bash
# Step-22 T1 pre-push gate (rules 25, 51). Fails on:
#   - files over the size limit
#   - files that look like request-body dumps
#   - credential-shaped or e-mail-shaped content
# Counts only; matched values and body content are never printed.
#
#   tools/prepush_scan.sh               # staged paths only: what the next commit adds or changes
#   tools/prepush_scan.sh --range A..B  # every blob reachable from the commits in a range (pre-push)
#
# Staged mode reads the content from the index, not from the working tree,
# and ignores untracked files, unstaged edits and staged deletions.
#
# Limits (bytes), overridable from the environment:
#   PREPUSH_MAX_BYTES   reject above this (default 104857600, the GitHub hard limit)
#   PREPUSH_WARN_BYTES  print a note above this (default 1048576)
#
# A file looks like a request-body dump when any of these holds:
#   name        it is non-empty and named *.body or *.har (optionally .gz)
#   json field  a JSON record in it has a non-empty body field (body,
#               request_body, raw_body, body_b64, request_body_b64, postData,
#               post_data) that is not directly under "response"
#   raw http    it starts with a POST/PUT/PATCH/DELETE request line and has
#               content after the header block
# .gz files are decompressed first. .png, .jpg, .pdf, .bin and .zip files get
# the size check only; archives are not opened.
set -euo pipefail
export PREPUSH_MAX_BYTES="${PREPUSH_MAX_BYTES:-$((100 * 1024 * 1024))}"
export PREPUSH_WARN_BYTES="${PREPUSH_WARN_BYTES:-$((1 * 1024 * 1024))}"

mode="${1:-staged}"
range=""
case "$mode" in
    staged) ;;
    --range) range="${2:?usage: prepush_scan.sh --range A..B}" ;;
    *) echo "usage: prepush_scan.sh [--range A..B]" >&2; exit 2 ;;
esac

exec python3 - "$mode" "$range" <<'PY'
import gzip
import json
import os
import re
import subprocess
import sys
import zlib

MODE, RANGE = sys.argv[1], sys.argv[2]
MAX_BYTES = int(os.environ["PREPUSH_MAX_BYTES"])
WARN_BYTES = int(os.environ["PREPUSH_WARN_BYTES"])

NO_CONTENT_SCAN = (".png", ".jpg", ".bin", ".zip", ".pdf")
BODY_NAMES = (".body", ".body.gz", ".har", ".har.gz")
BODY_KEYS = {"body", "request_body", "raw_body", "body_b64", "request_body_b64",
             "postData", "post_data"}
RAW_REQUEST = re.compile(r"\A(?:POST|PUT|PATCH|DELETE) \S+ HTTP/1\.[01]\r?\n")
HEADER_END = re.compile(r"\r?\n\r?\n")
CRED_SHAPES = {
    "jwt": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"),
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    "mapbox_token": re.compile(r"\b(pk|sk)\.(ey|access)[A-Za-z0-9._-]{20,}"),
    "private_key_block": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "slack_token": re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    "bearer_header": re.compile(r"[Aa]uthorization['\"]?\s*[:=]\s*['\"]?Bearer\s+[A-Za-z0-9._-]{20,}"),
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
}

failed = False


def note(msg):
    print(f"prepush: {msg}")


def deny(msg):
    global failed
    failed = True
    print(f"prepush: FAIL: {msg}", file=sys.stderr)


def git(*args):
    return subprocess.run(["git", *args], check=True, stdout=subprocess.PIPE).stdout


def staged_blobs():
    """(sha, path) of every path added or changed in the index against HEAD."""
    raw = git("diff", "--cached", "--raw", "-z", "--no-abbrev", "--no-renames",
              "--diff-filter=ACMT")
    parts = raw.split(b"\0")
    for meta, path in zip(parts[0::2], parts[1::2]):
        fields = meta.split()  # :oldmode newmode oldsha newsha status
        if fields[1] == b"160000":  # submodule link, no blob
            continue
        yield fields[3].decode(), os.fsdecode(path)


def range_blobs(rng):
    """(sha, path) of every object with a path reachable from the range."""
    for line in git("rev-list", "--objects", rng).splitlines():
        sha, _, path = line.partition(b" ")
        if path:
            yield sha.decode(), os.fsdecode(path)


def blob_sizes(shas):
    """sha -> size for blobs; other object types are left out."""
    if not shas:
        return {}
    out = subprocess.run(["git", "cat-file", "--batch-check"], check=True,
                         input="".join(s + "\n" for s in shas).encode(),
                         stdout=subprocess.PIPE).stdout
    sizes = {}
    for line in out.splitlines():
        sha, kind, size = line.decode().split()
        if kind == "blob":
            sizes[sha] = int(size)
    return sizes


class BlobReader:
    def __init__(self):
        self.proc = subprocess.Popen(["git", "cat-file", "--batch"],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    def read(self, sha):
        self.proc.stdin.write(sha.encode() + b"\n")
        self.proc.stdin.flush()
        size = int(self.proc.stdout.readline().split()[2])
        data = self.proc.stdout.read(size)
        self.proc.stdout.read(1)  # trailing newline
        return data

    def close(self):
        self.proc.stdin.close()
        self.proc.wait()


def text_of(path, data):
    if path.endswith(".gz"):
        try:
            data = gzip.decompress(data)
        except (OSError, EOFError, zlib.error):
            pass
    return data.decode("utf-8", "replace")


def body_keys_in(obj):
    """Names of the non-empty body fields in one JSON value."""
    found = set()
    stack = [(obj, None)]
    while stack:
        value, parent = stack.pop()
        if isinstance(value, dict):
            for key, child in value.items():
                if (key in BODY_KEYS and parent != "response"
                        and isinstance(child, (str, dict)) and child):
                    found.add(key)
                stack.append((child, key))
        elif isinstance(value, list):
            stack.extend((child, parent) for child in value)
    return found


def body_dump(path, text):
    """Why the file looks like a request-body dump, or None."""
    if path.lower().endswith(BODY_NAMES) and text:
        return "reason=name"
    records, keys = 0, set()
    parsed_any = False
    for line in text.split("\n"):  # not splitlines(): a body may hold U+2028, U+0085, ...
        line = line.strip()
        if not (line.startswith("{") and line.endswith("}")):
            continue
        try:
            found = body_keys_in(json.loads(line))
        except ValueError:
            continue
        parsed_any = True
        if found:
            records += 1
            keys |= found
    if not parsed_any and text.lstrip()[:1] in ("{", "["):
        try:  # one multi-line JSON document
            keys = body_keys_in(json.loads(text))
            records = 1 if keys else 0
        except ValueError:
            pass
    if records:
        return f"reason=json-body-field records={records} keys={','.join(sorted(keys))}"
    if RAW_REQUEST.match(text):
        end = HEADER_END.search(text)
        if end and text[end.end():].strip():
            return "reason=raw-http-request"
    return None


def cred_shapes(text):
    counts = dict.fromkeys(CRED_SHAPES, 0)
    for line in text.split("\n"):
        for name, rx in CRED_SHAPES.items():
            if rx.search(line):
                counts[name] += 1
    return ",".join(f"{k}={v}" for k, v in sorted(counts.items()) if v)


def main():
    entries = sorted(set(staged_blobs() if MODE == "staged" else range_blobs(RANGE)),
                     key=lambda e: (e[1], e[0]))
    sizes = blob_sizes(sorted({sha for sha, _ in entries}))
    entries = [e for e in entries if e[0] in sizes]
    reader = BlobReader()
    for sha, path in entries:
        size = sizes[sha]
        if size > MAX_BYTES:
            deny(f"SIZE {path} {size} bytes is over the limit of {MAX_BYTES}")
            continue
        if size > WARN_BYTES:
            note(f"large file: {path} ({size} bytes)")
        if path.lower().endswith(NO_CONTENT_SCAN):
            continue
        text = text_of(path, reader.read(sha))
        why = body_dump(path, text)
        if why:
            deny(f"BODY_DUMP {path} {why}")
        hits = cred_shapes(text)
        if hits:
            deny(f"CRED_SHAPES {path} {hits}")
    reader.close()
    what = "staged path(s)" if MODE == "staged" else f"blob(s) in {RANGE}"
    if failed:
        print(f"prepush: BLOCKED, {len(entries)} {what} scanned (fix the findings above; "
              "counts only, values never printed)", file=sys.stderr)
        return 1
    print(f"prepush: OK, {len(entries)} {what} scanned")
    return 0


sys.exit(main())
PY
