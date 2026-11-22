#!/usr/bin/env python3
"""Step-22 T1: enumerate body-bearing files and scan for credential shapes.

Counts only, never prints values (rule 51). Scans the working tree under
docs/ and data-adjacent run dirs, plus anything given on the command line.
"""
import gzip
import io
import json
import os
import re
import sys
import zipfile

PATTERNS = {
    "jwt": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"),
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    "mapbox_token": re.compile(r"\b(pk|sk)\.(ey|access)[A-Za-z0-9._-]{20,}"),
    "private_key_block": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "slack_token": re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    "bearer": re.compile(r"[Aa]uthorization['\"]?\s*[:=]\s*['\"]?Bearer\s+[A-Za-z0-9._-]{20,}"),
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "phone_intl": re.compile(r"(?<!\w)\+?\d[\d\s().-]{8,}\d(?!\w)"),
}
# phone regex is noisy; require a separator or leading + to reduce false hits
BODY_KEYS = {"body", "request_body", "postData", "content"}


def iter_text(path):
    opener = gzip.open if path.endswith(".gz") else open
    try:
        with opener(path, "rt", errors="replace") as f:
            for line in f:
                yield line
    except Exception as e:
        sys.stderr.write(f"scan skip {path}: {e}\n")


def classify(path):
    """Return (has_bodies, body_kind) by sampling content."""
    has_json_body = False
    has_audit = False
    name = os.path.basename(path)
    for line in iter_text(path):
        if has_json_body and has_audit:
            break
        if not has_json_body and ('"body"' in line or '"postData"' in line):
            has_json_body = True
        if not has_audit and '"transaction"' in line:
            has_audit = True
    if has_json_body:
        return True, "manifest-with-body-field"
    if has_audit:
        return True, "audit-headers-and-matches"
    if "responses.jsonl" in name or "events" in name or "stats" in name:
        return False, "outcomes-only"
    return False, "unknown"


def scan(path):
    counts = {k: 0 for k in PATTERNS}
    with open(path, "rb") as raw:
        pass
    for line in iter_text(path):
        for k, rx in PATTERNS.items():
            if rx.search(line):
                counts[k] += 1
    return counts


def main():
    roots = sys.argv[1:] or ["docs/logs"]
    files = []
    for root in roots:
        for dirpath, _, names in os.walk(root):
            for n in names:
                p = os.path.join(dirpath, n)
                if os.path.getsize(p) == 0:
                    continue
                if n.endswith((".bin", ".png", ".jpg")):
                    continue
                files.append(p)
    print(f"scanned {len(files)} files under {roots}")
    for p in sorted(files):
        size = os.path.getsize(p)
        has_bodies, kind = classify(p)
        c = scan(p)
        hits = {k: v for k, v in c.items() if v}
        flag = "BODIES" if has_bodies else "     "
        cred = "CREDS:" + ",".join(f"{k}={v}" for k, v in sorted(hits.items())) if hits else "clean"
        print(f"{flag} {kind:28s} {size:>10d}  {p}  {cred}")


if __name__ == "__main__":
    main()
