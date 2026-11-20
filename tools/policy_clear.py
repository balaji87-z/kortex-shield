#!/usr/bin/env python3
"""Step-13 T3/T5: policy-clear subset extraction (docs/decisions/0002).

A sample is policy-clear when its method is in the default allowed methods
(901160: GET HEAD POST OPTIONS) AND it has no content type, or its content
type is allowed by the default policy: the 901162 fallback list, the 901370
application/*+json wildcard, or the 901360 AWS JSON types — matched on the
media type before ';', case-insensitively (docs/decisions/0002).

Usage: policy_clear.py MANIFEST.jsonl [MORE.jsonl ...]
Prints one JSON line per policy-clear sample: id, method, has_body.
"""
import json
import sys

ALLOWED_METHODS = {"GET", "HEAD", "POST", "OPTIONS"}
ALLOWED_TYPES = {
    "application/x-www-form-urlencoded",
    "multipart/form-data",
    "text/xml",
    "application/xml",
    "application/soap+xml",
    "application/json",
    "application/x-amz-json-1.0",
    "application/x-amz-json-1.1",
}


def content_type_allowed(ct: str) -> bool:
    media = ct.split(";", 1)[0].strip().lower()
    if not media:
        return True  # no content type
    if media in ALLOWED_TYPES:
        return True
    if media.startswith("application/") and media.endswith("+json"):
        return True  # 901370 wildcard
    return False


def main() -> None:
    for path in sys.argv[1:]:
        with open(path) as f:
            for line in f:
                r = json.loads(line)
                ct = r.get("content_type") or ""
                if r["method"].upper() in ALLOWED_METHODS and content_type_allowed(ct):
                    print(json.dumps({
                        "id": r["id"],
                        "method": r["method"].upper(),
                        "has_body": bool(r.get("body")),
                    }))


if __name__ == "__main__":
    main()
