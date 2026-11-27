#!/usr/bin/env python3
"""Step-22: body-less index of a body-bearing JSONL file (rule 51).

Usage: step22_body_index.py <manifest-or-audit-log> <index-out>

Writes one JSON line per input record with ids, sizes and content types
only; no body, URI, header value or matched data is copied.
  manifest row      id, content_type, body_bytes
  audit log entry   sample_id (X-Kortex-Sample-Id), content_type, body_bytes,
                    status (response status), rule_ids (ids of the rules that
                    matched, from the entry's messages)
body_bytes is the UTF-8 length of the body string as stored in the input;
input bytes that are not valid UTF-8 count as one byte each.
Prints counts only.
"""
import json
import re
import sys

RULE_ID = re.compile(r'\[id "(\d+)"\]')


def header(headers, name):
    for key, value in (headers or {}).items():
        if key.lower() == name:
            return value[0] if isinstance(value, list) and value else value
    return None


def size(body):
    body = body or ""
    try:  # bytes that were not valid UTF-8 in the input count as one byte each
        return len(body.encode("utf-8", "surrogateescape"))
    except UnicodeEncodeError:  # JSON-escaped lone surrogates
        return len(body.encode("utf-8", "surrogatepass"))


def index_row(record):
    if "transaction" in record:
        req = record["transaction"].get("request") or {}
        rule_ids = set()
        for msg in record.get("messages") or []:
            rule_ids.update(RULE_ID.findall(msg.get("error_message") or ""))
        return {
            "sample_id": header(req.get("headers"), "x-kortex-sample-id"),
            "content_type": header(req.get("headers"), "content-type"),
            "body_bytes": size(req.get("body")),
            "status": (record["transaction"].get("response") or {}).get("status"),
            "rule_ids": sorted(rule_ids),
        }
    return {
        "id": record.get("id"),
        "content_type": record.get("content_type"),
        "body_bytes": size(record.get("body")),
    }


def main():
    src, dst = sys.argv[1], sys.argv[2]
    rows = []
    with open(src, encoding="utf-8", errors="surrogateescape") as fh:
        for line in fh.read().split("\n"):
            if line.strip():
                rows.append(index_row(json.loads(line)))
    with open(dst, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")
    with_body = sum(1 for r in rows if r["body_bytes"])
    print(f"{dst}: {len(rows)} records, {with_body} with a body, "
          f"{sum(r['body_bytes'] for r in rows)} body bytes in the source")
    return 0


if __name__ == "__main__":
    sys.exit(main())
