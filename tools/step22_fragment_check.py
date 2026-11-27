#!/usr/bin/env python3
"""Step-22: do rule-match messages in audit logs quote fragments of WCP
request bodies? Counts only; no matched data, URI or body is printed.

Usage: step22_fragment_check.py [<path> | <rev>:<path>] ...
With no arguments, every tracked file is checked. <rev>:<path> reads a file
from git history. .gz files are decompressed.

A message is counted for an audit record with a wcp- sample id whose matched
data names the variable it was found in ("found within VAR[:name]"). Source
of the variable, decided from the record itself:
  body      REQUEST_BODY, ARGS_POST*, FILES*, XML*; or ARGS / ARGS_NAMES whose
            argument name is NOT in the request's query string, on a request
            that carried a body (raw entry: Content-Length > 0; parsed entry:
            method POST/PUT/PATCH)
  query     ARGS / ARGS_NAMES whose argument name is in the query string
  other     any other variable (headers, URI, cookies, response)
  unknown   ARGS / ARGS_NAMES not in the query on a request without a body
The WCP bodies themselves are not consulted (they are not committed), so
"body" is an inference from the record, not a comparison.

Record formats: raw audit entries ({"transaction": ..., "messages": [...]})
and crs_audit rows ({"sample_id", "method", "uri", "rules": [{"message"}]}).
"""
import collections
import gzip
import json
import re
import subprocess
import sys
import urllib.parse

BODY_VARS = ("REQUEST_BODY", "ARGS_POST", "FILES", "XML")
FOUND = re.compile(r"found within ([A-Z_]+)(?::|\b)")
DATA = re.compile(r'\[data "(.*?)"\] \[severity', re.S)


def read(spec):
    if ":" in spec and not spec.startswith(("/", ".")) and subprocess.run(
            ["git", "cat-file", "-e", spec], capture_output=True).returncode == 0:
        data = subprocess.run(["git", "show", spec], check=True, capture_output=True).stdout
    else:
        with open(spec, "rb") as fh:
            data = fh.read()
    if spec.endswith(".gz"):
        try:
            data = gzip.decompress(data)
        except (OSError, EOFError):
            pass
    return data


def header(headers, name):
    for key, value in (headers or {}).items():
        if key.lower() == name:
            return value[0] if isinstance(value, list) and value else value
    return None


def record_view(record):
    """(sample id, uri, carried a body, matched-data strings) or None."""
    if isinstance(record.get("transaction"), dict):
        req = record["transaction"].get("request") or {}
        length = str(header(req.get("headers"), "content-length") or "")
        texts = []
        for msg in record.get("messages") or []:
            found = DATA.search(msg.get("error_message") or "")
            if found and found.group(1):
                texts.append(found.group(1))
        return (header(req.get("headers"), "x-kortex-sample-id") or "", req.get("uri") or "",
                length.isdigit() and int(length) > 0, texts)
    if "sample_id" in record and isinstance(record.get("rules"), list):
        texts = [r.get("message") or "" for r in record["rules"] if isinstance(r, dict)]
        return (record.get("sample_id") or "", record.get("uri") or "",
                record.get("method") in ("POST", "PUT", "PATCH"), texts)
    return None


def check(data):
    counts = collections.Counter()
    ids = set()
    for line in data.decode("utf-8", "replace").split("\n"):
        line = line.strip()
        if not (line.startswith("{") and line.endswith("}")):
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        view = record_view(record) if isinstance(record, dict) else None
        if view is None or not str(view[0]).lower().startswith("wcp-"):
            continue
        sid, uri, has_body, texts = view
        counts["wcp_records"] += 1
        names = {k for k, _ in urllib.parse.parse_qsl(urllib.parse.urlsplit(uri).query,
                                                      keep_blank_values=True)}
        for text in texts:
            for found in FOUND.finditer(text):
                var, rest = found.group(1), text[found.end():]
                counts["matched_data_msgs"] += 1
                if var.startswith(BODY_VARS):
                    source = "body"
                elif var in ("ARGS", "ARGS_NAMES"):
                    if any(rest.startswith(n) for n in names if n):
                        source = "query"
                    else:
                        source = "body" if has_body else "unknown"
                else:
                    source = "other"
                counts[source] += 1
                if source == "body":
                    ids.add(sid)
    counts["body_ids"] = len(ids)
    return counts


def main():
    specs = sys.argv[1:]
    if not specs:
        out = subprocess.run(["git", "ls-files", "-z"], check=True, capture_output=True).stdout
        specs = [p for p in out.decode().split("\0")
                 if p and not p.lower().endswith((".png", ".jpg", ".bin", ".zip", ".pdf", ".deb"))]
    total = collections.Counter()
    for spec in specs:
        c = check(read(spec))
        if not c["matched_data_msgs"]:
            continue
        total["files"] += 1
        total["files_with_body_fragments"] += bool(c["body"])
        print(f"{spec}\twcp_records={c['wcp_records']}\tmatched_data_msgs={c['matched_data_msgs']}"
              f"\tbody={c['body']}\tquery={c['query']}\tother={c['other']}\tunknown={c['unknown']}"
              f"\tbody_ids={c['body_ids']}")
    print(f"# {len(specs)} file(s) checked; {total['files']} have matched data on wcp records; "
          f"{total['files_with_body_fragments']} of them quote body fragments")
    return 0


if __name__ == "__main__":
    sys.exit(main())
