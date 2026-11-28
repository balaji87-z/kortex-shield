#!/usr/bin/env python3
"""Step-22: body-less index of a parsed audit.jsonl (rule 51).

Usage: step22_audit_jsonl_index.py <audit.jsonl> <index-out>

The parsed audit.jsonl (kortex_eval.crs_audit, tools/coraza_audit.py) carries
the request URI and the matched data of each rule, which quote request
content. This keeps, per entry: sample_id, method, status, engine, the ids
of the matched rules and the inbound score. Nothing else is copied.
Prints counts only.
"""
import json
import sys


def index_row(entry):
    return {
        "sample_id": entry.get("sample_id"),
        "method": entry.get("method"),
        "status": entry.get("status"),
        "engine": entry.get("engine"),
        "rule_ids": sorted({str(r["id"]) for r in (entry.get("rules") or []) if r.get("id")}),
        "inbound_score_from_949110": entry.get("inbound_score_from_949110"),
    }


def main():
    src, dst = sys.argv[1], sys.argv[2]
    n = 0
    with open(src, encoding="utf-8", errors="surrogateescape") as fh, open(dst, "w", encoding="utf-8") as out:
        for line in fh:
            if line.strip():
                out.write(json.dumps(index_row(json.loads(line))) + "\n")
                n += 1
    print(f"{dst}: {n} entries")


if __name__ == "__main__":
    main()
