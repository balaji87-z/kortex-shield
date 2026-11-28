#!/usr/bin/env python3
"""Step-27: the rows of a parsing-differential run that are not plain refusals.

Reads results.jsonl of tools/step27_parsing_diff.py and prints, per backend:
the count of every class, each row whose class is not
engine-refuses-backend-accepts, and for the two-request cases how many
answers came back and whether the second request was passed on. Counts and
ids only (rule 35).

Usage: step27_diff_classes.py RESULTS.jsonl [RESULTS.jsonl ...]
"""
import collections
import json
import sys


def report(path):
    rows = [json.loads(line) for line in open(path, encoding="utf-8") if line.strip()]
    out = [f"== {path}: {len(rows)} cases"]
    backends = list(rows[0]["engine"])
    for b in backends:
        counts = collections.Counter(d["class"] for r in rows for d in r["disagreements"][b])
        out.append(f"   {b}: " + (", ".join(f"{k} {v}" for k, v in sorted(counts.items())) or "no class"))
    out.append("   rows in a class other than engine-refuses-backend-accepts:")
    for r in rows:
        for b in backends:
            for d in r["disagreements"][b]:
                if d["class"] != "engine-refuses-backend-accepts":
                    out.append(f"      {r['id']} [{r['family']}] {b}: {d['class']}: {d['detail'][:140]}")
    out.append("   two requests in one write (second-request-served means more than one answer or a pass event for the second):")
    for r in rows:
        if r.get("second_id"):
            cells = ", ".join(f"{b} status {e['status']}, answers {e['answers']}, second passed on {e['second_passed']}"
                              for b, e in r["engine"].items())
            out.append(f"      {r['id']}: {cells}")
    served = sorted({r["id"] for r in rows for b in backends for d in r["disagreements"][b] if d["class"] == "second-request-served"})
    out.append(f"   second-request-served: {len(served)} cases" + (": " + ", ".join(served) if served else ""))
    return out


def main(argv):
    for path in argv[1:]:
        print("\n".join(report(path)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
