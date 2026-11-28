#!/usr/bin/env python3
"""Step-25: per-sample rule-id set differences between two sets of runs.

Usage: step25_ruleid_diff.py <base-a> <base-b> <run-name>...

Each run directory holds audit.index.jsonl (sample_id, rule_ids). A sample
without an audit entry has the empty set. Prints, per run, how many samples
have a different set and which ids were gained or lost, with counts, and the
sample ids (ids and rule ids only, never request data).
"""
import collections
import json
import os
import sys


def rule_sets(path):
    out = collections.defaultdict(set)
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as fh:
        for line in fh.read().split("\n"):
            if not line.strip():
                continue
            row = json.loads(line)
            out[row.get("sample_id") or ""].update(row.get("rule_ids") or [])
    return out


def main(argv):
    if len(argv) < 3:
        print(__doc__)
        return 2
    base_a, base_b, names = argv[0], argv[1], argv[2:]
    total = 0
    for name in names:
        a = rule_sets(os.path.join(base_a, name, "audit.index.jsonl"))
        b = rule_sets(os.path.join(base_b, name, "audit.index.jsonl"))
        if a is None or b is None:
            print(f"== {name}: NOT MEASURED (audit index missing in {'a' if a is None else 'b'})")
            continue
        ids = sorted(set(a) | set(b))
        differ = [s for s in ids if a.get(s, set()) != b.get(s, set())]
        gained = collections.Counter()
        lost = collections.Counter()
        for s in differ:
            gained.update(b.get(s, set()) - a.get(s, set()))
            lost.update(a.get(s, set()) - b.get(s, set()))
        total += len(differ)
        print(f"== {name}: samples with an audit entry a={len(a)} b={len(b)}; rule-id set differs for {len(differ)}; "
              f"ids gained in b: {dict(sorted(gained.items())) or 'none'}; ids lost in b: {dict(sorted(lost.items())) or 'none'}")
        for s in differ:
            print(f"   {s}: only a {sorted(a.get(s, set()) - b.get(s, set()))} | only b {sorted(b.get(s, set()) - a.get(s, set()))}")
    print(f"== total samples with a different rule-id set: {total}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
