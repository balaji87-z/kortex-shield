#!/usr/bin/env python3
"""Step-23 T2: what did the patched coraza change on the wcp datasets?

Usage: step23_parity_vs_c2.py <c2-dir> <s23-dir>
       (docs/logs/runs/s22-c2-outcomes  docs/logs/runs/s23-parity)

Compares, per sample id, the in-process run of step-22 C2 (stock coraza
v3.8.1) with the in-process run of step 23 (patched coraza) of the same
dataset and paranoia level: status, outcome and rule-id set. Every
differing id is listed (rules 28, 32, 39); none is dropped. Reads ids,
statuses, outcomes and rule ids only.

A difference here is one replay against one replay. With the stock library
the rule-id set of some requests varies between replays (step-22 F1), so a
difference can come from the patch or from that variation; the tool cannot
tell which and does not claim to.
"""
import collections
import gzip
import json
import os
import sys


def read(path):
    if not os.path.exists(path):
        path += ".gz"
    op = gzip.open if path.endswith(".gz") else open
    with op(path, "rt", encoding="utf-8") as fh:
        return {r["id"]: r for r in (json.loads(l) for l in fh if l.strip())}


def compare(a, b):
    """a, b: outcomes rows by id. Returns (ids, status diffs, outcome diffs, rule-set diffs)."""
    ids = sorted(set(a) | set(b))
    status, outcome, rules = [], [], []
    for i in ids:
        ra, rb = a.get(i, {}), b.get(i, {})
        if ra.get("status") != rb.get("status"):
            status.append((i, ra.get("status"), rb.get("status")))
        if ra.get("outcome") != rb.get("outcome"):
            outcome.append((i, ra.get("outcome"), rb.get("outcome")))
        sa, sb = set(ra.get("rule_ids") or []), set(rb.get("rule_ids") or [])
        if sa != sb:
            rules.append((i, sorted(sa - sb), sorted(sb - sa)))
    return ids, status, outcome, rules


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    c2, s23 = argv
    print("\n== stock coraza (step-22 C2, in-process) against patched coraza (step 23, in-process), per sample")
    for ds in ("benign-wcp-v0", "benign-wcp-v1"):
        for pl in (1, 2):
            a = read(f"{c2}/{ds}-inprocess-pl{pl}/outcomes.jsonl")
            b = read(f"{s23}/{ds}-inprocess-pl{pl}/outcomes.jsonl")
            ids, status, outcome, rules = compare(a, b)
            only = collections.Counter()
            for _, gone, new in rules:
                only[(tuple(gone), tuple(new))] += 1
            print(f"{ds} PL{pl}: {len(ids)} ids; status diffs {len(status)}; outcome diffs {len(outcome)}; "
                  f"rule-id set diffs {len(rules)}")
            for i, sa, sb in status:
                print(f"    status {i}: stock {sa} patched {sb}")
            for i, oa, ob in outcome:
                print(f"    outcome {i}: stock {oa} patched {ob}")
            for i, gone, new in rules:
                print(f"    rules {i}: only stock {gone} only patched {new}")
            if only:
                print("    rule-id set diffs by shape: " + "; ".join(
                    f"only stock {list(g)} / only patched {list(n)} x{c}" for (g, n), c in only.most_common()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
