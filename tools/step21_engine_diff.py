#!/usr/bin/env python3
"""Step-21 T3: per-sample decision diff between two engine runs of the same
dataset (in-process vs worker mode). Parity bar: zero status diffs.

Usage: step21_engine_diff.py <run_a> <run_b>
Reads responses.jsonl in each dir; compares status per sample id.
"""
from __future__ import annotations

import collections
import json
import sys


def load(run: str) -> dict[str, dict]:
    return {r["id"]: r for r in map(json.loads, open(f"{run}/responses.jsonl"))}


def main() -> int:
    a_run, b_run = sys.argv[1], sys.argv[2]
    a, b = load(a_run), load(b_run)
    ids = sorted(set(a) & set(b))
    diffs = [(i, a[i]["status"], b[i]["status"]) for i in ids if a[i]["status"] != b[i]["status"]]
    ca = collections.Counter(r["status"] for r in a.values())
    cb = collections.Counter(r["status"] for r in b.values())
    print(f"samples compared: {len(ids)} (a={len(a)} b={len(b)})")
    print(f"status counts a: {dict(sorted(ca.items(), key=lambda kv: (kv[0] is None, kv[0])))}")
    print(f"status counts b: {dict(sorted(cb.items(), key=lambda kv: (kv[0] is None, kv[0])))}")
    print(f"status diffs: {len(diffs)}")
    for i, sa, sb in diffs[:20]:
        print(f"  {i}: a={sa} b={sb}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
