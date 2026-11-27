#!/usr/bin/env python3
"""Step-21 T3: per-sample decision diff between two engine runs of the same
dataset (in-process vs worker mode). Parity bar: zero status diffs.

Usage: step21_engine_diff.py <run_a> <run_b>
Reads responses.jsonl in each dir (and outcomes.jsonl when BOTH dirs have
one). Every sample id seen in either run is compared; none is dropped.

Quantities reported (rule 32):
  - status per sample id
  - worst-case set per run: error + blocked + deny_status + inconsistent
      error         the sample has no status in that run: its row has
                    status null/absent (request failed or was never sent),
                    or the run has no row for the id at all
      blocked       responses.jsonl "blocked" (the block discriminator)
      deny_status   outcomes.jsonl outcome waf_deny_status
      inconsistent  outcomes.jsonl outcome inconsistent
    deny_status and inconsistent need audit evidence; without outcomes.jsonl
    in both dirs they are printed as NOT MEASURED (rule 52) and the set
    holds error + blocked only.
"""
from __future__ import annotations

import collections
import json
import os
import sys

WORST_CASE_CLASSES = ("error", "blocked", "deny_status", "inconsistent")
_OUTCOME_CLASS = {"waf_deny_status": "deny_status", "inconsistent": "inconsistent"}


def load(run: str, name: str = "responses.jsonl") -> dict[str, dict]:
    with open(f"{run}/{name}", encoding="utf-8") as fh:
        return {r["id"]: r for r in map(json.loads, filter(str.strip, fh))}


def load_outcomes(run: str) -> dict[str, dict] | None:
    if not os.path.exists(f"{run}/outcomes.jsonl"):
        return None
    return load(run, "outcomes.jsonl")


def status_of(row: dict | None):
    """The sample's status in one run, or None when it has none."""
    return None if row is None else row.get("status")


def sample_class(row: dict | None, outcome: dict | None = None) -> str | None:
    """Worst-case class of one sample in one run, or None when it is not in
    the worst-case set. A sample with no status is an error whatever else its
    row says."""
    if status_of(row) is None:
        return "error"
    if row.get("blocked"):
        return "blocked"
    if outcome is not None:
        return _OUTCOME_CLASS.get(outcome.get("outcome"))
    return None


def compare(a: dict[str, dict], b: dict[str, dict],
            a_out: dict[str, dict] | None = None,
            b_out: dict[str, dict] | None = None) -> dict:
    """Compare two runs over the union of their sample ids."""
    ids = sorted(set(a) | set(b))
    have_outcomes = a_out is not None and b_out is not None
    classes_a, classes_b = {}, {}
    for i in ids:
        ca = sample_class(a.get(i), a_out.get(i) if have_outcomes else None)
        cb = sample_class(b.get(i), b_out.get(i) if have_outcomes else None)
        if ca:
            classes_a[i] = ca
        if cb:
            classes_b[i] = cb
    return {
        "ids": ids,
        "only_a": sorted(set(a) - set(b)),
        "only_b": sorted(set(b) - set(a)),
        "have_outcomes": have_outcomes,
        "status_diffs": [(i, status_of(a.get(i)), status_of(b.get(i))) for i in ids
                         if status_of(a.get(i)) != status_of(b.get(i))],
        "no_status_a": [i for i in ids if status_of(a.get(i)) is None],
        "no_status_b": [i for i in ids if status_of(b.get(i)) is None],
        "classes_a": classes_a,
        "classes_b": classes_b,
        "worst_only_a": sorted(set(classes_a) - set(classes_b)),
        "worst_only_b": sorted(set(classes_b) - set(classes_a)),
    }


def _status_counts(rows: dict[str, dict]) -> dict:
    counts = collections.Counter(r.get("status") for r in rows.values())
    return dict(sorted(counts.items(), key=lambda kv: (kv[0] is None, kv[0])))


def _class_counts(classes: dict[str, str], have_outcomes: bool) -> str:
    counts = collections.Counter(classes.values())
    parts = []
    for name in WORST_CASE_CLASSES:
        if name in _OUTCOME_CLASS.values() and not have_outcomes:
            parts.append(f"{name}=NOT MEASURED")
        else:
            parts.append(f"{name}={counts[name]}")
    return " ".join(parts)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    a_run, b_run = argv[0], argv[1]
    a, b = load(a_run), load(b_run)
    res = compare(a, b, load_outcomes(a_run), load_outcomes(b_run))
    ids = res["ids"]
    print(f"samples compared: {len(ids)} (a={len(a)} b={len(b)} "
          f"only-a={len(res['only_a'])} only-b={len(res['only_b'])})")
    print(f"status counts a: {_status_counts(a)}")
    print(f"status counts b: {_status_counts(b)}")
    diffs = res["status_diffs"]
    print(f"status diffs: {len(diffs)}")
    for i, sa, sb in diffs:
        print(f"  {i}: a={sa} b={sb}")
    for name, key in (("a", "no_status_a"), ("b", "no_status_b")):
        print(f"no status in {name} (counted as error): {len(res[key])}")
        for i in res[key]:
            print(f"  {i}")
    if not res["have_outcomes"]:
        print("deny_status, inconsistent: NOT MEASURED (outcomes.jsonl missing in at least "
              "one run); worst-case set below = error + blocked only")
    for name, key in (("a", "classes_a"), ("b", "classes_b")):
        print(f"worst-case set {name}: {len(res[key])}/{len(ids)} "
              f"({_class_counts(res[key], res['have_outcomes'])})")
    only_a, only_b = res["worst_only_a"], res["worst_only_b"]
    print(f"worst-case set diffs: {len(only_a) + len(only_b)} "
          f"(only-a {len(only_a)} only-b {len(only_b)})")
    for i in only_a:
        print(f"  only-a {i}: a={res['classes_a'][i]} (status {status_of(a.get(i))}) "
              f"b status {status_of(b.get(i))}")
    for i in only_b:
        print(f"  only-b {i}: b={res['classes_b'][i]} (status {status_of(b.get(i))}) "
              f"a status {status_of(a.get(i))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
