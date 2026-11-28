#!/usr/bin/env python3
"""Step-21 T3: per-sample decision diff between two engine runs of the same
dataset (in-process vs worker mode). Parity bar: zero status diffs.

Usage: step21_engine_diff.py <run_a> <run_b>
Reads responses.jsonl in each dir (and outcomes.jsonl when BOTH dirs have
one). Every sample id seen in either run is compared; none is dropped.

Quantities reported (rule 32):
  - status per sample id
  - worst-case set per run: error + blocked + deny_status + inconsistent
    + the engine's own fail-closed answers
      error         the sample has no status in that run: its row has
                    status null/absent (request failed or was never sent),
                    or the run has no row for the id at all
      blocked       responses.jsonl "blocked" (the block discriminator)
      fail_closed_413, fail_closed_415, fail_closed_400,
      fail_closed_503_timeout, fail_closed_503_overload
                    responses.jsonl status + engine_decision: the engine's
                    413 limit, 415 content-encoding, 400 framing, 503
                    timeout and 503 overload answers (the same pairs as
                    kortex_eval.outcome's waf_fail_closed_* outcomes)
      deny_status   outcomes.jsonl outcome waf_deny_status
      inconsistent  outcomes.jsonl outcome inconsistent
    deny_status and inconsistent need audit evidence; without outcomes.jsonl
    in both dirs they are printed as NOT MEASURED (rule 52) and are not in
    the set. The fail-closed classes need the runner's engine_decision
    field; when a row with a status lacks it in either run (a run recorded
    before the field existed) they are printed as NOT MEASURED and are not
    in the set of either run.
"""
from __future__ import annotations

import collections
import json
import os
import sys

_OUTCOME_CLASS = {"waf_deny_status": "deny_status", "inconsistent": "inconsistent"}
# (status, engine_decision) of the engine's own refusals; keep in step with
# kortex_eval/outcome.py
_FAIL_CLOSED_CLASS = {
    (413, "limit"): "fail_closed_413",
    (415, "content-encoding"): "fail_closed_415",
    (400, "framing"): "fail_closed_400",
    (503, "timeout"): "fail_closed_503_timeout",
    (503, "overload"): "fail_closed_503_overload",
}
WORST_CASE_CLASSES = (("error", "blocked") + tuple(_OUTCOME_CLASS.values())
                      + tuple(_FAIL_CLOSED_CLASS.values()))


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


def has_decisions(rows: dict[str, dict]) -> bool:
    """True when every row with a status carries the runner's engine_decision."""
    return all("engine_decision" in r for r in rows.values() if status_of(r) is not None)


def sample_class(row: dict | None, outcome: dict | None = None,
                 decisions: bool = False) -> str | None:
    """Worst-case class of one sample in one run, or None when it is not in
    the worst-case set. A sample with no status is an error whatever else its
    row says. `decisions` says whether engine_decision may be used."""
    if status_of(row) is None:
        return "error"
    if row.get("blocked"):
        return "blocked"
    if decisions:
        refused = _FAIL_CLOSED_CLASS.get((row.get("status"), row.get("engine_decision")))
        if refused is not None:
            return refused
    if outcome is not None:
        return _OUTCOME_CLASS.get(outcome.get("outcome"))
    return None


def compare(a: dict[str, dict], b: dict[str, dict],
            a_out: dict[str, dict] | None = None,
            b_out: dict[str, dict] | None = None) -> dict:
    """Compare two runs over the union of their sample ids."""
    ids = sorted(set(a) | set(b))
    have_outcomes = a_out is not None and b_out is not None
    have_decisions = has_decisions(a) and has_decisions(b)
    classes_a, classes_b = {}, {}
    for i in ids:
        ca = sample_class(a.get(i), a_out.get(i) if have_outcomes else None, have_decisions)
        cb = sample_class(b.get(i), b_out.get(i) if have_outcomes else None, have_decisions)
        if ca:
            classes_a[i] = ca
        if cb:
            classes_b[i] = cb
    return {
        "ids": ids,
        "only_a": sorted(set(a) - set(b)),
        "only_b": sorted(set(b) - set(a)),
        "have_outcomes": have_outcomes,
        "have_decisions": have_decisions,
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


def _class_counts(classes: dict[str, str], have_outcomes: bool, have_decisions: bool) -> str:
    counts = collections.Counter(classes.values())
    parts = []
    for name in WORST_CASE_CLASSES:
        if name in _OUTCOME_CLASS.values() and not have_outcomes:
            parts.append(f"{name}=NOT MEASURED")
        elif name in _FAIL_CLOSED_CLASS.values() and not have_decisions:
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
              "one run); not in the worst-case set below")
    if not res["have_decisions"]:
        print("fail_closed_*: NOT MEASURED (responses.jsonl without engine_decision in at least "
              "one run); not in the worst-case set below")
    for name, key in (("a", "classes_a"), ("b", "classes_b")):
        print(f"worst-case set {name}: {len(res[key])}/{len(ids)} "
              f"({_class_counts(res[key], res['have_outcomes'], res['have_decisions'])})")
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
