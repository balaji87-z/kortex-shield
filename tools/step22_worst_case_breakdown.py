#!/usr/bin/env python3
"""Step-22 close-out: account for every sample of a run's worst case by class.

Usage: step22_worst_case_breakdown.py <run-dir> [<run-dir> ...]
       (a durable run dir with outcomes.jsonl and responses.jsonl, .gz allowed)

Each sample gets exactly one class. The first four come from the outcome
that kortex_eval.outcome wrote; the engine's own refusals are read from the
response row (status + engine_decision), so they are found whatever the
kortex_eval version that classified the run called them:

    waf_block, deny_status, inconsistent, error    outcomes.jsonl
    413 limit, 415 content-encoding, 400 framing,
    503 timeout, 503 overload                      responses.jsonl
    pass 200                                       not flagged, status 200
    other                                          anything left: listed by
                                                   outcome and status, never dropped

The worst case is every sample that is not "pass 200" and not "other". The
tool also prints how many samples of each class the outcomes file itself has
as waf_pass, i.e. outside the worst case kortex_eval counted for that run.
Reads ids, statuses, outcomes and engine decisions only.
"""
import collections
import gzip
import json
import os
import sys

OUTCOME_CLASSES = {
    "waf_block": "waf_block",
    "waf_deny_status": "deny_status",
    "inconsistent": "inconsistent",
    "error": "error",
}
ENGINE_REFUSALS = {
    (413, "limit"): "413 limit",
    (415, "content-encoding"): "415 content-encoding",
    (400, "framing"): "400 framing",
    (503, "timeout"): "503 timeout",
    (503, "overload"): "503 overload",
}
WORST_CASE_CLASSES = tuple(OUTCOME_CLASSES.values()) + tuple(ENGINE_REFUSALS.values())


def read(path):
    if not os.path.exists(path):
        path += ".gz"
    op = gzip.open if path.endswith(".gz") else open
    with op(path, "rt", encoding="utf-8") as fh:
        return [json.loads(l) for l in fh if l.strip()]


def sample_class(outcome, response):
    """The class of one sample from its outcome name and its response row."""
    if outcome in OUTCOME_CLASSES:
        return OUTCOME_CLASSES[outcome]
    response = response or {}
    refusal = ENGINE_REFUSALS.get((response.get("status"), response.get("engine_decision")))
    if refusal is not None:
        return refusal
    if outcome in ("waf_pass", None) and response.get("status") == 200:
        return "pass 200"
    return f"other ({outcome}, status {response.get('status')})"


def breakdown(outcomes, responses):
    """(Counter of classes, Counter of classes the outcomes file has as waf_pass)."""
    by_id = {r["id"]: r for r in responses}
    classes, as_pass = collections.Counter(), collections.Counter()
    for row in outcomes:
        cls = sample_class(row.get("outcome"), by_id.get(row["id"]))
        classes[cls] += 1
        if row.get("outcome") == "waf_pass":
            as_pass[cls] += 1
    return classes, as_pass


def lines(name, outcomes, responses):
    classes, as_pass = breakdown(outcomes, responses)
    n = len(outcomes)
    worst = sum(classes[c] for c in WORST_CASE_CLASSES)
    other = {c: k for c, k in classes.items() if c.startswith("other")}
    outside = sum(as_pass[c] for c in WORST_CASE_CLASSES)
    out = [f"{name}: n={n} worst case {worst}/{n} = {100 * worst / n:.2f}%",
           "    " + " + ".join(f"{c} {classes[c]}" for c in WORST_CASE_CLASSES) + f" = {worst}",
           f"    not in the worst case: pass 200 {classes['pass 200']}, other {sum(other.values())}"
           + ("" if not other else " [" + ", ".join(f"{c}={k}" for c, k in sorted(other.items())) + "]"),
           f"    check: worst case + pass 200 + other = {worst + classes['pass 200'] + sum(other.values())} of {n}",
           f"    of the worst case, classified waf_pass by the outcomes file of this run: {outside}"
           + ("" if not outside else " [" + ", ".join(
               f"{c}={as_pass[c]}" for c in WORST_CASE_CLASSES if as_pass[c]) + "]")]
    return out


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    for run in argv:
        print("\n".join(lines(run, read(f"{run}/outcomes.jsonl"), read(f"{run}/responses.jsonl"))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
