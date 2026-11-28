#!/usr/bin/env python3
"""Step-24 T3: compare two runs of the strict-parsing differential, case by case.

Reads the results.jsonl of two runs of tools/step23_parsing_diff.py (same
hand-written cases) and prints, per case, what changed in the engine's
answer (status, kortex decision, forwarded or not, events) and in the
disagreement classes against each backend. Counts and case ids only: the
cases are chosen, so nothing here is a rate (rule 35).

Usage: step24_parsing_compare.py BEFORE/results.jsonl AFTER/results.jsonl
"""
import collections
import json
import sys


def load(path):
    rows = {}
    for line in open(path, encoding="utf-8"):
        if line.strip():
            r = json.loads(line)
            rows[r["id"]] = r
    return rows


def answer(eng):
    """One line for what the engine did with a case."""
    if eng.get("forwarded"):
        return "forwarded"
    reasons = sorted({e["reason"] for e in eng.get("events", []) if e.get("decision") == eng.get("decision")})
    marker = f"kortex-decision={eng['decision']}" if eng.get("decision") else "no marker"
    event = f"event {', '.join(reasons)}" if reasons else "no event"
    return f"{eng.get('status')} {marker}, {event}"


def classes(row, backend):
    return sorted(d["class"] for d in row["disagreements"][backend])


def compare(before, after):
    out = []
    ids = [i for i in before if i in after]
    only = sorted(set(before) ^ set(after))
    out.append(f"== cases in both runs: {len(ids)}; in one run only: {len(only)}" + (": " + ", ".join(only) if only else ""))
    for backend in ("python", "go"):
        changed = [i for i in ids if answer(before[i]["engine"][backend]) != answer(after[i]["engine"][backend])]
        moves = collections.Counter((answer(before[i]["engine"][backend]).split(",")[0],
                                     answer(after[i]["engine"][backend]).split(",")[0]) for i in changed)
        out.append(f"== engine in front of the {backend} backend: answer changed in {len(changed)} of {len(ids)} cases, "
                   f"unchanged in {len(ids) - len(changed)}")
        for (a, b), n in sorted(moves.items()):
            out.append(f"   {n} x  {a}  ->  {b}")
        for i in changed:
            out.append(f"   {i}: {answer(before[i]['engine'][backend])}  ->  {answer(after[i]['engine'][backend])}")
        dis = [i for i in ids if classes(before[i], backend) != classes(after[i], backend)]
        out.append(f"== disagreement classes against the {backend} backend changed in {len(dis)} of {len(ids)} cases"
                   + (": " + ", ".join(dis) if dis else ""))
    for label, rows in (("before", before), ("after", after)):
        silent = sorted(i for i in ids if not rows[i]["engine"]["python"].get("forwarded")
                        and not rows[i]["engine"]["python"].get("decision"))
        out.append(f"== {label}: refused with no kortex marker: {len(silent)}" + (": " + ", ".join(silent) if silent else ""))
    return out


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 2:
        print(__doc__)
        return 2
    print("\n".join(compare(load(argv[0]), load(argv[1]))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
