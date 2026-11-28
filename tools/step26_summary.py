#!/usr/bin/env python3
"""Step-26: tables for the runs of attacks-v1 (docs/plan-attacks-v1.md).

Usage: step26_summary.py [--missed-out <file>] <label>=<run-dir> ...
       step26_summary.py compare <label-a>=<run-dir> <label-b>=<run-dir>

A run directory holds outcomes.jsonl (id, status, outcome, rule_ids) and a
body-less audit index. Labels, families and injection points come from
data/attacks-v1/annotations.jsonl. Prints ids, statuses, outcomes and rule
ids only.

Per run (rules 15, 20, 21, 30): requests and distinct payloads; outcome
counts; recall best case (only waf_block; the headline) and worst case
(every outcome that is not a pass), denominator all requests of the frozen
manifest, each with a 95% Wilson interval; the same per family kind (seen
families from unseen files, new families), per family and per injection
point; how many payloads are blocked at both points, one, none. Rule 18:
rule ids in 20% or more of the audit entries. A request without an outcome
row counts as an error.

The Wilson interval treats requests as independent draws. They are not (two
requests per payload, payloads from the same lists), so the request-level
interval is too narrow. The per-payload line (a payload counts when it is
blocked at both injection points) is the more honest one.
"""
import collections
import json
import math
import os
import sys

ANNOTATIONS = "data/attacks-v1/annotations.jsonl"
PASS_OUTCOMES = ("waf_pass",)


def read(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def wilson(k, n, z=1.959963984540054):
    """95% Wilson score interval for k of n."""
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    lo, hi = max(0.0, centre - half), min(1.0, centre + half)
    return (0.0 if k == 0 else lo, 1.0 if k == n else hi)


def rate(k, n):
    lo, hi = wilson(k, n)
    return f"{k}/{n} = {100 * k / n:.2f}% (95% Wilson {100 * lo:.2f} to {100 * hi:.2f})" if n else "0/0"


def run_lines(name, annotations, outcomes):
    by_id = {r["id"]: r["outcome"] for r in outcomes}
    oc = lambda a: by_id.get(a["id"], "error")
    n = len(annotations)
    counts = collections.Counter(oc(a) for a in annotations)
    out = [f"{name}: requests {n}, distinct payloads {len({(a['family'], a['payload']) for a in annotations})}; outcomes: "
           + ", ".join(f"{k} {v}" for k, v in sorted(counts.items()))]

    def both(rows):
        blocked = sum(1 for a in rows if oc(a) == "waf_block")
        flagged = sum(1 for a in rows if oc(a) not in PASS_OUTCOMES)
        return blocked, flagged, len(rows)

    b, f, _ = both(annotations)
    out.append(f"    recall best case (only waf_block) {rate(b, n)}; worst case (every outcome that is not a pass) {rate(f, n)}")
    for title, key in (("per family kind", "family_kind"), ("per family", "family"), ("per injection point", "injection_point")):
        groups = collections.OrderedDict()
        for a in annotations:
            groups.setdefault(a[key], []).append(a)
        out.append(f"    {title}:")
        for g, rows in groups.items():
            b, f, m = both(rows)
            out.append(f"      {g}: best {rate(b, m)}; worst {rate(f, m)}")
    per_payload = collections.Counter()
    for a in annotations:
        per_payload[(a["family"], a["payload"])] += oc(a) == "waf_block"
    dist = collections.Counter(per_payload.values())
    out.append(f"    payloads blocked at both injection points {dist[2]}, at one {dist[1]}, at none {dist[0]}")
    out.append(f"    per payload (blocked at both injection points): {rate(dist[2], len(per_payload))}")
    return out


def rule18(index):
    hits = collections.Counter(r for e in index for r in set(e.get("rule_ids") or []))
    common = [(r, c) for r, c in hits.most_common() if index and c >= 0.2 * len(index)]
    return (f"    rule 18: {len(index)} audit entries; rule ids in >=20% of them: "
            + (", ".join(f"{r}={c}" for r, c in common) or "none"))


def missed(annotations, outcomes):
    """({(family, injection point): count}, [(id, outcome)]) for every request that is not a waf_block."""
    by_id = {r["id"]: r["outcome"] for r in outcomes}
    table = collections.OrderedDict()
    ids = []
    for a in annotations:
        o = by_id.get(a["id"], "error")
        if o != "waf_block":
            table[(a["family"], a["injection_point"])] = table.get((a["family"], a["injection_point"]), 0) + 1
            ids.append((a["id"], o))
    return dict(table), sorted(ids)


def compare(a, b, label_a, label_b, limit=30):
    """Per-sample differences between two runs' outcomes.jsonl rows (rule 32:
    status, the worst-case set, rule-id sets)."""
    da, db = {r["id"]: r for r in a}, {r["id"]: r for r in b}
    ids = sorted(set(da) | set(db))
    get = lambda d, i, k: d[i].get(k) if i in d else None
    flag = lambda d, i: (d[i]["outcome"] not in PASS_OUTCOMES) if i in d else True
    status = [i for i in ids if get(da, i, "status") != get(db, i, "status")]
    only_a = [i for i in ids if flag(da, i) and not flag(db, i)]
    only_b = [i for i in ids if flag(db, i) and not flag(da, i)]
    # sets: an engine may list a rule id once per matched variable
    rules = [i for i in ids if set(get(da, i, "rule_ids") or []) != set(get(db, i, "rule_ids") or [])]
    out = [f"    {label_a} against {label_b}: {len(ids)} sample ids; status differs in {len(status)}; worst-case set "
           f"differs in {len(only_a) + len(only_b)} (only {label_a} {len(only_a)}, only {label_b} {len(only_b)}); "
           f"rule-id set differs in {len(rules)}"]
    gained, lost = collections.Counter(), collections.Counter()
    for i in rules:
        ra, rb = set(get(da, i, "rule_ids") or []), set(get(db, i, "rule_ids") or [])
        lost.update(ra - rb)
        gained.update(rb - ra)
    if rules:
        fmt = lambda c: ", ".join(f"{r} x{n}" for r, n in sorted(c.items())) or "none"
        out.append(f"      rule ids that make up the differences: only in {label_a}: {fmt(lost)}; only in {label_b}: {fmt(gained)}"
                   if lost else f"      rule ids that make up the differences: only in {label_b}: {fmt(gained)}")
    listed = sorted(set(status) | set(only_a) | set(only_b)) or rules
    for i in listed[:limit]:
        ra, rb = set(get(da, i, "rule_ids") or []), set(get(db, i, "rule_ids") or [])
        out.append(f"      {i}: status {get(da, i, 'status')} / {get(db, i, 'status')}; outcome {get(da, i, 'outcome')} / "
                   f"{get(db, i, 'outcome')}; rule ids only in {label_a} {sorted(ra - rb)}, only in {label_b} {sorted(rb - ra)}")
    if len(listed) > limit:
        out.append(f"      ... and {len(listed) - limit} more ids (all in the run files)")
    return out


def parse(arg):
    label, _, path = arg.partition("=")
    if not path or not os.path.isdir(path):
        raise SystemExit(f"not a run directory: {arg}")
    return label, path


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "compare":
        (la, pa), (lb, pb) = parse(argv[1]), parse(argv[2])
        print("\n".join(compare(read(f"{pa}/outcomes.jsonl"), read(f"{pb}/outcomes.jsonl"), la, lb)))
        return 0
    missed_out = None
    if argv and argv[0] == "--missed-out":
        missed_out, argv = argv[1], argv[2:]
    annotations = read(ANNOTATIONS)
    missed_lines = []
    for arg in argv:
        label, path = parse(arg)
        outcomes = read(f"{path}/outcomes.jsonl")
        print("\n".join(run_lines(label, annotations, outcomes)))
        print(rule18(read(f"{path}/audit.index.jsonl")))
        table, ids = missed(annotations, outcomes)
        print("    not blocked, by family and injection point: "
              + (", ".join(f"{f}/{p} {c}" for (f, p), c in table.items()) or "none"))
        missed_lines.append(f"== {label}: {len(ids)} requests not blocked")
        missed_lines.extend(f"{i} {o}" for i, o in ids)
    if missed_out:
        with open(missed_out, "w", encoding="utf-8") as fh:
            fh.write("\n".join(missed_lines) + "\n")
        print(f"ids of the requests not blocked, per run: {missed_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
