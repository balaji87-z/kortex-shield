#!/usr/bin/env python3
"""Step-15 T3 analysis: Coraza crs-default vs crs-ct-wide on benign WCP TEST
hosts at PL1. Counts and Wilson intervals only, no interpretation (the plan
docs/plan-ct-wide-benign.md fixes the analysis before the runs)."""
import json
import math

SCORING = {"949110", "949100", "949059", "949159", "949060", "949160"}
CELLS = {
    "default": "out/s15-t3-coraza-default-pl1",
    "ct-wide": "out/s15-t3-coraza-ct-wide-pl1",
}


def wilson(x, n, z=1.96):
    if n == 0:
        return (0.0, 0.0, 0.0)
    p = x / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = z / denom * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (p, max(0.0, center - half), min(1.0, center + half))


def outcomes(cell):
    rows = {}
    for line in open(f"{cell}/outcomes.jsonl"):
        r = json.loads(line)
        rows[r["id"]] = r
    return rows


def rules_for(cell):
    r = {}
    for line in open(f"{cell}/audit.jsonl"):
        e = json.loads(line)
        if e.get("sample_id"):
            r.setdefault(e["sample_id"], set()).update(x["id"] for x in e.get("rules", []))
    return r


def det_ids(ids):
    return ids - {"920420"} - {x for x in ids if x in ("949110",)}


def main():
    print("== step-15 T3: Coraza default vs ct-wide, benign WCP TEST hosts, PL1")
    data = {}
    for name, cell in CELLS.items():
        rows = outcomes(cell)
        rules = rules_for(cell)
        n = len(rows)
        blocked = {i for i, r in rows.items() if r["outcome"] == "waf_block"}
        worst = {i for i, r in rows.items()
                 if r["outcome"] in ("waf_block", "waf_deny_status", "inconsistent", "error")}
        errors = {i for i, r in rows.items() if r["outcome"] == "error"}
        deny = {i for i, r in rows.items() if r["outcome"] == "waf_deny_status"}
        incon = {i for i, r in rows.items() if r["outcome"] == "inconsistent"}
        data[name] = (rows, rules, blocked, worst)
        for label, s in (("blocked", blocked), ("worst-case", worst)):
            p, lo, hi = wilson(len(s), n)
            print(f"{name:8s} {label:10s} {len(s):5d}/{n}  {p*100:6.2f}%  Wilson95 [{lo*100:.2f}%, {hi*100:.2f}%]")
        print(f"{name:8s} errors={len(errors)} waf_deny_status={len(deny)} inconsistent={len(incon)}")
        if errors:
            print(f"{name:8s} error ids: {sorted(errors)}")

    rows_w, rules_w, blk_w, _ = data["ct-wide"]
    rows_d, _, blk_d, _ = data["default"]
    det_only = []
    for i in sorted(blk_w - blk_d):
        ids = det_ids(rules_w.get(i, set()))
        if any(r not in SCORING for r in ids):
            det_only.append((i, sorted(ids)))
    print(f"\ndetection-rule blocks under ct-wide NOT blocked under default: {len(det_only)}")
    for i, ids in det_only:
        print(f"  {i} rules={ids}")

    diff = sorted(blk_d ^ blk_w)
    print(f"\nper-sample blocked-set diff (default vs ct-wide): symmetric difference {len(diff)}")
    for i in diff:
        rd, rw = rows_d[i], rows_w[i]
        print(f"  {i} default: {rd['outcome']} status={rd['status']} | "
              f"ct-wide: {rw['outcome']} status={rw['status']} rules={sorted(det_ids(rules_w.get(i, set())))}")


if __name__ == "__main__":
    main()
