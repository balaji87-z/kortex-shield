#!/usr/bin/env python3
"""Step-16 T2 analysis: engine-vs-connector diff after the BUG fix, per
dataset and paranoia level, with each remaining difference classified
against the T1 class list (docs/logs/step16-t1-classes.txt).

Comparison quantity: the blocked set (outcome waf_block), per rule 32;
errors / waf_deny_status / inconsistent are reported separately (rule 30).

Usage: .venv/bin/python tools/analyze_step16_t2.py [engine-dir-prefix]
  (default engine prefix out/s16-t2-engine, ref prefix out/s16-t2-coraza)
"""
import json
import sys
import collections

ENGINE_PREFIX = sys.argv[1] if len(sys.argv) > 1 else "out/s16-t2-engine"
REF_PREFIX = "out/s16-t2-coraza"
DATASETS = ["smoke", "attacks-v0", "benign-browse-v1", "benign-hard-v0", "attacks-ct-v0"]

# T1 classification (rule 39), derived from docs/logs/step16-t1-classes.txt
# (per-cell id lists) plus the per-cell class split documented in
# docs/logs/step16-t1-summary.txt:
#   smoke                -> DESIGN-FRONT (trav-01, both PLs)
#   attacks-ct-v0        -> -json- carrier = BUG, other carriers = DESIGN-C4
#   attacks-v0           -> BUG, except command-injection-036c522d-q (PL2,
#                           UNEXPLAINED at T1 time; explained since, see report)
#   benign-browse-v1     -> ids already differing at PL1 = DESIGN-C4 (the same
#                           60 text/plain POSTs), the rest = BUG
#   benign-hard-v0       -> BUG
T1_CELL_IDS = {}
_cell = None
for line in open("docs/logs/step16-t1-classes.txt"):
    line = line.rstrip("\n")
    if line.startswith("== "):
        head, _, n = line[3:].rpartition(":")
        ds, _, pl = head.rpartition(" ")
        _cell = (ds, int(pl.replace("pl", "")))
        T1_CELL_IDS[_cell] = []
    elif _cell and line.startswith("  ") and line.strip() \
            and len(line) - len(line.lstrip(" ")) == 2:
        T1_CELL_IDS[_cell].append(line.strip())


def t1_class(sid, ds, pl):
    if ds == "smoke":
        return "DESIGN-FRONT"
    if ds == "attacks-ct-v0":
        return "BUG" if "-json-" in sid else "DESIGN-C4"
    if ds == "attacks-v0":
        if sid == "command-injection-036c522d-q" and pl == 2:
            return "UNEXPLAINED(T1)"
        return "BUG"
    if ds == "benign-browse-v1":
        pl1 = set(T1_CELL_IDS.get(("benign-browse-v1", 1), []))
        return "DESIGN-C4" if sid in pl1 else "BUG"
    if ds == "benign-hard-v0":
        return "BUG"
    return "UNKNOWN"


def load(path):
    rows = {}
    for line in open(path):
        r = json.loads(line)
        rows[r["id"]] = r
    return rows


def main():
    total_diff = 0
    remaining = collections.Counter()
    print(f"{'dataset':18s} {'pl':2s} {'eng_blk':>7s} {'ref_blk':>7s} {'diff':>4s}"
          f" {'eng-only':>8s} {'ref-only':>8s} {'err':>7s} {'deny':>7s} {'incons':>6s}")
    for ds in DATASETS:
        for pl in (1, 2):
            eng = load(f"{ENGINE_PREFIX}-{ds}-pl{pl}/outcomes.jsonl")
            ref = load(f"{REF_PREFIX}-{ds}-pl{pl}/outcomes.jsonl")
            eb = {i for i, r in eng.items() if r["outcome"] == "waf_block"}
            rb = {i for i, r in ref.items() if r["outcome"] == "waf_block"}
            eo, ro = eb - rb, rb - eb
            ee = sum(1 for r in eng.values() if r["outcome"] == "error")
            re_ = sum(1 for r in ref.values() if r["outcome"] == "error")
            ed = sum(1 for r in eng.values() if r["outcome"] == "waf_deny_status")
            rd = sum(1 for r in ref.values() if r["outcome"] == "waf_deny_status")
            inc = (sum(1 for r in eng.values() if r["outcome"] == "inconsistent")
                   + sum(1 for r in ref.values() if r["outcome"] == "inconsistent"))
            total_diff += len(eo) + len(ro)
            print(f"{ds:18s} {pl:2d} {len(eb):7d} {len(rb):7d} {len(eo)+len(ro):4d}"
                  f" {len(eo):8d} {len(ro):8d} {ee}/{re_:<5d} {ed}/{rd:<4d} {inc:6d}")
            for i in sorted(eo | ro):
                cls = t1_class(i, ds, pl)
                remaining[cls] += 1
                print(f"    diff: {i} class={cls} eng={eng[i]['outcome']}"
                      f" ref={ref[i]['outcome']} eng_rules={eng[i].get('rule_ids')}"
                      f" ref_rules={ref[i].get('rule_ids')}")
    print(f"total differing ids: {total_diff}")
    print("remaining diffs by T1 class:", dict(remaining))


if __name__ == "__main__":
    main()
