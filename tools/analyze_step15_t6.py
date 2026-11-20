#!/usr/bin/env python3
"""Step-15 T6 analysis (DIAGNOSTIC): per-sample diff of the engine skeleton
against the Coraza connector runs from steps 12-14, per dataset and PL.

Comparison quantity: the blocked set (outcome waf_block) plus the worst-case
set (waf_block + waf_deny_status + inconsistent + error), per rule 32.
Baseline dirs:
  smoke           out/coraza-smoke-pl{N}-default
  attacks-v0      out/coraza-attacks-v0-pl{N}-default
  benign-browse-v1 out/coraza-benign-browse-v1-pl{N}-default
  benign-hard-v0  out/coraza-benign-hard-v0-pl{N}-default
  attacks-ct-v0   out/t14-attacks-ct-coraza-default-pl{N}
Engine dirs: out/s15-t6-engine-{ds}-pl{N}
"""
import json
import sys

BASE = {
    "smoke": "out/coraza-smoke-pl{pl}-default/outcomes.jsonl",
    "attacks-v0": "out/coraza-attacks-v0-pl{pl}-default/outcomes.jsonl",
    "benign-browse-v1": "out/coraza-benign-browse-v1-pl{pl}-default/outcomes.jsonl",
    "benign-hard-v0": "out/coraza-benign-hard-v0-pl{pl}-default/outcomes.jsonl",
    "attacks-ct-v0": "out/t14-attacks-ct-coraza-default-pl{pl}/outcomes.jsonl",
}
WORST = {"waf_block", "waf_deny_status", "inconsistent", "error"}


def load(path):
    rows = {}
    for line in open(path):
        r = json.loads(line)
        rows[r["id"]] = r
    return rows


def sets(rows):
    blocked = {i for i, r in rows.items() if r["outcome"] == "waf_block"}
    worst = {i for i, r in rows.items() if r["outcome"] in WORST}
    return blocked, worst


def main():
    print("== step-15 T6 (DIAGNOSTIC): engine skeleton vs Coraza connector (default policy)")
    for ds, base in BASE.items():
        for pl in (1, 2):
            try:
                eng = load(f"out/s15-t6-engine-{ds}-pl{pl}/outcomes.jsonl")
                ref = load(base.format(pl=pl))
            except FileNotFoundError as e:
                print(f"{ds} pl{pl}: MISSING {e}")
                continue
            eb, ew = sets(eng)
            rb, rw = sets(ref)
            common = set(eng) & set(ref)
            only_eng = set(eng) - set(ref)
            only_ref = set(ref) - set(eng)
            print(f"\n{ds} pl{pl}: engine n={len(eng)} ref n={len(ref)} common={len(common)} "
                  f"only-engine={len(only_eng)} only-ref={len(only_ref)}")
            print(f"  blocked: engine {len(eb)} ref {len(rb)}; worst: engine {len(ew)} ref {len(rw)}")
            bd = sorted((eb & common) ^ (rb & common))
            wd = sorted((ew & common) ^ (rw & common))
            print(f"  blocked-set diff (common ids): {len(bd)}")
            print(f"  worst-case-set diff (common ids): {len(wd)}")
            for i in wd[:400]:
                er, rr = eng[i], ref[i]
                print(f"    {i} engine={er['outcome']}/{er['status']} ref={rr['outcome']}/{rr['status']}")
            if only_eng:
                print(f"  engine-only sample ids (first 20): {sorted(only_eng)[:20]}")
            if only_ref:
                print(f"  ref-only sample ids (first 20): {sorted(only_ref)[:20]}")


if __name__ == "__main__":
    main()
