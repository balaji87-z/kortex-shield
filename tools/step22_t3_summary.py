#!/usr/bin/env python3
"""Step-22 T3: rate table, rule-18 list and rule-id parity for the parity runs.

Usage: step22_t3_summary.py <durable-dir>      (docs/logs/runs/s22-t3-parity)

Per run: outcome counts and the false-positive rate on benign-labelled wcp
traffic, best case (blocked only) and worst case (blocked + deny_status +
inconsistent + error + the engine's fail-closed 413 and 415 answers, which
are counted apart from the 403 blocks), each over all samples (rules 20, 21,
30). Per run:
rule ids present in 20% or more of the audit entries (rule 18). Per
dataset and level: sample ids whose rule-id set differs between in-process
and worker mode (rule 32). Reads ids, statuses and rule ids only.
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
        return [json.loads(l) for l in fh if l.strip()]


WORST_CASE_OUTCOMES = ("waf_block", "waf_deny_status", "inconsistent", "error",
                       "waf_fail_closed_413", "waf_fail_closed_415")


def rate_lines(ds, pl, mode, oc, n):
    """The two lines of the rate table for one run; oc is a Counter of outcomes."""
    blocked = oc["waf_block"]
    worst = sum(oc[name] for name in WORST_CASE_OUTCOMES)
    return [
        f"{ds} PL{pl} {mode}: n={n} waf_block={blocked} waf_deny_status={oc['waf_deny_status']} "
        f"inconsistent={oc['inconsistent']} error={oc['error']} "
        f"waf_fail_closed_413={oc['waf_fail_closed_413']} waf_fail_closed_415={oc['waf_fail_closed_415']} "
        f"waf_pass={oc['waf_pass']} other={n - worst - oc['waf_pass']}",
        f"    FP rate best case (errors, deny_status, inconsistent, fail-closed 413/415 not flagged) "
        f"{blocked}/{n} = {100 * blocked / n:.2f}%; "
        f"worst case (all flagged) {worst}/{n} = {100 * worst / n:.2f}%",
    ]


def main():
    base = sys.argv[1]
    print("\n== rate table (benign-labelled external traffic; every block is a potential false positive)")
    for ds in ("benign-wcp-v0", "benign-wcp-v1"):
        for pl in (1, 2):
            sets = {}
            for mode in ("inprocess", "worker"):
                run = f"{base}/{ds}-{mode}-pl{pl}"
                outc = read(f"{run}/outcomes.jsonl")
                n = len(outc)
                oc = collections.Counter(r["outcome"] for r in outc)
                print("\n".join(rate_lines(ds, pl, mode, oc, n)))
                idx = read(f"{run}/audit.index.jsonl")
                hits = collections.Counter(r for e in idx for r in set(e.get("rule_ids") or []))
                common = [(r, c) for r, c in hits.most_common() if c >= 0.2 * len(idx)]
                print(f"    rule 18: {len(idx)} audit entries; rule ids in >=20% of them: "
                      + (", ".join(f"{r}={c}" for r, c in common) or "none"))
                sets[mode] = {r["id"]: tuple(sorted(r.get("rule_ids") or [])) for r in outc}
            a, b = sets["inprocess"], sets["worker"]
            diff = sorted(i for i in set(a) | set(b) if a.get(i) != b.get(i))
            print(f"{ds} PL{pl} rule-id sets, in-process vs worker: {len(diff)} ids differ of {len(set(a) | set(b))}")
            for i in diff[:50]:
                print(f"    {i}: only in-process {sorted(set(a.get(i, ())) - set(b.get(i, ())))} "
                      f"only worker {sorted(set(b.get(i, ())) - set(a.get(i, ())))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
