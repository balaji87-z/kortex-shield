#!/usr/bin/env python3
"""Step-22: per-id effect of a numeric-IP Host header on the wcp PL2 runs.

The first step-22 T3 runs replayed against http://127.0.0.1:PORT, so every
request carried "Host: 127.0.0.1:PORT" (CRS 920350, +3). The clean runs
replayed the same manifests against http://localhost:PORT with the same
engine binary. This lists, per dataset, the ids whose outcome differs
between the two (the only changed input is the base URL, see each run.json)
and the rule-id sets of the differing blocks. Reads ids, outcomes and rule
ids only.

Usage: step22_numeric_host_diff.py   (paths are fixed, see RUNS)
"""
import collections
import gzip
import json
import os

RUNS = "docs/logs/runs"
PAIRS = (
    ("benign-wcp-v1", "s22-numeric-host/benign-wcp-v1-inprocess-pl2-numeric-host",
     "s22-t3-parity/benign-wcp-v1-inprocess-pl2", "s19-t4-benign-wcp-v1-post-r1-pl2"),
    ("benign-wcp-v0", "s22-numeric-host/benign-wcp-v0-inprocess-pl2-numeric-host",
     "s22-t3-parity/benign-wcp-v0-inprocess-pl2", "s18-t4-engine-benign-wcp-v0-v2-pl2"),
)


def read(run):
    path = f"{RUNS}/{run}/outcomes.jsonl"
    if not os.path.exists(path):
        path += ".gz"
    op = gzip.open if path.endswith(".gz") else open
    with op(path, "rt", encoding="utf-8") as fh:
        return {r["id"]: r for r in map(json.loads, fh)}


def blocked(rows):
    return {i for i, r in rows.items() if r["outcome"] == "waf_block"}


def main():
    for ds, numeric, clean, earlier in PAIRS:
        a, b, c = read(numeric), read(clean), read(earlier)
        base = {k: json.load(open(f"{RUNS}/{r}/run.json"))["base_url"] for k, r in
                (("numeric", numeric), ("clean", clean), ("earlier", earlier))}
        print(f"== {ds} PL2 in-process, n={len(a)}")
        print(f"   numeric-Host run  base_url={base['numeric']}  blocked={len(blocked(a))}")
        print(f"   clean run         base_url={base['clean']}  blocked={len(blocked(b))}")
        print(f"   earlier step run  base_url={base['earlier']}  blocked={len(blocked(c))} ({earlier})")
        only_num, only_clean = blocked(a) - blocked(b), blocked(b) - blocked(a)
        print(f"   blocked only with the numeric Host: {len(only_num)}; only in the clean run: {len(only_clean)}")
        sets = collections.Counter(",".join(r for r in a[i]["rule_ids"] if r != "949110") or "(no rule message)"
                                   for i in only_num)
        for rule_set, n in sets.most_common():
            print(f"      x{n}: logged rules [{rule_set}]")
        print(f"      ids: {' '.join(sorted(only_num))}")
        vs = blocked(b) ^ blocked(c)
        print(f"   clean run vs the earlier step run: {len(blocked(b) - blocked(c))} blocked only now, "
              f"{len(blocked(c) - blocked(b))} blocked only then; ids: {' '.join(sorted(vs)) or 'none'}")
        for i in sorted(vs):
            print(f"      {i}: then status={c[i]['status']} outcome={c[i]['outcome']}; "
                  f"now status={b[i]['status']} outcome={b[i]['outcome']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
