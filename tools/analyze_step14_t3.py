#!/usr/bin/env python3
"""Step-14 T3 analysis: per-cell blocked counts, 920420-only vs detection,
cross-engine carrier differences, default->ct-wide detection drops.
Counts only (rule 35: this set is chosen to probe carriers, not traffic)."""
import collections
import json
import sys

FAMS = ["sqli", "xss", "path-traversal", "command-injection"]
CARRIERS = ["query", "urlencoded", "json", "multipart", "text-plain",
            "octet-stream", "unknown-ct", "no-ct"]
CELLS = ["modsec-default-pl1", "modsec-default-pl2", "modsec-ct-wide-pl1",
         "modsec-ct-wide-pl2", "coraza-default-pl1", "coraza-default-pl2",
         "coraza-ct-wide-pl1", "coraza-ct-wide-pl2"]


def split_id(sid):
    rest = sid[len("actv0-"):]
    for fam in FAMS:
        if fam in rest:
            i = rest.index(fam)
            return rest[:i - 1], rest[i:]
    raise ValueError(sid)


def load(cell):
    return {d["id"]: d for d in
            (json.loads(l) for l in open(f"out/t14-attacks-ct-{cell}/outcomes.jsonl"))}


def rules_for(cell):
    r = {}
    for line in open(f"out/t14-attacks-ct-{cell}/audit.jsonl"):
        e = json.loads(line)
        if e.get("sample_id"):
            r.setdefault(e["sample_id"], set()).update(x["id"] for x in e.get("rules", []))
    return r


def det_ids(ids):
    return ids - {"920420"} - {x for x in ids if x in ("949110",)}


def main():
    data = {c: load(c) for c in CELLS}
    rules = {c: rules_for(c) for c in CELLS}

    print("# T3 per-cell: blocked/320; per-carrier blocked")
    print(f"{'cell':26} {'blocked':>7}  " + " ".join(f"{c:>10}" for c in CARRIERS))
    for c in CELLS:
        per = collections.Counter()
        blocked = 0
        for sid, o in data[c].items():
            if o["outcome"] == "waf_block":
                blocked += 1
                per[split_id(sid)[0]] += 1
        print(f"{c:26} {blocked:>4}/320  " +
              " ".join(f"{per.get(k, 0):>10}" for k in CARRIERS))

    print()
    print("# 920420-only (policy) vs detection-rule blocks per cell")
    for c in CELLS:
        pol = det = neither = 0
        for sid, o in data[c].items():
            if o["outcome"] != "waf_block":
                continue
            ids = rules[c].get(sid, set())
            if det_ids(ids):
                det += 1
            elif "920420" in ids:
                pol += 1
            else:
                neither += 1
        print(f"{c:26} 920420-only={pol:3} detection={det:3} blocked-no-rules={neither:3}")

    print()
    print("# carriers where one engine blocked fewer (per config, per PL)")
    for pl in ["pl1", "pl2"]:
        for cfg in ["default", "ct-wide"]:
            m, cz = data[f"modsec-{cfg}-{pl}"], data[f"coraza-{cfg}-{pl}"]
            pm = collections.Counter(split_id(s)[0] for s, o in m.items() if o["outcome"] == "waf_block")
            pc = collections.Counter(split_id(s)[0] for s, o in cz.items() if o["outcome"] == "waf_block")
            diffs = [(k, pm.get(k, 0), pc.get(k, 0)) for k in CARRIERS
                     if pm.get(k, 0) != pc.get(k, 0)]
            print(f"{cfg} {pl}: " + ("; ".join(f"{k}: modsec={a} coraza={b}"
                  for k, a, b in diffs) if diffs else "none"))

    print()
    print("# carriers where DETECTION blocks drop default -> ct-wide (same engine+PL)")
    for eng in ["modsec", "coraza"]:
        for pl in ["pl1", "pl2"]:
            rd, rw = rules[f"{eng}-default-{pl}"], rules[f"{eng}-ct-wide-{pl}"]
            dd, dw = data[f"{eng}-default-{pl}"], data[f"{eng}-ct-wide-{pl}"]
            drops = collections.Counter()
            for sid in dd:
                if det_ids(rd.get(sid, set())) and not det_ids(rw.get(sid, set())):
                    drops[split_id(sid)[0]] += 1
            print(f"{eng} {pl}: " + (", ".join(f"{k}:{v}" for k, v in sorted(drops.items()))
                  if drops else "none"))

    print()
    print("# payloads detected under >=2 but not all 8 carriers (same engine+cell); and on all 8")
    for c in CELLS:
        bybase = collections.defaultdict(set)
        for sid, o in data[c].items():
            car, base = split_id(sid)
            if o["outcome"] == "waf_block" and det_ids(rules[c].get(sid, set())):
                bybase[base].add(car)
        n = sum(1 for b, cs in bybase.items() if 2 <= len(cs) < 8)
        n_all = sum(1 for b, cs in bybase.items() if len(cs) == 8)
        print(f"{c:26} partial-carrier: {n:3}   all-carrier: {n_all:3}")

    print()
    print("# per-carrier detection-block counts per cell (detail)")
    for c in CELLS:
        per = collections.Counter()
        for sid, o in data[c].items():
            if o["outcome"] == "waf_block" and det_ids(rules[c].get(sid, set())):
                per[split_id(sid)[0]] += 1
        print(f"{c:26} " + " ".join(f"{per.get(k, 0):>3}" for k in CARRIERS))


if __name__ == "__main__":
    main()
