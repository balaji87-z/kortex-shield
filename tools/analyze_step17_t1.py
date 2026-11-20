#!/usr/bin/env python3
"""Step-17 T1 replay analysis: C4 per-carrier table measured on the ENGINE.

Inputs: one or more engine outcome dirs named out/s17-t1-engine-attacks-ct-v0-pl{1,2}
(produced by tools/run_step17_t1_engine.sh). Recomputes, per paranoia level:
  - per carrier: blocked/40, and for each blocked sample whether the block has
    a detection rule or is policy-only (920420/920640 family only) — exact counts
  - payloads detected under one carrier and not another, with rule IDs
C4 criterion (decision 0002 addendum): detection blocks on a carrier do not
depend on whether its content type is on the allow-list. The engine has no
content-type allow-list (config 900220 sets the allowed list to the request's
own type), so any detection block on a raw-body carrier is evidence FOR C4.

Usage: .venv/bin/python tools/analyze_step17_t1.py
"""
import json
import sys
from collections import defaultdict

CARRIERS = ["query", "urlencoded", "json", "multipart",
            "text-plain", "octet-stream", "unknown-ct", "no-ct"]
POLICY_ONLY = {"920420", "920640", "949110"}  # 949110 = the block marker rule


def carrier_of(sample_id: str) -> str:
    # ids look like actv0-<carrier>-<payload>; carriers themselves contain
    # hyphens (text-plain, octet-stream, unknown-ct, no-ct)
    rest = sample_id[len("actv0-"):]
    for c in CARRIERS:
        if rest.startswith(c + "-"):
            return c
    return rest.split("-")[0]


def payload_of(sample_id: str) -> str:
    rest = sample_id[len("actv0-"):]
    for c in CARRIERS:
        if rest.startswith(c + "-"):
            return rest[len(c) + 1:]
    return "-".join(rest.split("-")[1:])


def main():
    out = sys.stdout
    for pl in (1, 2):
        path = f"out/s17-t1-engine-attacks-ct-v0-pl{pl}/outcomes.jsonl"
        try:
            rows = [json.loads(l) for l in open(path)]
        except OSError:
            print(f"PL{pl}: MISSING {path}", file=out)
            continue
        by_carrier = defaultdict(dict)  # carrier -> payload -> (outcome, rules)
        for r in rows:
            by_carrier[carrier_of(r["id"])][payload_of(r["id"])] = (
                r["outcome"], r.get("rule_ids") or [])
        print(f"\n== PL{pl} per-carrier blocked/40 (engine, default config):",
              file=out)
        for c in CARRIERS:
            d = by_carrier.get(c, {})
            blocked = {p: (o, rs) for p, (o, rs) in d.items() if o == "waf_block"}
            det = {p: rs for p, (o, rs) in blocked.items()
                   if set(rs) - POLICY_ONLY}
            pol = {p for p, (o, rs) in blocked.items()
                   if not (set(rs) - POLICY_ONLY)}
            print(f"  {c:13s} engine {len(blocked)}/40 | "
                  f"detection-rule blocks: {len(det)}, "
                  f"policy-only blocks: {len(pol)}", file=out)
        # cross-carrier detection differences (engine), in the committed
        # step17-t1-c4.txt shape: payloads detected under >=1 structured
        # carrier but missed under a raw-body carrier (and the reverse gap
        # count), plus payloads detected under no structured carrier
        struct = ["query", "urlencoded", "json", "multipart"]
        raw = ["text-plain", "octet-stream", "unknown-ct"]
        detect = defaultdict(dict)  # payload -> carrier -> rules (detection only)
        outcome = defaultdict(dict)  # payload -> carrier -> outcome
        for c in CARRIERS:
            for p, (o, rs) in by_carrier.get(c, {}).items():
                outcome[p][c] = o
                if o == "waf_block" and set(rs) - POLICY_ONLY:
                    detect[p][c] = sorted(set(rs) - POLICY_ONLY)
        print("  cross-carrier detection differences (engine):", file=out)
        n_struct_detected = 0
        for p in sorted(outcome):
            sd = set(detect[p]) & set(struct)
            rd = set(detect[p]) & set(raw)
            if sd:
                n_struct_detected += 1
                if not rd:
                    s_rules = sorted(set().union(*[set(detect[p][c])
                                                   for c in sd]))
                    print(f"    {p}: detected under {sorted(sd)} "
                          f"rules {s_rules}; NOT detected under "
                          f"{sorted(set(raw) - rd)} "
                          f"(outcome {outcome[p][raw[0]]})", file=out)
        print(f"  payloads detected under >=1 structured carrier: "
              f"{n_struct_detected}", file=out)
        no_struct = [p for p in sorted(outcome)
                     if not (set(detect[p]) & set(struct))]
        print(f"  payloads detected under NO structured carrier "
              f"({len(no_struct)}): {no_struct}", file=out)
        # blocked-set equality across structured carriers
        sets = {c: {p for p, (o, rs) in by_carrier.get(c, {}).items()
                    if o == "waf_block"} for c in struct}
        print(f"  blocked-set equality across structured carriers: "
              f"{all(s == sets[struct[0]] for s in sets.values())}", file=out)


if __name__ == "__main__":
    main()
