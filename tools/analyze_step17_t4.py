#!/usr/bin/env python3
"""Step-17 T4 analysis: engine vs step-13 connector reference on
benign-wcp-v0 (20,000 samples, PL1/PL2), per rule 32 and rule 39.

Quantities (rule 32):
  - blocked set (outcome waf_block)
  - worst-case set = blocked + waf_deny_status + inconsistent + error
Policy-clear subset (docs/decisions/0002, via tools/policy_clear.py) split
body-less / body-bearing; differing policy-clear ids listed with both
sides' status and rule ids and a rule-39 class.

Engine decision counts (overload/timeout/limit) come from the engine events
file; errors and budget overruns from the runner summary + events.

Usage: .venv/bin/python tools/analyze_step17_t4.py
"""
import collections
import json
import subprocess
import sys

ENGINE_PREFIX = "out/s17-t4-engine-benign-wcp-v0-pl"
REF_PREFIX = "out/coraza-benign-wcp-v0-pl"
REF_SUFFIX = "-default"
MANIFEST = "data/benign-wcp-v0/manifest.jsonl"


def load(path):
    rows = {}
    for line in open(path):
        r = json.loads(line)
        rows[r["id"]] = r
    return rows


def policy_clear():
    out = subprocess.run(
        [sys.executable, "tools/policy_clear.py", MANIFEST],
        capture_output=True, text=True, check=True)
    ids = {}
    for line in out.stdout.splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        ids[r["id"]] = bool(r["has_body"])
    return ids


def main():
    clear = policy_clear()
    print(f"policy-clear samples: {len(clear)} "
          f"(body-less {sum(1 for v in clear.values() if not v)}, "
          f"body-bearing {sum(1 for v in clear.values() if v)})")
    for pl in (1, 2):
        eng = load(f"{ENGINE_PREFIX}{pl}/outcomes.jsonl")
        ref = load(f"{REF_PREFIX}{pl}{REF_SUFFIX}/outcomes.jsonl")
        eb = {i for i, r in eng.items() if r["outcome"] == "waf_block"}
        rb = {i for i, r in ref.items() if r["outcome"] == "waf_block"}
        ew = {i for i, r in eng.items()
              if r["outcome"] in ("waf_block", "waf_deny_status",
                                  "inconsistent", "error")}
        rw = {i for i, r in ref.items()
              if r["outcome"] in ("waf_block", "waf_deny_status",
                                  "inconsistent", "error")}
        print(f"\n== PL{pl}: engine n={len(eng)} ref n={len(ref)}")
        print(f"   blocked set: engine {len(eb)}  ref {len(rb)}  "
              f"engine-only {len(eb - rb)}  ref-only {len(rb - eb)}")
        print(f"   worst-case set: engine {len(ew)}  ref {len(rw)}  "
              f"engine-only {len(ew - rw)}  ref-only {len(rw - ew)}")
        ec = collections.Counter(r["outcome"] for r in eng.values())
        rc = collections.Counter(r["outcome"] for r in ref.values())
        print(f"   engine outcomes: {dict(ec)}")
        print(f"   ref outcomes:    {dict(rc)}")
        # policy-clear subset
        for label, want in (("body-less", False), ("body-bearing", True)):
            ids = {i for i, b in clear.items() if b == want}
            e_ids = {i for i in ids if eng[i]["outcome"] == "waf_block"}
            r_ids = {i for i in ids if ref[i]["outcome"] == "waf_block"}
            e_w = {i for i in ids if eng[i]["outcome"] in
                   ("waf_block", "waf_deny_status", "inconsistent", "error")}
            r_w = {i for i in ids if ref[i]["outcome"] in
                   ("waf_block", "waf_deny_status", "inconsistent", "error")}
            print(f"   policy-clear {label}: n={len(ids)}  "
                  f"blocked eng {len(e_ids)} ref {len(r_ids)}  "
                  f"worst-case eng {len(e_w)} ref {len(r_w)}  "
                  f"diff {len(e_w ^ r_w)}")
            for i in sorted(e_w ^ r_w):
                er, rr = eng[i], ref[i]
                print(f"     DIFF {i}: engine {er['outcome']} "
                      f"status={er.get('status')} rules={er['rule_ids']} | "
                      f"ref {rr['outcome']} status={rr.get('status')} "
                      f"rules={rr['rule_ids']}")
        # engine decisions from events
        try:
            ev = [json.loads(l) for l in
                  open(f"{ENGINE_PREFIX}{pl}/kortex-events-full.jsonl")]
            dec = collections.Counter(e["decision"] for e in ev)
            print(f"   engine events: {dict(dec)}")
        except FileNotFoundError:
            print("   engine events: MISSING")


if __name__ == "__main__":
    main()
