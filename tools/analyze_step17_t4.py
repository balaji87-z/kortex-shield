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


def load_ref(pl):
    path = f"{REF_PREFIX}{pl}{REF_SUFFIX}/outcomes.jsonl"
    try:
        return load(path), path
    except OSError:
        return None, path


def main():
    clear = policy_clear()
    print(f"policy-clear samples: {len(clear)} "
          f"(body-less {sum(1 for v in clear.values() if not v)}, "
          f"body-bearing {sum(1 for v in clear.values() if v)})")
    for pl in (1, 2):
        eng = load(f"{ENGINE_PREFIX}{pl}/outcomes.jsonl")
        ref, ref_path = load_ref(pl)
        BAD = ("waf_block", "waf_deny_status", "inconsistent", "error")
        eb = {i for i, r in eng.items() if r["outcome"] == "waf_block"}
        ew = {i for i, r in eng.items() if r["outcome"] in BAD}
        print(f"\n== PL{pl}: engine n={len(eng)}")
        print(f"   engine blocked set: {len(eb)}  "
              f"worst-case set (block+deny_status+inconsistent+error): {len(ew)}")
        ec = collections.Counter(r["outcome"] for r in eng.values())
        print(f"   engine outcomes: {dict(ec)}")
        if ref is None:
            print(f"   REFERENCE MISSING: {ref_path} not on this host (the "
                  f"step-13 connector runs live in gitignored out/ on the lab "
                  f"host; docker is unavailable here, so they cannot be "
                  f"reproduced). Per-id rule-32 comparison and rule-39 "
                  f"classes are NOT COMPUTED. Aggregate comparison against "
                  f"the committed step-13 numbers (docs/logs/step13-t5-parity.txt) "
                  f"is done in the step-17 report.")
        else:
            rb = {i for i, r in ref.items() if r["outcome"] == "waf_block"}
            rw = {i for i, r in ref.items()
                  if r["outcome"] in ("waf_block", "waf_deny_status",
                                      "inconsistent", "error")}
            print(f"   ref n={len(ref)}  blocked set: engine {len(eb)}  "
                  f"ref {len(rb)}  engine-only {len(eb - rb)}  "
                  f"ref-only {len(rb - eb)}")
            print(f"   worst-case set: engine {len(ew)}  ref {len(rw)}  "
                  f"engine-only {len(ew - rw)}  ref-only {len(rw - ew)}")
            rc = collections.Counter(r["outcome"] for r in ref.values())
            print(f"   ref outcomes:    {dict(rc)}")
        # policy-clear subset (engine side; both sides when ref exists)
        for label, want in (("body-less", False), ("body-bearing", True)):
            ids = {i for i, b in clear.items() if b == want}
            e_ids = {i for i in ids if eng[i]["outcome"] == "waf_block"}
            e_w = {i for i in ids if eng[i]["outcome"] in BAD}
            line = (f"   policy-clear {label}: n={len(ids)}  "
                    f"blocked eng {len(e_ids)}  "
                    f"worst-case eng {len(e_w)}")
            if ref is not None:
                r_ids = {i for i in ids if ref[i]["outcome"] == "waf_block"}
                r_w = {i for i in ids if ref[i]["outcome"] in BAD}
                line += (f"  ref {len(r_ids)}/{len(r_w)}  "
                         f"diff {len(e_w ^ r_w)}")
                for i in sorted(e_w ^ r_w):
                    er, rr = eng[i], ref[i]
                    line += (f"\n     DIFF {i}: engine {er['outcome']} "
                             f"status={er.get('status')} rules={er['rule_ids']} | "
                             f"ref {rr['outcome']} status={rr.get('status')} "
                             f"rules={rr['rule_ids']}")
            print(line)
        # engine decisions from events
        try:
            ev = [json.loads(l) for l in
                  open(f"{ENGINE_PREFIX}{pl}/kortex-events-full.jsonl")]
            dec = collections.Counter(e["decision"] for e in ev)
            print(f"   engine events: {dict(dec)}")
            for e in ev:
                if e["decision"] in ("overload", "timeout"):
                    print(f"     {e['decision']} {e['sample_id']} "
                          f"status={e.get('status')}")
        except FileNotFoundError:
            print("   engine events: MISSING")


if __name__ == "__main__":
    main()
