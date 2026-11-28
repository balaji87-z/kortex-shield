#!/usr/bin/env python3
"""Step-22: per-sample comparison of the ModSecurity and Coraza connector
runs of tools/run_step22_modsec_connector.sh (rule 32: names the quantity).

For each paranoia level: the blocked set (block discriminator, responses
"blocked"), the worst-case set (every outcome except waf_pass: blocked +
deny_status + inconsistent + proxy_reject + error) and the rule-id sets,
with every differing id listed. Reads only the body-less durable copies.

Usage: step22_modsec_connector_summary.py [run-root] [dataset]
"""
import collections, gzip, json, os, sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else "docs/logs/runs/s22-modsec-connector"
DS = sys.argv[2] if len(sys.argv) > 2 else "benign-wcp-v0"


def rows(path):
    if not os.path.exists(path):
        path += ".gz"
    op = gzip.open if path.endswith(".gz") else open
    with op(path, "rt") as f:
        return {r["id"]: r for r in map(json.loads, f)}


def main():
    for pl in (1, 2):
        m, c = (f"{ROOT}/{e}-{DS}-pl{pl}" for e in ("modsec", "coraza"))
        if not (os.path.isdir(m) and os.path.isdir(c)):
            print(f"== PL{pl}: run directory missing -> NOT MEASURED")
            continue
        mo, co = rows(m + "/outcomes.jsonl"), rows(c + "/outcomes.jsonl")
        mr, cr = rows(m + "/responses.jsonl"), rows(c + "/responses.jsonl")
        ids = sorted(set(mo) | set(co))
        print(f"== {DS} PL{pl}: {len(ids)} ids (modsec {len(mo)}, coraza {len(co)})")
        for name, o in (("modsec", mo), ("coraza", co)):
            cnt = collections.Counter(r["outcome"] for r in o.values())
            n = len(o)
            worst = n - cnt["waf_pass"]
            print(f"   {name}: outcomes {dict(sorted(cnt.items()))}; blocked-only {cnt['waf_block']}/{n} = "
                  f"{cnt['waf_block']/n:.2%}; worst case {worst}/{n} = {worst/n:.2%}")
        mb = {i for i in ids if mr.get(i, {}).get("blocked")}
        cb = {i for i in ids if cr.get(i, {}).get("blocked")}
        print(f"   blocked set: modsec {len(mb)}, coraza {len(cb)}, both {len(mb & cb)}, "
              f"only modsec {len(mb - cb)}, only coraza {len(cb - mb)} (symmetric difference {len(mb ^ cb)})")
        for i in sorted(mb ^ cb):
            print(f"      {i}: modsec {mr[i]['status']} {mo[i]['outcome']} | coraza {cr[i]['status']} {co[i]['outcome']}")
        mw = {i for i in ids if mo.get(i, {}).get("outcome") != "waf_pass"}
        cw = {i for i in ids if co.get(i, {}).get("outcome") != "waf_pass"}
        print(f"   worst-case set: modsec {len(mw)}, coraza {len(cw)}, only modsec {len(mw - cw)}, "
              f"only coraza {len(cw - mw)} (symmetric difference {len(mw ^ cw)})")
        for i in sorted(mw ^ cw):
            print(f"      {i}: modsec {mr[i]['status']} {mo[i]['outcome']} | coraza {cr[i]['status']} {co[i]['outcome']}")
        both = sorted(mb & cb)
        diff = [i for i in both if set(mo[i]["rule_ids"]) != set(co[i]["rule_ids"])]
        only_m, only_c = collections.Counter(), collections.Counter()
        for i in diff:
            only_m.update(set(mo[i]["rule_ids"]) - set(co[i]["rule_ids"]))
            only_c.update(set(co[i]["rule_ids"]) - set(mo[i]["rule_ids"]))
        print(f"   rule-id sets on the {len(both)} ids blocked by both: {len(diff)} ids differ")
        print(f"      rules only in the modsec set (ids): {dict(only_m.most_common(12))}")
        print(f"      rules only in the coraza set (ids): {dict(only_c.most_common(12))}")
        errs = [(i, mr[i].get("error_class"), cr[i].get("error_class")) for i in ids
                if mr[i].get("error") or cr[i].get("error")]
        print(f"   errors: {len(errs)} ids: " + "; ".join(f"{i} modsec={a} coraza={b}" for i, a, b in errs))


if __name__ == "__main__":
    main()
