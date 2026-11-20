#!/usr/bin/env python3
"""Step-13 T6 (DIAGNOSTIC) analysis: per-sample rule-ID sets and outcome for
the recorded vs urlenc variants on both engines. Prints counts and the
deciding comparisons; no request values (rule 25)."""
import json

def load(run, name):
    key = "sample_id" if name.startswith("audit") else "id"
    return {json.loads(l)[key]: json.loads(l)
            for l in open(f"{run}/{name}")}

def rules(aud, i):
    return sorted({x["id"] for x in aud.get(i, {}).get("rules", []) if x.get("id")})

ids = [l.strip() for l in open("out/step13-t6/picked.txt") if l.strip()]
E = {}
for eng in ("modsec", "coraza"):
    for v in ("recorded", "urlenc"):
        E[(eng, v)] = (
            load(f"out/step13-t6/{eng}-{v}", "outcomes.jsonl"),
            load(f"out/step13-t6/{eng}-{v}", "audit.jsonl"),
        )

BODY_RULE_PREFIX = ("93", "94", "921", "930", "932", "933", "942", "943", "944", "920270", "920271", "200007")

def body_rules(rs):
    return [r for r in rs if r.startswith(BODY_RULE_PREFIX) or r in ("920270", "920271", "200007")]

# 1. deciding counts
n_200007_rec = sum(1 for i in ids if "200007" in rules(E[("coraza", "recorded")][1], i))
n_200007_url = sum(1 for i in ids if "200007" in rules(E[("coraza", "urlenc")][1], i))
n_200007_mod_rec = sum(1 for i in ids if "200007" in rules(E[("modsec", "recorded")][1], i))
n_200007_mod_url = sum(1 for i in ids if "200007" in rules(E[("modsec", "urlenc")][1], i))
print(f"200007 (argument-count, body-parser indicator): coraza recorded {n_200007_rec}, coraza urlenc {n_200007_url}; modsec recorded {n_200007_mod_rec}, modsec urlenc {n_200007_mod_url}")

# body-derived rule matches per engine/variant
for eng in ("modsec", "coraza"):
    for v in ("recorded", "urlenc"):
        aud = E[(eng, v)][1]
        n = sum(1 for i in ids if body_rules(rules(aud, i)))
        print(f"{eng} {v}: samples with >=1 body-derived rule match: {n}/100")

# 2. per-sample delta: ModSec body-derived matches that appear ONLY in urlenc
gained = [i for i in ids
          if body_rules(rules(E[("modsec", "urlenc")][1], i))
          and not body_rules(rules(E[("modsec", "recorded")][1], i))]
print(f"modsec: samples gaining body-derived matches after CT rewrite: {len(gained)}")
lost = [i for i in ids
        if body_rules(rules(E[("modsec", "recorded")][1], i))
        and not body_rules(rules(E[("modsec", "urlenc")][1], i))]
print(f"modsec: samples LOSING body-derived matches after CT rewrite: {len(lost)}")

# 3. coraza behaviour under rewrite (does coraza also change?)
cgained = [i for i in ids
           if body_rules(rules(E[("coraza", "urlenc")][1], i))
           and not body_rules(rules(E[("coraza", "recorded")][1], i))]
print(f"coraza: samples gaining body-derived matches after CT rewrite: {len(cgained)}")

# 4. status/outcome table per variant
for eng in ("modsec", "coraza"):
    for v in ("recorded", "urlenc"):
        out, aud = E[(eng, v)]
        b = sum(1 for i in ids if out[i]["outcome"] in ("waf_block", "waf_deny_status", "inconsistent", "error"))
        print(f"{eng} {v}: worst-case blocked {b}/100")

# 5. show 3 example samples' rule sets (ids only)
shown = 0
for i in ids:
    mr = rules(E[("modsec", "recorded")][1], i)
    mu = rules(E[("modsec", "urlenc")][1], i)
    if body_rules(mu) and not body_rules(mr):
        print(f"example {i}: modsec recorded {mr} -> urlenc {mu}")
        shown += 1
        if shown == 3:
            break
