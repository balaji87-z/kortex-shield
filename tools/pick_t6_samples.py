#!/usr/bin/env python3
"""Step-13 T6 sample picker (DIAGNOSTIC): 100 body-bearing samples from the
step-11/12 only-Coraza-rule set (Coraza matched a rule ModSec did not, in the
PL1 WCP run), seed 0. Prints ids, one per line."""
import json
import random

random.seed(0)

mod = {json.loads(l)["sample_id"]: json.loads(l)
       for l in open("out/modsec-benign-wcp-v0-pl1-stub/audit.jsonl")}
cor = {json.loads(l)["sample_id"]: json.loads(l)
       for l in open("out/coraza-benign-wcp-v0-pl1-default/audit.jsonl")}
rows = {json.loads(l)["id"]: json.loads(l)
        for l in open("data/benign-wcp-v0/manifest.jsonl")}

only_coraza = []
for i, e in cor.items():
    if i not in rows or not rows[i]["body"]:
        continue
    mr = {x["id"] for x in mod.get(i, {}).get("rules", []) if x.get("id")}
    cr = {x["id"] for x in e.get("rules", []) if x.get("id")}
    if cr - mr:
        only_coraza.append(i)

random.shuffle(only_coraza)
for i in sorted(only_coraza[:100]):
    print(i)
