#!/usr/bin/env python3
"""Step-22 T4: engine false-positive decomposition on benign-wcp-v0/v1.

Reads existing run outcomes (rule 42 evidence), decomposes by sole-rule
attribution, rule family, body-less vs body-bearing, top-15 rules; compares
with the coraza connector's detection-involved counts; and attributes
REQUEST_BODY-target-only blocks via the step-19 pre/post difference.
Counts only; no body content is read or emitted (rule 51).
"""
import json
import collections
import gzip
import os

RUNS = "docs/logs/runs"
OUT = "docs/logs/step22-t4-fp-decomposition.txt"

FAMILY = {
    "920": "protocol", "921": "protocol",
    "932": "rce", "942": "sqli", "941": "xss",
}


def fam(rid):
    return FAMILY.get(rid[:3], "other")


def manifest_meta(dataset):
    """id -> (method, has_body, body_size, content_type)."""
    meta = {}
    p = f"data/{dataset}/manifest.jsonl"
    for line in open(p):
        e = json.loads(line)
        meta[e["id"]] = (e.get("method", "GET"), bool(e.get("body")),
                         len(e.get("body") or ""), e.get("content_type", ""))
    return meta


def load(run):
    rows = []
    with open(f"{RUNS}/{run}/outcomes.jsonl") as f:
        for line in f:
            rows.append(json.loads(line))
    return rows


def analyze(run, dataset, label, out):
    meta = manifest_meta(dataset)
    rows = load(run)
    n = len(rows)
    blocked = [r for r in rows if r["outcome"] == "waf_block"]
    deny = [r for r in rows if r["outcome"] == "waf_deny_status"]
    err = [r for r in rows if r["outcome"] == "error"]
    worst = len(blocked) + len(deny) + len(err)
    out.write(f"\n== {label}: n={n} blocked={len(blocked)} deny_status={len(deny)} "
              f"error={len(err)}  WORST-CASE rate={worst}/{n} = {worst/n:.2%} "
              f"(blocked-only {len(blocked)/n:.2%})\n")
    # sole-rule attribution (non-949110)
    sole = collections.Counter()
    multi = 0
    famcnt = collections.Counter()
    rulecnt = collections.Counter()
    bodyless_b = bodyful_b = 0
    for r in blocked:
        rules = [x for x in (r.get("rule_ids") or []) if x != "949110"]
        for x in rules:
            rulecnt[x] += 1
            famcnt[fam(x)] += 1
        if len(rules) == 1:
            sole[rules[0]] += 1
        elif len(rules) == 0:
            sole["(none)"] += 1
        else:
            multi += 1
        m = meta.get(r["id"])
        if m and m[1]:
            bodyful_b += 1
        else:
            bodyless_b += 1
    out.write(f"sole-rule blocks: {sum(sole.values())}  multi-rule blocks: {multi}\n")
    out.write("sole-rule top: " + ", ".join(f"{k}={v}" for k, v in sole.most_common(10)) + "\n")
    out.write("family hits (per block-rule occurrence): " +
              ", ".join(f"{k}={v}" for k, v in famcnt.most_common()) + "\n")
    out.write("top 15 rules: " + ", ".join(f"{k}={v}" for k, v in rulecnt.most_common(15)) + "\n")
    out.write(f"body-less blocked={bodyless_b} body-bearing blocked={bodyful_b}\n")
    # worst case split by body presence
    bl = sum(1 for r in rows if not (meta.get(r["id"]) or ("", False, 0, ""))[1])
    bf = n - bl
    out.write(f"denominator: body-less={bl} body-bearing={bf}\n")
    return rows, meta, blocked


def connector_side(run, label, out):
    """detection-involved = connector blocks whose rules include anything but 920420."""
    path = f"{RUNS}/{run}/audit.jsonl"
    opener = open
    if not os.path.exists(path) and os.path.exists(path + ".gz"):
        # preserve_run.sh stores files over 5 MB gzip-compressed
        path, opener = path + ".gz", lambda p: gzip.open(p, "rt")
    if not os.path.exists(path):
        out.write(f"\n== {label}: audit.jsonl missing -> NOT MEASURED\n")
        return
    n = 0
    blocks = 0
    det = 0
    famcnt = collections.Counter()
    rulecnt = collections.Counter()
    for line in opener(path):
        d = json.loads(line)
        n += 1
        st = d.get("status")
        if st in (403, 401, 400):
            blocks += 1
        rules = [r["id"] for r in (d.get("rules") or []) if r.get("id")]
        non = [r for r in rules if r != "949110" and r != "920420"]
        if st == 403 and non:
            det += 1
            for x in non:
                rulecnt[x] += 1
                famcnt[fam(x)] += 1
    out.write(f"\n== {label}: n={n} 403-blocks={blocks} detection-involved={det} "
              f"(920420-only blocks={blocks - det})\n")
    out.write("connector family hits: " + ", ".join(f"{k}={v}" for k, v in famcnt.most_common()) + "\n")
    out.write("connector top 10: " + ", ".join(f"{k}={v}" for k, v in rulecnt.most_common(10)) + "\n")


def main():
    with open(OUT, "w") as out:
        out.write("# Step-22 T4: engine FP decomposition (existing runs, counts only)\n")
        out.write("# worst case per rule 21: blocked + deny_status + error over N\n")
        eng = [
            ("s18-t4-engine-benign-wcp-v0-post-pl1", "benign-wcp-v0", "engine v0 PL1 (step-18 post)"),
            ("s18-t4-engine-benign-wcp-v0-post-pl2", "benign-wcp-v0", "engine v0 PL2 (step-18 post)"),
            ("s19-t4-benign-wcp-v1-post-r1-pl1", "benign-wcp-v1", "engine v1 PL1 (step-19 post r1)"),
            ("s19-t4-benign-wcp-v1-post-r1-pl2", "benign-wcp-v1", "engine v1 PL2 (step-19 post r1)"),
        ]
        kept = {}
        for run, ds, label in eng:
            if os.path.exists(f"{RUNS}/{run}/outcomes.jsonl"):
                kept[label] = analyze(run, ds, label, out)
            else:
                out.write(f"\n== {label}: run missing -> NOT MEASURED\n")
        connector_side("coraza-benign-wcp-v0-pl1-default", "connector v0 PL1", out)
        connector_side("coraza-benign-wcp-v0-pl2-default", "connector v0 PL2", out)
        connector_side("coraza-benign-wcp-v1-pl1-default", "connector v1 PL1", out)
        connector_side("coraza-benign-wcp-v1-pl2-default", "connector v1 PL2", out)
        # REQUEST_BODY-target attribution: pre/post difference on v1 (step-19)
        out.write("\n== REQUEST_BODY-target attribution (v1, step-19 pre vs post r1)\n")
        for pl in (1, 2):
            pre = {r["id"] for r in load(f"s19-t4-benign-wcp-v1-pre-r1-pl{pl}")
                   if r["outcome"] == "waf_block"}
            post = {r["id"] for r in load(f"s19-t4-benign-wcp-v1-post-r1-pl{pl}")
                    if r["outcome"] == "waf_block"}
            new = post - pre
            gone = pre - post
            out.write(f"PL{pl}: pre_blocked={len(pre)} post_blocked={len(post)} "
                      f"new_in_post={len(new)} gone_in_post={len(gone)}\n")
        out.write("\nNOTE (rule 45/46): WCP samples are third-party captured telemetry with\n")
        out.write("cookies dropped; 'attack' labels in public lists mean 'listed under this\n")
        out.write("family in this source', not verified exploitable. The number a later ML\n")
        out.write("layer would have to beat is the engine worst-case FP rate on v1 (above).\n")


if __name__ == "__main__":
    main()
print("written")
