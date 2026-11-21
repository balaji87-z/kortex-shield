#!/usr/bin/env python3
"""Step-18 T4 analysis: pre/post REQUEST_BODY-target-fix comparison on the
engine (same host, same config, only the fix differs), per rule 16/27/32/35.

For each dataset/PL cell:
  - blocked-set diff pre vs post (ids, with rule ids from the audit logs)
  - worst-case set (blocked + waf_deny_status + inconsistent + error) diff
  - outcome class counts
attacks-ct-v0 / attacks-v0 are IN-SAMPLE (the fix was derived from
attacks-ct-v0 observations): reported as COUNTS of an effect (rule 35),
never as rates. benign-browse-v1 / benign-hard-v0 / benign-wcp-v0 are
held-out: new false positives are reported per id with counts and rates.

Usage: .venv/bin/python tools/analyze_step18_t4.py
"""
import collections
import json
import subprocess
import sys

DATASETS = ["attacks-ct-v0", "attacks-v0", "benign-browse-v1", "benign-hard-v0"]
IN_SAMPLE = {"attacks-ct-v0", "attacks-v0"}
WCP_PRE = "docs/logs/runs/s17-t4-engine-benign-wcp-v0-pl"


def load(path):
    rows = {}
    try:
        fh = open(path)
    except OSError:
        return None
    with fh:
        for line in fh:
            r = json.loads(line)
            rows[r["id"]] = r
    return rows


def rule_ids_for(audit_path, ids):
    """rule ids seen in the audit for the given sample ids (phase-2 messages)."""
    out = collections.defaultdict(set)
    try:
        fh = open(audit_path)
    except OSError:
        return out
    with fh:
        for line in fh:
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            sid = e.get("sample_id") or e.get("id")
            if sid in ids:
                for m in e.get("rules", []) or []:
                    rid = str(m.get("id") or "")
                    if rid:
                        out[sid].add(rid)
    return out


def wc_row(r):
    """worst-case membership: blocked, deny_status, inconsistent or error."""
    o = r.get("outcome")
    return o in ("waf_block", "waf_deny_status", "inconsistent", "error")


def summarize(tag, rows):
    c = collections.Counter(r.get("outcome") for r in rows.values())
    errs = [r for r in rows.values() if r.get("error") or r.get("error_class")]
    return c, errs


def diff_cell(name, pre, post, audit_pre, audit_post, in_sample):
    if pre is None or post is None:
        print(f"\n== {name}: MISSING ARTIFACTS (pre={pre is not None}, post={post is not None})")
        return
    pre_b = {i for i, r in pre.items() if r.get("outcome") == "waf_block"}
    post_b = {i for i, r in post.items() if r.get("outcome") == "waf_block"}
    pre_wc = {i for i, r in pre.items() if wc_row(r)}
    post_wc = {i for i, r in post.items() if wc_row(r)}
    gained, lost = sorted(post_b - pre_b), sorted(pre_b - post_b)
    wc_gained, wc_lost = sorted(post_wc - pre_wc), sorted(pre_wc - post_wc)
    kind = "IN-SAMPLE (counts only, rule 35)" if in_sample else "HELD-OUT"
    print(f"\n== {name} [{kind}] n={len(post)}")
    print(f"   blocked pre={len(pre_b)} post={len(post_b)} gained={len(gained)} lost={len(lost)}")
    print(f"   worst-case pre={len(pre_wc)} post={len(post_wc)} gained={len(wc_gained)} lost={len(wc_lost)}")
    cp, _ = summarize("pre", pre)
    cc, _ = summarize("post", post)
    print(f"   outcomes pre: {dict(sorted(cp.items()))}")
    print(f"   outcomes post: {dict(sorted(cc.items()))}")
    if gained:
        rpre = rule_ids_for(audit_pre, set())  # pre audit has no entry for newly blocked
        rpost = rule_ids_for(audit_post, set(gained))
        print("   gained ids (post rule ids):")
        for i in gained:
            print(f"     {i} rules={sorted(rpost.get(i, [])) or 'NONE-IN-AUDIT'}")
    if lost:
        rpre = rule_ids_for(audit_pre, set(lost))
        print("   lost ids (pre rule ids):")
        for i in lost:
            print(f"     {i} rules={sorted(rpre.get(i, [])) or 'NONE-IN-AUDIT'}")
    if wc_gained and set(wc_gained) - set(gained):
        print("   worst-case-only gained ids (not blocked):")
        for i in sorted(set(wc_gained) - set(gained)):
            print(f"     {i} pre_outcome={pre[i].get('outcome')} post_outcome={post[i].get('outcome')} "
                  f"pre_status={pre[i].get('status')} post_status={post[i].get('status')} "
                  f"post_error={post[i].get('error')}")
    if wc_lost and set(wc_lost) - set(lost):
        print("   worst-case-only lost ids:")
        for i in sorted(set(wc_lost) - set(lost)):
            print(f"     {i} pre_outcome={pre[i].get('outcome')} post_outcome={post[i].get('outcome')}")


def main():
    for ds in DATASETS:
        for pl in (1, 2):
            pre = load(f"out/s18-t4-engine-{ds}-pre-pl{pl}/outcomes.jsonl")
            post = load(f"out/s18-t4-engine-{ds}-v2-pl{pl}/outcomes.jsonl")
            diff_cell(f"{ds} pl{pl} pre vs post", pre, post,
                      f"out/s18-t4-engine-{ds}-pre-pl{pl}/audit.jsonl",
                      f"out/s18-t4-engine-{ds}-v2-pl{pl}/audit.jsonl",
                      ds in IN_SAMPLE)
    # WCP: pre = preserved step-17 run (same host, pre-fix binary)
    for pl in (1, 2):
        pre = load(f"{WCP_PRE}{pl}/outcomes.jsonl")
        post = load(f"out/s18-t4-engine-benign-wcp-v0-v2-pl{pl}/outcomes.jsonl")
        diff_cell(f"benign-wcp-v0 pl{pl} pre(s17) vs post", pre, post,
                  f"{WCP_PRE}{pl}/audit.jsonl",
                  f"out/s18-t4-engine-benign-wcp-v0-v2-pl{pl}/audit.jsonl",
                  False)


if __name__ == "__main__":
    main()
