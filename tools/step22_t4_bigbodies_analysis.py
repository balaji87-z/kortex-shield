#!/usr/bin/env python3
"""Step-22 T4: big-body audited re-run, per-sample rule attribution.

Usage: step22_t4_bigbodies_analysis.py <ids-index.jsonl> <run-dir> <step21-run-dir>

<run-dir>/bigbodies-pl{1,2}/ hold responses.jsonl, outcomes.jsonl, run.json.
Prints counts only (ids, sizes, content types, statuses, rule ids); no body,
query or header value is read or printed (rule 51). The 402 samples were
selected by body size, so every figure is a count with its denominator, not
a traffic rate.
"""
import collections
import gzip
import json
import os
import sys

BANDS = (("<64K", 0, 65536), ("64K-<128K", 65536, 131072), (">=128K", 131072, 1 << 62))
FAMILY = {"920": "protocol", "921": "protocol", "932": "rce", "942": "sqli", "941": "xss"}
SCORE_RULES = {"949110", "949111", "980170"}


def read_jsonl(path):
    if not os.path.exists(path) and os.path.exists(path + ".gz"):
        with gzip.open(path + ".gz", "rt", encoding="utf-8") as fh:
            return [json.loads(l) for l in fh if l.strip()]
    with open(path, encoding="utf-8") as fh:
        return [json.loads(l) for l in fh if l.strip()]


def band(size):
    for name, lo, hi in BANDS:
        if lo <= size < hi:
            return name


def pct(values, q):
    values = sorted(values)
    return values[min(len(values) - 1, int(round(q * (len(values) - 1))))] if values else None


def counts(counter):
    return dict(sorted(counter.items(), key=lambda kv: (kv[0] is None, str(kv[0]))))


def top(counter, n=10):
    return ", ".join(f"{k}={v}" for k, v in counter.most_common(n)) or "(none)"


def main():
    ids_path, run_dir, old_dir = sys.argv[1:4]
    meta = {e["id"]: e for e in read_jsonl(ids_path)}
    for pl in (1, 2):
        run = f"{run_dir}/bigbodies-pl{pl}"
        resp = {r["id"]: r for r in read_jsonl(f"{run}/responses.jsonl")}
        outc = {r["id"]: r for r in read_jsonl(f"{run}/outcomes.jsonl")}
        info = json.load(open(f"{run}/run.json"))
        n = len(meta)
        print(f"\n== PL{pl}: n={n} (rows in responses {len(resp)}, in outcomes {len(outc)})")
        print(f"   load average start {info.get('load_avg_start')} end {info.get('load_avg_end')} (rule 38)")
        print(f"   status: {counts(collections.Counter(resp.get(i, {}).get('status') for i in meta))}")
        oc = collections.Counter(outc.get(i, {}).get("outcome", "no-outcome-row") for i in meta)
        print(f"   outcome: {counts(oc)}")
        blocked = [i for i in meta if outc.get(i, {}).get("outcome") == "waf_block"]
        other_worst = [i for i in meta if outc.get(i, {}).get("outcome")
                       in ("waf_deny_status", "inconsistent", "error", None)]
        print(f"   blocked {len(blocked)}/{n}; worst case (blocked + deny_status + inconsistent + error) "
              f"{len(blocked) + len(other_worst)}/{n}; best case (blocked only) {len(blocked)}/{n}")
        el = [resp[i]["elapsed_ms"] for i in meta if i in resp and resp[i].get("elapsed_ms") is not None]
        print(f"   elapsed ms: min={min(el)} p50={pct(el, .5)} p95={pct(el, .95)} p99={pct(el, .99)} max={max(el)}")
        slow = [i for i in meta if i in resp and (resp[i].get("elapsed_ms") or 0) > 2000]
        print(f"   over 2000 ms (would be 503 at the default 2 s budget): {len(slow)}/{n}")
        for i in slow:
            print(f"     {i} size={meta[i]['body_size']} ct={meta[i].get('content_type')!r} "
                  f"status={resp[i]['status']} elapsed={resp[i]['elapsed_ms']}")
        for name, _, _ in BANDS:
            ids = [i for i in meta if band(meta[i]["body_size"]) == name]
            st = collections.Counter(resp.get(i, {}).get("status") for i in ids)
            e = [resp[i]["elapsed_ms"] for i in ids if i in resp and resp[i].get("elapsed_ms") is not None]
            print(f"   band {name}: n={len(ids)} status={counts(st)} p50={pct(e, .5)} max={max(e) if e else None}")
            rules, sole, fams = collections.Counter(), collections.Counter(), collections.Counter()
            nb = 0
            for i in ids:
                if outc.get(i, {}).get("outcome") != "waf_block":
                    continue
                nb += 1
                rids = [r for r in outc[i].get("rule_ids") or [] if r not in SCORE_RULES]
                rules.update(rids)
                fams.update(FAMILY.get(r[:3], "other") for r in rids)
                sole[rids[0] if len(rids) == 1 else ("(none)" if not rids else "(multi)")] += 1
            print(f"       waf_block {nb}/{len(ids)}; rule hits top 10: {top(rules)}")
            print(f"       families (per rule hit): {top(fams)}; sole-rule blocks: {top(sole)}")
            deny = collections.Counter()
            for i in ids:
                if resp.get(i, {}).get("status") == 400:
                    rids = [r for r in outc.get(i, {}).get("rule_ids") or [] if r not in SCORE_RULES]
                    deny[",".join(rids) or "(no rule id in audit)"] += 1
            if deny:
                print(f"       status 400 by rule ids: {top(deny)}")
        by_ct = collections.defaultdict(collections.Counter)
        for i in meta:
            ct = (meta[i].get("content_type") or "").split(";")[0].strip().lower()
            by_ct[ct][resp.get(i, {}).get("status")] += 1
        print("   by content type (n, status):")
        for ct, st in sorted(by_ct.items(), key=lambda kv: -sum(kv[1].values())):
            print(f"     {ct or '(none)'}: n={sum(st.values())} {counts(st)}")
        old_path = f"{old_dir}/bigbodies-pl{pl}/responses.jsonl"
        if os.path.exists(old_path):
            old = {r["id"]: r for r in read_jsonl(old_path)}
            diffs = [(i, old.get(i, {}).get("status"), resp.get(i, {}).get("status")) for i in meta
                     if old.get(i, {}).get("status") != resp.get(i, {}).get("status")]
            print(f"   status vs the step-21 run (worker mode, other host), per id: {len(diffs)} differ of {n}")
            for i, a, b in diffs:
                print(f"     {i}: step-21={a} step-22={b} size={meta[i]['body_size']}")
        else:
            print("   status vs the step-21 run: NOT MEASURED (no step-21 responses.jsonl)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
