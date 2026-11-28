#!/usr/bin/env python3
"""Step-24 T4: tables for the runs of our own datasets on the step-24 engine.

Usage: step24_own_summary.py <durable-dir> [<step-21 parity dir>]
       (docs/logs/runs/s24-own, docs/logs/runs/s21-t3-parity)

Reads, per run, outcomes.jsonl, responses.jsonl and the body-less audit
index, plus the frozen manifests for labels, families and scenario counts.
Prints ids, statuses, outcomes and rule ids only.

Per run (rules 15, 20, 21, 30): requests, distinct payloads (attack) or
distinct endpoints (benign), outcome counts, and
  attack datasets  recall, best case (only waf_block counts; the headline)
                   and worst case (every outcome that is not a pass counts),
                   denominator all requests; per family
  benign datasets  blocks as potential false positives, best case and worst
                   case (the headline), denominator all requests
Rule 18: rule ids in 20% or more of a run's audit entries.
Parity per sample id (rule 32): status, worst-case set and rule-id set,
in-process against worker, patched against the DIAGNOSTIC stock build, and
Host localhost against the DIAGNOSTIC numeric-Host run.
"""
import collections
import gzip
import json
import os
import re
import sys

DATASETS = ("attacks-v0", "attacks-ct-v0", "encoding-diff-v0", "benign-browse-v1", "benign-hard-v0")
# rules 19, 45: the REQUEST_BODY target list of step 18 was shaped on these
IN_SAMPLE = {"attacks-v0": "IN-SAMPLE for the REQUEST_BODY target choice of step 18",
             "attacks-ct-v0": "IN-SAMPLE for the REQUEST_BODY target choice of step 18"}
# rule 35: chosen encodings of chosen payloads
COUNTS_ONLY = {"encoding-diff-v0"}
BENIGN_KIND = {"benign-browse-v1": "natural benign, held-out", "benign-hard-v0": "hard benign, held-out"}
PASS_OUTCOMES = ("waf_pass",)
_HASH = re.compile(r"(?<![0-9a-f])[0-9a-f]{8}(?![0-9a-f])")


def read(path):
    if not os.path.exists(path):
        path += ".gz"
    op = gzip.open if path.endswith(".gz") else open
    with op(path, "rt", encoding="utf-8") as fh:
        return [json.loads(l) for l in fh if l.strip()]


def scenario_counts(manifest):
    """(requests, label, distinct payloads or endpoints, what the second count is)."""
    label = manifest[0]["label"]
    if label == "attack":
        payloads = set()
        for r in manifest:
            m = _HASH.findall(r["id"])
            payloads.add((r["family"], m[-1] if m else r["id"]))
        return len(manifest), label, len(payloads), "distinct payloads"
    return len(manifest), label, len({(r["method"], r["path"]) for r in manifest}), "distinct endpoints"


def pct(k, n):
    return f"{k}/{n} = {100 * k / n:.2f}%"


def run_lines(ds, name, manifest, outcomes):
    """The table lines of one run. outcomes: rows of outcomes.jsonl."""
    n, label, distinct, what = scenario_counts(manifest)
    by_id = {r["id"]: r["outcome"] for r in outcomes}
    oc = collections.Counter(by_id.get(r["id"], "error") for r in manifest)  # no row = no answer = error
    blocked = oc["waf_block"]
    flagged = n - sum(oc[o] for o in PASS_OUTCOMES)
    out = [f"{name}: requests {n}, {what} {distinct}; outcomes: "
           + ", ".join(f"{k} {v}" for k, v in sorted(oc.items()))]
    if label == "attack":
        note = IN_SAMPLE.get(ds, "")
        if ds in COUNTS_ONLY:
            out.append(f"    blocked {blocked} of {n}; not passed {flagged} of {n} (chosen cases: counts, not a rate, rule 35)")
        else:
            out.append(f"    recall best case (only waf_block) {pct(blocked, n)}; worst case (every outcome that is "
                       f"not a pass) {pct(flagged, n)}" + (f"  [{note}]" if note else ""))
        fam_n = collections.Counter(r["family"] for r in manifest)
        fam_b = collections.Counter(r["family"] for r in manifest if by_id.get(r["id"]) == "waf_block")
        out.append("    per family, blocked of requests: "
                   + ", ".join(f"{f} {fam_b[f]}/{fam_n[f]}" for f in sorted(fam_n)))
    else:
        out.append(f"    potential false positives ({BENIGN_KIND.get(ds, 'benign')}): best case (only waf_block) "
                   f"{pct(blocked, n)}; worst case (every outcome that is not a pass) {pct(flagged, n)}")
    return out


def rule18(index):
    hits = collections.Counter(r for e in index for r in set(e.get("rule_ids") or []))
    common = [(r, c) for r, c in hits.most_common() if index and c >= 0.2 * len(index)]
    return (f"    rule 18: {len(index)} audit entries; rule ids in >=20% of them: "
            + (", ".join(f"{r}={c}" for r, c in common) or "none"))


def compare(a, b, label_a, label_b, limit=40):
    """Per-sample differences between two runs' outcomes.jsonl rows."""
    da, db = {r["id"]: r for r in a}, {r["id"]: r for r in b}
    ids = sorted(set(da) | set(db))
    get = lambda d, i, k: d[i].get(k) if i in d else None
    status = [i for i in ids if get(da, i, "status") != get(db, i, "status")]
    flag = lambda d, i: (d[i]["outcome"] not in PASS_OUTCOMES) if i in d else True
    worst = [i for i in ids if flag(da, i) != flag(db, i)]
    rules = [i for i in ids if sorted(get(da, i, "rule_ids") or []) != sorted(get(db, i, "rule_ids") or [])]
    out = [f"    {label_a} against {label_b}: {len(ids)} sample ids; status differs in {len(status)}; "
           f"worst-case set differs in {len(worst)}; rule-id set differs in {len(rules)}"]
    for i in sorted(set(status) | set(worst) | set(rules))[:limit]:
        ra, rb = set(get(da, i, "rule_ids") or []), set(get(db, i, "rule_ids") or [])
        out.append(f"      {i}: status {get(da, i, 'status')} / {get(db, i, 'status')}; outcome "
                   f"{get(da, i, 'outcome')} / {get(db, i, 'outcome')}; rule ids only in {label_a} "
                   f"{sorted(ra - rb)}, only in {label_b} {sorted(rb - ra)}")
    extra = len(set(status) | set(worst) | set(rules)) - limit
    if extra > 0:
        out.append(f"      ... and {extra} more ids (all in the run files)")
    return out


def status_diff(resp_a, resp_b):
    """Sample ids whose HTTP status differs between two responses.jsonl."""
    sa = {r["id"]: r.get("status") for r in resp_a}
    sb = {r["id"]: r.get("status") for r in resp_b}
    return sorted(i for i in set(sa) | set(sb) if sa.get(i) != sb.get(i)), len(set(sa) | set(sb))


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    base = argv[0]
    s21 = argv[1] if len(argv) > 1 else None
    have = lambda name: os.path.isdir(f"{base}/{name}")
    for pl in (1, 2):
        print(f"\n== PL{pl}: rates and counts per run")
        for ds in DATASETS:
            manifest = read(f"data/{ds}/manifest.jsonl")
            for mode in ("inprocess", "worker"):
                name = f"{ds}-{mode}-pl{pl}"
                if not have(name):
                    print(f"{name}: NOT MEASURED (no run files)")
                    continue
                print("\n".join(run_lines(ds, name, manifest, read(f"{base}/{name}/outcomes.jsonl"))))
                print(rule18(read(f"{base}/{name}/audit.index.jsonl")))
    print("\n== parity per sample id: in-process against worker (patched engine)")
    for pl in (1, 2):
        for ds in DATASETS:
            a, b = f"{ds}-inprocess-pl{pl}", f"{ds}-worker-pl{pl}"
            if have(a) and have(b):
                print(f"{ds} PL{pl}")
                print("\n".join(compare(read(f"{base}/{a}/outcomes.jsonl"), read(f"{base}/{b}/outcomes.jsonl"),
                                        "in-process", "worker")))
    print("\n== DIAGNOSTIC stock coraza v3.8.1 (same commit, replace dropped), in-process: counts, then per sample id "
          "against the patched in-process run")
    for pl in (1, 2):
        for ds in DATASETS:
            a, b = f"{ds}-inprocess-pl{pl}", f"{ds}-inprocess-pl{pl}-DIAGNOSTIC-stock"
            if not (have(a) and have(b)):
                print(f"{ds} PL{pl}: NOT MEASURED")
                continue
            manifest = read(f"data/{ds}/manifest.jsonl")
            print("\n".join(run_lines(ds, b, manifest, read(f"{base}/{b}/outcomes.jsonl"))[:1]))
            print("\n".join(compare(read(f"{base}/{a}/outcomes.jsonl"), read(f"{base}/{b}/outcomes.jsonl"),
                                    "patched", "stock")))
    print("\n== DIAGNOSTIC numeric Host (requests to 127.0.0.1), patched engine, in-process, PL1: counts, then per "
          "sample id against the Host-localhost run")
    for ds in DATASETS:
        a, b = f"{ds}-inprocess-pl1", f"{ds}-inprocess-pl1-DIAGNOSTIC-numeric-host"
        if not (have(a) and have(b)):
            print(f"{ds}: NOT MEASURED")
            continue
        manifest = read(f"data/{ds}/manifest.jsonl")
        ob = read(f"{base}/{b}/outcomes.jsonl")
        print("\n".join(run_lines(ds, b, manifest, ob)[:1]))
        for label, name in (("Host localhost", a), ("Host 127.0.0.1", b)):
            idx = read(f"{base}/{name}/audit.index.jsonl")
            print(f"    {label}: audit entries {len(idx)}, with rule 920350 (numeric Host): "
                  f"{sum(1 for e in idx if '920350' in (e.get('rule_ids') or []))}")
        print("\n".join(compare(read(f"{base}/{a}/outcomes.jsonl"), ob, "localhost", "numeric")))
        if s21 and os.path.isdir(f"{s21}/{ds}-inprocess"):
            old = read(f"{s21}/{ds}-inprocess/responses.jsonl")
            for label, name in (("today's numeric-Host run", b), ("today's Host-localhost run", a)):
                diff, total = status_diff(old, read(f"{base}/{name}/responses.jsonl"))
                print(f"    step-21 run (stock coraza, 127.0.0.1) against {label}: status differs in {len(diff)} of "
                      f"{total} sample ids" + (": " + ", ".join(diff[:30]) + (" ..." if len(diff) > 30 else "") if diff else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
