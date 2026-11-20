#!/usr/bin/env python3
"""Step-12 T3: WCP parity deep-dive on the step-11 fixed-harness runs
(out/modsec-benign-wcp-v0-pl{1,2}-stub vs out/coraza-benign-wcp-v0-pl{1,2}-default).

Outputs (counts and ids only; NO matched values - rule 25):
  A. blocked-set diff and worst-case-set diff (blocked + waf_deny_status +
     inconsistent + error), each id with per-engine status/outcome/rule IDs.
  B. for samples where Coraza matched a rule ModSecurity did not:
     masked (sample already blocked on ModSecurity) vs unmasked (not blocked
     on either engine); plus the share of only-Coraza matches that are 920420.
  C. top-15 only-Coraza rules per PL (paranoia-level tags added separately
     from the CRS files in the image).
  D. top-5 only-Coraza rules x 3 samples: matched variable + matched-data
     LENGTH from the raw Coraza audit; whether the same variable occurs in the
     ModSecurity entry of the same sample (and its matched length there).
"""
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

THRESHOLD = {"949110", "959100", "950100"}
WORST = {"waf_block", "waf_block_outbound", "waf_deny_status", "inconsistent", "error"}
MOD_RUN = {1: "out/modsec-benign-wcp-v0-pl1-stub", 2: "out/modsec-benign-wcp-v0-pl2-stub"}
COR_RUN = {1: "out/coraza-benign-wcp-v0-pl1-default", 2: "out/coraza-benign-wcp-v0-pl2-default"}


def outcomes(run):
    return {r["id"]: r for r in map(json.loads, open(f"{run}/outcomes.jsonl"))}


def rule_sets(run):
    """sample_id -> set of rule ids (all audit entries)."""
    d = defaultdict(set)
    for l in open(f"{run}/audit.jsonl"):
        e = json.loads(l)
        for m in e.get("rules", []):
            d[e["sample_id"]].add(str(m.get("id")))
    return d


def part_a(pl):
    mo, co = outcomes(MOD_RUN[pl]), outcomes(COR_RUN[pl])
    ids = sorted(set(mo) & set(co))
    mb = {i for i in ids if mo[i]["outcome"] in WORST}
    cb = {i for i in ids if co[i]["outcome"] in WORST}
    print(f"\n### PL{pl} worst-case set (blocked+deny_status+inconsistent+error)")
    print(f"modsec {len(mb)} coraza {len(cb)} only-modsec {len(mb-cb)} only-coraza {len(cb-mb)}")
    for i in sorted((mb - cb) | (cb - mb)):
        side = "only-modsec" if i in mb - cb else "only-coraza"
        other = co[i] if side == "only-modsec" else mo[i]
        own = mo[i] if side == "only-modsec" else co[i]
        print(f"  {side} {i}: own status={own['status']} outcome={own['outcome']} rules={sorted(own['rule_ids'])} "
              f"| other status={other['status']} outcome={other['outcome']} rules={sorted(other['rule_ids'])}")
    # also the plain blocked-set diff ids with rule ids
    mresp = {r["id"]: r for r in map(json.loads, open(f"{MOD_RUN[pl]}/responses.jsonl"))}
    cresp = {r["id"]: r for r in map(json.loads, open(f"{COR_RUN[pl]}/responses.jsonl"))}
    mbl = {i for i in ids if mresp[i]["blocked"]}
    cbl = {i for i in ids if cresp[i]["blocked"]}
    print(f"blocked-set diff: only-modsec {sorted(mbl-cbl)}")
    print(f"                  only-coraza {sorted(cbl-mbl)}")
    for i in sorted((mbl - cbl) | (cbl - mbl)):
        side = "only-modsec" if i in mbl - cbl else "only-coraza"
        other = co[i] if side == "only-modsec" else mo[i]
        own = mo[i] if side == "only-modsec" else co[i]
        print(f"  {side} {i}: own status={own['status']} outcome={own['outcome']} rules={sorted(own['rule_ids'])} "
              f"| other status={other['status']} outcome={other['outcome']} rules={sorted(other['rule_ids'])}")


def part_b(pl):
    mr, cr = rule_sets(MOD_RUN[pl]), rule_sets(COR_RUN[pl])
    mo, co = outcomes(MOD_RUN[pl]), outcomes(COR_RUN[pl])
    ids = set(mo) & set(co)
    only_cor_rules = Counter()
    masked = Counter()
    unmasked = Counter()
    unmasked_by_rule = Counter()
    for i in ids:
        extra = cr.get(i, set()) - mr.get(i, set()) - THRESHOLD
        for r in extra:
            only_cor_rules[r] += 1
            if mo[i]["outcome"] in WORST:
                masked[r] += 1
            else:
                unmasked[r] += 1
                unmasked_by_rule[r] += 1
    total = sum(only_cor_rules.values())
    # share of only-Coraza-match samples whose ModSecurity block was driven
    # ONLY by the policy rule 920420 (no detection, no other policy rule)
    only920420 = 0
    n_extra_samples = 0
    for i in ids:
        extra = cr.get(i, set()) - mr.get(i, set()) - THRESHOLD
        if not extra:
            continue
        n_extra_samples += 1
        nonthr = {r for r in mr.get(i, set()) if r not in THRESHOLD}
        if nonthr == {"920420"}:
            only920420 += 1
    print(f"samples with >=1 only-Coraza rule match: {n_extra_samples}; of those, ModSecurity block "
          f"driven only by 920420: {only920420} ({100*only920420/max(n_extra_samples,1):.1f}%)")
    print(f"\n### PL{pl} only-Coraza rule matches: total {total}; masked (sample already worst-case on modsec) "
          f"{sum(masked.values())}; unmasked {sum(unmasked.values())}")
    print("top 15 only-Coraza rules by samples:")
    for r, n in only_cor_rules.most_common(15):
        print(f"  {r}: samples {n} (masked {masked[r]}, unmasked {unmasked[r]})")
    print(f"920420 share of only-Coraza matches: {only_cor_rules.get('920420', 0)}/{total}")
    print(f"unmasked samples (not worst-case on either engine): {sum(unmasked.values())}")
    print("top unmasked-by-rule:", dict(unmasked_by_rule.most_common(10)))
    return only_cor_rules


def coraza_match_details(run_log, want_ids):
    """sample_id -> {rule_id: (variable_class, argname_len, matched_len)}.

    variable_class is the CRS transaction variable (ARGS, ARGS_NAMES,
    REQUEST_BODY, ...); any argument NAME is reduced to its LENGTH so no
    recorded data is printed (rule 25).
    """
    out = defaultdict(dict)
    var_re = re.compile(r"found within ([A-Z_0-9]+)(?::([^\s\]]*))?")
    for line in open(run_log):
        if f'"9' not in line:
            continue
        e = json.loads(line)
        hdrs = {k.lower(): v for k, v in (e["transaction"]["request"].get("headers") or {}).items()}
        v = hdrs.get("x-kortex-sample-id") or [""]
        sid = v[0] if isinstance(v, list) else v
        if sid not in want_ids:
            continue
        for m in e.get("messages") or []:
            em = m.get("error_message") or ""
            idm = re.search(r'\[id "(\d+)"\]', em)
            if not idm or idm.group(1) not in want_ids[sid]:
                continue
            dm = re.search(r'\[data "Matched Data: (.*?) found within ', em)
            vm = var_re.search(em)
            if vm:
                vclass, argname = vm.group(1), vm.group(2) or ""
                details = (vclass, len(argname), len(dm.group(1)) if dm else None)
            else:
                details = (None, None, len(dm.group(1)) if dm else None)
            out[sid][idm.group(1)] = details
    return out


def modsec_match_details(run_log, want_ids):
    """sample_id -> {rule_id|'__all__': [(variable_class, argname_len, matched_len)]}.

    '__all__' collects every rule's match in the sample (used for the
    same-variable-exists check); argument NAMES are reduced to lengths
    (rule 25).
    """
    out = defaultdict(lambda: defaultdict(list))
    var_re = re.compile(r"against variable `([A-Z_0-9]+)(?::([^'`]*))?'")
    ref_re = re.compile(r"\bo(\d+),(\d+)")
    for line in open(run_log):
        if '"messages"' not in line:
            continue
        e = json.loads(line)
        t = e["transaction"]
        hdrs = {k.lower(): v for k, v in (t["request"].get("headers") or {}).items()}
        v = hdrs.get("x-kortex-sample-id") or [""]
        sid = v[0] if isinstance(v, list) else v
        if sid not in want_ids:
            continue
        for m in t.get("messages") or []:
            rid = str(m.get("ruleId") or "")
            match = (m.get("details") or {}).get("match") or ""
            vm = var_re.search(match)
            # first o,len pair = matched-data offset/length in the target
            refs = ref_re.findall(match[:400])
            ln = int(refs[0][1]) if refs else None
            if vm:
                out[sid]["__all__"].append((vm.group(1), len(vm.group(2) or ""), ln))
            if rid in want_ids[sid]:
                out[sid][rid].append((vm.group(1) if vm else None,
                                      len(vm.group(2) or "") if vm else None, ln))
    return out


def part_d(pl, only_cor_rules):
    top5 = [r for r, _ in only_cor_rules.most_common(5)]
    print(f"\n### PL{pl} top-5 only-Coraza rules match-shape check (3 samples each, seed-0 first-sorted)")
    # choose samples: for each rule, ids where coraza matched it and modsec did not
    mr, cr = rule_sets(MOD_RUN[pl]), rule_sets(COR_RUN[pl])
    want = defaultdict(set)
    chosen = {}
    for r in top5:
        cands = sorted(i for i in cr if r in cr.get(i, set()) and r not in mr.get(i, set()))
        chosen[r] = cands[:3]
        for i in chosen[r]:
            want[i].add(r)
    cor_d = coraza_match_details(f"{COR_RUN[pl]}/coraza-audit.log", dict(want))
    mod_d = modsec_match_details(f"{MOD_RUN[pl]}/modsec-audit.log", dict(want))
    for r in top5:
        print(f"  rule {r}:")
        for i in chosen[r]:
            cv, al, cl = cor_d.get(i, {}).get(r, (None, None, None))
            allvars = mod_d.get(i, {}).get("__all__", [])
            same_var = any(v == cv for v, _, _ in allvars)
            print(f"    {i}: coraza variable={cv} argname_len={al} matched_len={cl} | "
                  f"modsec same-variable-class-present={same_var} "
                  f"modsec variable-classes={sorted({v for v, _, _ in allvars})}")


if __name__ == "__main__":
    for pl in (1, 2):
        part_a(pl)
        oc = part_b(pl)
        part_d(pl, oc)
