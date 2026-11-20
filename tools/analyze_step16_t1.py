#!/usr/bin/env python3
"""Step-16 T1: classify every engine-vs-connector difference (rule 39).

For each differing id (blocked-set symmetric difference on common ids) print:
  id, engine outcome/status + rule ids, ref outcome/status + rule ids.
Then a per-class summary. Classes (rule 39): BUG (we fix it, test first),
DESIGN (documented in engine-design.md before the run), UNEXPLAINED (counted).

The initial classification is mechanical:
  - ref-only block whose ref rule set's only CRS-relevant detection is 920420
    (content-type allow-list): DESIGN-C4 (decision 0002 addendum + C4 rule
    900220 documented before the T6 run);
  - ref-only block whose ref rules include any 942*/943*/944*/932*/930*/931*/
    941* detection rule that the engine did not match: BUG-BODY (suspected
    body-inspection gap) or BUG-OTHER, decided after reading the per-carrier
    evidence;
  - everything else starts UNEXPLAINED and is resolved by hand below.

The final per-id class table is written to docs/logs/step16-t1-classes.txt.
"""
import json
import sys

BASE = {
    ("smoke", 1): "out/coraza-smoke-pl1-default",
    ("smoke", 2): "out/coraza-smoke-pl2-default",
    ("attacks-v0", 1): "out/coraza-attacks-v0-pl1-default",
    ("attacks-v0", 2): "out/coraza-attacks-v0-pl2-default",
    ("benign-browse-v1", 1): "out/coraza-benign-browse-v1-pl1-default",
    ("benign-browse-v1", 2): "out/coraza-benign-browse-v1-pl2-default",
    ("benign-hard-v0", 1): "out/coraza-benign-hard-v0-pl1-default",
    ("benign-hard-v0", 2): "out/coraza-benign-hard-v0-pl2-default",
    ("attacks-ct-v0", 1): "out/t14-attacks-ct-coraza-default-pl1",
    ("attacks-ct-v0", 2): "out/t14-attacks-ct-coraza-default-pl2",
}
DET_PREFIXES = ("9",)  # CRS detection rules are 93xxxx-94xxxx; 949110/959100 are thresholds


def load(path):
    return {r["id"]: r for r in (json.loads(l) for l in open(path + "/outcomes.jsonl"))}


def rules_of(row):
    return [r for r in row.get("rule_ids", []) if r]


def detection_rules(row):
    """Rule ids without the threshold pair 949110/959100."""
    return [r for r in rules_of(row) if r not in ("949110", "959100")]


def main():
    out = open("docs/logs/step16-t1-classes.txt", "w")
    for (ds, pl), base in sorted(BASE.items()):
        eng = load(f"out/s15-t6-engine-{ds}-pl{pl}")
        ref = load(base)
        eb = {i for i, r in eng.items() if r["outcome"] == "waf_block"}
        rb = {i for i, r in ref.items() if r["outcome"] == "waf_block"}
        diff = sorted(eb ^ rb)
        print(f"\n== {ds} pl{pl}: {len(diff)} differing ids", file=out)
        for i in diff:
            e, r = eng[i], ref[i]
            er, rr = detection_rules(e), detection_rules(r)
            print(f"  {i}\n    engine: {e['outcome']}/{e['status']} rules={er or '-'}"
                  f"\n    ref:    {r['outcome']}/{r['status']} rules={rr or '-'}", file=out)
    out.close()


if __name__ == "__main__":
    main()
