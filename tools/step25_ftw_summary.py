#!/usr/bin/env python3
"""Step-25: summaries and per-test comparisons of go-ftw runs.

  step25_ftw_summary.py one <run-dir>            counts of one run
  step25_ftw_summary.py compact <events.jsonl> <run-dir>   write events-counts.json and events-nonpass.jsonl
  step25_ftw_summary.py table <base-dir> <run>...  one line per run
  step25_ftw_summary.py diff <run-dir-a> <run-dir-b>   per-test differences
  step25_ftw_summary.py failed <run-dir> [<ref-run-dir>] [--tests <dir>] [--overrides <yaml>]
                                                 every failed test with what it expected and what was logged
  step25_ftw_summary.py groups <run-dir> [--probe <probe.txt>] [--diag <label>=<run-dir>]... [--ref <run-dir>]
                                                 every failed test in exactly one group

A run directory holds go-ftw's `-o json --report-triggered-rules` output as
ftw.json and, for engine runs, the compact form of the engine's events.
"""
import collections
import json
import os
import re
import sys

CLASSES = ("success", "failed", "skipped", "ignored", "forced-pass", "forced-fail")


def load(run_dir):
    path = os.path.join(run_dir, "ftw.json")
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    if not text.strip():
        raise SystemExit(f"{path}: empty (go-ftw wrote no result)")
    doc = json.loads(text)
    doc["_aborted"] = load_aborted(run_dir)
    doc["_unsent"] = load_aborted(run_dir, "unsent.txt")
    return doc


def load_aborted(run_dir, name="aborted.txt"):
    """Test ids that stopped go-ftw (retry_once, failed twice) and were then
    excluded: go-ftw lists them as skipped, they count as failed. With
    name="unsent.txt": tests go-ftw itself refused to send; they stay skipped."""
    path = os.path.join(run_dir, name)
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as fh:
        return [line.strip() for line in fh.read().split("\n") if line.strip()]


def results(doc):
    """test id -> class. A test listed in two classes is an error. A test
    that aborted the runner is `failed`, whatever go-ftw lists it as."""
    out = {}
    for cls in CLASSES:
        for tid in doc.get(cls) or []:
            if tid in out:
                raise SystemExit(f"test {tid} is in {out[tid]} and in {cls}")
            out[tid] = cls
    for tid in doc.get("_aborted") or []:
        out[tid] = "failed"
    return out


def triggered(doc, tid):
    """Sorted rule ids go-ftw found in the log for a test (all stages)."""
    ids = set()
    for stage in (doc.get("triggered-rules") or {}).get(tid) or []:
        ids.update(stage or [])
    return sorted(ids)


def rule_file_of(tid):
    return tid.split("-")[0]


def family(tid):
    """The CRS rule file prefix: 920, 942, 95x ..."""
    return rule_file_of(tid)[:3]


def events_by_decision(run_dir):
    """Counts of the engine's events by decision. A run directory holds either
    the whole events.jsonl or events-counts.json written by `compact`."""
    counts_path = os.path.join(run_dir, "events-counts.json")
    if os.path.exists(counts_path):
        with open(counts_path, encoding="utf-8") as fh:
            return collections.Counter(json.load(fh))
    path = os.path.join(run_dir, "events.jsonl")
    if not os.path.exists(path):
        return None
    return count_events(path)[0]


def count_events(path):
    counts = collections.Counter()
    kept = []
    with open(path, encoding="utf-8") as fh:
        for line in fh.read().split("\n"):
            if not line.strip():
                continue
            try:
                ev = json.loads(line)
            except ValueError:
                counts["unparsed"] += 1
                kept.append(line)
                continue
            decision = str(ev.get("decision"))
            counts[decision] += 1
            if decision != "pass":
                kept.append(line)
    return counts, kept


def cmd_compact(events_path, run_dir):
    """Durable form of an events file: counts by decision and every event that
    is not a plain pass (the pass events carry no sample id in these runs)."""
    counts, kept = count_events(events_path)
    with open(os.path.join(run_dir, "events-counts.json"), "w", encoding="utf-8") as fh:
        json.dump(dict(sorted(counts.items())), fh)
        fh.write("\n")
    with open(os.path.join(run_dir, "events-nonpass.jsonl"), "w", encoding="utf-8") as fh:
        for line in kept:
            fh.write(line + "\n")


def counts_of(doc):
    res = results(doc)
    c = collections.Counter(res.values())
    return res, c


def one_line(name, doc):
    res, c = counts_of(doc)
    aborted = doc.get("_aborted") or []
    # go-ftw's `run` counts the excluded (skipped) tests too
    run = doc.get("run") or 0
    total = len(res)
    passed = c["success"] + c["forced-pass"]
    rate = f"{passed}/{run} = {100.0 * passed / run:.2f}%" if run else "no tests run"
    line = (f"{name}: tests listed {total}, run {run}, passed {c['success']}, failed {c['failed']}, "
            f"ignored {c['ignored']}, skipped {c['skipped']}, forced-pass {c['forced-pass']}, "
            f"forced-fail {c['forced-fail']}; pass rate (denominator: every test go-ftw lists as run, the ones that stopped it included) {rate}")
    if aborted:
        line += (f"; {len(aborted)} of the failed tests stopped go-ftw (retry_once, failed twice) and were "
                 f"excluded from the restart: {' '.join(aborted)}")
    if doc.get("_unsent"):
        line += (f"; {len(doc['_unsent'])} of the skipped tests were not sent because go-ftw refused to "
                 f"build the request: {' '.join(doc['_unsent'])}")
    return line


def cmd_one(run_dir):
    doc = load(run_dir)
    print("== " + one_line(os.path.basename(run_dir.rstrip("/")), doc))
    res, _ = counts_of(doc)
    fam = collections.Counter(family(t) for t, cls in res.items() if cls == "failed")
    if fam:
        print("== failed by rule file prefix: " + ", ".join(f"{k}: {v}" for k, v in sorted(fam.items())))
    ev = events_by_decision(run_dir)
    if ev is not None:
        print("== engine events by decision: " + (", ".join(f"{k} {v}" for k, v in sorted(ev.items())) or "none"))


def cmd_table(base, names):
    print("| run | tests run | passed | failed | ignored | skipped | pass rate |")
    print("|---|---|---|---|---|---|---|")
    for name in names:
        doc = load(os.path.join(base, name))
        res, c = counts_of(doc)
        run = doc.get("run") or 0
        passed = c["success"] + c["forced-pass"]
        rate = f"{passed}/{run} = {100.0 * passed / run:.2f}%" if run else "-"
        print(f"| {name} | {run} | {c['success']} | {c['failed']} | {c['ignored']} | {c['skipped']} | {rate} |")


def cmd_diff(dir_a, dir_b):
    a, b = load(dir_a), load(dir_b)
    ra, rb = results(a), results(b)
    na, nb = os.path.basename(dir_a.rstrip("/")), os.path.basename(dir_b.rstrip("/"))
    ids = sorted(set(ra) | set(rb), key=sort_key)
    differ = [t for t in ids if ra.get(t, "absent") != rb.get(t, "absent")]
    same_result_other_rules = [t for t in ids if t in ra and t in rb and ra[t] == rb[t]
                               and triggered(a, t) != triggered(b, t)]
    print(f"== {na} against {nb}: {len(ids)} test ids in the union, {len(differ)} with a different result, "
          f"{len(same_result_other_rules)} with the same result and a different logged rule-id set")
    trans = collections.Counter((ra.get(t, "absent"), rb.get(t, "absent")) for t in differ)
    for (x, y), n in sorted(trans.items()):
        print(f"   {x} -> {y}: {n}")
    for t in differ:
        print(f"   {t}: {na} {ra.get(t, 'absent')} {triggered(a, t)} | {nb} {rb.get(t, 'absent')} {triggered(b, t)}")
    for t in same_result_other_rules:
        only_a = sorted(set(triggered(a, t)) - set(triggered(b, t)))
        only_b = sorted(set(triggered(b, t)) - set(triggered(a, t)))
        print(f"   {t} ({ra[t]}): only {na} {only_a} | only {nb} {only_b}")


def sort_key(tid):
    m = re.match(r"^(\d+)-(\d+)$", tid)
    return (int(m.group(1)), int(m.group(2))) if m else (10 ** 9, 0, tid)


# --- expectations of a test, read from the yaml without a yaml library -------

def test_expectations(tests_dir):
    """test id -> {'expect_ids': [...], 'no_expect_ids': [...], 'status': ..., 'uri': ..., 'method': ...,
    'version': ..., 'encoded': bool, 'file': ...} for the LAST stage that has an output block.

    The CRS test files are regular enough to be read line by line: `rule_id:`
    at column 0, `- test_id: N` per test, then keys inside `input:` and
    `output:`. Anything this reader cannot place is left out, never guessed.
    """
    out = {}
    for root, _dirs, files in os.walk(tests_dir):
        for name in sorted(files):
            if not name.endswith((".yaml", ".yml")):
                continue
            path = os.path.join(root, name)
            rule_id = None
            cur = None
            section = None
            list_key = None
            with open(path, encoding="utf-8") as fh:
                for raw in fh.read().split("\n"):
                    line = raw.rstrip()
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    m = re.match(r"^rule_id:\s*(\d+)", line)
                    if m:
                        rule_id = m.group(1)
                        continue
                    m = re.match(r"^\s*- test_id:\s*(\d+)", line)
                    if m and rule_id:
                        cur = {"expect_ids": [], "no_expect_ids": [], "file": os.path.relpath(path, tests_dir)}
                        out[f"{rule_id}-{m.group(1)}"] = cur
                        section = None
                        list_key = None
                        continue
                    if cur is None:
                        continue
                    if re.match(r"^\s*(- )?input:", line):
                        section, list_key = "input", None
                        continue
                    if re.match(r"^\s*output:", line):
                        section, list_key = "output", None
                        continue
                    if section == "input":
                        m = re.match(r"^\s*(uri|method|version):\s*(.*)$", line)
                        if m:
                            cur[m.group(1)] = m.group(2).strip().strip("'\"")[:200]
                        elif re.match(r"^\s*encoded_request:", line):
                            cur["encoded"] = True
                    elif section == "output":
                        m = re.match(r"^\s*status:\s*(.+)$", line)
                        if m:
                            cur["status"] = m.group(1).strip()
                            list_key = None
                            continue
                        m = re.match(r"^\s*(expect_ids|no_expect_ids):\s*(.*)$", line)
                        if m:
                            list_key = m.group(1)
                            cur[list_key].extend(re.findall(r"\d+", m.group(2)))
                            continue
                        m = re.match(r"^\s*-\s*(\d+)\s*$", line)
                        if m and list_key:
                            cur[list_key].append(m.group(1))
                            continue
                        if re.match(r"^\s*(log|response_contains|retry_once|isolated):", line):
                            list_key = None
    return out


def override_ids(path):
    """test ids named in a go-ftw platform overrides file."""
    ids = set()
    rule = None
    with open(path, encoding="utf-8") as fh:
        for line in fh.read().split("\n"):
            m = re.match(r"^\s*- rule_id:\s*(\d+)", line)
            if m:
                rule = m.group(1)
                continue
            m = re.match(r"^\s*test_ids:\s*\[(.*)\]", line)
            if m and rule:
                for n in re.findall(r"\d+", m.group(1)):
                    ids.add(f"{rule}-{n}")
    return ids


def cmd_failed(argv):
    run_dir = argv[0]
    ref_dir = None
    tests_dir = None
    overrides = None
    i = 1
    while i < len(argv):
        if argv[i] == "--tests":
            tests_dir = argv[i + 1]
            i += 2
        elif argv[i] == "--overrides":
            overrides = argv[i + 1]
            i += 2
        else:
            ref_dir = argv[i]
            i += 1
    doc = load(run_dir)
    res = results(doc)
    ref_doc = load(ref_dir) if ref_dir else None
    ref_res = results(ref_doc) if ref_doc else {}
    exp = test_expectations(tests_dir) if tests_dir else {}
    ov = override_ids(overrides) if overrides else set()
    failed = sorted((t for t, cls in res.items() if cls == "failed"), key=sort_key)
    name = os.path.basename(run_dir.rstrip("/"))
    print(f"== {name}: {len(failed)} failed tests")
    if ref_doc:
        both = [t for t in failed if ref_res.get(t) == "failed"]
        print(f"== of these, failed by the reference too: {len(both)}; passed by the reference: "
              f"{len([t for t in failed if ref_res.get(t) == 'success'])}; other: "
              f"{len([t for t in failed if ref_res.get(t) not in ('failed', 'success')])}")
        ref_only = sorted((t for t, cls in ref_res.items() if cls == "failed" and res.get(t) != "failed"), key=sort_key)
        print(f"== failed by the reference and not by {name}: {len(ref_only)}: {' '.join(ref_only)}")
    if ov:
        print(f"== failed tests named in the overrides file: {len([t for t in failed if t in ov])}")
    print("| test | file | expects | status wanted | logged ids | reference | in CRS overrides |")
    print("|---|---|---|---|---|---|---|")
    for t in failed:
        e = exp.get(t, {})
        wants = []
        if e.get("expect_ids"):
            wants.append("ids " + ",".join(e["expect_ids"]))
        if e.get("no_expect_ids"):
            wants.append("not " + ",".join(e["no_expect_ids"]))
        if e.get("encoded"):
            wants.append("(raw request)")
        ref = ref_res.get(t, "-") if ref_doc else "-"
        if ref_doc and ref != "-":
            ref = f"{ref} {triggered(ref_doc, t)}"
        print(f"| {t} | {e.get('file', '?')} | {'; '.join(wants) or '?'} | {e.get('status', '-')} | "
              f"{triggered(doc, t)} | {ref} | {'yes' if t in ov else 'no'} |")


def probe_framing(path):
    """Test ids for which the per-test probe recorded a framing answer of the gate."""
    out = set()
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            cells = [c.strip() for c in line.split("|")]
            if len(cells) >= 4 and re.match(r"^\d+-\d+$", cells[1]) and cells[2].startswith("framing "):
                out.add(cells[1])
    return out


def cmd_groups(argv):
    """Each failed test goes to the first group that holds, in this order:
    its rule is a response rule (files 950 to 959); the probe shows the gate
    refused the request; it passes in a DIAGNOSTIC run (in the order given);
    the reference fails it too; otherwise UNEXPLAINED."""
    run_dir = argv[0]
    probe = None
    diags = []
    ref_dir = None
    i = 1
    while i < len(argv):
        if argv[i] == "--probe":
            probe = argv[i + 1]
        elif argv[i] == "--diag":
            label, _, path = argv[i + 1].partition("=")
            diags.append((label, results(load(path))))
        elif argv[i] == "--ref":
            ref_dir = argv[i + 1]
        else:
            raise SystemExit(f"groups: unknown argument {argv[i]}")
        i += 2
    res = results(load(run_dir))
    framing = probe_framing(probe) if probe else set()
    ref_res = results(load(ref_dir)) if ref_dir else {}
    names = (["response rule", "refused by the gate"] + [label for label, _ in diags]
             + ["failed by the reference too", "UNEXPLAINED"])
    groups = {n: [] for n in names}
    failed = sorted((t for t, cls in res.items() if cls == "failed"), key=sort_key)
    for t in failed:
        if family(t).startswith("95"):
            groups["response rule"].append(t)
        elif t in framing:
            groups["refused by the gate"].append(t)
        else:
            for label, diag_res in diags:
                if diag_res.get(t) == "success":
                    groups[label].append(t)
                    break
            else:
                if ref_res.get(t) == "failed":
                    groups["failed by the reference too"].append(t)
                else:
                    groups["UNEXPLAINED"].append(t)
    print(f"== {os.path.basename(run_dir.rstrip('/'))}: {len(failed)} failed tests")
    for n in names:
        print(f"== {n}: {len(groups[n])}: {' '.join(groups[n])}")
    print(f"== sum of the groups: {sum(len(v) for v in groups.values())}")


def main(argv):
    if len(argv) >= 2 and argv[0] == "one":
        cmd_one(argv[1])
    elif len(argv) == 3 and argv[0] == "compact":
        cmd_compact(argv[1], argv[2])
    elif len(argv) >= 3 and argv[0] == "table":
        cmd_table(argv[1], argv[2:])
    elif len(argv) == 3 and argv[0] == "diff":
        cmd_diff(argv[1], argv[2])
    elif len(argv) >= 2 and argv[0] == "failed":
        cmd_failed(argv[1:])
    elif len(argv) >= 2 and argv[0] == "groups":
        cmd_groups(argv[1:])
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
