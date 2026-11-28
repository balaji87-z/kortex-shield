"""Tests for the step-25 tools (hand-written inputs, no run data)."""
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"


def load(name):
    spec = importlib.util.spec_from_file_location(name, TOOLS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def write_run(tmp_path, name, doc, aborted=(), unsent=(), events=None):
    run = tmp_path / name
    run.mkdir()
    (run / "ftw.json").write_text(json.dumps(doc))
    if aborted:
        (run / "aborted.txt").write_text("".join(t + "\n" for t in aborted))
    if unsent:
        (run / "unsent.txt").write_text("".join(t + "\n" for t in unsent))
    if events is not None:
        (run / "events.jsonl").write_text("".join(json.dumps(e) + "\n" for e in events))
    return run


def doc(success=(), failed=(), skipped=(), triggered=None):
    return {"run": len(success) + len(failed) + len(skipped), "success": list(success), "failed": list(failed),
            "skipped": list(skipped), "ignored": [], "forced-pass": [], "forced-fail": [],
            "triggered-rules": triggered or {}}


def test_a_test_that_stopped_the_runner_counts_as_failed(tmp_path, capsys):
    fs = load("step25_ftw_summary")
    run = write_run(tmp_path, "r", doc(success=["911100-1", "911100-2"], failed=["920100-5"], skipped=["959100-1"]),
                    aborted=["959100-1"])
    loaded = fs.load(str(run))
    res = fs.results(loaded)
    assert res["959100-1"] == "failed"
    fs.cmd_one(str(run))
    out = capsys.readouterr().out
    assert "run 4, passed 2, failed 2" in out
    assert "2/4 = 50.00%" in out
    assert "959100-1" in out
    assert "950: " not in out and "959: 1" in out and "920: 1" in out


def test_a_test_the_runner_refused_to_send_stays_skipped(tmp_path, capsys):
    fs = load("step25_ftw_summary")
    run = write_run(tmp_path, "r", doc(success=["911100-1"], skipped=["921140-1"]), unsent=["921140-1"])
    assert fs.results(fs.load(str(run)))["921140-1"] == "skipped"
    fs.cmd_one(str(run))
    out = capsys.readouterr().out
    assert "skipped 1" in out and "not sent because go-ftw refused" in out


def test_a_test_in_two_classes_is_an_error(tmp_path):
    fs = load("step25_ftw_summary")
    run = write_run(tmp_path, "r", doc(success=["1-1"], failed=["1-1"]))
    with pytest.raises(SystemExit):
        fs.results(fs.load(str(run)))


def test_empty_result_file_is_an_error_not_zero_tests(tmp_path):
    fs = load("step25_ftw_summary")
    run = tmp_path / "r"
    run.mkdir()
    (run / "ftw.json").write_text("")
    with pytest.raises(SystemExit):
        fs.load(str(run))


def test_diff_lists_result_changes_and_rule_id_changes(tmp_path, capsys):
    fs = load("step25_ftw_summary")
    a = write_run(tmp_path, "a", doc(success=["1-1", "1-2"], failed=["1-3"],
                                     triggered={"1-1": [[941100]], "1-2": [[942100, 949110]], "1-3": [[]]}))
    b = write_run(tmp_path, "b", doc(success=["1-1", "1-2", "1-3"],
                                     triggered={"1-1": [[941100]], "1-2": [[949110]], "1-3": [[920100]]}))
    fs.cmd_diff(str(a), str(b))
    out = capsys.readouterr().out
    assert "3 test ids in the union, 1 with a different result, 1 with the same result and a different logged rule-id set" in out
    assert "failed -> success: 1" in out
    assert "1-3: a failed [] | b success [920100]" in out
    assert "1-2 (success): only a [942100] | only b []" in out


def test_compact_keeps_counts_and_every_event_that_is_not_a_pass(tmp_path):
    fs = load("step25_ftw_summary")
    events = [{"decision": "pass", "status": 0, "reason": "forwarding"}] * 3 + [
        {"decision": "framing", "status": 400, "reason": "parser:http-version"},
        {"decision": "would_reject", "status": 0, "reason": "invalid-percent-sequence-in-query"}]
    run = write_run(tmp_path, "r", doc(success=["1-1"]), events=events)
    fs.cmd_compact(str(run / "events.jsonl"), str(run))
    assert json.loads((run / "events-counts.json").read_text()) == {"framing": 1, "pass": 3, "would_reject": 1}
    kept = [json.loads(x) for x in (run / "events-nonpass.jsonl").read_text().split("\n") if x]
    assert [e["decision"] for e in kept] == ["framing", "would_reject"]
    (run / "events.jsonl").unlink()
    assert fs.events_by_decision(str(run)) == {"framing": 1, "pass": 3, "would_reject": 1}


def test_expectations_are_read_from_the_test_files_and_never_guessed(tmp_path):
    fs = load("step25_ftw_summary")
    d = tmp_path / "tests" / "REQUEST-920"
    d.mkdir(parents=True)
    (d / "920100.yaml").write_text("""---
meta:
  author: "x"
rule_id: 920100
tests:
  - test_id: 1
    stages:
      - input:
          method: "GET"
          uri: "/a"
          version: "HTTP/1.1"
        output:
          status: 400
  - test_id: 2
    stages:
      - input:
          encoded_request: "R0VU"
        output:
          log:
            expect_ids: [920100, 920101]
            no_expect_ids:
              - 920102
""")
    exp = fs.test_expectations(str(tmp_path / "tests"))
    assert exp["920100-1"]["status"] == "400" and exp["920100-1"]["expect_ids"] == []
    assert exp["920100-1"]["uri"] == "/a" and exp["920100-1"]["method"] == "GET"
    assert exp["920100-2"]["expect_ids"] == ["920100", "920101"]
    assert exp["920100-2"]["no_expect_ids"] == ["920102"]
    assert exp["920100-2"].get("encoded") is True and "status" not in exp["920100-2"]


def test_override_ids(tmp_path):
    fs = load("step25_ftw_summary")
    p = tmp_path / "o.yaml"
    p.write_text("test_overrides:\n  - rule_id: 920100\n    test_ids: [4]\n  - rule_id: 934131\n    test_ids: [5, 7]\n")
    assert fs.override_ids(str(p)) == {"920100-4", "934131-5", "934131-7"}


def test_ruleid_diff_counts_gained_and_lost_ids_per_sample(tmp_path, capsys):
    rd = load("step25_ruleid_diff")
    for base, rows in (("a", [{"sample_id": "s1", "rule_ids": ["942130", "949110"]}, {"sample_id": "s2", "rule_ids": ["941100"]}]),
                       ("b", [{"sample_id": "s1", "rule_ids": ["949110"]}, {"sample_id": "s2", "rule_ids": ["941100"]},
                              {"sample_id": "s3", "rule_ids": ["942130"]}])):
        d = tmp_path / base / "run1"
        d.mkdir(parents=True)
        (d / "audit.index.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    assert rd.main([str(tmp_path / "a"), str(tmp_path / "b"), "run1", "missing"]) == 0
    out = capsys.readouterr().out
    assert "rule-id set differs for 2" in out
    assert "ids gained in b: {'942130': 1}; ids lost in b: {'942130': 1}" in out
    assert "missing: NOT MEASURED" in out
    assert "total samples with a different rule-id set: 2" in out


def test_groups_puts_every_failed_test_in_exactly_one_group(tmp_path, capsys):
    fs = load("step25_ftw_summary")
    failed = ["951100-1", "920430-5", "920420-2", "942432-5", "920100-5", "933100-9"]
    run = write_run(tmp_path, "engine", doc(success=["911100-1"], failed=failed))
    ref = write_run(tmp_path, "ref", doc(success=["911100-1", "951100-1", "920420-2", "942432-5", "933100-9"],
                                         failed=["920430-5", "920100-5"]))
    no_ct = write_run(tmp_path, "no-ct", doc(success=["911100-1", "920420-2"],
                                            failed=[t for t in failed if t != "920420-2"]))
    no_body = write_run(tmp_path, "no-body", doc(success=["911100-1", "942432-5"],
                                                failed=[t for t in failed if t != "942432-5"]))
    probe = tmp_path / "probe.txt"
    probe.write_text("| test | engine events | statuses | result |\n|---|---|---|---|\n"
                     "| 920430-5 | framing 400 parser:http-version (3 events in all) | 200 400 200 | failed |\n"
                     "| 920100-5 | pass 0 forwarding (3 events in all) | 200 200 200 | failed |\n")
    assert fs.main(["groups", str(run), "--probe", str(probe), "--diag", f"no allow-list={no_ct}",
                    "--diag", f"body targets={no_body}", "--ref", str(ref)]) == 0
    out = capsys.readouterr().out
    assert "6 failed tests" in out
    assert "response rule: 1: 951100-1" in out
    # refused by the gate wins over "the reference fails it too"
    assert "refused by the gate: 1: 920430-5" in out
    assert "no allow-list: 1: 920420-2" in out
    assert "body targets: 1: 942432-5" in out
    assert "failed by the reference too: 1: 920100-5" in out
    assert "UNEXPLAINED: 1: 933100-9" in out
    assert "sum of the groups: 6" in out
