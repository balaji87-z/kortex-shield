"""Step-24 tools: per-case comparison of two parsing-differential runs."""
import importlib.util
import json
import pathlib

TOOLS = pathlib.Path(__file__).resolve().parents[1] / "tools"


def load(name):
    spec = importlib.util.spec_from_file_location(name, TOOLS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _row(cid, status, decision, forwarded, events, dis=()):
    eng = {"status": status, "decision": decision, "forwarded": forwarded, "events": list(events)}
    return {"id": cid, "engine": {"python": eng, "go": eng},
            "disagreements": {"python": [{"class": c} for c in dis], "go": [{"class": c} for c in dis]}}


def test_answer_names_marker_and_event():
    pc = load("step24_parsing_compare")
    assert pc.answer({"forwarded": True, "status": 200}) == "forwarded"
    assert pc.answer({"forwarded": False, "status": 400, "decision": None, "events": []}) == "400 no marker, no event"
    ev = [{"decision": "framing", "reason": "parser:content-length"}]
    assert pc.answer({"forwarded": False, "status": 400, "decision": "framing", "events": ev}) == \
        "400 kortex-decision=framing, event parser:content-length"
    assert pc.answer({"forwarded": False, "status": 400, "decision": "framing", "events": []}) == \
        "400 kortex-decision=framing, no event"


def test_compare_lists_changed_cases_and_silent_refusals(tmp_path):
    pc = load("step24_parsing_compare")
    fr = [{"decision": "framing", "reason": "parser:transfer-encoding"}]
    before = [_row("a", 501, None, False, [], ["engine-refuses-backend-accepts"]),
              _row("b", 200, None, True, [{"decision": "pass", "reason": "forwarding"}]),
              _row("gone", 200, None, True, [])]
    after = [_row("a", 400, "framing", False, fr, ["engine-refuses-backend-accepts"]),
             _row("b", 200, None, True, [{"decision": "pass", "reason": "forwarding"}])]
    paths = []
    for name, rows in (("before", before), ("after", after)):
        p = tmp_path / f"{name}.jsonl"
        p.write_text("".join(json.dumps(r) + "\n" for r in rows))
        paths.append(str(p))
    out = pc.compare(pc.load(paths[0]), pc.load(paths[1]))
    assert out[0] == "== cases in both runs: 2; in one run only: 1: gone"
    assert "== engine in front of the python backend: answer changed in 1 of 2 cases, unchanged in 1" in out
    assert "   1 x  501 no marker  ->  400 kortex-decision=framing" in out
    assert "   a: 501 no marker, no event  ->  400 kortex-decision=framing, event parser:transfer-encoding" in out
    assert "== disagreement classes against the python backend changed in 0 of 2 cases" in out
    assert "== before: refused with no kortex marker: 1: a" in out
    assert "== after: refused with no kortex marker: 0" in out


# ---------- own-dataset summary ----------

def _attack(i, family="sqli", h="0933fb66"):
    return {"id": i, "label": "attack", "family": family, "method": "GET", "path": "/"}


def test_scenario_counts_distinct_payloads_and_endpoints():
    s = load("step24_own_summary")
    attacks = [_attack("sqli-01f86083-q"), _attack("sqli-01f86083-login"),
               _attack("actv0-json-sqli-0933fb66"), _attack("xss-01f86083-q", family="xss")]
    assert s.scenario_counts(attacks) == (4, "attack", 3, "distinct payloads")
    benign = [{"id": "a", "label": "benign", "method": "GET", "path": "/x"},
              {"id": "b", "label": "benign", "method": "GET", "path": "/x"},
              {"id": "c", "label": "benign", "method": "POST", "path": "/x"}]
    assert s.scenario_counts(benign) == (3, "benign", 2, "distinct endpoints")


def test_run_lines_attack_recall_best_and_worst_never_drop_a_sample():
    s = load("step24_own_summary")
    manifest = [_attack("sqli-00000001-q"), _attack("sqli-00000002-q"), _attack("sqli-00000003-q"),
                _attack("xss-00000004-q", family="xss")]
    outcomes = [{"id": "sqli-00000001-q", "outcome": "waf_block"},
                {"id": "sqli-00000002-q", "outcome": "waf_fail_closed_400"},
                {"id": "sqli-00000003-q", "outcome": "waf_pass"}]   # the xss sample has no row: counted as error
    lines = s.run_lines("attacks-v0", "run", manifest, outcomes)
    assert lines[0] == ("run: requests 4, distinct payloads 4; outcomes: error 1, waf_block 1, "
                        "waf_fail_closed_400 1, waf_pass 1")
    assert "recall best case (only waf_block) 1/4 = 25.00%" in lines[1]
    assert "worst case (every outcome that is not a pass) 3/4 = 75.00%" in lines[1]
    assert "IN-SAMPLE" in lines[1]
    assert lines[2] == "    per family, blocked of requests: sqli 1/3, xss 0/1"


def test_run_lines_counts_only_and_benign():
    s = load("step24_own_summary")
    manifest = [_attack("encd-query-plain-sqli-00000001"), _attack("encd-query-plain-sqli-00000002")]
    lines = s.run_lines("encoding-diff-v0", "run", manifest, [{"id": manifest[0]["id"], "outcome": "waf_block"},
                                                              {"id": manifest[1]["id"], "outcome": "waf_pass"}])
    assert "%" not in lines[1] and "blocked 1 of 2" in lines[1] and "rule 35" in lines[1]
    benign = [{"id": "a", "label": "benign", "method": "GET", "path": "/x"},
              {"id": "b", "label": "benign", "method": "GET", "path": "/y"}]
    lines = s.run_lines("benign-hard-v0", "run", benign, [{"id": "a", "outcome": "waf_block"},
                                                          {"id": "b", "outcome": "inconsistent"}])
    assert "potential false positives (hard benign, held-out)" in lines[1]
    assert "best case (only waf_block) 1/2 = 50.00%" in lines[1] and "2/2 = 100.00%" in lines[1]


def test_compare_lists_status_worst_case_and_rule_differences():
    s = load("step24_own_summary")
    a = [{"id": "x", "status": 403, "outcome": "waf_block", "rule_ids": ["942100", "949110"]},
         {"id": "y", "status": 200, "outcome": "waf_pass", "rule_ids": []},
         {"id": "z", "status": 403, "outcome": "waf_block", "rule_ids": ["941100"]}]
    b = [{"id": "x", "status": 403, "outcome": "waf_block", "rule_ids": ["942100", "942130", "949110"]},
         {"id": "y", "status": 403, "outcome": "waf_block", "rule_ids": ["920350"]},
         {"id": "z", "status": 403, "outcome": "waf_block", "rule_ids": ["941100"]}]
    out = s.compare(a, b, "patched", "stock")
    assert out[0] == ("    patched against stock: 3 sample ids; status differs in 1; worst-case set differs in 1; "
                      "rule-id set differs in 2")
    assert any(l.startswith("      x: status 403 / 403") and "only in stock ['942130']" in l for l in out)
    assert any(l.startswith("      y: status 200 / 403") for l in out)
    assert not any(l.startswith("      z:") for l in out)


def test_rule18_and_status_diff():
    s = load("step24_own_summary")
    idx = [{"rule_ids": ["920350", "949110"]}, {"rule_ids": ["920350"]}, {"rule_ids": []}, {"rule_ids": ["1"]},
           {"rule_ids": ["2"]}, {"rule_ids": ["3"]}]
    assert s.rule18(idx) == "    rule 18: 6 audit entries; rule ids in >=20% of them: 920350=2"
    diff, total = s.status_diff([{"id": "a", "status": 200}, {"id": "b", "status": 403}],
                                [{"id": "a", "status": 403}, {"id": "b", "status": 403}, {"id": "c", "status": 200}])
    assert diff == ["a", "c"] and total == 3
