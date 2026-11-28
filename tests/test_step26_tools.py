"""Tests for tools/step26_summary.py (hand-written inputs, no run data)."""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_tool():
    spec = importlib.util.spec_from_file_location("step26_summary", ROOT / "tools" / "step26_summary.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def ann(i, family, kind, point):
    return {"id": i, "family": family, "family_kind": kind, "injection_point": point, "payload": i.rsplit("-", 1)[0]}


ANN = [ann("v1-sqli-aaaaaaaa-q", "sqli", "seen-family", "q"), ann("v1-sqli-aaaaaaaa-login", "sqli", "seen-family", "login"),
       ann("v1-sqli-bbbbbbbb-q", "sqli", "seen-family", "q"), ann("v1-sqli-bbbbbbbb-login", "sqli", "seen-family", "login"),
       ann("v1-ldap-cccccccc-q", "ldap", "new-family", "q"), ann("v1-ldap-cccccccc-login", "ldap", "new-family", "login")]


def test_wilson_interval_known_values():
    t = load_tool()
    lo, hi = t.wilson(5, 10)
    assert round(lo, 4) == 0.2366 and round(hi, 4) == 0.7634
    lo, hi = t.wilson(0, 10)
    assert lo == 0.0 and round(hi, 4) == 0.2775
    lo, hi = t.wilson(10, 10)
    assert round(lo, 4) == 0.7225 and hi == 1.0
    assert t.wilson(0, 0) == (0.0, 1.0)


def test_recall_best_and_worst_case_never_drop_a_sample():
    t = load_tool()
    outcomes = [{"id": "v1-sqli-aaaaaaaa-q", "outcome": "waf_block"}, {"id": "v1-sqli-aaaaaaaa-login", "outcome": "waf_pass"},
                {"id": "v1-sqli-bbbbbbbb-q", "outcome": "waf_deny_status"}, {"id": "v1-ldap-cccccccc-q", "outcome": "inconsistent"},
                {"id": "v1-ldap-cccccccc-login", "outcome": "waf_block"}]   # v1-sqli-bbbbbbbb-login has no row
    text = "\n".join(t.run_lines("run-x", ANN, outcomes))
    assert "requests 6, distinct payloads 3" in text
    assert "error 1" in text and "inconsistent 1" in text and "waf_deny_status 1" in text   # rule 30, and no row = error
    assert "recall best case (only waf_block) 2/6 = 33.33%" in text
    assert "worst case (every outcome that is not a pass) 5/6 = 83.33%" in text
    assert "seen-family: best 1/4 = 25.00%" in text and "new-family: best 1/2 = 50.00%" in text
    assert "sqli: best 1/4 = 25.00%" in text and "ldap: best 1/2 = 50.00%" in text
    assert "q: best 1/3 = 33.33%" in text and "login: best 1/3 = 33.33%" in text
    # per payload: blocked at both points, at one, at none
    assert "payloads blocked at both injection points 0, at one 2, at none 1" in text


def test_missed_lists_every_request_that_was_not_blocked():
    t = load_tool()
    outcomes = [{"id": a["id"], "outcome": "waf_block"} for a in ANN]
    outcomes[1]["outcome"] = "waf_pass"
    outcomes[4]["outcome"] = "inconsistent"
    table, ids = t.missed(ANN, outcomes)
    assert table == {("sqli", "login"): 1, ("ldap", "q"): 1}
    assert ids == [("v1-ldap-cccccccc-q", "inconsistent"), ("v1-sqli-aaaaaaaa-login", "waf_pass")]


def test_compare_names_the_quantity_and_lists_ids():
    t = load_tool()
    a = [{"id": "x-1", "status": 403, "outcome": "waf_block", "rule_ids": ["942100", "949110"]},
         {"id": "x-2", "status": 200, "outcome": "waf_pass", "rule_ids": []},
         {"id": "x-3", "status": 403, "outcome": "waf_block", "rule_ids": ["941100", "949110"]}]
    b = [{"id": "x-1", "status": 403, "outcome": "waf_block", "rule_ids": ["942100", "942130", "949110"]},
         {"id": "x-2", "status": 403, "outcome": "waf_block", "rule_ids": ["920420", "949110"]},
         {"id": "x-3", "status": 403, "outcome": "waf_block", "rule_ids": ["941100", "949110"]}]
    lines = t.compare(a, b, "engine", "modsec")
    assert "3 sample ids; status differs in 1; worst-case set differs in 1 (only engine 0, only modsec 1); rule-id set differs in 2" in lines[0]
    text = "\n".join(lines)
    assert "x-2: status 200 / 403" in text and "only in modsec ['920420', '949110']" in text
    assert "rule ids that make up the differences: only in modsec: 920420 x1, 942130 x1, 949110 x1" in text


def test_compare_ignores_how_often_a_rule_id_is_listed():
    t = load_tool()
    a = [{"id": "x-1", "status": 403, "outcome": "waf_block", "rule_ids": ["941100", "949110"]}]
    b = [{"id": "x-1", "status": 403, "outcome": "waf_block", "rule_ids": ["941100", "941100", "949110"]}]
    assert "rule-id set differs in 0" in t.compare(a, b, "engine", "modsec")[0]
