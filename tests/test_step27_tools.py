"""Tests for tools/step27_parsing_diff.py and the body parsing of the Python backend (hand-written inputs)."""
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_cases_have_unique_ids_and_every_body_family_has_a_control():
    d = load("step27_parsing_diff")
    cases = d.build_cases()
    assert len({c["id"] for c in cases}) == len(cases)
    assert sum(1 for c in cases if c["kind"] == "step23") == 61
    for fam in ("urlencoded", "multipart", "json", "xml"):
        assert [c["id"] for c in cases if c["family"] == fam and c["control"]] == [{"urlencoded": "ue", "multipart": "mp", "json": "json", "xml": "xml"}[fam] + "-control"]
    # every raw request carries its sample id, so the engine's events can be matched to it
    for c in cases:
        if c["kind"] != "step23":
            assert ("X-Kortex-Sample-Id: " + c["id"]).encode() in c["raw"]


def test_classify_names_the_bypass_only_when_the_request_was_forwarded():
    d = load("step27_parsing_diff")
    case = {"canary": d.CANARY, "second_id": None}
    view = {"path_decoded": "/body", "query_decoded": {}, "body_len": 1, "body_sha256": "x",
            "body_parse": {"kind": "json", "strings": ["q", d.CANARY], "file_strings": [], "error": None}}
    direct = {"status": 200, "view": view, "error": None}
    forwarded = {"status": 200, "decision": None, "view": view, "forwarded": True, "answers": 1, "second_passed": False, "events": [{"decision": "pass"}]}
    blocked = {"status": 403, "decision": "block", "view": None, "forwarded": False, "answers": 1, "second_passed": False, "events": [{"decision": "block"}]}
    assert ("canary-reaches-parser", "the backend's json parser yields the canary") in d.classify(case, forwarded, direct)
    assert "canary-reaches-parser" not in [c for c, _ in d.classify(case, blocked, direct)]
    file_view = dict(view, body_parse={"kind": "multipart", "strings": ["q", "x.txt"], "file_strings": [d.CANARY], "error": None})
    fwd_file = dict(forwarded, view=file_view)
    classes = [c for c, _ in d.classify(case, fwd_file, {"status": 200, "view": file_view, "error": None})]
    assert "canary-in-file-part" in classes and "canary-reaches-parser" not in classes


def test_a_second_request_served_is_reported():
    d = load("step27_parsing_diff")
    case = {"canary": None, "second_id": "x-second"}
    view = {"path_decoded": "/first", "query_decoded": {}, "body_len": 0, "body_sha256": "e"}
    direct = {"status": 200, "view": view, "error": None}
    one = {"status": 200, "decision": None, "view": view, "forwarded": True, "answers": 1, "second_passed": False, "events": []}
    two = dict(one, answers=2)
    passed = dict(one, second_passed=True)
    assert "second-request-served" not in [c for c, _ in d.classify(case, one, direct)]
    assert "second-request-served" in [c for c, _ in d.classify(case, two, direct)]
    assert "second-request-served" in [c for c, _ in d.classify(case, passed, direct)]


def test_engine_problem_counts_silent_refusals_and_missing_answers():
    d = load("step27_parsing_diff")
    base = {"forwarded": False, "status": 400, "decision": "framing", "events": [{"decision": "framing"}], "error": None}
    assert d.engine_problem(base) is None
    assert d.engine_problem(dict(base, forwarded=True)) is None
    assert d.engine_problem(dict(base, decision=None)) == "400 without a kortex marker"
    assert d.engine_problem(dict(base, events=[])) == "400 framing without an event"
    assert d.engine_problem(dict(base, status=None, error="no-response")) == "no answer (no-response)"


def test_python_backend_body_parsing():
    b = load("step23_parsing_backend")
    can = "<script>alert(1)</script>"
    assert can in b.parse_body("application/x-www-form-urlencoded", b"a=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")["strings"]
    mp = (b'--B\r\nContent-Disposition: form-data; name="q"\r\n\r\n' + can.encode() + b'\r\n--B\r\n'
          b'Content-Disposition: form-data; name="f"; filename="x.txt"\r\n\r\nfile-text\r\n--B--\r\n')
    got = b.parse_body("multipart/form-data; boundary=B", mp)
    assert got["kind"] == "multipart" and can in got["strings"] and "x.txt" in got["strings"] and got["file_strings"] == ["file-text"]
    assert can in b.parse_body("application/json", b'{"a":[{"q":"\\u003cscript\\u003ealert(1)\\u003c/script\\u003e"}]}')["strings"]
    assert b.parse_body("application/json", b"{broken")["error"] == "JSONDecodeError"
    assert can in b.parse_body("application/xml", b"<r><q><![CDATA[" + can.encode() + b"]]></q></r>")["strings"]
    assert b.parse_body("text/plain", b"q=1") == {"kind": "none", "strings": [], "file_strings": [], "error": None}


def test_an_event_without_a_sample_id_is_matched_by_its_position(tmp_path):
    d = load("step27_parsing_diff")
    f = tmp_path / "events.jsonl"
    f.write_text(
        '{"sample_id":"a","decision":"pass","status":0,"reason":"forwarding"}\n'
        '{"sample_id":"","decision":"framing","status":400,"reason":"parser:header-line"}\n'
        '{"sample_id":"","decision":"framing","status":400,"reason":"head-timeout"}\n')
    assert d.line_count(str(f)) == 3
    assert d.line_count(str(tmp_path / "missing")) == 0
    got = d.unnamed_events(str(f), 0, 2)
    assert got == [{"decision": "framing", "status": 400, "reason": "parser:header-line", "no_sample_id": True}]
    assert d.unnamed_events(str(f), 0, 1) == []
    assert len(d.unnamed_events(str(f), 1, 3)) == 2


def test_pl_effect_reads_rule_ids_from_the_audit_messages(tmp_path):
    e = load("step27_pl_effect")

    def entry(sid, ids):
        msgs = [{"error_message": f'Coraza: Warning. x [file "f"] [line "1"] [id "{i}"] [rev ""]'} for i in ids]
        return json.dumps({"transaction": {"request": {"headers": {"x-kortex-sample-id": [sid]}}}, "messages": msgs})

    a, b = tmp_path / "pl1.log", tmp_path / "pl2.log"
    a.write_text(entry("c1", [941100]) + "\n" + entry("c2", [942100]) + "\nnot json\n")
    b.write_text(entry("c1", [941100, 941320]) + "\n" + entry("c2", [942100]) + "\n")
    assert e.rule_ids(str(a)) == {"c1": {941100}, "c2": {942100}}
    lines = e.compare(e.rule_ids(str(a)), e.rule_ids(str(b)))
    assert "differs between PL1 and PL2 for 1 of 2" in lines[0]
    assert lines[1].endswith("1: 941320")
