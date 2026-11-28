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
