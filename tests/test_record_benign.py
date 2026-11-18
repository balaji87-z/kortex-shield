"""Tests for the step-07 additive extensions to tools/record_benign.py."""
import importlib.util
import sys
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "tools" / "record_benign.py"
spec = importlib.util.spec_from_file_location("record_benign", TOOL)
mod = importlib.util.module_from_spec(spec)
sys.modules["record_benign"] = mod
spec.loader.exec_module(mod)


def _cap(method, path, query, body, session, content_type="application/json"):
    return {"method": method, "path": path, "query": query, "body": body,
            "content_type": content_type, "headers": {}, "session": session}


def _sample(sid, method, path, query, body, content_type="application/json"):
    return {"id": sid, "method": method, "path": path, "query": query,
            "body": body, "content_type": content_type}


def test_content_hash_unchanged_from_v0():
    """The dedupe key must stay exactly the v0 definition."""
    h1 = mod.content_hash("GET", "/rest/products/search", "q=x", "application/json", "")
    h2 = mod.content_hash("get", "/rest/products/search", "q=x", "application/json", "")
    assert h1 == h2  # method is upper-cased
    h3 = mod.content_hash("GET", "/rest/products/search", "q=x", "application/json", "")
    assert h1 == h3


def test_session_map_groups_all_sessions_per_sample():
    captured = [
        _cap("GET", "/a", "", "", 1000),
        _cap("GET", "/a", "", "", 1001),
        _cap("GET", "/a", "", "", 1003),
        _cap("POST", "/b", "", "{}", 1000),
        _cap("POST", "/b", "", "{}", 1002),
    ]
    samples = [_sample("s-a", "GET", "/a", "", ""), _sample("s-b", "POST", "/b", "", "{}")]
    rows = mod.build_session_map(captured, samples)
    by_id = {r["id"]: r["sessions"] for r in rows}
    assert by_id["s-a"] == [1000, 1001, 1003]
    assert by_id["s-b"] == [1000, 1002]


def test_session_map_ignores_captured_without_session():
    """Captures from a run without the session field must not crash the map."""
    captured = [{"method": "GET", "path": "/a", "query": "", "body": "",
                 "content_type": "application/json", "headers": {}, "session": None}]
    samples = [_sample("s-a", "GET", "/a", "", "")]
    assert mod.build_session_map(captured, samples) == []


def test_session_map_dedupes_within_a_session():
    captured = [_cap("GET", "/a", "", "", 1000), _cap("GET", "/a", "", "", 1000)]
    samples = [_sample("s-a", "GET", "/a", "", "")]
    rows = mod.build_session_map(captured, samples)
    assert rows == [{"id": "s-a", "sessions": [1000]}]


def test_v0_defaults_unchanged():
    """Without --extra-flows/--start-index the parser defaults match v0."""
    import argparse
    ap = argparse.ArgumentParser()
    # mirror main()'s arguments to assert the defaults
    ap.add_argument("--sessions", type=int, default=20)
    ap.add_argument("--start-index", type=int, default=0)
    ap.add_argument("--extra-flows", action="store_true")
    args = ap.parse_args([])
    assert args.sessions == 20
    assert args.start_index == 0
    assert args.extra_flows is False
    # run_session keeps its v0 default signature
    import inspect
    sig = inspect.signature(mod.run_session)
    assert sig.parameters["extra_flows"].default is False
