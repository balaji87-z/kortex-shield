"""Tests for the step-23 tools (hand-written inputs, no run data, local sockets only)."""
import importlib.util
import json
import shutil
import subprocess
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"


def load(name):
    spec = importlib.util.spec_from_file_location(name, TOOLS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------- events index ----------

def test_events_index_counts_and_keeps_only_what_is_not_pass_or_block():
    ei = load("step23_events_index")
    prefix = "compressed-body-without-content-encoding:"
    lines = [json.dumps(e) for e in [
        {"sample_id": "a", "decision": "pass", "status": 0, "reason": "forwarding"},
        {"sample_id": "b", "decision": "block", "status": 403, "reason": "rules=1"},
        {"sample_id": "c", "decision": "would_reject", "status": 0, "reason": prefix + "gzip"},
        {"sample_id": "d", "decision": "would_reject", "status": 0, "reason": prefix + "zlib"},
        {"sample_id": "e", "decision": "would_reject", "status": 0, "reason": prefix + "zlib"},
        {"sample_id": "f", "decision": "would_reject", "status": 0, "reason": "invalid-percent-sequence-in-query"},
        {"sample_id": "g", "decision": "framing", "status": 400, "reason": "duplicate-content-length"},
        {"sample_id": "h", "decision": "overload", "status": 503, "reason": "per-client in-flight cap"},
    ]] + [""]
    kept, decisions, magic, framing = ei.index(lines)
    assert decisions == {"pass": 1, "block": 1, "would_reject": 4, "framing": 1, "overload": 1}
    assert magic == {"gzip": 1, "zlib": 2}
    assert framing == {"duplicate-content-length": 1}
    assert [r["sample_id"] for r in kept] == ["c", "d", "e", "f", "g", "h"]
    assert set(kept[0]) == {"sample_id", "decision", "status", "reason"}


# ---------- stock against patched, per sample ----------

def test_parity_vs_c2_lists_every_difference():
    pc = load("step23_parity_vs_c2")
    a = {"s1": {"id": "s1", "status": 403, "outcome": "waf_block", "rule_ids": ["942130", "949110"]},
         "s2": {"id": "s2", "status": 200, "outcome": "waf_pass", "rule_ids": []},
         "s3": {"id": "s3", "status": 403, "outcome": "waf_block", "rule_ids": ["941100", "949110"]},
         "s4": {"id": "s4", "status": 200, "outcome": "waf_pass", "rule_ids": []}}
    b = {"s1": {"id": "s1", "status": 403, "outcome": "waf_block", "rule_ids": ["949110", "942130"]},
         "s2": {"id": "s2", "status": 403, "outcome": "waf_block", "rule_ids": ["942130", "949110"]},
         "s3": {"id": "s3", "status": 403, "outcome": "waf_block", "rule_ids": ["941100", "941390", "949110"]}}
    ids, status, outcome, rules = pc.compare(a, b)
    assert ids == ["s1", "s2", "s3", "s4"]           # the union: s4 is not dropped
    assert status == [("s2", 200, 403), ("s4", 200, None)]
    assert outcome == [("s2", "waf_pass", "waf_block"), ("s4", "waf_pass", None)]
    assert rules == [("s2", [], ["942130", "949110"]), ("s3", [], ["941390"])]


# ---------- vendored coraza ----------

def test_coraza_patch_replaces_exactly_the_expected_loops():
    cv = load("step23_coraza_vendor")
    text = ("func a() {\n\tfor _, data := range c.data {\n\t\tfor _, d := range data {\n\t\t}\n\t}\n}\n"
            "func b() {\n\tfor k, data := range c.data {\n\t\tif key.MatchString(k) {\n\t\t}\n\t}\n}\n"
            "func keep() {\n\tfor _, data := range c.data {\n\t\tn += len(data)\n\t}\n}\n")
    out = cv.patch_text("internal/collections/map.go", text)
    assert out.count("sortedKeys(c.data)") == 2
    assert "for _, data := range c.data {\n\t\tn += len(data)" in out     # the counting loop is left alone
    assert cv.patch_text("internal/collections/sized.go", text) == text   # other files are not touched
    with pytest.raises(SystemExit):
        cv.patch_text("internal/collections/map.go", "package collections\n")   # anchors missing


def test_vendored_coraza_matches_the_module_cache():
    if shutil.which("go") is None:
        pytest.skip("go is not installed")
    cache = subprocess.run(["go", "env", "GOMODCACHE"], capture_output=True, text=True).stdout.strip()
    if not (Path(cache) / "github.com/corazawaf/coraza/v3@v3.8.1").is_dir():
        pytest.skip("coraza v3.8.1 is not in the Go module cache")
    proc = subprocess.run(["python3", str(TOOLS / "step23_coraza_vendor.py"), "check"],
                          capture_output=True, text=True, cwd=ROOT)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "vendor check: OK" in proc.stdout
    assert "differing: 2 ['internal/collections/map.go', 'internal/collections/named.go']" in proc.stdout


# ---------- strict-parsing differential ----------

def test_parsing_cases_are_unique_and_cover_the_four_families():
    pd = load("step23_parsing_diff")
    cases = pd.build_cases()
    assert len({c["id"] for c in cases}) == len(cases)
    assert {c["family"] for c in cases} == {"content-length", "transfer-encoding", "percent", "overlong"}
    for c in cases:
        assert c["raw"].startswith((b"GET ", b"POST ")) and b"\r\n\r\n" in c["raw"]
        assert b"X-Kortex-Sample-Id: " + c["id"].encode() in c["raw"]
        assert b"Host: localhost" in c["raw"]          # rule 6: nothing but the local testbed


def test_parse_answer_tells_a_backend_view_from_an_engine_answer():
    pd = load("step23_parsing_diff")
    view, decision = pd.parse_answer(200, json.dumps({"backend": "x", "body_len": 5}).encode())
    assert view == {"backend": "x", "body_len": 5} and decision is None
    assert pd.parse_answer(400, b"400 kortex-decision=framing\n") == (None, "framing")
    assert pd.parse_answer(403, b"403 kortex-decision=block rules=941100,949110\n") == (None, "block")
    assert pd.parse_answer(400, b"400 Bad Request") == (None, None)
    assert pd.parse_answer(200, b"400 kortex-decision=framing\n") == (None, None)   # status must match


def _view(path="/s", query=None, body_len=0, sha="e3"):
    return {"backend": "t", "path_decoded": path, "query_decoded": query or {}, "body_len": body_len,
            "body_sha256": sha, "leftover_len": 0, "body_framing": "content-length-first"}


def test_chunked_engine_answers_are_decoded():
    pd = load("step23_parsing_diff")
    assert pd.dechunk(b"1c\r\n503 kortex-decision=timeout\n\r\n0\r\n\r\n") == b"503 kortex-decision=timeout\n"
    assert pd.dechunk(b"not chunked") == b"not chunked"


def test_refusal_kind_names_who_refused():
    pd = load("step23_parsing_diff")
    assert pd.refusal_kind({"forwarded": True}) == "forwarded"
    assert pd.refusal_kind({"forwarded": False, "decision": "framing", "status": 400}) == "framing gate (400, event)"
    assert pd.refusal_kind({"forwarded": False, "decision": "block", "status": 403}) == "rule block (403, event)"
    assert pd.refusal_kind({"forwarded": False, "decision": None, "status": 400, "events": []}) == \
        "HTTP parser of the engine (400, no marker, no event)"


def test_compare_classes():
    pd = load("step23_parsing_diff")
    case = {"id": "c", "canary": None}
    refused = {"status": 400, "decision": "framing", "forwarded": False, "view": None}
    forwarded = {"status": 200, "decision": None, "forwarded": True, "view": _view(body_len=5, sha="aa")}
    accepts = {"status": 200, "view": _view(body_len=5, sha="aa"), "error": None}
    rejects = {"status": 400, "view": None, "error": None}
    assert pd.compare(case, refused, rejects) == []                       # both refuse: agree
    assert pd.compare(case, forwarded, accepts) == []                     # same view: agree
    got = pd.compare(case, refused, accepts)
    assert [c for c, _ in got] == ["engine-refuses-backend-accepts"]
    assert "body 5 bytes" in got[0][1] and "0 bytes left on the connection" in got[0][1]
    assert [c for c, _ in pd.compare(case, forwarded, rejects)] == ["engine-forwards-backend-refuses"]
    other = {"status": 200, "view": _view(body_len=11, sha="bb"), "error": None}
    got = pd.compare(case, forwarded, other)
    assert [c for c, _ in got] == ["view-differs"]
    assert "body_len: through engine 5, direct 11" in got[0][1] and "body_sha256" in got[0][1]


def test_compare_flags_a_canary_that_reaches_the_backend():
    pd = load("step23_parsing_diff")
    case = {"id": "c", "canary": pd.CANARY}
    seen = _view(query={"q": ["<script>alert(1)</script>"]})
    forwarded = {"status": 200, "decision": None, "forwarded": True, "view": seen}
    direct = {"status": 200, "view": seen, "error": None}
    assert [c for c, _ in pd.compare(case, forwarded, direct)] == ["canary-reaches-backend"]
    blocked = {"status": 403, "decision": "block", "forwarded": False, "view": None}
    assert [c for c, _ in pd.compare(case, blocked, direct)] == ["engine-refuses-backend-accepts"]
    undecoded = {"status": 200, "view": _view(query={"q": ["\ufffd\ufffdscript"]}), "error": None}
    fwd2 = dict(forwarded, view=undecoded["view"])
    assert pd.compare(case, fwd2, undecoded) == []
    assert pd.canary_in_view(_view(path="/<script>"), pd.CANARY) is True
    assert pd.canary_in_view(_view(), None) is False


@pytest.fixture()
def python_backend():
    pb = load("step23_parsing_backend")
    srv = pb.serve(0)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv.server_address[1]
    srv.shutdown()
    srv.server_close()


def test_python_backend_reports_what_it_sees(python_backend):
    pd = load("step23_parsing_diff")
    cases = {c["id"]: c for c in pd.build_cases()}

    def view_of(case_id):
        status, body, error = pd.send_raw(python_backend, cases[case_id]["raw"])
        assert error is None and status == 200, (case_id, status, error)
        view, decision = pd.parse_answer(status, body)
        assert decision is None
        return view

    control = view_of("cl-control")
    assert control["body_len"] == 5 and control["leftover_len"] == 0
    assert control["body_framing"] == "content-length-first"
    # two Content-Length headers: this backend takes the first and leaves the rest on the connection
    small_first = view_of("cl-dup-small-first")
    assert small_first["content_length_headers"] == ["5", "11"]
    assert small_first["body_len"] == 5 and small_first["leftover_len"] == 6
    # chunked is not decoded by http.server: no body, the chunks are left over
    chunked = view_of("te-control")
    assert chunked["body_len"] == 0 and chunked["leftover_len"] == len(pd.CHUNKED_HELLO)
    assert chunked["transfer_encoding_headers"] == ["chunked"]
    pct = view_of("pct-control")
    assert pct["path_decoded"] == "/a b" and pct["query_decoded"] == {"q": ["a b"]}
    canary = view_of("pct-canary-control")
    assert pd.canary_in_view(canary, pd.CANARY) is True
    overlong = view_of("ovl-query-canary-pct")
    assert pd.canary_in_view(overlong, pd.CANARY) is False   # unquote does not turn C0 BC into '<'


# ---------- compressed-body event analysis ----------

def test_magic_analysis_prints_counts_only():
    import zlib
    ma = load("step23_magic_analysis")
    prefix = "compressed-body-without-content-encoding:"
    real = zlib.compress(b"hello hello hello").decode("latin-1")      # starts with 78 9c; latin-1 keeps it one str char per byte
    events = [
        {"sample_id": "t1", "decision": "would_reject", "status": 0, "reason": prefix + "zlib"},
        {"sample_id": "t2", "decision": "would_reject", "status": 0, "reason": prefix + "zlib"},
        {"sample_id": "t3", "decision": "would_reject", "status": 0, "reason": "invalid-percent-sequence-in-query"},
        {"sample_id": "gone", "decision": "would_reject", "status": 0, "reason": prefix + "zlib"},
    ]
    samples = {
        "t1": {"id": "t1", "method": "post", "body": "x^2 + y^2 = r^2", "content_type": "text/plain; charset=utf-8"},
        "t2": {"id": "t2", "method": "POST", "body": "x\x01" + "rest", "headers": {"Content-Type": "application/octet-stream"}},
        "t3": {"id": "t3", "method": "GET", "body": ""},
    }
    assert real.startswith("x")
    lines = ma.analyse(events, samples)
    text = "\n".join(lines)
    assert "samples with a compressed-body event: 3 {'zlib': 3}; not in the manifest: 1" in text
    assert "{'application/octet-stream': 1, 'text/plain': 1}" in text
    assert "{'7801': 1, '785e': 1}" in text
    assert "{'not a complete stream': 2}" in text
    assert "y^2" not in text and "rest" not in text          # nothing of a body is printed
    assert ma.inflates(zlib.compress(b"hello hello hello")) == "complete zlib stream"
