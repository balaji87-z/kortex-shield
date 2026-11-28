"""Tests for tools/build_attacks_v1.py (hand-written source files, no external data)."""
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load_tool():
    spec = importlib.util.spec_from_file_location("build_attacks_v1", ROOT / "tools" / "build_attacks_v1.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def make_sources(tmp_path, families):
    """families: [(name, cap, [(relative path, bytes)])] -> (external dir, list file)."""
    ext = tmp_path / "ext"
    lines = ["# a comment line"]
    for name, cap, files in families:
        lines.append(f"# family {name} cap {cap}")
        for rel, data in files:
            p = ext / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
            lines.append(f"{hashlib.sha256(data).hexdigest()}  {rel}")
    lst = tmp_path / "sources.sha256"
    lst.write_text("\n".join(lines) + "\n")
    return ext, lst


def v0_annotations(tmp_path, payloads):
    p = tmp_path / "v0-annotations.jsonl"
    p.write_text("".join(json.dumps({"id": f"x-{i}-q", "payload": pl}) + "\n" for i, pl in enumerate(payloads)))
    return p


def rows(path):
    return [json.loads(line) for line in Path(path).read_text().splitlines() if line]


def build(tmp_path, families, v0=(), seed=1):
    tool = load_tool()
    ext, lst = make_sources(tmp_path, families)
    out = tmp_path / "out"
    stats = tool.build(ext, lst, v0_annotations(tmp_path, list(v0)), out, seed=seed)
    return tool, out, stats


def test_line_terminators_blank_lines_duplicates_and_hash_lines(tmp_path):
    data = b"' or 1=1--\r\n\r\n# not a comment\n' or 1=1--\n   \nlast without newline"
    _tool, out, stats = build(tmp_path, [("sqli", 0, [("SQL Injection/a.txt", data)])])
    ann = rows(out / "annotations.jsonl")
    assert [a["payload"] for a in ann if a["injection_point"] == "q"] == [
        "' or 1=1--", "# not a comment", "last without newline"]
    s = stats["families"]["sqli"]
    assert (s["raw_lines"], s["blank_removed"], s["duplicates_removed"], s["sampled"]) == (6, 2, 1, 3)


def test_two_requests_per_payload_with_the_v0_shapes(tmp_path):
    _tool, out, _stats = build(tmp_path, [("ssti", 0, [("SSTI/Intruder/ssti.fuzz", b"{{7*7}} &x\n")])])
    cand = rows(out / "candidates.jsonl")
    sha8 = hashlib.sha256(b"{{7*7}} &x").hexdigest()[:8]
    assert cand == [
        {"id": f"v1-ssti-{sha8}-q", "label": "attack", "family": "ssti",
         "source": "PayloadsAllTheThings@08ea40e77db3f42ef8f20c65196f3936a19b6c86:SSTI/Intruder/ssti.fuzz:1",
         "method": "GET", "path": "/rest/products/search", "query": "q=%7B%7B7%2A7%7D%7D%20%26x", "body": "",
         "content_type": ""},
        {"id": f"v1-ssti-{sha8}-login", "label": "attack", "family": "ssti",
         "source": "PayloadsAllTheThings@08ea40e77db3f42ef8f20c65196f3936a19b6c86:SSTI/Intruder/ssti.fuzz:1",
         "method": "POST", "path": "/rest/user/login", "query": "",
         "body": json.dumps({"email": "{{7*7}} &x", "password": "x"}), "content_type": "application/json"},
    ]


def test_a_payload_of_attacks_v0_is_excluded_to_a_named_file(tmp_path):
    # the v0 builder kept the CR of CRLF files: it is ignored for the comparison
    _tool, out, stats = build(tmp_path, [("xss", 0, [("XSS/a.txt", b"<script>alert(1)</script>\n../etc/passwd\nnew one\n")])],
                              v0=["<script>alert(1)</script>", "../etc/passwd\r"])
    assert [a["payload"] for a in rows(out / "annotations.jsonl")] == ["new one", "new one"]
    exc = rows(out / "excluded-in-v0.jsonl")
    assert [(e["family"], e["payload"], e["source"].rsplit(":", 1)[1]) for e in exc] == [
        ("xss", "<script>alert(1)</script>", "1"), ("xss", "../etc/passwd", "2")]
    assert stats["families"]["xss"]["in_v0_removed"] == 2


def test_a_payload_belongs_to_the_first_family_that_lists_it(tmp_path):
    _tool, out, stats = build(tmp_path, [
        ("path-traversal", 0, [("DT/a.txt", b"../../etc/passwd\n..%2f\n")]),
        ("lfi", 0, [("FI/b.txt", b"php://filter\n../../etc/passwd\n")]),
    ])
    ann = rows(out / "annotations.jsonl")
    assert sorted({(a["family"], a["payload"]) for a in ann}) == [
        ("lfi", "php://filter"), ("path-traversal", "..%2f"), ("path-traversal", "../../etc/passwd")]
    exc = rows(out / "excluded-cross-family.jsonl")
    assert [(e["family"], e["owner_family"], e["payload"]) for e in exc] == [("lfi", "path-traversal", "../../etc/passwd")]
    assert stats["families"]["lfi"]["cross_family_removed"] == 1
    assert stats["distinct_payloads"] == 3 and stats["requests"] == 6


def test_unsendable_payloads_are_recorded_with_the_reason_and_without_their_text(tmp_path):
    long_line = b"A" * 2001
    data = b"ok\n" + b"caf\xe9 or 1=1\n" + long_line + b"\n" + b"B" * 2000 + b"\n"
    _tool, out, stats = build(tmp_path, [("sqli", 0, [("SQL/a.txt", data)])])
    assert sorted(a["payload"] for a in rows(out / "annotations.jsonl") if a["injection_point"] == "q") == ["B" * 2000, "ok"]
    exc = rows(out / "excluded-unsendable.jsonl")
    assert [(e["reason"], e["bytes"], e["source"].rsplit(":", 1)[1]) for e in exc] == [
        ("not-utf8", 11, "2"), ("longer-than-2000-bytes", 2001, "3")]
    assert all("payload" not in e and len(e["sha256"]) == 64 for e in exc)
    assert stats["families"]["sqli"]["unsendable_removed"] == {"longer-than-2000-bytes": 1, "not-utf8": 1}


def test_the_cap_samples_with_the_seed_and_sorts(tmp_path):
    data = "".join(f"payload-{i:03d}\n" for i in range(50)).encode()
    fams = [("xss", 10, [("XSS/a.txt", data)]), ("nosql", 0, [("NoSQL/b.txt", b"{$ne:1}\n")])]
    _t, out1, stats = build(tmp_path / "one", fams)
    _t, out2, _ = build(tmp_path / "two", fams)
    _t, out3, _ = build(tmp_path / "three", fams, seed=2)
    picked = [a["payload"] for a in rows(out1 / "annotations.jsonl") if a["family"] == "xss" and a["injection_point"] == "q"]
    assert len(picked) == 10 and picked == sorted(picked)
    assert (out1 / "candidates.jsonl").read_bytes() == (out2 / "candidates.jsonl").read_bytes()
    assert (out1 / "candidates.jsonl").read_bytes() != (out3 / "candidates.jsonl").read_bytes()
    assert stats["families"]["xss"]["after_filters"] == 50 and stats["families"]["xss"]["sampled"] == 10
    assert stats["families"]["nosql"]["sampled"] == 1


def test_a_source_file_with_another_hash_stops_the_build(tmp_path):
    tool = load_tool()
    ext, lst = make_sources(tmp_path, [("ldap", 0, [("LDAP/a.txt", b"*)(uid=*\n")])])
    (ext / "LDAP/a.txt").write_bytes(b"*)(uid=*\nchanged\n")
    with pytest.raises(SystemExit) as exc:
        tool.build(ext, lst, v0_annotations(tmp_path, []), tmp_path / "out", seed=1)
    assert "sha256" in str(exc.value)


def test_freeze_removes_only_requests_the_rules_did_not_judge(tmp_path):
    tool, out, _stats = build(tmp_path, [("sqli", 0, [("SQL/a.txt", b"one\ntwo\nthree\nfour\nfive\n")])])
    cand = rows(out / "candidates.jsonl")
    outcome = {c["id"]: "waf_pass" for c in cand}
    by_payload = {a["payload"]: a["id"] for a in rows(out / "annotations.jsonl") if a["injection_point"] == "q"}
    outcome[by_payload["one"]] = "waf_would_block"
    outcome[by_payload["two"]] = "error"
    outcome[by_payload["three"]] = "waf_fail_closed_400"
    outcome[by_payload["four"]] = "inconsistent"
    reach = tmp_path / "reach-outcomes.jsonl"
    reach.write_text("".join(json.dumps({"id": i, "outcome": o}) + "\n" for i, o in outcome.items()))
    res = tool.freeze(out, reach)
    manifest = rows(out / "manifest.jsonl")
    quarantine = rows(out / "quarantine.jsonl")
    assert len(manifest) == 7 and res["kept"] == 7
    assert by_payload["one"] in {m["id"] for m in manifest}
    assert sorted((q["id"], q["reason"]) for q in quarantine) == sorted([
        (by_payload["two"], "error"), (by_payload["three"], "waf_fail_closed_400"), (by_payload["four"], "inconsistent")])
    want = hashlib.sha256((out / "manifest.jsonl").read_bytes()).hexdigest()
    assert (out / "MANIFEST.sha256").read_text().split()[0] == want
    # a second freeze must not replace a frozen manifest (rule 10)
    with pytest.raises(SystemExit):
        tool.freeze(out, reach)


def test_freeze_needs_an_outcome_for_every_candidate(tmp_path):
    tool, out, _stats = build(tmp_path, [("sqli", 0, [("SQL/a.txt", b"one\n")])])
    reach = tmp_path / "reach-outcomes.jsonl"
    reach.write_text(json.dumps({"id": rows(out / "candidates.jsonl")[0]["id"], "outcome": "waf_pass"}) + "\n")
    with pytest.raises(SystemExit) as exc:
        tool.freeze(out, reach)
    assert "no reach-check outcome" in str(exc.value)
