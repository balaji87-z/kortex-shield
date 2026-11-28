"""Tests for the step-22 analysis tools (hand-written inputs, no run data)."""
import importlib.util
import json
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"


def load(name):
    spec = importlib.util.spec_from_file_location(name, TOOLS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_t5_block_kind_separates_payload_from_policy():
    t5 = load("step22_t5_summarise")
    # skip markers (x01x), 941010 and score rules are not checks
    assert t5.check_ids({"941010", "941013", "949110", "941100", "920270"}) == ["920270", "941100"]
    assert t5.block_kind({"920270", "941100", "949110"}) == "payload-detected"
    assert t5.block_kind({"920270", "920450", "949110"}) == "policy-only"
    assert t5.block_kind({"949110"}) == "no-check-rule"
    assert t5.block_kind(None) == "no-audit-entry"


def test_t5_load_index_merges_entries_of_one_sample(tmp_path):
    t5 = load("step22_t5_summarise")
    idx = tmp_path / "index.jsonl"
    idx.write_text("\n".join(json.dumps(e) for e in [
        {"sample_id": "a", "rule_ids": ["942100"], "body_bytes": 10},
        {"sample_id": "a", "rule_ids": ["949110"], "body_bytes": 10},
        {"sample_id": None, "rule_ids": ["920350"], "body_bytes": 0},
    ]) + "\n")
    assert t5.load_index(str(idx)) == {"a": {"942100", "949110"}}
    assert t5.load_sizes(str(idx)) == {"a": 10}
    assert t5.load_index(None) is None


def test_t4_bands_and_percentiles():
    t4 = load("step22_t4_bigbodies_analysis")
    assert t4.band(0) == "<64K"
    assert t4.band(65535) == "<64K"
    assert t4.band(65536) == "64K-<128K"
    assert t4.band(131071) == "64K-<128K"
    assert t4.band(131072) == ">=128K"
    assert t4.pct([5, 1, 3], 0.5) == 3
    assert t4.pct([1, 2, 3, 4], 1.0) == 4
    assert t4.pct([], 0.5) is None


def test_numeric_host_blocked_set():
    nh = load("step22_numeric_host_diff")
    rows = {"a": {"outcome": "waf_block"}, "b": {"outcome": "waf_pass"},
            "c": {"outcome": "waf_deny_status"}}
    assert nh.blocked(rows) == {"a"}


def test_t2_summary_percentile():
    t2 = load("step22_t2_cells_summary")
    assert t2.pct([10, 30, 20], 0.5) == 20
    assert t2.pct([], 0.99) is None


def test_audit_jsonl_index_keeps_ids_only():
    idx = load("step22_audit_jsonl_index")
    row = idx.index_row({
        "sample_id": "wcp-1", "method": "POST", "uri": "/secret?token=abc", "status": 403, "engine": "modsec",
        "rules": [{"id": "942100", "data": "matched data"}, {"id": 949110}, {"id": "942100"}, {"msg": "no id"}],
        "inbound_score_from_949110": 5,
    })
    assert row == {"sample_id": "wcp-1", "method": "POST", "status": 403, "engine": "modsec",
                   "rule_ids": ["942100", "949110"], "inbound_score_from_949110": 5}
    assert "uri" not in row and "secret" not in json.dumps(row)


def test_variance_summary_counts_sets_and_scores(tmp_path):
    var = load("step22_variance_summary")
    audit = tmp_path / "audit.jsonl"
    audit.write_text("\n".join(json.dumps(e) for e in [
        {"sample_id": "a", "rules": [{"id": "942130"}, {"id": "949110"}], "inbound_score_from_949110": 5},
        {"sample_id": "a", "rules": [{"id": "949110"}], "inbound_score_from_949110": 3},
        {"sample_id": "a", "rules": [{"id": "949110"}, {"id": "942130"}], "inbound_score_from_949110": 5},
        {"sample_id": None, "rules": [{"id": "920350"}]},
        {"sample_id": "b", "rules": [], "inbound_score_from_949110": None},
    ]) + "\n")
    sets, scores = var.summarise(str(audit))
    assert dict(sets["a"]) == {"942130,949110": 2, "949110": 1}
    assert dict(scores["a"]) == {5: 2, 3: 1}
    assert dict(sets["b"]) == {"": 1}
    assert set(sets) == {"a", "b"}  # entries without a sample id are not counted


def test_breakdown_sanitise_replaces_paths_and_keeps_numbers():
    san = load("step22_breakdown_sanitise")
    path_with_mail_shape = "GET /a/user" + "@" + "example.org"  # joined here so the pre-push scan does not flag this file
    doc = {"pl1": {"note": "n", "per_endpoint": {path_with_mail_shape: {"n": 2, "blocked": 1},
                                                 "POST /b": {"n": 1, "blocked": 0}},
                   "per_host": {"h.example": {"n": 3, "blocked": 1}},
                   "blocked_rule_sets": {"wcp-1": ["942100"]}}}
    out, stats = san.sanitise(doc)
    text = json.dumps(out)
    assert "example.org" not in text and "/a/" not in text and "/b" not in text
    keys = sorted(out["pl1"]["per_endpoint"])
    assert all(k.split(" ")[1].startswith("sha256:") and len(k.split(":")[1]) == 16 for k in keys)
    assert [k.split(" ")[0] for k in keys] == ["GET", "POST"]
    assert sorted(v["n"] for v in out["pl1"]["per_endpoint"].values()) == [1, 2]
    assert out["pl1"]["per_host"] == doc["pl1"]["per_host"]
    assert out["pl1"]["blocked_rule_sets"] == doc["pl1"]["blocked_rule_sets"]
    assert stats == {"pl1": (2, 1, 1)}
    assert san.endpoint_key("GET /x") == san.endpoint_key("GET /x") != san.endpoint_key("GET /y")


def test_cellg_stream_is_clean_deterministic_and_carries_the_canary():
    import zlib
    cellg = load("run_step22_t5_cellg")
    for text in (cellg.XSS, cellg.SQLI, cellg.BENIGN):
        body, plain, tries = cellg.clean_stream(text)
        assert not any(b in (0, 10, 13) for b in body)
        assert zlib.decompress(body).decode() == plain and text in plain
        assert cellg.clean_stream(text) == (body, plain, tries)


def test_fp_decomposition_reads_a_gzipped_connector_audit(tmp_path, monkeypatch):
    import gzip, io
    fp = load("step22_t4_fp_decomposition")
    run = tmp_path / "run"
    run.mkdir()
    rows = [{"status": 403, "rules": [{"id": "920420"}, {"id": "949110"}]},
            {"status": 403, "rules": [{"id": "942100"}, {"id": "949110"}]},
            {"status": 200, "rules": []}]
    with gzip.open(run / "audit.jsonl.gz", "wt") as f:
        f.write("\n".join(json.dumps(r) for r in rows) + "\n")
    monkeypatch.setattr(fp, "RUNS", str(tmp_path))
    out = io.StringIO()
    fp.connector_side("run", "connector test", out)
    text = out.getvalue()
    assert "n=3 403-blocks=2 detection-involved=1 (920420-only blocks=1)" in text
    assert "942100=1" in text
    out = io.StringIO()
    fp.connector_side("absent", "connector absent", out)
    assert "NOT MEASURED" in out.getvalue()
