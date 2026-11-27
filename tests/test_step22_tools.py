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
