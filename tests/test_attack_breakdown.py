"""Tests for tools/attack_breakdown.py per-family denominators (step-07 T1)."""
import importlib.util
import json
import sys
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "tools" / "attack_breakdown.py"
spec = importlib.util.spec_from_file_location("attack_breakdown", TOOL)
mod = importlib.util.module_from_spec(spec)
sys.modules["attack_breakdown"] = mod
spec.loader.exec_module(mod)


def _manifest():
    return [
        {"id": "sqli-1", "family": "sqli"},
        {"id": "sqli-2", "family": "sqli"},
        {"id": "sqli-3", "family": "sqli"},
        {"id": "xss-1", "family": "xss"},
    ]


def test_outbound_cut_stays_in_denominator():
    """Rule 21: an outbound-cut sample is never dropped from the denominator."""
    statuses = {
        "sqli-1": "waf_block",
        "sqli-2": "waf_block_outbound",
        "sqli-3": "waf_pass",
        "xss-1": "waf_block",
    }
    got = mod.family_recall(_manifest(), statuses)
    assert got["sqli"] == {"denominator": 3, "best": 1, "worst": 2}
    assert got["xss"] == {"denominator": 1, "best": 1, "worst": 1}


def test_missing_status_row_stays_in_denominator():
    statuses = {"sqli-1": "waf_block", "xss-1": "waf_block"}
    got = mod.family_recall(_manifest(), statuses)
    # sqli-2 and sqli-3 have no row at all: denominator 3, best 1
    assert got["sqli"] == {"denominator": 3, "best": 1, "worst": 1}


def test_error_counts_only_in_worst_case():
    statuses = {
        "sqli-1": "waf_block",
        "sqli-2": "error",
        "sqli-3": "waf_pass",
        "xss-1": "waf_pass",
    }
    got = mod.family_recall(_manifest(), statuses)
    assert got["sqli"]["best"] == 1
    assert got["sqli"]["worst"] == 2
    assert got["sqli"]["denominator"] == 3


def test_grouped_recall_injection_point(tmp_path):
    manifest = [
        {"id": "sqli-1", "family": "sqli"},
        {"id": "sqli-2", "family": "sqli"},
    ]
    statuses = {"sqli-1": "waf_block", "sqli-2": "waf_block_outbound"}
    got = mod.grouped_recall(manifest, statuses, lambda s: (s["family"], "q"))
    assert got[("sqli", "q")] == {"denominator": 2, "best": 1, "worst": 2}


def test_load_statuses_from_outcomes_file(tmp_path):
    p = tmp_path / "outcomes.jsonl"
    p.write_text(
        json.dumps({"id": "sqli-1", "outcome": "waf_block_outbound"}) + "\n"
        + json.dumps({"id": "sqli-2", "outcome": "waf_block"}) + "\n"
    )
    class Args:  # minimal argparse-like namespace
        outcomes = str(p)
        predictions = None
    got = mod.load_statuses(Args)
    assert got == {"sqli-1": "waf_block_outbound", "sqli-2": "waf_block"}
