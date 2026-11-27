"""Tests for tools/step21_engine_diff.py: a sample with no status is counted
as an error in the worst-case set of that run and is never dropped from the
comparison (rules 20, 21, 30, 32). Fixture rows are hand-written."""
import importlib.util
import json
import sys
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "tools" / "step21_engine_diff.py"
spec = importlib.util.spec_from_file_location("step21_engine_diff", TOOL)
mod = importlib.util.module_from_spec(spec)
sys.modules["step21_engine_diff"] = mod
spec.loader.exec_module(mod)


def _row(sid, status, blocked=False, error=None):
    return {"id": sid, "status": status, "blocked": blocked, "error": error}


def _runs():
    """Two runs of the same eight samples.

    id              run a            run b
    s-pass          200              200
    s-block         403 blocked      403 blocked
    s-deny          400              400
    s-none-both     no status        no status
    s-none-a        no status        403 blocked
    s-none-b        200              no status
    s-missing-b     200              (no row at all)
    s-status-diff   200              403 blocked
    """
    a = [
        _row("s-pass", 200),
        _row("s-block", 403, blocked=True),
        _row("s-deny", 400),
        _row("s-none-both", None, error="timeout"),
        {"id": "s-none-a", "blocked": False, "error": "encoding: UnicodeEncodeError"},  # no status key
        _row("s-none-b", 200),
        _row("s-missing-b", 200),
        _row("s-status-diff", 200),
    ]
    b = [
        _row("s-pass", 200),
        _row("s-block", 403, blocked=True),
        _row("s-deny", 400),
        _row("s-none-both", None, error="timeout"),
        _row("s-none-a", 403, blocked=True),
        _row("s-none-b", None, error="connection_error: ConnectionResetError"),
        _row("s-status-diff", 403, blocked=True),
    ]
    return {r["id"]: r for r in a}, {r["id"]: r for r in b}


ALL_IDS = sorted(["s-pass", "s-block", "s-deny", "s-none-both", "s-none-a",
                  "s-none-b", "s-missing-b", "s-status-diff"])


def test_no_sample_is_dropped_from_the_comparison():
    a, b = _runs()
    res = mod.compare(a, b)
    assert res["ids"] == ALL_IDS
    assert res["only_a"] == ["s-missing-b"]
    assert res["only_b"] == []


def test_no_status_in_both_runs_is_an_error_in_both_worst_case_sets():
    a, b = _runs()
    res = mod.compare(a, b)
    assert res["classes_a"]["s-none-both"] == "error"
    assert res["classes_b"]["s-none-both"] == "error"
    # the two runs agree on it, so it is not a difference, but it is counted
    assert "s-none-both" not in [i for i, _, _ in res["status_diffs"]]
    assert "s-none-both" in res["no_status_a"] and "s-none-both" in res["no_status_b"]


def test_no_status_in_one_run_is_an_error_there_and_a_difference():
    a, b = _runs()
    res = mod.compare(a, b)
    assert res["classes_b"]["s-none-b"] == "error"
    assert "s-none-b" not in res["classes_a"]
    assert "s-none-b" in res["worst_only_b"]
    assert ("s-none-b", 200, None) in res["status_diffs"]
    # a row with no "status" key at all is treated like status null
    assert res["classes_a"]["s-none-a"] == "error"
    assert res["classes_b"]["s-none-a"] == "blocked"
    assert ("s-none-a", None, 403) in res["status_diffs"]


def test_sample_missing_from_one_run_is_an_error_there():
    a, b = _runs()
    res = mod.compare(a, b)
    assert res["classes_b"]["s-missing-b"] == "error"
    assert "s-missing-b" in res["no_status_b"]
    assert "s-missing-b" in res["worst_only_b"]
    assert ("s-missing-b", 200, None) in res["status_diffs"]


def test_worst_case_sets_and_diffs_without_outcomes():
    a, b = _runs()
    res = mod.compare(a, b)
    assert res["have_outcomes"] is False
    assert res["classes_a"] == {"s-block": "blocked", "s-none-both": "error", "s-none-a": "error"}
    assert res["classes_b"] == {
        "s-block": "blocked", "s-none-both": "error", "s-none-a": "blocked",
        "s-none-b": "error", "s-missing-b": "error", "s-status-diff": "blocked",
    }
    assert res["worst_only_a"] == []
    assert res["worst_only_b"] == ["s-missing-b", "s-none-b", "s-status-diff"]
    assert sorted(i for i, _, _ in res["status_diffs"]) == [
        "s-missing-b", "s-none-a", "s-none-b", "s-status-diff"]


def test_deny_status_and_inconsistent_come_from_outcomes():
    a, b = _runs()
    a_out = {"s-deny": {"id": "s-deny", "outcome": "waf_deny_status"},
             "s-pass": {"id": "s-pass", "outcome": "waf_pass"},
             # an outcome cannot move a no-status sample out of "error"
             "s-none-both": {"id": "s-none-both", "outcome": "waf_pass"}}
    b_out = {"s-deny": {"id": "s-deny", "outcome": "waf_deny_status"},
             "s-pass": {"id": "s-pass", "outcome": "inconsistent"}}
    res = mod.compare(a, b, a_out, b_out)
    assert res["have_outcomes"] is True
    assert res["classes_a"]["s-deny"] == "deny_status"
    assert res["classes_b"]["s-deny"] == "deny_status"
    assert res["classes_b"]["s-pass"] == "inconsistent"
    assert "s-pass" not in res["classes_a"]
    assert res["classes_a"]["s-none-both"] == "error"
    assert "s-pass" in res["worst_only_b"]
    # outcomes for one run only are not enough: both classes stay unmeasured
    assert mod.compare(a, b, a_out, None)["have_outcomes"] is False
    assert "s-deny" not in mod.compare(a, b, a_out, None)["classes_a"]


def _write_run(path, rows, outcomes=None):
    path.mkdir()
    (path / "responses.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows.values()))
    if outcomes is not None:
        (path / "outcomes.jsonl").write_text("".join(json.dumps(r) + "\n" for r in outcomes.values()))


def test_main_prints_counts_ids_and_not_measured(tmp_path, capsys):
    a, b = _runs()
    _write_run(tmp_path / "a", a)
    _write_run(tmp_path / "b", b)
    assert mod.main([str(tmp_path / "a"), str(tmp_path / "b")]) == 0
    out = capsys.readouterr().out
    assert "samples compared: 8 (a=8 b=7 only-a=1 only-b=0)" in out
    assert "status diffs: 4" in out
    assert "no status in a (counted as error): 2" in out
    assert "no status in b (counted as error): 3" in out
    assert "deny_status, inconsistent: NOT MEASURED" in out
    assert "worst-case set a: 3/8 (error=2 blocked=1 deny_status=NOT MEASURED inconsistent=NOT MEASURED)" in out
    assert "worst-case set b: 6/8 (error=3 blocked=3 deny_status=NOT MEASURED inconsistent=NOT MEASURED)" in out
    assert "worst-case set diffs: 3 (only-a 0 only-b 3)" in out
    assert "  only-b s-missing-b: b=error (status None) a status 200" in out


def test_main_uses_outcomes_when_both_runs_have_them(tmp_path, capsys):
    a, b = _runs()
    deny = {"s-deny": {"id": "s-deny", "outcome": "waf_deny_status"}}
    _write_run(tmp_path / "a", a, deny)
    _write_run(tmp_path / "b", b, deny)
    assert mod.main([str(tmp_path / "a"), str(tmp_path / "b")]) == 0
    out = capsys.readouterr().out
    assert "NOT MEASURED" not in out
    assert "worst-case set a: 4/8 (error=2 blocked=1 deny_status=1 inconsistent=0)" in out
    assert "worst-case set b: 7/8 (error=3 blocked=3 deny_status=1 inconsistent=0)" in out
