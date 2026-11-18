import pytest

from kortex_eval.manifest import Sample
from kortex_eval.metrics import evaluate, wilson_interval
from kortex_eval.report import render


def s(i, label, family):
    return Sample(id=i, label=label, family=family, source="t", method="GET", path="/", query=i)


def test_wilson_known_values():
    lo, hi = wilson_interval(0, 10)
    assert lo == 0.0 and hi == pytest.approx(0.2775, abs=1e-3)   # the "10/10 benign" case
    lo, hi = wilson_interval(50, 100)
    assert (lo, hi) == pytest.approx((0.4038, 0.5962), abs=1e-3)
    assert wilson_interval(0, 0) == (0.0, 1.0)


def test_wilson_rejects_bad_counts():
    with pytest.raises(ValueError):
        wilson_interval(5, 3)


def test_evaluate_counts_per_family():
    samples = [s("a1", "attack", "sqli"), s("a2", "attack", "sqli"),
               s("a3", "attack", "xss"), s("b1", "benign", "benign"), s("b2", "benign", "benign")]
    flagged = {"a1": True, "a2": False, "a3": True, "b1": False, "b2": True}
    ev = evaluate(samples, flagged)
    assert (ev.recall_by_family["sqli"].count, ev.recall_by_family["sqli"].total) == (1, 2)
    assert (ev.recall_by_family["xss"].count, ev.recall_by_family["xss"].total) == (1, 1)
    assert (ev.overall_recall.count, ev.overall_recall.total) == (2, 3)
    assert (ev.false_positive_rate.count, ev.false_positive_rate.total) == (1, 2)


def test_missing_prediction_raises_not_skipped():
    with pytest.raises(KeyError, match="no prediction"):
        evaluate([s("a1", "attack", "sqli")], {})


def test_zero_false_positives_report_states_the_upper_bound():
    benign = [s(f"b{i}", "benign", "benign") for i in range(10)]
    ev = evaluate(benign, {x.id: False for x in benign})
    text = render("demo", ev)
    assert "0/10" in text and "does not mean the rate is zero" in text
    assert "27.75%" in text
