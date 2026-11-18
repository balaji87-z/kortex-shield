import pytest

from kortex_eval.manifest import Sample
from kortex_eval.split import assert_no_leakage, dedupe, split


def attack(i, family, query=None):
    return Sample(id=f"a{i}", label="attack", family=family, source="tool",
                  method="GET", path="/p", query=query or f"{family}={i}")


def benign(i, query=None):
    return Sample(id=f"b{i}", label="benign", family="benign", source="browse",
                  method="GET", path="/p", query=query or f"page={i}")


def corpus():
    data = []
    for fam in ("sqli", "xss", "lfi", "ssrf"):
        data += [attack(i, fam) for i in range(100)]
    data += [benign(i) for i in range(400)]
    return data


def test_holdout_family_only_in_unseen():
    sp = split(corpus(), holdout_families={"ssrf"}, seed=1)
    assert_no_leakage(sp)
    assert {s.family for s in sp.test_unseen_attacks} == {"ssrf"}
    assert len(sp.test_unseen_attacks) == 100
    assert all(s.family != "ssrf" for s in sp.train)
    assert all(s.family != "ssrf" for s in sp.test_seen_attacks)


def test_split_is_deterministic():
    a = split(corpus(), {"ssrf"}, seed=7)
    b = split(corpus(), {"ssrf"}, seed=7)
    assert [s.id for s in a.train] == [s.id for s in b.train]
    assert [s.id for s in a.test_benign] == [s.id for s in b.test_benign]


def test_benign_and_seen_attacks_reach_test():
    sp = split(corpus(), {"ssrf"}, test_fraction=0.3, seed=2)
    assert sp.test_benign and sp.test_seen_attacks and sp.train
    # roughly 30% of 400 benign; wide tolerance, only guarding against a broken split
    assert 80 <= len(sp.test_benign) <= 160


def test_duplicates_removed_before_split():
    data = corpus() + [attack(1000, "sqli", query="sqli=0")]  # same content as a0
    kept, removed = dedupe(data)
    assert removed == 1 and len(kept) == len(data) - 1
    assert_no_leakage(split(data, {"ssrf"}, seed=3))


def test_conflicting_labels_for_same_request_raise():
    clash = [attack(1, "sqli", query="same"), benign(1, query="same")]
    with pytest.raises(ValueError, match="labelled both"):
        dedupe(clash)


def test_cannot_holdout_unknown_or_all_families():
    with pytest.raises(ValueError, match="not present"):
        split(corpus(), {"nosuchfamily"})
    with pytest.raises(ValueError, match="every attack family"):
        split(corpus(), {"sqli", "xss", "lfi", "ssrf"})


def test_leak_detector_catches_a_leak():
    sp = split(corpus(), {"ssrf"}, seed=4)
    sp.test_benign.append(sp.train[0])  # force an overlap
    with pytest.raises(AssertionError):
        assert_no_leakage(sp)
