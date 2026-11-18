import pytest

from kortex_eval import manifest
from kortex_eval.manifest import ManifestError, Sample


def mk(i, label="attack", family="sqli", source="sqlmap", **kw):
    return Sample(id=i, label=label, family=family, source=source,
                  method="GET", path="/x", query=kw.pop("query", f"q={i}"), **kw)


def test_valid_sample_passes():
    mk("a").validate()
    mk("b", label="benign", family="benign", source="browse").validate()


def test_source_is_required():
    with pytest.raises(ManifestError, match="source"):
        mk("a", source="  ").validate()


def test_benign_must_use_benign_family():
    with pytest.raises(ManifestError):
        mk("a", label="benign", family="sqli").validate()


def test_attack_cannot_use_benign_family():
    with pytest.raises(ManifestError):
        mk("a", label="attack", family="benign").validate()


def test_unknown_label_rejected():
    with pytest.raises(ManifestError, match="label"):
        mk("a", label="suspicious").validate()


def test_content_hash_ignores_id_source_headers():
    a = mk("a", query="q=1", source="one")
    b = mk("b", query="q=1", source="two")
    assert a.content_hash() == b.content_hash()
    assert a.content_hash() != mk("c", query="q=2").content_hash()


def test_roundtrip_and_duplicate_id(tmp_path):
    p = tmp_path / "m.jsonl"
    manifest.dump([mk("a"), mk("b")], p)
    assert [s.id for s in manifest.load(p)] == ["a", "b"]
    manifest.dump([mk("a"), mk("a", query="other")], p)
    with pytest.raises(ManifestError, match="duplicate id"):
        manifest.load(p)
