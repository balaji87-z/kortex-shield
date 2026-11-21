"""Step-13 T2: tests for the two build_benign_wcp fixes for FUTURE dataset
versions (the frozen v0 manifest is NOT rebuilt)."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from build_benign_wcp import (
    canonicalize_dropped_cookie,
    drop_inconsistent_content_encoding,
)


def test_dropped_cookie_marker_normalized_to_lowercase():
    headers = {"Host": "example.com", "Cookie": "[DROPPED]"}
    out = canonicalize_dropped_cookie(headers)
    assert list(out) == ["Host", "cookie"]
    assert out["cookie"] == "[DROPPED]"


def test_dropped_cookie_lowercase_already_canonical():
    headers = {"cookie": "[DROPPED]"}
    assert canonicalize_dropped_cookie(headers) == {"cookie": "[DROPPED]"}


def test_real_cookie_value_keeps_recorded_casing():
    headers = {"Cookie": "session=abc"}
    assert canonicalize_dropped_cookie(headers) == {"Cookie": "session=abc"}


def test_content_encoding_gzip_dropped():
    headers = {"Content-Encoding": "gzip", "Content-Type": "application/json"}
    out, n = drop_inconsistent_content_encoding(headers)
    assert n == 1
    assert out == {"Content-Type": "application/json"}


def test_identity_content_encoding_kept():
    headers = {"Content-Encoding": "identity"}
    out, n = drop_inconsistent_content_encoding(headers)
    assert n == 0
    assert out == {"Content-Encoding": "identity"}


def test_other_headers_untouched():
    headers = {"Accept-Encoding": "gzip, deflate", "Content-Type": "text/plain"}
    out, n = drop_inconsistent_content_encoding(headers)
    assert n == 0
    assert out == headers


# ---- Step-19 A1: publishable-token scrub for FUTURE dataset versions ----

def test_scrub_mapbox_pk_token_in_query():
    from build_benign_wcp import scrub_publishable_tokens
    # fixture SINTETICO (nunca un token real; regla 25)
    q = "access_token=pk.eyJ0ZXN0ZmFrZXRva2Vu.fakeSignatureValue123&v=1"
    out, n = scrub_publishable_tokens(query=q, body="", headers={})
    assert n == 1
    assert "eyJ" not in out["query"]
    assert "access_token=[REDACTED-TOKEN]" in out["query"]
    assert "v=1" in out["query"]


def test_scrub_sk_token_in_body_and_header():
    from build_benign_wcp import scrub_publishable_tokens
    tok = "sk.eyJabc123def.ghi456jkl789"
    out, n = scrub_publishable_tokens(
        query="", body="map key: " + tok, headers={"X-Map-Key": tok})
    assert n == 2
    assert tok not in out["body"] and tok not in str(out["headers"])
    assert "[REDACTED-TOKEN]" in out["body"]


def test_scrub_leaves_normal_urls_untouched():
    from build_benign_wcp import scrub_publishable_tokens
    q = "utm_source=google&q=pk cet&session=abc"
    out, n = scrub_publishable_tokens(query=q, body="plain body", headers={})
    assert n == 0
    assert out["query"] == q and out["body"] == "plain body"
