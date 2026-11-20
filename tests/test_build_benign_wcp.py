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
