"""Tests for kortex_eval.endpoints."""
from kortex_eval.endpoints import endpoint


def s(method, path):
    return {"method": method, "path": path}


def test_numeric_segment_replaced():
    assert endpoint(s("GET", "/rest/product/1")) == "GET /rest/product/{id}"


def test_long_hex_segment_replaced():
    assert endpoint(s("GET", "/rest/warehouse/p/9f86d081884c7d65")) == "GET /rest/warehouse/p/{id}"


def test_uuid_replaced():
    assert endpoint(s("POST", "/rest/basket/550e8400-e29b-41d4-a716-446655440000")) == \
        "POST /rest/basket/{id}"


def test_short_hex_kept():
    # 7 hex chars is below the 8+ threshold: it is a name, not an id
    assert endpoint(s("GET", "/rest/deadbee")) == "GET /rest/deadbee"
    # exactly 8 hex chars IS replaced
    assert endpoint(s("GET", "/rest/deadbeef")) == "GET /rest/{id}"


def test_query_excluded():
    assert endpoint(s("GET", "/rest/products/search")) == "GET /rest/products/search"


def test_multi_segment_mixed():
    assert endpoint(s("GET", "/rest/product/1/reviews/42")) == "GET /rest/product/{id}/reviews/{id}"


def test_root_path():
    assert endpoint(s("GET", "/")) == "GET /"


def test_method_uppercased():
    assert endpoint(s("post", "/rest/user/login")) == "POST /rest/user/login"


def test_nonnumeric_word_segment_kept():
    assert endpoint(s("GET", "/rest/user/whoami")) == "GET /rest/user/whoami"


def test_numeric_word_not_confused():
    # "whoami2" is not a pure number: kept
    assert endpoint(s("GET", "/rest/user/whoami2")) == "GET /rest/user/whoami2"
