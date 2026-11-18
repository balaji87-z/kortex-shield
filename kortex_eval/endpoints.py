"""Endpoint templates for benign-traffic aggregation (rule 14/15 reporting).

endpoint(sample) = METHOD + " " + path, where numeric path segments and
hex/UUID-like segments of 8+ characters are replaced by {id}. The query is
excluded. Example:

    GET /rest/warehouse/p/9f86d081884c7d65 → GET /rest/warehouse/p/{id}
    GET /rest/product/1                    → GET /rest/product/{id}
"""
from __future__ import annotations

import re

_SEGMENT_ID = re.compile(r"^[0-9]+$|^[0-9a-fA-F]{8,}$|^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-"
                         r"[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def endpoint(sample) -> str:
    """Template the sample's method+path; query excluded."""
    path = sample.path if hasattr(sample, "path") else sample["path"]
    method = (sample.method if hasattr(sample, "method") else sample["method"]).upper()
    segments = path.strip("/").split("/") if path.strip("/") else []
    templated = "/".join("{id}" if _SEGMENT_ID.match(seg) else seg for seg in segments)
    return f"{method} /{templated}" if templated else method + " /"
