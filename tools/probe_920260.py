#!/usr/bin/env python3
"""Step-11 T5: 920260 differential probes, both engines, PL1 default config.

Exploratory, local stub backend only (AGENTS rule 6). The probe list is
fixed and documented here BEFORE any run. Each probe is a GET to
/rest/products/search with one hand-written q value (plus two URI-path
probes). For every probe we record the HTTP status from each engine and,
when the engine logged an audit entry, the rule IDs.

Probe families (28 total):
  plain controls (5): no encoding, single-encoded traversal, plain filename,
    dot-dot-slash, single-encoded percent-u on the wire
  percent-u forms (7): fullwidth dot/slash, unicode division/fraction slashes,
    fullwidth sequences, u2216, repeated
  double/triple encoding (4): %25uff0e (the step-10 divergence), %2525uff0e,
    %25u2216, %25uff0e%25uff0e
  overlong UTF-8 (5): %c0%af, %c0%ae, %c1%9c, %e0%80%af, %c0%80 (null)
  invalid percent (4): %zz, bare %, %1 (truncated), %%
  mixed-case hex (3): %Uff0e, %UFF0E, %uFF0E
"""
from __future__ import annotations

import json
import sys
import urllib.parse
import urllib.request

PROBES = [
    ("plain-none",       "../etc/passwd"),
    ("plain-single",     "%2e%2e%2fetc%2fpasswd"),
    ("plain-file",       "boot.ini"),
    ("plain-ddslash",    "..%2f"),
    ("plain-u-onwire",   "%uff0e"),
    ("u-fullwidth-dot",  "%uff0e%uff0e"),
    ("u-fullwidth-slash","%uff0f"),
    ("u-divide",         "%u2216"),
    ("u-fraction",       "%u2215"),
    ("u-mixed",          "%uff0e%u2216%uff0e"),
    ("u-repeated",       "%uff0e%uff0e%uff0e%uff0e"),
    ("u-plus-path",      "%2f%uff0e%uff0e%u2216boot.ini"),
    ("dbl-u-dot",        "%25uff0e"),
    ("dbl-u-dot2",       "%25uff0e%25uff0e"),
    ("dbl-u-slash",      "%25u2216"),
    ("triple-u-dot",     "%2525uff0e"),
    ("overlong-slash",   "%c0%af"),
    ("overlong-dot",     "%c0%ae"),
    ("overlong-c1",      "%c1%9c"),
    ("overlong-e0",      "%e0%80%af"),
    ("overlong-null",    "%c0%80"),
    ("bad-percent-zz",   "%zz"),
    ("bad-bare",         "%"),
    ("bad-truncated",    "%1"),
    ("bad-double",       "%%"),
    ("case-Uff0e",       "%Uff0e"),
    ("case-UFF0E",       "%UFF0E"),
    ("case-uFF0E",       "%uFF0E"),
]


def send(base_url: str, path: str, query: str) -> int:
    url = f"{base_url}{path}"
    if query:
        url += "?" + query
    req = urllib.request.Request(url, headers={"User-Agent": "kortex-probe/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return -1


def main() -> int:
    base = sys.argv[1]
    out_path = sys.argv[2]
    rows = []
    for name, q in PROBES:
        status = send(base, "/rest/products/search", "q=" + q)
        rows.append({"probe": name, "q": q, "uri": "/rest/products/search?q=" + q,
                     "status": status})
        print(f"{name:18s} {status}")
    # two URI-path probes (no query)
    for name, raw in (("path-u-dot", "/rest/products/%uff0e%uff0e"),
                      ("path-dbl-u", "/rest/products/%25uff0e")):
        status = send(base, raw, "")
        rows.append({"probe": name, "q": None, "uri": raw, "status": status})
        print(f"{name:18s} {status}")
    with open(out_path, "w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
