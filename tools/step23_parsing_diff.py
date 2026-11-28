#!/usr/bin/env python3
"""Step-23 T5: strict-parsing differential, first slice.

Sends hand-written raw HTTP/1.1 requests (no external data) to
  - the engine in front of a Python http.server backend,
  - the engine in front of a Go net/http backend,
  - each of the two backends directly,
and records, per case, what the engine decided and what each backend sees
of the same bytes (tools/step23_parsing_backend.py,
tools/parsing-diff-gobackend). Local testbed only (rule 6): every address
is 127.0.0.1 / localhost.

Families: content-length (duplicate, conflicting, odd values),
transfer-encoding (with Content-Length, duplicated, odd spellings),
percent (invalid percent sequences in path and query), overlong (overlong
UTF-8 in path and query, percent-encoded and as raw bytes).

Per case and backend the engine and the backend AGREE or DISAGREE:
  engine-refuses-backend-accepts   the engine answered itself (framing 400,
                                   rule block 403, ...) and the backend,
                                   given the same bytes, answers 200
  engine-forwards-backend-refuses  the engine forwarded the request and the
                                   backend, given the same bytes directly,
                                   answers an error of its own
  view-differs                     both accept, but what the backend gets
                                   THROUGH the engine differs from what it
                                   parses from the same bytes DIRECTLY in
                                   the decoded path, the decoded query or
                                   the body (length, SHA-256)
  canary-reaches-backend           the engine forwarded the request and the
                                   backend's decoded path or query holds the
                                   case's canary string (an attack marker
                                   the engine blocks when it is sent
                                   plainly; rule 47)
A case can be in more than one class for one backend. Nothing is a rate:
the cases are chosen, not sampled (rule 35).

Usage: step23_parsing_diff.py --engine-py URL --engine-go URL --py-port N --go-port N
           --events-py FILE --events-go FILE --out DIR
"""
import argparse
import collections
import json
import os
import socket
import sys
import time

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36")
CANARY = "<script>"
XSS_PLAIN = "%3Cscript%3Ealert(1)%3C/script%3E"
# overlong two-byte forms: '<' = C0 BC, '>' = C0 BE
XSS_OVERLONG_PCT = "%C0%BCscript%C0%BEalert(1)%C0%BC/script%C0%BE"
XSS_OVERLONG_RAW = b"\xc0\xbcscript\xc0\xbealert(1)\xc0\xbc/script\xc0\xbe"


def request(case_id, method, target, header_lines=(), payload=b""):
    """Raw request bytes. target may be str or bytes; header_lines are raw
    lines without CRLF and are sent exactly as given."""
    if isinstance(target, str):
        target = target.encode("latin-1")
    head = [method.encode() + b" " + target + b" HTTP/1.1",
            b"Host: localhost", b"User-Agent: " + UA.encode(), b"Accept: */*",
            b"X-Kortex-Sample-Id: " + case_id.encode()]
    for line in header_lines:
        head.append(line if isinstance(line, bytes) else line.encode("latin-1"))
    return b"\r\n".join(head) + b"\r\n\r\n" + payload


def post(case_id, header_lines, payload, content_type="text/plain"):
    return request(case_id, "POST", "/form", [f"Content-Type: {content_type}"] + list(header_lines), payload)


CHUNKED_HELLO = b"5\r\nhello\r\n0\r\n\r\n"


def build_cases():
    """[(id, family, note, raw bytes, canary or None)]"""
    c = []

    def add(cid, family, note, raw, canary=None):
        c.append({"id": cid, "family": family, "note": note, "raw": raw, "canary": canary})

    # ---- Content-Length ----
    add("cl-control", "content-length", "one Content-Length, matching body (control)",
        post("cl-control", ["Content-Length: 5"], b"hello"))
    add("cl-dup-same", "content-length", "two Content-Length headers, same value",
        post("cl-dup-same", ["Content-Length: 5", "Content-Length: 5"], b"hello"))
    add("cl-dup-small-first", "content-length", "two Content-Length headers, 5 then 11, 11 bytes sent",
        post("cl-dup-small-first", ["Content-Length: 5", "Content-Length: 11"], b"hello world"))
    add("cl-dup-large-first", "content-length", "two Content-Length headers, 11 then 5, 11 bytes sent",
        post("cl-dup-large-first", ["Content-Length: 11", "Content-Length: 5"], b"hello world"))
    add("cl-dup-case", "content-length", "content-length and CONTENT-LENGTH, 5 and 11",
        post("cl-dup-case", ["content-length: 5", "CONTENT-LENGTH: 11"], b"hello world"))
    add("cl-list-same", "content-length", "one header, value '5, 5'",
        post("cl-list-same", ["Content-Length: 5, 5"], b"hello"))
    add("cl-list-conflict", "content-length", "one header, value '5, 11', 11 bytes sent",
        post("cl-list-conflict", ["Content-Length: 5, 11"], b"hello world"))
    add("cl-plus", "content-length", "value '+5'", post("cl-plus", ["Content-Length: +5"], b"hello"))
    add("cl-leading-zeros", "content-length", "value '005'", post("cl-leading-zeros", ["Content-Length: 005"], b"hello"))
    add("cl-hex", "content-length", "value '0x5'", post("cl-hex", ["Content-Length: 0x5"], b"hello"))
    add("cl-negative", "content-length", "value '-1'", post("cl-negative", ["Content-Length: -1"], b"hello"))
    add("cl-empty", "content-length", "empty value", post("cl-empty", ["Content-Length:"], b"hello"))
    add("cl-non-numeric", "content-length", "value 'abc'", post("cl-non-numeric", ["Content-Length: abc"], b"hello"))
    add("cl-underscore", "content-length", "value '1_1', 11 bytes sent",
        post("cl-underscore", ["Content-Length: 1_1"], b"hello world"))
    add("cl-trailing-tab", "content-length", "value '5' followed by a tab",
        post("cl-trailing-tab", ["Content-Length: 5\t"], b"hello"))
    add("cl-space-before-colon", "content-length", "'Content-Length : 5' (space before the colon)",
        post("cl-space-before-colon", ["Content-Length : 5"], b"hello"))
    add("cl-space-before-colon-dup", "content-length",
        "'Content-Length: 5' and 'Content-Length : 11', 11 bytes sent",
        post("cl-space-before-colon-dup", ["Content-Length: 5", "Content-Length : 11"], b"hello world"))
    add("cl-obs-fold", "content-length", "value on a folded continuation line",
        post("cl-obs-fold", ["Content-Length:\r\n 5"], b"hello"))
    add("cl-short-body", "content-length", "Content-Length 5, 11 bytes sent (6 bytes left over)",
        post("cl-short-body", ["Content-Length: 5"], b"hello world"))

    # ---- Transfer-Encoding ----
    add("te-control", "transfer-encoding", "Transfer-Encoding: chunked, valid chunks (control)",
        post("te-control", ["Transfer-Encoding: chunked"], CHUNKED_HELLO))
    add("te-then-cl", "transfer-encoding", "Transfer-Encoding: chunked, then Content-Length: 5",
        post("te-then-cl", ["Transfer-Encoding: chunked", "Content-Length: 5"], CHUNKED_HELLO))
    add("cl-then-te", "transfer-encoding", "Content-Length: 5, then Transfer-Encoding: chunked",
        post("cl-then-te", ["Content-Length: 5", "Transfer-Encoding: chunked"], CHUNKED_HELLO))
    add("te-dup", "transfer-encoding", "two Transfer-Encoding: chunked headers",
        post("te-dup", ["Transfer-Encoding: chunked", "Transfer-Encoding: chunked"], CHUNKED_HELLO))
    add("te-dup-identity", "transfer-encoding", "Transfer-Encoding: chunked and Transfer-Encoding: identity",
        post("te-dup-identity", ["Transfer-Encoding: chunked", "Transfer-Encoding: identity"], CHUNKED_HELLO))
    add("te-list-identity", "transfer-encoding", "Transfer-Encoding: identity, chunked",
        post("te-list-identity", ["Transfer-Encoding: identity, chunked"], CHUNKED_HELLO))
    add("te-gzip-chunked", "transfer-encoding", "Transfer-Encoding: gzip, chunked (body is not gzip)",
        post("te-gzip-chunked", ["Transfer-Encoding: gzip, chunked"], CHUNKED_HELLO))
    add("te-case", "transfer-encoding", "Transfer-Encoding: Chunked",
        post("te-case", ["Transfer-Encoding: Chunked"], CHUNKED_HELLO))
    add("te-xchunked", "transfer-encoding", "Transfer-Encoding: xchunked",
        post("te-xchunked", ["Transfer-Encoding: xchunked"], CHUNKED_HELLO))
    add("te-xchunked-cl", "transfer-encoding", "Transfer-Encoding: xchunked with Content-Length: 5",
        post("te-xchunked-cl", ["Transfer-Encoding: xchunked", "Content-Length: 5"], b"hello"))
    add("te-space-before-colon", "transfer-encoding", "'Transfer-Encoding : chunked' with Content-Length: 5",
        post("te-space-before-colon", ["Transfer-Encoding : chunked", "Content-Length: 5"], CHUNKED_HELLO))
    add("te-tab", "transfer-encoding", "'Transfer-Encoding:<tab>chunked' with Content-Length: 5",
        post("te-tab", ["Transfer-Encoding:\tchunked", "Content-Length: 5"], CHUNKED_HELLO))
    add("te-obs-fold", "transfer-encoding", "Transfer-Encoding value on a folded line, with Content-Length: 5",
        post("te-obs-fold", ["Transfer-Encoding:\r\n chunked", "Content-Length: 5"], CHUNKED_HELLO))
    add("te-identity-cl", "transfer-encoding", "Transfer-Encoding: identity with Content-Length: 5",
        post("te-identity-cl", ["Transfer-Encoding: identity", "Content-Length: 5"], b"hello"))
    add("te-chunk-ext", "transfer-encoding", "chunk size with an extension ('5;x=1')",
        post("te-chunk-ext", ["Transfer-Encoding: chunked"], b"5;x=1\r\nhello\r\n0\r\n\r\n"))
    add("te-chunk-hex-prefix", "transfer-encoding", "chunk size '0x5'",
        post("te-chunk-hex-prefix", ["Transfer-Encoding: chunked"], b"0x5\r\nhello\r\n0\r\n\r\n"))
    add("te-chunk-lf-only", "transfer-encoding", "chunks ended by LF only",
        post("te-chunk-lf-only", ["Transfer-Encoding: chunked"], b"5\nhello\n0\n\n"))

    # ---- invalid percent sequences ----
    add("pct-control", "percent", "valid %20 in path and query (control)",
        request("pct-control", "GET", "/a%20b?q=a%20b"))
    add("pct-path-short", "percent", "path ends with '%2'", request("pct-path-short", "GET", "/a%2"))
    add("pct-path-nonhex", "percent", "path has '%zz'", request("pct-path-nonhex", "GET", "/a%zzb"))
    add("pct-path-bare", "percent", "path ends with a bare '%'", request("pct-path-bare", "GET", "/a%"))
    add("pct-path-nul", "percent", "path has %00", request("pct-path-nul", "GET", "/a%00b"))
    add("pct-query-short", "percent", "query value ends with '%2'", request("pct-query-short", "GET", "/s?q=a%2"))
    add("pct-query-nonhex", "percent", "query value has '%zz'", request("pct-query-nonhex", "GET", "/s?q=a%zzb"))
    add("pct-query-bare", "percent", "query value ends with a bare '%'", request("pct-query-bare", "GET", "/s?q=100%"))
    add("pct-query-nul", "percent", "query value has %00", request("pct-query-nul", "GET", "/s?q=a%00b"))
    add("pct-query-u", "percent", "query value has %u003c (IIS-style)",
        request("pct-query-u", "GET", "/s?q=%u003cscript%u003e"))
    add("pct-query-double", "percent", "query value double-encoded (%253C)",
        request("pct-query-double", "GET", "/s?q=%253Cscript%253Ealert(1)%253C/script%253E"), CANARY)
    add("pct-canary-control", "percent", "plain %3Cscript%3E in the query (canary control: must be blocked)",
        request("pct-canary-control", "GET", "/s?q=" + XSS_PLAIN), CANARY)
    add("pct-canary-broken-tail", "percent", "the canary followed by an invalid '%zz'",
        request("pct-canary-broken-tail", "GET", "/s?q=" + XSS_PLAIN + "%zz"), CANARY)
    add("pct-canary-broken-inside", "percent", "the canary with an invalid '%' inside the tag name ('%3Cscr%ipt%3E')",
        request("pct-canary-broken-inside", "GET", "/s?q=%3Cscr%ipt%3Ealert(1)%3C/script%3E"), CANARY)

    # ---- overlong UTF-8 ----
    add("ovl-path-slash-pct", "overlong", "path traversal with overlong '/' (%C0%AF)",
        request("ovl-path-slash-pct", "GET", "/static/..%C0%AF..%C0%AFetc/passwd"))
    add("ovl-path-dot-pct", "overlong", "path with overlong '.' (%C0%AE%C0%AE/)",
        request("ovl-path-dot-pct", "GET", "/static/%C0%AE%C0%AE/secret"))
    add("ovl-path-3byte-pct", "overlong", "path with three-byte overlong '/' (%E0%80%AF)",
        request("ovl-path-3byte-pct", "GET", "/static/..%E0%80%AFsecret"))
    add("ovl-path-nul-pct", "overlong", "path with overlong NUL (%C0%80)",
        request("ovl-path-nul-pct", "GET", "/a%C0%80b"))
    add("ovl-path-raw", "overlong", "path with raw bytes C0 AF (not percent-encoded)",
        request("ovl-path-raw", "GET", b"/static/..\xc0\xaf..\xc0\xafetc/passwd"))
    add("ovl-query-canary-pct", "overlong", "query canary with overlong '<' and '>' (%C0%BC, %C0%BE)",
        request("ovl-query-canary-pct", "GET", "/s?q=" + XSS_OVERLONG_PCT), CANARY)
    add("ovl-query-canary-raw", "overlong", "query canary with raw overlong bytes C0 BC / C0 BE",
        request("ovl-query-canary-raw", "GET", b"/s?q=" + XSS_OVERLONG_RAW), CANARY)
    add("ovl-query-canary-3byte", "overlong", "query canary with three-byte overlong '<' (%E0%80%BC)",
        request("ovl-query-canary-3byte", "GET", "/s?q=%E0%80%BCscript%E0%80%BEalert(1)"), CANARY)
    add("ovl-path-canary-pct", "overlong", "path canary with overlong '<' and '>'",
        request("ovl-path-canary-pct", "GET", "/" + XSS_OVERLONG_PCT), CANARY)
    add("ovl-path-canary-control", "overlong", "plain %3Cscript%3E in the path (canary control)",
        request("ovl-path-canary-control", "GET", "/" + XSS_PLAIN), CANARY)
    add("ovl-query-valid-utf8", "overlong", "valid two-byte UTF-8 in the query (%C3%A9, control)",
        request("ovl-query-valid-utf8", "GET", "/s?q=caf%C3%A9"))
    ids = [x["id"] for x in c]
    assert len(ids) == len(set(ids)), "duplicate case id"
    return c


def send_raw(port, raw, timeout=4.0):
    """Send raw bytes to 127.0.0.1:port; return (status or None, response body bytes, error or None)."""
    data = b""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
            s.sendall(raw)
            s.settimeout(timeout)
            while True:
                try:
                    chunk = s.recv(65536)
                except (socket.timeout, TimeoutError):
                    break
                if not chunk:
                    break
                data += chunk
    except OSError as exc:
        if not data:
            return None, b"", f"{type(exc).__name__}"
    head, sep, body = data.partition(b"\r\n\r\n")
    if any(line.lower().replace(b" ", b"") == b"transfer-encoding:chunked" for line in head.split(b"\r\n")[1:]):
        body = dechunk(body)
    status = None
    first = head.split(b"\r\n", 1)[0].split()
    if len(first) >= 2 and first[0].startswith(b"HTTP/") and first[1].isdigit():
        status = int(first[1])
    if not data:
        return None, b"", "no-response"
    return status, body, None


def dechunk(body):
    """Decode a chunked RESPONSE body (the engine answers some refusals chunked)."""
    out, rest = b"", body
    while rest:
        line, sep, rest = rest.partition(b"\r\n")
        try:
            size = int(line.split(b";")[0].strip(), 16)
        except ValueError:
            return body
        if size == 0:
            break
        out, rest = out + rest[:size], rest[size + 2:]
    return out


def parse_answer(status, body):
    """(view dict or None, engine decision or None) from a response."""
    text = body.decode("utf-8", "replace")
    try:
        doc = json.loads(text)
        if isinstance(doc, dict) and "backend" in doc:
            return doc, None
    except ValueError:
        pass
    first = text.split("\n", 1)[0]
    if status is not None and first.startswith(f"{status} kortex-decision="):
        return None, first.split("kortex-decision=", 1)[1].split()[0]
    return None, None


def canary_in_view(view, canary):
    if not canary or not view:
        return False
    if canary in (view.get("path_decoded") or ""):
        return True
    for key, values in (view.get("query_decoded") or {}).items():
        if canary in key or any(canary in v for v in values):
            return True
    return False


VIEW_FIELDS = ("path_decoded", "query_decoded", "body_len", "body_sha256")


def compare(case, engine, direct):
    """Disagreement classes of one case for one backend.

    engine: {"status", "decision", "forwarded", "view"} (the engine in front of this backend)
    direct: {"status", "view", "error"}                  (this backend, given the same bytes)
    Returns a list of (class, detail).
    """
    out = []
    backend_accepts = direct["view"] is not None
    if engine["forwarded"] and not backend_accepts:
        out.append(("engine-forwards-backend-refuses",
                    f"backend alone answers {direct['status'] if direct['status'] is not None else direct['error']}"))
    if not engine["forwarded"] and backend_accepts:
        v = direct["view"]
        out.append(("engine-refuses-backend-accepts",
                    f"backend alone accepts: body {v.get('body_len')} bytes ({v.get('body_framing')}), "
                    f"{v.get('leftover_len')} bytes left on the connection"))
    if engine["forwarded"] and backend_accepts and engine["view"] is not None:
        diff = [f for f in VIEW_FIELDS if engine["view"].get(f) != direct["view"].get(f)]
        if diff:
            parts = []
            for f in diff:
                if f == "body_sha256":
                    parts.append("body_sha256")
                else:
                    parts.append(f"{f}: through engine {engine['view'].get(f)!r}, direct {direct['view'].get(f)!r}")
            out.append(("view-differs", "; ".join(parts)))
    if engine["forwarded"] and backend_accepts and canary_in_view(direct["view"], case.get("canary")):
        out.append(("canary-reaches-backend", "the backend's decoded view holds the canary and the engine forwarded it"))
    return out


def load_events(path):
    by_id = collections.defaultdict(list)
    if path and os.path.exists(path):
        for line in open(path, encoding="utf-8"):
            if line.strip():
                ev = json.loads(line)
                by_id[ev.get("sample_id")].append({"decision": ev.get("decision"), "status": ev.get("status"),
                                                   "reason": ev.get("reason")})
    return by_id


def observe_engine(port, case):
    status, body, error = send_raw(port, case["raw"])
    view, decision = parse_answer(status, body)
    return {"status": status, "decision": decision, "view": view, "error": error}


def observe_direct(port, case):
    status, body, error = send_raw(port, case["raw"])
    view, _ = parse_answer(status, body)
    return {"status": status, "view": view, "error": error}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--engine-py-port", type=int, required=True)
    ap.add_argument("--engine-go-port", type=int, required=True)
    ap.add_argument("--py-port", type=int, required=True)
    ap.add_argument("--go-port", type=int, required=True)
    ap.add_argument("--events-py", required=True)
    ap.add_argument("--events-go", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    cases = build_cases()
    rows = []
    for case in cases:
        row = {"id": case["id"], "family": case["family"], "note": case["note"],
               "request_bytes": len(case["raw"]), "canary": bool(case["canary"]),
               "engine": {"python": observe_engine(args.engine_py_port, case),
                          "go": observe_engine(args.engine_go_port, case)},
               "direct": {"python": observe_direct(args.py_port, case),
                          "go": observe_direct(args.go_port, case)}}
        rows.append(row)
    time.sleep(0.5)  # let the engines finish writing their events
    events = {"python": load_events(args.events_py), "go": load_events(args.events_go)}
    for case, row in zip(cases, rows):
        row["disagreements"] = {}
        for b in ("python", "go"):
            evs = events[b].get(case["id"], [])
            eng = row["engine"][b]
            eng["events"] = evs
            # forwarded = the engine wrote a pass event for the request
            eng["forwarded"] = any(e["decision"] == "pass" for e in evs)
            row["disagreements"][b] = [{"class": c, "detail": d} for c, d in compare(case, eng, row["direct"][b])]
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "results.jsonl"), "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=True, sort_keys=True) + "\n")
    print("\n".join(summary(rows)))
    return 0


def engine_label(eng):
    if eng["forwarded"]:
        return "forwarded"
    if eng["decision"]:
        return f"{eng['status']} {eng['decision']}"
    if eng["status"] is None:
        return f"no answer ({eng['error']})"
    return f"{eng['status']} (no marker)"


def refusal_kind(eng):
    """Who in the engine refused: the framing gate, a rule, the body reader,
    or Go's HTTP parser (which answers before the engine's handler runs, with
    no kortex marker and no event)."""
    if eng["forwarded"]:
        return "forwarded"
    if eng["decision"] == "framing":
        return "framing gate (400, event)"
    if eng["decision"] == "block":
        return "rule block (403, event)"
    if eng["decision"]:
        return f"engine {eng['status']} {eng['decision']} (event)"
    events = "event" if eng.get("events") else "no event"
    return f"HTTP parser of the engine ({eng['status']}, no marker, {events})"


def body_of(direct):
    v = direct["view"]
    return None if v is None else (v.get("body_len"), v.get("body_sha256"))


def summary(rows):
    out = [f"== cases: {len(rows)} hand-written requests; "
           + ", ".join(f"{fam} {n}" for fam, n in sorted(collections.Counter(r['family'] for r in rows).items()))]
    out.append("== engine decision per family (engine in front of the Python backend / in front of the Go backend)")
    for fam in sorted({r["family"] for r in rows}):
        for b in ("python", "go"):
            cnt = collections.Counter(engine_label(r["engine"][b]) for r in rows if r["family"] == fam)
            out.append(f"   {fam} [{b}]: " + ", ".join(f"{k} {v}" for k, v in sorted(cnt.items())))
    same = sum(1 for r in rows if engine_label(r["engine"]["python"]) == engine_label(r["engine"]["go"]))
    out.append(f"== the engine decided the same in front of both backends in {same} of {len(rows)} cases")
    for r in rows:
        if engine_label(r["engine"]["python"]) != engine_label(r["engine"]["go"]):
            out.append(f"   {r['id']}: python-backed {engine_label(r['engine']['python'])}, "
                       f"go-backed {engine_label(r['engine']['go'])}")
    out.append("== who decided in the engine (python-backed run)")
    cnt = collections.Counter(refusal_kind(r["engine"]["python"]) for r in rows)
    out.append("   " + ", ".join(f"{k} {v}" for k, v in sorted(cnt.items())))
    silent = [r["id"] for r in rows if refusal_kind(r["engine"]["python"]).startswith("HTTP parser")]
    out.append(f"   refused by the engine's HTTP parser without a kortex marker and without an event: {len(silent)}: "
               + ", ".join(silent))
    out.append("== each backend given the same bytes directly")
    for b in ("python", "go"):
        acc = sum(1 for r in rows if r["direct"][b]["view"] is not None)
        st = collections.Counter(str(r["direct"][b]["status"]) if r["direct"][b]["status"] is not None
                                 else f"no answer ({r['direct'][b]['error']})" for r in rows)
        left = sum(1 for r in rows if r["direct"][b]["view"] and r["direct"][b]["view"].get("leftover_len"))
        out.append(f"   {b}: accepts {acc} of {len(rows)}; statuses {dict(sorted(st.items()))}; "
                   f"accepted with bytes left on the connection {left}")
    for b in ("python", "go"):
        by_class = collections.Counter(d["class"] for r in rows for d in r["disagreements"][b])
        cases_dis = sum(1 for r in rows if r["disagreements"][b])
        out.append(f"== engine vs {b} backend: {cases_dis} of {len(rows)} cases disagree; "
                   f"agree {len(rows) - cases_dis}; by class: "
                   + (", ".join(f"{k} {v}" for k, v in sorted(by_class.items())) or "none"))
        for r in rows:
            for d in r["disagreements"][b]:
                out.append(f"   {r['id']} [{r['family']}] {d['class']}: engine {engine_label(r['engine'][b])}; {d['detail']}")
    pair = [r for r in rows if body_of(r["direct"]["python"]) != body_of(r["direct"]["go"])]
    fwd = [r["id"] for r in pair if r["engine"]["python"]["forwarded"]]
    out.append(f"== the two backends, given the same bytes directly, differ from EACH OTHER (one refuses, or they read "
               f"a different body) in {len(pair)} of {len(rows)} cases; the engine refuses {len(pair) - len(fwd)} of "
               f"them and forwards {len(fwd)} with its own framing: {', '.join(fwd) or 'none'}")
    canaries = [r for r in rows if r["canary"]]
    out.append(f"== canary cases: {len(canaries)}; forwarded by the engine: "
               f"{sum(1 for r in canaries if r['engine']['python']['forwarded'])}; "
               f"blocked 403: {sum(1 for r in canaries if r['engine']['python']['decision'] == 'block')}")
    out.append("== log-only events of the engine (python-backed run), by reason")
    cnt = collections.Counter(e["reason"] for r in rows for e in r["engine"]["python"]["events"]
                              if e["decision"] == "would_reject")
    out.append("   " + (", ".join(f"{k} {v}" for k, v in sorted(cnt.items())) or "none"))
    return out


if __name__ == "__main__":
    sys.exit(main())
