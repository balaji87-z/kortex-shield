# Baseline v2.2 (step-27, 2026-11-28)

Host and tools are those of baseline v2.1 (macOS 27.0 arm64, Apple M6,
go1.27.4, Python 3.15.2, pytest 9.2.0; Docker client 29.10.1, server 29.5.2
linux/arm64 under colima). The engine changed in this step: the gate
(E57 to E62), the forwarded request target (E64, E65) and one new switch
(E66). Engine binary of the final runs: sha256 a0618939...b50fd1a7, built
from 70e6477; coraza v3.8.1 with the step-23 patch, CRS 4.25.2. kortex_eval
is unchanged. Raw outputs and deviations: reports/step-27.md.

Images (rule 7):

| use | image |
|---|---|
| Node backend of the differential | node@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293 (node v20.20.2, llhttp 9.3.1, linux/arm64) |
| ModSecurity reference (DIAGNOSTIC only) | owasp/modsecurity-crs:4.25.2-nginx-lts@sha256:6296ce68...44de661, OWASP_CRS/4.25.2 read inside |
| Coraza connector reference (DIAGNOSTIC only) | ghcr.io/coreruleset/coraza-crs:4.25.2-nginx-lts@sha256:bfbfe70b...1c28f4a6, OWASP_CRS/4.25.2 read inside |

## What changed in the engine

| change | tests | setting |
|---|---|---|
| `OPTIONS *` is refused by the gate: `400 kortex-decision=framing`, reason `parser:options-asterisk` | E57 | none |
| A head over 65,536 bytes, or one that does not end in time, is answered `400 kortex-decision=framing` and logged (`head-too-large`, `head-timeout`); before, the connection was closed with no answer and no event | E58 | `KORTEX_HEAD_TIMEOUT_MS`, default 30000 (the old constant) |
| The end of the head is found as Go finds it (a blank line ended by LF or CRLF); a head ending with a bare-LF blank line is judged at once instead of after 30 s; 88 of 88 line-ending mixes of four heads are decided as bare net/http decides them | E59, E60, E63 | none |
| Each connection is gated in its own goroutine: one unfinished head no longer stops the listener | E61 | none |
| Connections waiting in the gate are counted (`pending_heads` on `/__kortex/stats`) and capped; one more gets `503 kortex-decision=overload`, reason `pending-heads` | E62 | `KORTEX_MAX_PENDING_HEADS`, default 256 |
| The backend is sent the path and query the rules were given (before: Go's re-encoded path) | E64 | none |
| A target that cannot be forwarded unchanged (starts with `//` and holds a byte Go escapes) is refused: `400 kortex-decision=framing`, reason `target-not-forwardable` | E65 | none |
| XML attribute values can be inspected | E66 | `KORTEX_XML_ATTR_INSPECT`, default off |

The default configuration of baseline v2.1 is unchanged: no baseline run
sets any of the three new settings.

## A3: the parsing differential (first measurement)

Frameworks in scope, fixed before testing: Go net/http (go1.27.4), Python
http.server (3.15.2), Node.js http (v20.20.2). HTTP stacks with their
standard parsers; application frameworks are NOT MEASURED.

158 hand-written requests, engine in-process, blocking, PL1 and PL2, each
backend behind its own engine and alone. Counts of chosen cases, never
rates (rule 35). The two levels give the same rows; PL2 is shown to be in
effect by the audit log (the matched rule-id set differs for 56 of 84
audit entries; 8 rule ids appear only at PL2).

| quantity | PL1 | PL2 |
|---|---|---|
| cases (step-23 heads / new heads / bodies) | 61 / 35 / 62 | same |
| engine decided the same in front of all three backends | 158 of 158 | 158 of 158 |
| engine refusals without a marker or without an event, or no answer | 0 | 0 |
| canary controls blocked with 403 | 7 of 7 | 7 of 7 |
| canary reaches a backend in path or query | 0 | 0 |
| second request of one write served | 0 of 4 | 0 of 4 |
| **canary reaches a backend's body parser (A3's failure condition)** | **1: `xml-attr`** | **1: `xml-attr`** |
| canary as the content of an uploaded file, forwarded | 1: `mp-filename` | 1 |

Per backend, final run (classes; a case can be in more than one):

| backend | engine refuses, backend alone accepts | engine forwards, backend alone refuses | view differs | canary reaches parser | canary in file part |
|---|---|---|---|---|---|
| Python http.server | 122 | 0 | 4 | 1 | 1 |
| Go net/http | 93 | 0 | 0 | 1 | 1 |
| Node http | 91 | 9 | 1 | not measured for XML and multipart | not measured |

- `xml-attr`: the canary as an XML attribute value. Forwarded with no rule
  match; Go's and Python's XML parsers yield it. CRS v4.25.2 removes the
  attribute target from its attack rules unless `tx.crs_xml_attr_inspect`
  is set. Both pinned reference images pass the same request and block
  its element-text control (DIAGNOSTIC), so the engine does what the
  reference does. PROVEN on the engine by E66: the switch is the only
  difference between forwarded and blocked.
- With `KORTEX_XML_ATTR_INSPECT=on` (DIAGNOSTIC run of all 158 cases): 0
  canaries reach a parser; every other row unchanged.
- `mp-filename-canary` (the canary as a file name) is forwarded as well;
  the backends read the name as `script>` (Go) and
  `script>alert(1)</script` (Python), not as the canary, so it is in no
  class.
- The 9 Node rows: 8 are heads Node refuses and the engine re-writes
  (bare LF, a trailing tab or folded Content-Length, a short body); the
  ninth is `ovl-path-raw`, forwarded as sent and refused by Node through
  the engine as alone.
- Against step 24, the 61 old cases: 60 answered as before; `ovl-path-raw`
  is forwarded where it was blocked (below).

## The forwarded target (E64) and `ovl-path-raw`

Since step 25 the rules judge the request target as sent; until this step
the request was forwarded with Go's re-encoded path. A raw byte Go escapes
(0x80 to 0xFF, `"`, `<`, `>`, `^`, a backtick, `{`, `|`, `}`, `\`) reached
the rules in one spelling and the backend in another: 9 of 11 test
targets, both modes. Fixed: the path and query go out as sent.

`GET /static/..\xC0\xAF..\xC0\xAFetc/passwd` (raw bytes), blocking, PL1:

| WAF | answer | rule |
|---|---|---|
| engine, step 24 (rules saw `%C0%AF`, backend got `%C0%AF`) | 403 | 930100 |
| engine, step 25 to the first run of this step (rules saw raw bytes, backend got `%C0%AF`) | forwarded | none |
| engine, final (rules and backend get the raw bytes) | forwarded | none |
| Coraza connector image (DIAGNOSTIC) | 200 | no audit entry |
| ModSecurity image (DIAGNOSTIC) | 403 | 930110 |

The percent-encoded spelling is blocked by all three with 930100. Engine
against ModSecurity on the raw spelling: 1 request, UNEXPLAINED
(HYPOTHESIS: `t:utf8toUnicode` of 930110; coraza's turns the overlong
bytes into `%ufffd%ufffd`).

## encoding-diff-v0 with every request sent (raw-socket runner)

The Python client cannot build 10 of the 192 requests (a raw space in the
query). `tools/raw_runner.py` sends all 192; chosen cases, so counts (rule
35). Final engine, in-process equal to worker:

| PL | waf_block | waf_fail_closed_400 | waf_pass | client errors |
|---|---|---|---|---|
| 1 | 137 | 10 | 45 | 0 |
| 2 | 147 | 10 | 35 | 0 |

The 10 are refused by the gate (`parser:http-version`); the rules never
judge them. On the other 182: 0 status and 0 rule-id-set differences
between the raw runner and the Python client.

## Datasets after the engine changes

Per sample id against the step-25 runs (in-process and worker, PL1 and
PL2), final engine:

| dataset | requests | status diffs | worst-case-set diffs | rule-id-set diffs |
|---|---|---|---|---|
| attacks-v0 | 1,054 | 0 | 0 | 0 |
| attacks-ct-v0 | 320 | 0 | 0 | 0 |
| encoding-diff-v0 | 192 | 0 | 0 | 0 |
| benign-browse-v1 | 774 | 0 | 0 | 0 |
| benign-hard-v0 | 180 | 0 | 0 | 0 |
| benign-wcp-v0 | 20,000 | 0 | 0 (outcome diffs 0) | 0 |
| benign-wcp-v1 | 10,000 | 0 | 0 (outcome diffs 0) | 0 |

So every rate of baseline v2.0 on these datasets stands unchanged: wcp
worst case 2,284 / 8,967 of 20,000 (v0, PL1 / PL2) and 1,133 / 4,480 of
10,000 (v1); benign-labelled traffic, every block a potential false
positive.

## attacks-v1 and the CRS suite on the step-27 engine

| run | result | against the earlier run, per sample or test |
|---|---|---|
| attacks-v1 (held-out), in-process and worker, PL1 | 2,214 of 2,670 blocked (82.92%), 456 passed; best case equals worst case | step 26: 0 status, 0 worst-case-set, 0 rule-id-set differences |
| attacks-v1, PL2 | 2,444 of 2,670 blocked (91.54%), 226 passed | step 26: 0 / 0 / 0 |
| CRS v4.25.2 regression suite, go-ftw 2.1.0, DetectionOnly, PL4, in-process | 4,862 passed, 125 failed of 4,987 (97.49%) | step 25: 0 tests with a different result, 0 with a different logged rule-id set |
| the same, worker mode | 4,862 / 125 | step 25: 0 / 0; against in-process: 0 / 0 |

So A1 (failing, 97.49%) and the attacks-v1 recall of baseline v2.1 stand
unchanged on the step-27 engine.

## Not measured in this step

Application frameworks; multipart and XML on Node; the WAFFLED corpus
itself; HTTP/2; response parsing; timing; `KORTEX_XML_ATTR_INSPECT=on` on
any dataset (it was run on the 158 cases only); a per-client limit on
connections waiting in the gate.
