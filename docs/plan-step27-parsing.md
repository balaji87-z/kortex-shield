# Step-27 plan: finishing the parsing work (written BEFORE code and runs)

Brief (instructor, 2026-11-27): "do all 4"; this is the third of the four
steps. As offered: a raw-socket runner for requests the Python client
cannot send, the new request shapes against real backends and at PL2, and
the four gate questions of step 24, for which I choose defaults and flag
them. Acceptance A3 ("zero parsing-discrepancy bypasses on frameworks in
scope; the list of frameworks is fixed before testing") has been `not
started`; this step gives it its first measurement.

No run of this plan exists when it is written. One probe was made to read
the engine's present behaviour (hand-written requests to the local engine,
quoted in the design note); it informed the defaults below.

## Frameworks in scope (fixed here, before testing)

| backend | version | how it runs |
|---|---|---|
| Go net/http | go1.27.4 | tools/parsing-diff-gobackend, on the host |
| Python http.server | Python 3.15.2 | tools/step23_parsing_backend.py, on the host |
| Node.js http (llhttp 9.3.1) | v20.20.2, image `node@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293` (linux/arm64) | tools/parsing-diff-nodebackend, in a container, port published on localhost |

These are HTTP stacks with their standard-library parsers, not application
frameworks (Express, Django, Spring, ...). The step says so wherever A3 is
reported; frameworks with their own body parsers are NOT MEASURED.

## T1. Gate decisions (engine, tests first: rules 37, 40)

Defaults chosen for the step-24 questions 1 to 4. Each is listed again
under "Questions for instructor" in the report.

| question | default | change |
|---|---|---|
| 1. `OPTIONS *` is answered 200 by net/http itself: not inspected, no event | refuse it at the gate | E57: `400 kortex-decision=framing`, one `framing` event, reason `parser:options-asterisk` |
| 2. a head the gate cannot read is closed with no answer and no event | announce it | E58: more than 65,536 bytes: 400 framing, event reason `head-too-large`; no end of head within the time limit: 400 framing, event reason `head-timeout`. The limit stays 30 s; `KORTEX_HEAD_TIMEOUT_MS` makes it settable (tests, rule 48) and it is printed on `/__kortex/config` |
| 3. bare LF: accepted when it hides no framing problem | keep accepting | no change of policy. Found by the probe: a head whose last line ends with a bare LF is not recognised as complete; the client gets no answer until the 30 s limit. E59: the gate finds the end of the head the way Go's parser does (a blank line ended by LF or CRLF) |
| 4. every parser refusal is 400 | keep one status | none; kortex_eval is not touched (rule 5) |

Why refuse `OPTIONS *`: the engine cannot forward it as an ordinary request
(the target has no path), browsers do not send it (a CORS preflight names a
path), and an answer that no rule saw and no event records contradicts the
engine's own claim that every answer is logged.

E45 (19,257 damaged heads, gate against bare net/http) must still pass;
heads that end with a bare-LF blank line are added to it.

## T2. Raw-socket runner

`tools/raw_runner.py`: sends each sample of a manifest as the bytes the
manifest stores (method, path, `?`, query, body, written without any URL
or header validation), one connection per request, and writes
`responses.jsonl` and `run.json` in the format of `kortex_eval.runner`, so
`kortex_eval.outcome` reads them unchanged. kortex_eval is not changed.

- Check of the runner itself (canary, rule 47): encoding-diff-v0 has 182
  requests the Python client can send. Their statuses through the raw
  runner are compared per sample id with the step-25 runs of the same
  engine code path; any difference is listed.
- Then the 10 requests the Python client refuses to build
  (`encd-query-plain-*`, a raw space in the query): sent for the first
  time, engine in-process and worker, PL1 and PL2. The dataset is frozen
  and unchanged; its counts are reported as counts (rule 35), now with 0
  client errors.

## T3. Head differential, second slice

The 61 cases of step 23 and new families, against the three backends, each
backend also alone, PL1 and PL2:

- bare-lf: every line ended by LF; only the blank line; mixed; with a
  framing header after a bare LF; with a canary.
- conn-reuse: two requests in one write (the second with a canary; the
  second one the gate refuses when sent alone).
- host: no Host on HTTP/1.1, two Host lines (same and different values),
  an absolute-form target whose host differs from the Host line, empty
  Host.
- version: HTTP/1.0 with and without Host, HTTP/0.9-style request line,
  HTTP/1.2, HTTP/2.0, lower-case `http/1.1`.
- expect: `Expect: 100-continue` with a body, another Expect value.
- request-line: two spaces, a tab, a raw space inside the query (the shape
  of the 10 unsendable requests), `OPTIONS *`.
- head-size: a head over 65,536 bytes.

Classes as in step 23 (engine-refuses-backend-accepts,
engine-forwards-backend-refuses, view-differs, canary-reaches-backend), one
row per case and backend, no rate (rule 35). New in this slice: every
engine refusal must carry the kortex marker and one event (the step-24
criterion), counted again.

## T4. Body differential, first slice (A3's own method)

Hand-written body mutations in the manner of WAFFLED (arXiv 2503.10846),
no external data. Each case carries the canary `<script>alert(1)</script>`
as the value of a field `q` and a control in which the same canary is sent
plainly and must be blocked (rule 47). Each backend parses the body with
its standard parser and reports the value of `q` it gets:

| body kind | mutations | Go | Python | Node |
|---|---|---|---|---|
| urlencoded | duplicate key, `;` separator, charset parameter, content type in other case, with parameters, plus and percent mixes | `ParseForm` | `urllib.parse.parse_qs` | `URLSearchParams` |
| multipart | boundary quoted, boundary with other parameters before and after, two boundary parameters, LF-only part lines, no final boundary, `name` without quotes, two `name` parameters, a `filename` on the canary part, header folding in a part | `ParseMultipartForm` | `email` parser | NOT MEASURED (no standard parser) |
| JSON | `\u003c` escapes, duplicate key, a BOM, trailing comma, comments, nested value | `encoding/json` | `json` | `JSON.parse` |
| XML | CDATA, character entities, an encoding declaration | `encoding/xml` | `xml.etree` | NOT MEASURED |
| content-type confusion | a form body labelled JSON, a JSON body labelled text/plain, no content type | by the label | by the label | by the label |

A3's failure condition is counted as: the engine forwards the request, no
rule matched, and a backend's parser yields the canary in `q`
(`canary-reaches-parser`). Each such case is listed by id and classified
(rule 39): BUG (fixed test first if the fix is in the engine's existing
request path), DESIGN, or UNEXPLAINED. A case where the backend's parser
yields no canary (it rejects the body or reads another value) is not a
bypass and is reported as such.

The engine's settings are those of baseline v2.0 / v2.1 (blocking, PL1 and
PL2, in-process; worker mode for T2 only).

## What is reported

- Per engine change: failing test, passing test, Go suite.
- T2: per-sample status comparison raw runner against the Python client;
  the counts of encoding-diff-v0 with all 192 requests sent.
- T3, T4: per case and backend the class, at PL1 and PL2; refusals without
  a marker or without an event; canary rows; changes against the step-24
  result for the 61 old cases.
- A3 status with its denominator: cases, backends, and what is NOT
  MEASURED (application frameworks, multipart and XML on Node).
- After the engine changes: our own datasets and the wcp datasets against
  the step-25 runs, per sample; Go and Python suites.

## Not in this plan

Application frameworks; HTTP/2; response parsing; timing; any rule or
setting change in response to a result (rule 17).

## Addendum (2026-11-28, written after the first run of T3 / T4 and BEFORE the changes it names)

The first run (docs/logs/step27-parsing-diff-run1.txt, engine 7616436)
gave three things to act on. This addendum fixes what is done about each
before any code for it exists.

1. `ovl-path-raw` (a step-23 case): blocked at step 24, forwarded now. The
   rules have been given the request target as sent since step 25, and the
   request is still forwarded with Go's re-encoded path: raw bytes C0 AF
   are judged as raw bytes and reach the backend as `%C0%AF`. BUG in the
   engine's request path, so it is fixed in this step, test first (T5:
   E64, E65). The fix is to forward what was judged, not to judge another
   form: the rules' view (step 25, CRS suite) does not change.
2. `xml-attr`: a payload in an XML attribute value is forwarded. CRS
   v4.25.2 (LTS) removes the attribute target from its attack rules unless
   `tx.crs_xml_attr_inspect` is set (rules 901180 / 901181), and the setup
   of the pinned images, which the engine mirrors, does not set it. This
   plan said "no setting change in response to a result". Kept for the
   default: the engine's default configuration does not change, and A3 is
   reported on the default. Added, as a deviation from that sentence: a
   switch `KORTEX_XML_ATTR_INSPECT`, off by default, documented in
   docs/baseline-config.md before its first run (rule 17), test first
   (E66). Runs with it on are DIAGNOSTIC (rule 34). Whether it becomes the
   default is a question for the instructor.
3. `blf-cr-only` was counted as a refusal without an event. The event is
   there with an empty sample id: the id line is glued to the Host line by
   the bare CR, so the engine cannot read it. A limit of the tool, not of
   the engine; the tool now also takes the events without a sample id that
   were written while the case was sent (unit test added). No engine
   change.

Added runs:

- T5: the differential again on the fixed engine (the final reading), and
  once more with `KORTEX_XML_ATTR_INSPECT=on` (DIAGNOSTIC).
- DIAGNOSTIC: `xml-attr`, its control and `ovl-path-raw` sent to the two
  pinned reference images (ModSecurity and the Coraza connector, CRS
  v4.25.2, blocking, PL1), to say whether the engine differs from the
  reference on them (rule 39) or shares the behaviour. (Run while this
  addendum was being written, before any engine change:
  docs/logs/step27-DIAGNOSTIC-reference.txt. Both images pass `xml-attr`;
  ModSecurity blocks `ovl-path-raw` with 930110, the Coraza connector
  passes it.)
- The datasets after the last engine change (own datasets, wcp, the raw
  runs of T2) are run again on the final engine; the runs on 7616436 are
  replaced, not kept beside them.
