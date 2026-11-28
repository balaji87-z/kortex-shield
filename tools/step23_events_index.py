#!/usr/bin/env python3
"""Step-23: a durable index of an engine events file (kortex-events.jsonl).

Usage: step23_events_index.py <events.jsonl> <out.index.jsonl>

Keeps every event that is not a plain pass or block (those are in
responses.jsonl and the audit index already): sample id, decision, status
and reason, nothing else. Prints one line of counts: all events by
decision, the compressed-body events of E40 by kind, and the framing events
of E35 by reason. Events carry no request data (engine/events.go).
"""
import collections
import json
import sys

MAGIC_PREFIX = "compressed-body-without-content-encoding:"


def index(lines):
    """(kept rows, counts by decision, magic counts by kind, framing counts by reason)."""
    kept, decisions = [], collections.Counter()
    magic, framing = collections.Counter(), collections.Counter()
    for line in lines:
        if not line.strip():
            continue
        ev = json.loads(line)
        decision, reason = ev.get("decision"), ev.get("reason") or ""
        decisions[decision] += 1
        if decision in ("pass", "block"):
            continue
        if decision == "would_reject" and reason.startswith(MAGIC_PREFIX):
            magic[reason[len(MAGIC_PREFIX):]] += 1
        if decision == "framing":
            framing[reason] += 1
        kept.append({"sample_id": ev.get("sample_id"), "decision": decision,
                     "status": ev.get("status"), "reason": reason})
    return kept, decisions, magic, framing


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    src, dst = argv
    with open(src, encoding="utf-8") as fh:
        kept, decisions, magic, framing = index(fh)
    with open(dst, "w", encoding="utf-8") as fh:
        for row in kept:
            fh.write(json.dumps(row) + "\n")
    print(f"{sum(decisions.values())} events {dict(sorted(decisions.items(), key=lambda kv: str(kv[0])))}; "
          f"compressed-body events {sum(magic.values())} {dict(sorted(magic.items()))}; "
          f"framing events {sum(framing.values())} {dict(sorted(framing.items()))}; kept {len(kept)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
