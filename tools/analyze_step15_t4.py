#!/usr/bin/env python3
"""Step-15 T4 analysis: min/median/max elapsed_ms per (source, content-type,
size, paranoia level) from docs/logs/step15-t4-scaling.txt job lines.
Counts of statuses per cell are also printed. No cap recommendation here."""
import re
import statistics
import sys

LINE = re.compile(
    r"^job (\S+) rep=(\d+) status=(\d+) elapsed_ms=([0-9.]+)")


def main(path):
    cells = {}
    for line in open(path):
        m = LINE.match(line.strip())
        if not m:
            continue
        jid, rep, status, ms = m.group(1), int(m.group(2)), int(m.group(3)), float(m.group(4))
        cells.setdefault(jid, []).append((status, ms))
    print(f"{'job':32} {'reps':>4} {'statuses':>14} {'min_ms':>9} {'med_ms':>9} {'max_ms':>9}")
    for jid in sorted(cells, key=lambda j: (j.split("-")[0], j.split("-")[1], int(j.rsplit("-", 1)[1]))):
        reps = cells[jid]
        ms = [m for _, m in reps]
        sts = ",".join(str(s) for s, _ in reps)
        print(f"{jid:32} {len(reps):>4} {sts:>14} {min(ms):9.1f} {statistics.median(ms):9.1f} {max(ms):9.1f}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "docs/logs/step15-t4-scaling.txt")
