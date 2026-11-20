#!/bin/bash
# Rule 42 (step-18): durable evidence. Copy a run's outcomes.jsonl,
# audit.jsonl, responses.jsonl and run.json into docs/logs/runs/<run-name>/
# (compressed if a file is over 5 MB) so nothing needed for a comparison
# lives only under gitignored out/. Usage: tools/preserve_run.sh <out-dir>...
set -u
cd "$(cd "$(dirname "$0")/.." && pwd)"
LIMIT=$((5 * 1024 * 1024))
for DIR in "$@"; do
  [ -d "$DIR" ] || { echo "preserve_run: $DIR missing, skipped" >&2; continue; }
  NAME=$(basename "$DIR")
  DEST="docs/logs/runs/$NAME"
  mkdir -p "$DEST"
  for F in outcomes.jsonl audit.jsonl responses.jsonl run.json; do
    [ -f "$DIR/$F" ] || { echo "preserve_run: $DIR/$F missing" >&2; continue; }
    if [ "$(stat -c%s "$DIR/$F")" -gt "$LIMIT" ]; then
      gzip -c "$DIR/$F" > "$DEST/$F.gz"
    else
      cp "$DIR/$F" "$DEST/$F"
    fi
  done
  echo "preserve_run: $DIR -> $DEST"
done
