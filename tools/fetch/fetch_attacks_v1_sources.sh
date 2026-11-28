#!/bin/bash
# Step-26: fetch the source files of attacks-v1 (docs/plan-attacks-v1.md).
# PayloadsAllTheThings, https://github.com/swisskyrepo/PayloadsAllTheThings ,
# commit 08ea40e77db3f42ef8f20c65196f3936a19b6c86, licence MIT. Each file is
# downloaded from raw.githubusercontent.com at that commit into gitignored
# data/external/patt-08ea40e/ (or $1) and checked against the SHA-256 in
# tools/fetch/attacks_v1_sources.sha256. A file that is already there is
# only checked. Needs network for missing files.
set -euo pipefail
cd "$(dirname "$0")/../.."
COMMIT=08ea40e77db3f42ef8f20c65196f3936a19b6c86
LIST=tools/fetch/attacks_v1_sources.sha256
D=${1:-data/external/patt-08ea40e}
mkdir -p "$D"
n=0; fetched=0
while IFS= read -r line; do
  case "$line" in "#"*|"") continue ;; esac
  want=${line%%  *}
  path=${line#*  }
  if [ ! -f "$D/$path" ]; then
    mkdir -p "$D/$(dirname "$path")"
    url="https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/$COMMIT/$(printf '%s' "$path" | sed 's/ /%20/g')"
    curl -sSfL -o "$D/$path" "$url"
    fetched=$((fetched + 1))
  fi
  got=$(shasum -a 256 "$D/$path" | awk '{print $1}')
  [ "$got" = "$want" ] || { echo "sha256 mismatch for $path: $got (want $want)"; exit 1; }
  n=$((n + 1))
done < "$LIST"
echo "PayloadsAllTheThings@$COMMIT: $n files in $D, $fetched downloaded now, every sha256 as in $LIST (list sha256 $(shasum -a 256 $LIST | awk '{print $1}'))"
