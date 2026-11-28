#!/bin/bash
# Step-25: fetch what the CRS regression suite needs (rule 25: nothing of it
# is committed; licence Apache-2.0 for all four; docs/plan-step25-crs-regression.md).
#   CRS v4.25.2 source tarball -> data/external/crs-v4.25.2/ (tests/regression)
#   go-ftw v2.1.0 (the version the CRS workflow pins at that tag) -> out/step25/bin210/go-ftw
#   go-ftw v2.7.0 (tool cross-check)                              -> out/step25/bin/go-ftw
#   albedo v0.3.0 (the suite's backend)                           -> out/step25/bin/albedo
# Needs network once; `go install` verifies the modules against sum.golang.org.
set -euo pipefail
cd "$(dirname "$0")/../.."
TARBALL_SHA=a3ecf5d5b0f8001e2eaf2006448fc8e22d6b645d7fc1c71268be5b99a7395a2d
TESTS_LISTING_SHA=aec74fa450ee0b5f97d8a5e8edabeea06d0b78eaa7d3eebd6e0b85b137472e25
OVERRIDES_SHA=58c2ae7ad6412a71c9d4c61877ee7f210478ec3b0c15c07159196387cc0655ec
sha() { shasum -a 256 "$@" | awk '{print $1}'; }

D=data/external/crs-v4.25.2
mkdir -p "$D" out/step25/bin out/step25/bin210
if [ ! -f "$D/crs-v4.25.2.tar.gz" ]; then
  curl -sSL -o "$D/crs-v4.25.2.tar.gz" https://github.com/coreruleset/coreruleset/archive/refs/tags/v4.25.2.tar.gz
fi
got=$(sha "$D/crs-v4.25.2.tar.gz")
[ "$got" = "$TARBALL_SHA" ] || { echo "tarball sha256 mismatch: $got"; exit 1; }
[ -d "$D/coreruleset-4.25.2" ] || tar xzf "$D/crs-v4.25.2.tar.gz" -C "$D"
got=$(cd "$D/coreruleset-4.25.2" && find tests/regression/tests -name '*.yaml' | LC_ALL=C sort | xargs shasum -a 256 | shasum -a 256 | awk '{print $1}')
[ "$got" = "$TESTS_LISTING_SHA" ] || { echo "test files listing sha256 mismatch: $got"; exit 1; }
got=$(sha "$D/coreruleset-4.25.2/tests/regression/coraza-overrides.yaml")
[ "$got" = "$OVERRIDES_SHA" ] || { echo "coraza-overrides.yaml sha256 mismatch: $got"; exit 1; }
diff -rq "$D/coreruleset-4.25.2/rules" engine/crs/owasp-crs/rules || { echo "engine rules differ from the tag"; exit 1; }

[ -x out/step25/bin210/go-ftw ] || GOBIN=$PWD/out/step25/bin210 GOFLAGS=-mod=mod go install github.com/coreruleset/go-ftw/v2@v2.1.0
[ -x out/step25/bin/go-ftw ]    || GOBIN=$PWD/out/step25/bin    GOFLAGS=-mod=mod go install github.com/coreruleset/go-ftw/v2@v2.7.0
[ -x out/step25/bin/albedo ]    || GOBIN=$PWD/out/step25/bin    GOFLAGS=-mod=mod go install github.com/coreruleset/albedo@v0.3.0

echo "tarball sha256 $TARBALL_SHA ok"
echo "test files: $(find "$D/coreruleset-4.25.2/tests/regression/tests" -name '*.yaml' | wc -l | tr -d ' ') yaml, listing sha256 $TESTS_LISTING_SHA ok"
echo "coraza-overrides.yaml sha256 $OVERRIDES_SHA ok"
echo "rules: identical to engine/crs/owasp-crs/rules"
for b in out/step25/bin210/go-ftw out/step25/bin/go-ftw out/step25/bin/albedo; do
  echo "$b sha256 $(sha $b) $(go version -m $b | awk '$1=="mod"{print $2" "$3" "$4}')"
done
