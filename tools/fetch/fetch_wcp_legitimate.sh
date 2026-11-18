#!/bin/sh
# Fetch the openappsec WCP legitimate dataset (rule 25: fetch script + SHA
# instead of committing 1.2 GB of third-party data; Apache 2.0).
# Expected SHA-256: 58faee18c54229759287a574f6f8cb1e3b951fa135e403ea9a679d2b18efd778
set -e
cd "$(dirname "$0")/../.."
mkdir -p data/external
curl -L -C - -o data/external/legitimate.zip https://downloads.openappsec.io/waf-comparison-project/legitimate.zip
sha256sum data/external/legitimate.zip
