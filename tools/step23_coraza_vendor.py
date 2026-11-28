#!/usr/bin/env python3
"""Step-23 T2: the vendored, patched copy of coraza v3.8.1 the engine builds
against (engine/go.mod: replace github.com/corazawaf/coraza/v3 =>
./third_party/coraza-v3.8.1-kortex). Design: docs/engine-design.md.

Usage: step23_coraza_vendor.py make    build the copy from the Go module cache,
                                       apply the patch, write the .patch file
       step23_coraza_vendor.py check   prove the copy: every vendored file is
                                       byte-identical to the module cache except
                                       the patched files, and their diff equals
                                       the committed .patch file; exit 1 if not

No network: the source is $GOMODCACHE/github.com/corazawaf/coraza/v3@v3.8.1,
which `go mod download` verified against engine/go.sum when it was fetched.
Only the non-test .go files of the packages the engine imports are copied,
plus go.mod, go.sum and LICENSE.

The patch: map-backed collections are walked in ascending key order instead
of Go's random map order (step-22 F1: capture order for chained rules, and
the position-keyed transformation cache).
"""
import difflib
import hashlib
import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = "github.com/corazawaf/coraza/v3"
VERSION = "v3.8.1"
DEST = ROOT / "engine" / "third_party" / "coraza-v3.8.1-kortex"
PATCH = ROOT / "engine" / "third_party" / "coraza-v3.8.1-kortex.patch"
TOP_FILES = ("go.mod", "go.sum", "LICENSE")
# the coraza packages in `go list -deps` of the engine (25), as directories
PACKAGE_DIRS = (
    ".", "collection", "debuglog", "experimental/plugins/macro", "experimental/plugins/plugintypes",
    "internal/actions", "internal/auditlog", "internal/bodyprocessors", "internal/collections",
    "internal/cookies", "internal/corazarules", "internal/corazatypes", "internal/corazawaf",
    "internal/environment", "internal/io", "internal/memoize", "internal/operators", "internal/seclang",
    "internal/strings", "internal/sync", "internal/transformations", "internal/url", "internal/variables",
    "types", "types/variables",
)
NEW_FILE = "internal/collections/kortex_sorted.go"
NEW_FILE_TEXT = '''// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// kortex-shield patch (step 23): not part of coraza v3.8.1.

package collections

import "sort"

// sortedKeys returns the keys of a collection's map in ascending order, so
// that FindAll and FindRegex hand rules the same variables in the same order
// on every call instead of Go's random map order.
func sortedKeys(m map[string][]keyValue) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
'''
# (file, data expression, number of "walk every value" loops, number of "walk matching keys" loops)
PATCHED = (
    ("internal/collections/map.go", "c.data", 1, 1),
    ("internal/collections/named.go", "c.collection.data", 2, 1),
)


def module_dir() -> pathlib.Path:
    cache = subprocess.run(["go", "env", "GOMODCACHE"], capture_output=True, text=True, check=True).stdout.strip()
    path = pathlib.Path(cache) / f"{MODULE}@{VERSION}"
    if not path.is_dir():
        sys.exit(f"coraza {VERSION} is not in the module cache: {path}")
    return path


def source_files(src: pathlib.Path) -> list[str]:
    files = [f for f in TOP_FILES]
    for d in PACKAGE_DIRS:
        for p in sorted((src / d).glob("*.go")):
            if not p.name.endswith("_test.go"):
                files.append(str(p.relative_to(src)))
    return sorted(files)


def patch_text(rel: str, text: str) -> str:
    for name, data, n_all, n_regex in PATCHED:
        if name != rel:
            continue
        for old, new, count in (
            (f"\tfor _, data := range {data} {{\n\t\tfor _, d := range data {{",
             f"\tfor _, k := range sortedKeys({data}) {{\n\t\tdata := {data}[k]\n\t\tfor _, d := range data {{", n_all),
            (f"\tfor k, data := range {data} {{\n\t\tif key.MatchString(k) {{",
             f"\tfor _, k := range sortedKeys({data}) {{\n\t\tdata := {data}[k]\n\t\tif key.MatchString(k) {{", n_regex),
        ):
            if text.count(old) != count:
                sys.exit(f"{rel}: expected {count} occurrence(s) of a patch anchor, found {text.count(old)}")
            text = text.replace(old, new)
    return text


def unified(rel: str, before: str, after: str) -> str:
    return "".join(difflib.unified_diff(
        before.splitlines(keepends=True), after.splitlines(keepends=True),
        fromfile=f"a/{rel}" if before else "/dev/null", tofile=f"b/{rel}"))


def expected_patch(src: pathlib.Path) -> str:
    parts = [f"# kortex-shield patch to {MODULE} {VERSION} (step 23, docs/engine-design.md).\n"
             "# Map-backed collections are walked in ascending key order.\n"
             "# Generated and checked by tools/step23_coraza_vendor.py.\n"]
    parts.append(unified(NEW_FILE, "", NEW_FILE_TEXT))
    for rel, *_ in PATCHED:
        before = (src / rel).read_text(encoding="utf-8")
        parts.append(unified(rel, before, patch_text(rel, before)))
    return "".join(parts)


def make() -> int:
    src = module_dir()
    if DEST.exists():
        shutil.rmtree(DEST)
    files = source_files(src)
    for rel in files:
        out = DEST / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        text = (src / rel).read_bytes()
        if any(rel == name for name, *_ in PATCHED):
            text = patch_text(rel, text.decode("utf-8")).encode("utf-8")
        out.write_bytes(text)
    (DEST / NEW_FILE).write_text(NEW_FILE_TEXT, encoding="utf-8")
    PATCH.write_text(expected_patch(src), encoding="utf-8")
    print(f"vendored {len(files)} file(s) of {MODULE} {VERSION} from {src} + 1 new file into {DEST.relative_to(ROOT)}")
    return check()


def sha(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check() -> int:
    src = module_dir()
    want = set(source_files(src))
    have = {str(p.relative_to(DEST)) for p in DEST.rglob("*") if p.is_file()}
    patched = {name for name, *_ in PATCHED}
    problems = []
    extra = sorted(have - want - {NEW_FILE})
    missing = sorted(want - have)
    if extra:
        problems.append(f"file(s) not from the module and not the patch's new file: {extra}")
    if missing:
        problems.append(f"file(s) of the module missing from the copy: {missing}")
    if NEW_FILE not in have:
        problems.append(f"the patch's new file is missing: {NEW_FILE}")
    identical, differing = 0, []
    for rel in sorted(want & have):
        if sha(src / rel) == sha(DEST / rel):
            identical += 1
        else:
            differing.append(rel)
    if set(differing) != patched:
        problems.append(f"files that differ from the module: {differing}; expected exactly {sorted(patched)}")
    for rel in sorted(patched & have):
        if (DEST / rel).read_text(encoding="utf-8") != patch_text(rel, (src / rel).read_text(encoding="utf-8")):
            problems.append(f"{rel}: content is not the module file with the patch applied")
    if NEW_FILE in have and (DEST / NEW_FILE).read_text(encoding="utf-8") != NEW_FILE_TEXT:
        problems.append(f"{NEW_FILE}: content differs from the patch's new file")
    if not PATCH.exists() or PATCH.read_text(encoding="utf-8") != expected_patch(src):
        problems.append(f"{PATCH.relative_to(ROOT)} is not the diff between the module and the copy")
    size = sum((DEST / rel).stat().st_size for rel in have)
    print(f"module: {src}")
    print(f"copy:   {DEST.relative_to(ROOT)}: {len(have)} file(s), {size} bytes")
    print(f"byte-identical to the module: {identical}; differing: {len(differing)} {differing}; "
          f"new: {len(have - want)} {sorted(have - want)}; module files of these packages not copied: {len(missing)}")
    patch_lines = PATCH.read_text(encoding="utf-8").splitlines() if PATCH.exists() else []
    added = sum(1 for l in patch_lines if l.startswith("+") and not l.startswith("+++"))
    removed = sum(1 for l in patch_lines if l.startswith("-") and not l.startswith("---"))
    print(f"patch:  {PATCH.relative_to(ROOT)}: +{added} -{removed} lines, sha256 {sha(PATCH) if PATCH.exists() else 'absent'}")
    for p in problems:
        print(f"PROBLEM: {p}")
    print("vendor check: " + ("OK" if not problems else f"FAILED ({len(problems)} problem(s))"))
    return 1 if problems else 0


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ("make", "check"):
        sys.exit(__doc__)
    sys.exit(make() if sys.argv[1] == "make" else check())
