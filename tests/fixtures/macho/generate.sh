#!/usr/bin/env bash
set -euo pipefail
# Rebuild the Mach-O fixtures of tests/macho.rs from hello.c with the Xcode
# toolchain (xcrun clang and ld), then gzip them without names or times.
#
# Usage: tests/fixtures/macho/generate.sh
# Needs macOS with Xcode command-line tools. The arm64 executable is
# ad-hoc signed by ld, and the signature names the output file, so the
# outputs must keep these names to reproduce the recorded hashes.

cd "$(dirname "$0")"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cp hello.c "$work/"
(
    cd "$work"
    xcrun clang -target arm64-apple-macos12.0 -O2 -o hello-arm64 hello.c
    xcrun clang -target x86_64-apple-macos10.15 -O2 -mavx2 -mfma -o hello-x86_64 hello.c
    xcrun clang -target arm64-apple-macos12.0 -O2 -c -o hello-arm64.o hello.c
    for file in hello-arm64 hello-x86_64 hello-arm64.o; do
        shasum -a 256 "$file"
        gzip -9 -n -c "$file" > "$file.gz"
    done
)
cp "$work/hello-arm64.gz" "$work/hello-x86_64.gz" "$work/hello-arm64.o.gz" .
