#!/usr/bin/env bash
set -euo pipefail
# Merge corpora (build_corpus.py layout) into OUT with symlinked samples.
# Usage: merge.sh OUT CORPUS...
out="$1"; shift
rm -rf "$out"; mkdir -p "$out/samples"
: > "$out/manifest.jsonl"
for c in "$@"; do
  c="$(cd "$c" && pwd)"
  cat "$c/manifest.jsonl" >> "$out/manifest.jsonl"
  for d in "$c"/samples/*/; do
    cls="$(basename "$d")"
    mkdir -p "$out/samples/$cls"
    find "$d" -name '*.bin' -exec ln -sf {} "$out/samples/$cls/" \;
  done
done
wc -l < "$out/manifest.jsonl"
