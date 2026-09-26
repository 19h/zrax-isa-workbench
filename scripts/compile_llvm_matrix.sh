#!/usr/bin/env bash
# Compile the armgen C programs for every LLVM target configuration in
# scripts/llvm_targets.txt, producing ground-truth objects for
# scripts/build_corpus.py (--gen OUT).
#
# Output layout: OUT/<class>/t<N>_<opt>/<set>__<program>.o
# (the corpus builder splits train/test on the part after "__").
#
# Usage: scripts/compile_llvm_matrix.sh OUT [CLANG] [JOBS]
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
out="${1:?usage: $0 OUT [CLANG] [JOBS]}"
clang="${2:-/opt/homebrew/opt/llvm/bin/clang}"
jobs="${3:-12}"
armgen="${ARMGEN:-$here/../../armgen}"
mkdir -p "$out"
jobfile="$(mktemp)"
n=0
while IFS='|' read -r cls triple flags; do
  [ -z "$cls" ] && continue
  n=$((n + 1))
  for opt in O0 O1 O2 Os O3; do
    for src in "$armgen"/programs/*.c "$armgen"/programs2/*.c; do
      set_name="$(basename "$(dirname "$src")")"
      prog="$(basename "$src" .c)"
      dst="$out/$cls/t${n}_$opt/${set_name}__${prog}.o"
      printf '%s\n' "mkdir -p '$(dirname "$dst")' && '$clang' --target=$triple $flags -$opt -c -w -ffreestanding -fno-builtin -fno-stack-protector -isystem '$here/stubinc' -I'$armgen/programs' '$src' -o '$dst'" >> "$jobfile"
    done
  done
done < "$here/llvm_targets.txt"
# Each line is a full shell command; failures (programs that need a hosted
# libc or unsupported features on a target) are expected and skipped.
tr '\n' '\0' < "$jobfile" | xargs -0 -P "$jobs" -n 1 sh -c 'eval "$1" 2>/dev/null || true' _
rm -f "$jobfile"
find "$out" -name '*.o' -type f | wc -l
