#!/usr/bin/env bash
# Ground-truth machine code for 8-bit ISAs from SDCC and cc65: the armgen C
# programs compiled, linked and reduced to their executable code bytes, plus
# every module of the compilers' prebuilt libraries (hand-written asm and a
# different C code base). Output feeds the byte-bigram ISA models
# (docs/architecture/raw-code-model.md), so only instruction bytes are kept.
#
#   scripts/sdcc_matrix/build.sh WORK [prep|libs|progs|dedupe|summary|check|all] [JOBS]
#
# Environment: ARMGEN (default ../../../armgen from here), OUT (default
# corpus_extra/sdcc-objects), FORCE=1 to redo finished jobs.
# Needs sdcc (4.6: mcs51 ds390 hc08 s08 z80 z180 ez80 r800 sm83 stm8 mos6502
# mos65c02 ports), cc65 (cc65/ca65/ld65/ar65/od65) and python3 with pycparser.
#
# Output (class = directory name used by scripts/build_corpus.py):
#   OUT/<class>/<config>_<opt>/<set>__<program>.bin   one program (+ the library
#       routines it links), <set> = programs|programs2, <opt> = default|size|speed
#       (SDCC: --opt-code-size/--opt-code-speed) or none|O|Oirs (cc65)
#   OUT/<class>/lib_<lib>/lib<name>__<module>.bin     one prebuilt library module;
#       the part after "__" is the bare module name, so the same module built for
#       different ports/models lands in the same train/test group
# Classes/configs: variants.txt. Outputs < 64 bytes (and programs > 64 KB: SDCC
# expands some large local initialisers into ~100k stores) are skipped, and
# byte-identical outputs within a class are removed (stage dedupe). Work files and
# per-job result.json/log.txt (why a program failed, which attempt worked, what
# was excluded) stay in WORK; finished jobs are skipped on re-runs.
#
# What counts as code:
# * SDCC: programs are compiled (-c) and linked by sdcc (crt0 + the port's
#   libraries). Taken: areas CSEG/CODE/HOME/GSINIT*/GSFINAL from the .map, bytes
#   from the .ihx (.s19 for hc08/s08). Excluded: CONST/RODATA (const data, string
#   literals), XINIT/INITIALIZER (initialised-data images), CABS, CODEIVT (vector
#   tables), z80/sm83 _HEADERn (crt0 RST/interrupt vectors, ABS), all RAM areas,
#   gaps. Inside code areas, bytes emitted by data directives (.db/.dw/.ascii/...)
#   are removed using the assembler listing (.lst) of the program module, placed
#   at its link addresses via its global symbols (the linker-updated .rst is
#   garbled by sdld6808): the z80-family ports keep string literals/const tables
#   in _CODE, and switch jump tables of several ports are .db/.dw tables in code.
# * SDCC libraries: each .rel module (sdar/GNU ar archives; share/sdcc/lib/<dir>)
#   is linked together with the port's libraries so calls into the runtime get
#   real addresses, and its code areas are located through its global symbols;
#   if that fails it is linked on its own (--nostdlib; undefined globals -> 0).
#   To find data inside code areas, the module is rebuilt from share/sdcc/lib/src
#   with a listing: no data -> prebuilt bytes as is; data and identical layout ->
#   prebuilt bytes minus the data; data and a different layout (library built
#   with other flags) -> the rebuilt module's code. Only z80/z180/ez80/r800/sm83
#   have such modules (time, printf_large, strtoul, atanf, ...: C string literals
#   and const tables in _CODE); those are also dropped from the linked programs.
#   Modules whose source does not rebuild here (3 ds390 serial modules) are kept
#   and marked "unverified" in WORK/libinfo/<dir>.json.
# * cc65: C99 -> C89 first (cc65 2.19 rejects declarations after statements and
#   in for-init): the program is preprocessed by cc65, parsed with pycparser, every
#   late declaration opens a nested block (same scope), and it is printed back.
#   int64_t/uint64_t are typedef'd to 32-bit longs (cc65 has no 64-bit type).
#   Linked with ld65 (-t none crt0 + none.lib) using a config that puts
#   STARTUP/LOWCODE/ONCE/CODE in the output file and RODATA/DATA/INIT (and the
#   constructor tables none.cfg keeps in ONCE) elsewhere; per-module ranges come
#   from the ld65 map. Unresolved externals are defined as 0 by a generated stub.
#   Programs whose generated assembly has data directives in a code segment would
#   be rejected (none do). cc65 library modules (no source installed) are linked
#   alone (imports -> 0) and rejected if a linear 6502/65C02 sweep of their code
#   hits an undefined opcode (data in CODE: only getcpu); the written bytes come
#   from a second link with the library (real runtime addresses). Modules whose
#   code equals one of an earlier library (sim6502 vs none) are not written again.
#
# Source preparation (copies in WORK/src; armgen is not modified): GNU
# __attribute__, inline asm and alignas are stripped, a few GNU builtins become
# plain expressions or calls to undefined functions, and bit-fields wider than
# 16 bits are narrowed to 16 (SDCC/cc65 limit; for cc65 their type becomes
# (un)signed int). SDCC compile attempts, first success wins: own headers
# --std-sdcc11, scripts/stubinc (declares fprintf/stderr etc.) --std-sdcc11, then
# the same with --std-sdcc2y (GNU case ranges); a compile that times out (600 s)
# is not retried. cc65: own headers, then stubinc. If a program's variables do
# not fit the memory model (8051 small model), it is relinked with its RAM areas
# shrunk to size 0: code bytes are unchanged, only data addresses wrap.
#
# Quirks: SDCC 4.6 calls the eZ80 (Z80-mode) port -mez80 (the old ez80_z80).
# --opt-code-size/--opt-code-speed change nothing for most mcs51/ds390 programs
# (those duplicates are removed by dedupe). OUT may be shared with other
# generators: summary/check/dedupe only touch the classes in variants.txt.
# Programs that need hosted headers, 64-bit/float beyond the target, huge arrays,
# VLAs, computed goto etc. fail and are skipped; so do the few that crash SDCC.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
work="${1:?usage: $0 WORK [prep|libs|progs|dedupe|summary|check|all] [JOBS]}"
stage="${2:-all}"
jobs="${3:-$(sysctl -n hw.ncpu 2>/dev/null || nproc)}"
armgen="${ARMGEN:-$here/../../../armgen}"
out="${OUT:-$here/../../corpus_extra/sdcc-objects}"
py="python3 $here/extract.py"
force=""; [ "${FORCE:-0}" = 1 ] && force="--force"
mkdir -p "$work" "$out"
work="$(cd "$work" && pwd)"; out="$(cd "$out" && pwd)"; armgen="$(cd "$armgen" && pwd)"
libinfo="$work/libinfo"

if [ "$stage" = prep ] || [ "$stage" = all ]; then
  $py prep "$armgen" "$work"
fi

# Libraries first: program extraction reads WORK/libinfo to drop library modules
# that carry data in code areas.
if [ "$stage" = libs ] || [ "$stage" = all ]; then
  seen=()
  while read -r tag cls port libdir flags; do
    [ "$tag" = lib ] || continue
    if [ "$port" = cc65 ]; then
      dd=(); for s in "${seen[@]+"${seen[@]}"}"; do dd+=(--dedupe "$s"); done
      $py cc65-lib --lib "$libdir" --cpu "$flags" --work "$work/lib" --out "$out/$cls/lib_cc65-$libdir" \
        --libinfo "$libinfo" --jobs "$jobs" "${dd[@]+"${dd[@]}"}"
      seen+=("$libdir")
    else
      [ "$flags" = none ] && fl="" || fl="$(echo "$flags" | tr ',' ' ')"
      [ "$libdir" = "$port" ] && name="$port" || { case "$libdir" in "$port"-*) name="$libdir" ;; *) name="$port-$libdir" ;; esac; }
      $py sdcc-lib --port "$port" --libdir "$libdir" --flags="$fl" --work "$work/lib" \
        --out "$out/$cls/lib_$name" --libinfo "$libinfo" --jobs "$jobs"
    fi
  done < "$here/variants.txt"
fi

if [ "$stage" = progs ] || [ "$stage" = all ]; then
  jobfile="$work/jobs.txt"; : > "$jobfile"
  while read -r cls cfg comp flags; do
    case "$cls" in ''|\#*|lib) continue ;; esac
    if [ "$comp" = sdcc ]; then
      fl="$(echo "$flags" | tr ',' ' ')"
      for opt in default size speed; do
        case $opt in default) of="" ;; size) of=" --opt-code-size" ;; speed) of=" --opt-code-speed" ;; esac
        for src in "$work"/src/sdcc/*.c; do
          printf '%s\n' "$py sdcc-prog --flags='$fl$of' --src '$src' --inc '$armgen/programs' --work '$work/build/$cls/${cfg}_$opt' --out '$out/$cls/${cfg}_$opt' --libinfo '$libinfo' $force" >> "$jobfile"
        done
      done
    else
      for opt in none O Oirs; do
        [ $opt = none ] && of="" || of="-$opt"
        for src in "$work"/src/cc65/*.c; do
          printf '%s\n' "$py cc65-prog --cpu $flags --opt='$of' --src '$src' --inc '$armgen/programs' --work '$work/build/$cls/${cfg}_$opt' --out '$out/$cls/${cfg}_$opt' --libinfo '$libinfo' $force" >> "$jobfile"
        done
      done
    fi
  done < "$here/variants.txt"
  echo "$(wc -l < "$jobfile") program jobs"
  # slowest configs first would be nicer; shuffle so long SDCC compiles spread out
  sort -R "$jobfile" | tr '\n' '\0' | xargs -0 -P "$jobs" -n 1 sh -c 'eval "$1" || echo "job failed: $1" >&2' _
fi

# Byte-identical outputs within a class add nothing (the corpus builder drops
# them too): --opt-code-size/--opt-code-speed leave most mcs51/ds390 programs
# unchanged, and z80/z180/r800 share many library modules.
if [ "$stage" = dedupe ] || [ "$stage" = all ]; then
  $py dedupe "$out"
fi

if [ "$stage" = summary ] || [ "$stage" = all ]; then
  $py summary "$out" --work "$work"
fi
if [ "$stage" = check ] || [ "$stage" = all ]; then
  $py check "$out"
fi
