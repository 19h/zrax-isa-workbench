#!/usr/bin/env bash
# Ground-truth Microchip PIC code from SDCC: the armgen C programs compiled with
# SDCC's pic14 (midrange 14-bit core) and pic16 (PIC18 16-bit core) ports,
# linked with gputils' gplink, plus SDCC's own PIC libraries, module by module.
#
#   scripts/sdcc_matrix/pic/build.sh WORK [sdk|programs|libs|all] [JOBS]
#
# Environment:
#   ARMGEN            armgen checkout (default: ../../../../armgen from here)
#   OUT               output root     (default: classifier/corpus_extra/sdcc-objects)
#   SDCC_SRC_TARBALL  SDCC 4.6.0 source (default: WORK/sdcc-src-4.6.0.tar.bz2,
#                     downloaded from SourceForge if missing; only device/ is used)
#
# Output (raw little-endian program words, code sections only):
#   OUT/<class>/<config>/<set>__<program>.bin      class = pic14 | pic18
#   OUT/<class>/lib_<port>/lib<lib>__<module>.bin  port  = pic14 | pic16
# Every run rewrites the config/lib directories it builds; logs, objects,
# linked COFF/map files and a manifest.tsv per config are kept in WORK/build.
#
# Stages:
#   sdk       Homebrew's SDCC ships the free PIC libraries but not the non-free
#             device headers/libraries (SFR definitions; for PIC18 also the
#             EEPROM generic-pointer dispatch stubs), so nothing links.  They are
#             built here from the SDCC source tarball for the devices below into
#             WORK/sdk/{include,lib}/<port> (same flags as SDCC's Makefiles).
#   programs  pic_corpus.py programs: see that file for the details.
#   libs      pic_corpus.py libs: every module of libsdcc/libc/libm (pic14 regular
#             and enhanced-core variants) and libsdcc/libc18f/libm18f/libio/
#             libdebug/crt0* (pic16).
#
# Quirks:
# * The armgen programs are GCC-flavoured C.  pic_corpus.py compiles a copy with
#   __attribute__/__asm__/_Alignas stripped, bit-fields wider than 16 bits
#   (SDCC's limit) turned into plain members, a prelude for common
#   __builtin_*/__sync_* names and M_PI, and -- pic14 only, which has no
#   64-bit type -- `long long`/int64_t narrowed to long.  SDCC's own headers are
#   tried first, then scripts/stubinc (pic16's stdlib.h has no malloc, pic14's
#   stdio.h no stderr, ...).  Programs SDCC cannot compile (POSIX headers,
#   __int128, struct arguments/returns by value, compound literals with
#   bit-fields, compiler internal errors, ...) are skipped.
# * gplink uses the stock <device>_g.lkr.  Externals no library provides
#   (fprintf, stderr, time, __pic_* builtins, ...) are resolved to generated
#   stub labels (code or data, from the relocation types), so the program's own
#   code is relocated like in a real image.  The armgen programs mostly have far
#   more data than a PIC (pic14 banks hold 80-96 bytes, PIC18 RAM is < 4 KB), so
#   when the stock script fails the link is retried with (pic16) the gpr banks
#   merged into one region, then with a script that adds fake RAM/ROM (and, for
#   pic14, one flat data region and one code page).  Instruction bytes are
#   unchanged by this; only data/code addresses in operand fields are not
#   those of a real part.  manifest.tsv records linked / linked-mergedram /
#   linked-fakemem (or "unlinked": code cut from the object, never needed in
#   practice).
# * pic14 "Out of stack Space" (argument stack) is retried with --stack-size 64.
# * GNU case ranges need --std-c2y, which makes SDCC take minutes per file, so
#   those programs are skipped.
# * SDCC links only libsdcc by default; libc/libm (pic14) and libc18f/libm18f
#   (pic16, with crt0iz.o as SDCC does) are passed explicitly.
# * pic16's --optimize-goto is the default (BRA instead of GOTO); the variant
#   is --no-optimize-goto.  --opt-code-size is a no-op for both ports (see
#   CONFIGS).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
work="${1:?usage: $0 WORK [sdk|programs|libs|all] [JOBS]}"
stage="${2:-all}"
jobs="${3:-8}"
armgen="${ARMGEN:-$here/../../../../armgen}"
out="${OUT:-$here/../../../corpus_extra/sdcc-objects}"
mkdir -p "$work" "$out"
work="$(cd "$work" && pwd)"
out="$(cd "$out" && pwd)"
tarball="${SDCC_SRC_TARBALL:-$work/sdcc-src-4.6.0.tar.bz2}"
url="https://sourceforge.net/projects/sdcc/files/sdcc/4.6.0/sdcc-src-4.6.0.tar.bz2/download"
py="python3 $here/pic_corpus.py"

PIC14_DEVICES="16f877a 16f1789"
PIC16_DEVICES="18f4620 18f46k22 18f97j60"

# --opt-code-size/--opt-code-speed are accepted but do not change PIC code
# (measured: 0 of 68 pic16 and 1 of 63 pic14 programs differ), so the variants
# are the switches that do: pic14 --no-peep / --no-pcode-opt /
# --no-extended-instructions; pic16 SDCC's own library flags (--obanksel=9
# --denable-peeps --optimize-cmp --optimize-df --fomit-frame-pointer),
# --no-optimize-goto, --pstack-model=large, --stack-auto, --obanksel=2.
# class  config                       port   device    flags (commas separate)
CONFIGS="
pic14  p16f877a_default               pic14  16f877a   none
pic14  p16f877a_nopeep                pic14  16f877a   --no-peep
pic14  p16f1789_default               pic14  16f1789   none
pic14  p16f1789_nopcodeopt_noext      pic14  16f1789   --no-pcode-opt,--no-extended-instructions
pic18  p18f4620_default               pic16  18f4620   none
pic18  p18f4620_libflags              pic16  18f4620   --obanksel=9,--denable-peeps,--optimize-cmp,--optimize-df,--fomit-frame-pointer
pic18  p18f46k22_default              pic16  18f46k22  none
pic18  p18f46k22_nogoto_lstack        pic16  18f46k22  --no-optimize-goto,--pstack-model=large
pic18  p18f46k22_stackauto            pic16  18f46k22  --stack-auto
pic18  p18f97j60_obanksel2_peeps      pic16  18f97j60  --obanksel=2,--denable-peeps
"

stage_sdk() {
  local D="$work/sdcc-4.6.0/device" dev src s
  if [ ! -d "$D/non-free" ]; then
    [ -f "$tarball" ] || curl -fsSL -o "$tarball" "$url"
    tar -xjf "$tarball" -C "$work" sdcc-4.6.0/device
  fi
  mkdir -p "$work"/sdk/include/{pic14,pic16} "$work"/sdk/lib/{pic14,pic16} "$work/logs"
  cp -R "$D/non-free/include/pic14/." "$work/sdk/include/pic14/"
  cp -R "$D/non-free/include/pic16/." "$work/sdk/include/pic16/"
  for dev in $PIC14_DEVICES; do
    local b="$work/sdk/lib/pic14/build-$dev"
    rm -rf "$b" && mkdir -p "$b"
    ( cd "$b" && sdcc -mpic14 -p"$dev" --std-c99 --no-warn-non-free \
        -I "$D/include/pic14" -I "$D/non-free/include/pic14" \
        -c "$D/non-free/lib/pic14/libdev/pic$dev.c" -o "pic$dev.o" \
      && rm -f "../pic$dev.lib" && gplib -c "../pic$dev.lib" "pic$dev.o" ) >> "$work/logs/sdk.log" 2>&1
    echo "built pic$dev.lib"
  done
  for dev in $PIC16_DEVICES; do
    local b="$work/sdk/lib/pic16/build-$dev"
    rm -rf "$b" && mkdir -p "$b"
    (
      cd "$b"
      sdcc -mpic16 -p"$dev" --std-c99 --no-warn-non-free \
        -I "$D/include/pic16" -I "$D/non-free/include/pic16" \
        -c "$D/non-free/lib/pic16/libdev/pic$dev.c" -o "pic$dev.o"
      # the generic-pointer dispatch sources listed for this device in Makefile.am
      for s in $(grep -E "^libdev${dev}_a_SOURCES" "$D/non-free/lib/pic16/libdev/Makefile.am" | grep -oE 'gptr/[^ ]+\.S'); do
        gpasm -c -p"$dev" -I "$D/include/pic16" -I "$D/non-free/include/pic16" \
          -I "$D/non-free/lib/pic16/libdev" -I "$D/non-free/lib/pic16/libdev/gptr" \
          -o "$(basename "$s" .S).o" "$D/non-free/lib/pic16/libdev/$s"
      done
      rm -f "../libdev$dev.lib" && gplib -c "../libdev$dev.lib" ./*.o
    ) >> "$work/logs/sdk.log" 2>&1
    echo "built libdev$dev.lib ($(ls "$b"/*.o | wc -l | tr -d ' ') objects)"
  done
}

stage_programs() {
  local srcs=() f cls config port device flags
  for f in "$armgen"/programs/*.c "$armgen"/programs2/*.c; do srcs+=("$f"); done
  # drop output directories of configs that are no longer in the table
  for f in "$out"/pic14/*/ "$out"/pic18/*/; do
    [ -d "$f" ] || continue
    case "$(basename "$f")" in lib_*) continue ;; esac
    grep -qE "^pic1[48] +$(basename "$f") " <<< "$CONFIGS" || rm -rf "$f"
  done
  while read -r cls config port device flags; do
    [ -n "$cls" ] || continue
    [ "$flags" = none ] && flags="" || flags="${flags//,/ }"
    $py programs --work "$work" --out "$out" --cls "$cls" --config "$config" \
      --port "$port" --device "$device" --flags="$flags" --jobs "$jobs" "${srcs[@]}"
  done <<< "$CONFIGS"
}

stage_libs() {
  rm -f "$work"/libs/pic14/manifest.tsv "$work"/libs/pic16/manifest.tsv
  $py libs --work "$work" --out "$out" --cls pic14 --port pic14 --device 16f877a \
    --devlib pic16f877a.lib --jobs "$jobs" libsdcc.lib libc.lib libm.lib
  $py libs --work "$work" --out "$out" --cls pic14 --port pic14 --device 16f1789 \
    --devlib pic16f1789.lib --jobs "$jobs" libsdcce.lib libce.lib libme.lib
  $py libs --work "$work" --out "$out" --cls pic18 --port pic16 --device 18f4620 \
    --devlib libdev18f4620.lib --jobs "$jobs" \
    libsdcc.lib libc18f.lib libm18f.lib libdebug.lib libcrt0.lib libcrt0i.lib libcrt0iz.lib libio18f4620.lib
  $py libs --work "$work" --out "$out" --cls pic18 --port pic16 --device 18f46k22 \
    --devlib libdev18f46k22.lib --jobs "$jobs" libio18f46k22.lib
  $py libs --work "$work" --out "$out" --cls pic18 --port pic16 --device 18f97j60 \
    --devlib libdev18f97j60.lib --jobs "$jobs" libio18f97j60.lib
}

case "$stage" in
  sdk) stage_sdk ;;
  programs) stage_programs ;;
  libs) stage_libs ;;
  all) stage_sdk; stage_programs; stage_libs ;;
  *) echo "unknown stage $stage" >&2; exit 2 ;;
esac
