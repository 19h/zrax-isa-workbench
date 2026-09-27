#!/usr/bin/env bash
# Build bare-metal GCC cross compilers (C only, compile-to-object only) and
# compile the armgen C programs with them, producing ground-truth objects for
# scripts/build_corpus.py (--gen WORK/out).
#
#   scripts/gcc_matrix/build.sh WORK [toolchains|compile|all] [JOBS] [TARGET...]
#
# Environment:
#   GCC_SRC       GCC source tree        (default: ~/hexrays/gcc, GCC 16)
#   BINUTILS_SRC  binutils source tree   (default: ~/hexrays/binutils-2.43)
#   ARMGEN        armgen checkout        (default: ../../../armgen from here)
#
# Classes, targets and flag variants are in variants.txt, one per line:
#   class target flags [gcc-source]
# ("none" = no flags, commas separate flags). Output:
#   WORK/out/<class>/<target>_<slug>_<Ox>/<set>__<program>.o
# Optional TARGET arguments restrict both stages to those targets.
#
# The optional 4th column builds that target from another GCC: a git ref of
# GCC_SRC (e.g. releases/gcc-11.5.0), checked out as a detached `git worktree`
# in WORK/src/<basename of ref> (GCC_SRC's own checkout is not touched), or an
# absolute path to a source tree. A target is built from a single source (the
# 4th column of its first line in variants.txt).
#
# a.out targets (*-aout, i.e. pdp11): build_corpus.py cannot parse a.out, so
# each object's .text is extracted as a raw binary
# (<target>-objcopy -O binary -j .text) to <set>__<program>.bin, the .o is
# removed, and .bin files under 64 bytes are dropped. (pdp11 gnu-asm puts
# read-only data in .data, so .text is code only.)
#
# Notes from getting this to build on macOS arm64 (Apple clang host):
# * rl78 and m32c are obsolete in GCC 16: --enable-obsolete.
# * No makeinfo: MAKEINFO=true.
# * GCC configures its in-tree gmp/mpfr/mpc/isl if present even with --with-*;
#   we configure from a symlink farm of the source that leaves them out.
# * --enable-host-pie, or libiberty is not built PIC and cc1 fails to link.
# * Patches in this directory are applied to private copies in the farm (the
#   source tree is not modified): gcc<N>-*.patch to GCC N sources only, other
#   *.patch wherever they apply.
# * m32c's cc1 asserts in m32c_leaf_function_p on every function:
#   m32c-leaf-function.patch.
# * pdp11: -m45 -msoft-float generates exactly the -m40 code, hence -mlra as
#   the 5th variant.
# * cr16 was removed in GCC 13, and GCC 12 removed cc0, which the cr16 port
#   still uses (genpreds: "unknown rtx code `cc0'"), so cr16 is built from
#   releases/gcc-11.5.0. Workarounds for that tree (build_target applies the
#   flags when BASE-VER major < 13):
#   - CXXFLAGS=-std=gnu++11. Apple clang defaults to gnu++17. libcody's
#     configure accepts only __cplusplus == 201103 and fails with a -std=gnu++14
#     in CXXFLAGS. Not tried with the compiler default.
#   - --with-system-zlib: the in-tree zlib 1.2.11 defines fdopen() to NULL on
#     TARGET_OS_MAC, which breaks the macOS SDK's <stdio.h>.
#   - gcc11-aarch64-darwin-host-hooks.patch: config.host has no aarch64-darwin
#     host hooks before GCC 12, so cc1 fails to link (undefined _host_hooks);
#     the patch adds host-default.o. (--enable-host-pie is unknown to GCC 11
#     and ignored; its cc1 links anyway.)
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
work="${1:?usage: $0 WORK [toolchains|compile|all] [JOBS] [TARGET...]}"
stage="${2:-all}"
jobs="${3:-4}"
shift $(( $# < 3 ? $# : 3 ))
only_targets=" $* "
gcc_src="${GCC_SRC:-$HOME/hexrays/gcc}"
binutils_src="${BINUTILS_SRC:-$HOME/hexrays/binutils-2.43}"
armgen="${ARMGEN:-$here/../../../armgen}"
stub="$here/../stubinc"
mkdir -p "$work"/{build,logs,out,prefix}
work="$(cd "$work" && pwd)"

wanted() { [ "$only_targets" = "  " ] || [[ "$only_targets" == *" $1 "* ]]; }

# resolve_src [REF|PATH|-] -> GCC source tree path.
resolve_src() {
  case "${1:--}" in
    -) echo "$gcc_src" ;;
    /*) echo "$1" ;;
    *) local d="$work/src/$(basename "$1")"
       if [ ! -d "$d" ]; then
         mkdir -p "$work/src"
         git -C "$gcc_src" worktree add -q --detach "$d" "$1" >&2
       fi
       echo "$d" ;;
  esac
}

# privatize FARM REL: turn FARM/REL into a private copy that can be patched,
# replacing symlinked parent directories by directories of symlinks.
privatize() {
  local cur="$1" rest="$2" part tgt e
  while [[ "$rest" == */* ]]; do
    part="${rest%%/*}" rest="${rest#*/}"
    if [ -L "$cur/$part" ]; then
      tgt="$(readlink "$cur/$part")"
      rm "$cur/$part" && mkdir "$cur/$part"
      for e in "$tgt"/* "$tgt"/.[!.]*; do
        if [ -e "$e" ]; then ln -s "$e" "$cur/$part/"; fi
      done
    fi
    cur="$cur/$part"
  done
  if [ -L "$cur/$rest" ]; then
    tgt="$(readlink "$cur/$rest")"
    rm "$cur/$rest" && cp -R "$tgt" "$cur/$rest"
  fi
}

# Symlink farm of a GCC source tree without in-tree support libraries, with
# the patches in this directory applied to private copies of the files they
# touch (the source tree is not modified): gcc<major>-*.patch for sources of
# that BASE-VER major, any other *.patch wherever it applies cleanly.
# make_farm SRC -> farm path (WORK/gccsrc for GCC_SRC, WORK/gccsrc-<name> else).
make_farm() {
  local src="$1" farm="$work/gccsrc" major pf f name
  [ "$src" = "$gcc_src" ] || farm="$work/gccsrc-$(basename "$src")"
  major="$(cut -d. -f1 "$src/gcc/BASE-VER")"
  if [ ! -d "$farm" ]; then
    mkdir -p "$farm"
    for e in "$src"/*; do
      case "$(basename "$e")" in gmp|mpfr|mpc|isl) ;; *) ln -s "$e" "$farm/" ;; esac
    done
    for pf in "$here"/*.patch; do
      name="$(basename "$pf")"
      case "$name" in
        gcc[0-9]*-*) [ "${name%%-*}" = "gcc$major" ] || continue ;;
      esac
      for f in $(sed -n 's|^+++ b/\([^[:space:]]*\).*|\1|p' "$pf"); do privatize "$farm" "$f"; done
      if (cd "$farm" && patch -p1 -N -f --dry-run -s < "$pf") >/dev/null 2>&1; then
        (cd "$farm" && patch -p1 -s < "$pf") >&2
      else
        echo "note: $name does not apply to $src; skipped" >&2
      fi
    done
  fi
  echo "$farm"
}

build_target() {
  local t="$1" src="$2" farm="$3" p="$work/prefix/$1"
  local log="$work/logs/$t.log"
  local major cxxflags="-O2 -g0" cflags="-O2 -g0" extra=""
  major="$(cut -d. -f1 "$src/gcc/BASE-VER")"
  if [ "$major" -lt 13 ]; then
    cxxflags="$cxxflags -std=gnu++11"
    extra="--with-system-zlib"
  fi
  # set -e must see every step as a plain command: bash ignores it inside a
  # subshell run in an &&/|| context and for all but the last command of an
  # && list (the old `( ... ) && echo built` marked failed builds as done).
  local rc=0
  set +e
  (
    export PATH="$p/bin:/opt/homebrew/opt/bison/bin:/opt/homebrew/opt/flex/bin:/usr/bin:/bin:/usr/sbin:/sbin"
    export CC=/usr/bin/clang CXX=/usr/bin/clang++ CFLAGS="$cflags" CXXFLAGS="$cxxflags"
    unset MAKEFLAGS MFLAGS
    set -e
    if [ ! -e "$work/build/$t/.binutils-done" ]; then
      rm -rf "$work/build/$t/binutils"; mkdir -p "$work/build/$t/binutils"; cd "$work/build/$t/binutils"
      "$binutils_src/configure" --target="$t" --prefix="$p" --disable-nls --disable-werror --without-zstd \
        --disable-gdb --disable-gdbserver --disable-sim --disable-gprofng --disable-gold --disable-ld
      make -j"$jobs" MAKEINFO=true all-gas all-binutils
      make MAKEINFO=true install-gas install-binutils
      touch "$work/build/$t/.binutils-done"
    fi
    if [ ! -e "$work/build/$t/.gcc-done" ]; then
      rm -rf "$work/build/$t/gcc"; mkdir -p "$work/build/$t/gcc"; cd "$work/build/$t/gcc"
      "$farm/configure" --target="$t" --prefix="$p" --enable-languages=c --without-headers --with-newlib \
        --disable-libssp --disable-libgcc --disable-libquadmath --disable-shared --disable-threads --disable-nls \
        --disable-bootstrap --disable-multilib --enable-obsolete --disable-lto --disable-libcc1 --enable-host-pie \
        --disable-werror --without-zstd \
        --with-gmp=/opt/homebrew/opt/gmp --with-mpfr=/opt/homebrew/opt/mpfr \
        --with-mpc=/opt/homebrew/opt/libmpc --with-isl=/opt/homebrew/opt/isl $extra
      make -j"$jobs" MAKEINFO=true all-gcc
      make MAKEINFO=true install-gcc
      touch "$work/build/$t/.gcc-done"
    fi
  ) >> "$log" 2>&1
  rc=$?
  set -e
  if [ "$rc" -eq 0 ]; then echo "built $t"; else echo "FAILED $t (see $log)"; fi
}

if [ "$stage" = toolchains ] || [ "$stage" = all ]; then
  while read -r t src; do
    wanted "$t" || continue
    src="$(resolve_src "$src")"
    build_target "$t" "$src" "$(make_farm "$src")" &
    while [ "$(jobs -rp | wc -l)" -ge 4 ]; do sleep 5; done
  done < <(awk '!/^#/ && NF && !seen[$2]++ {print $2, (NF >= 4 ? $4 : "-")}' "$here/variants.txt")
  wait
fi

if [ "$stage" = compile ] || [ "$stage" = all ]; then
  jobfile="$(mktemp)"
  while read -r cls t flags _src; do
    case "$cls" in ''|\#*) continue ;; esac
    wanted "$t" || continue
    gcc="$work/prefix/$t/bin/$t-gcc"
    [ -x "$gcc" ] || { echo "skip $cls: no $gcc"; continue; }
    if [ "$flags" = none ]; then slug=default; fl=""; else
      slug="$(echo "$flags" | sed -E 's/\+/p/g; s/^-+//; s/,-+/_/g; s/[=.,]/_/g; s/[^A-Za-z0-9_]/_/g')"
      fl="$(echo "$flags" | tr ',' ' ')"
    fi
    for opt in O0 O1 O2 Os O3; do
      for set_name in programs programs2; do
        for src in "$armgen/$set_name"/*.c; do
          dst="$work/out/$cls/${t}_${slug}_${opt}/${set_name}__$(basename "$src" .c).o"
          printf '%s\n' "mkdir -p '$(dirname "$dst")' && '$gcc' -c -w -ffreestanding -fno-builtin -isystem '$stub' -I'$armgen/programs' $fl -$opt '$src' -o '$dst'" >> "$jobfile"
        done
      done
    done
  done < "$here/variants.txt"
  # Failures (hosted-only programs, >64 KB arrays on 16-bit targets, a few
  # internal compiler errors) are expected and skipped.
  tr '\n' '\0' < "$jobfile" | xargs -0 -P "$((jobs * 3))" -n 1 sh -c 'eval "$1" 2>/dev/null || true' _
  rm -f "$jobfile"
  # a.out objects -> raw .text (.bin); drop outputs under 64 bytes.
  for t in $(awk '!/^#/ && NF && $2 ~ /-aout$/ {print $2}' "$here/variants.txt" | sort -u); do
    wanted "$t" || continue
    objcopy="$work/prefix/$t/bin/$t-objcopy"
    [ -x "$objcopy" ] || continue
    find "$work/out" -path "*/${t}_*/*.o" -type f | while read -r o; do
      b="${o%.o}.bin"
      "$objcopy" -O binary -j .text "$o" "$b" 2>/dev/null || rm -f "$b"
      rm -f "$o"
      if [ -f "$b" ] && [ "$(wc -c < "$b")" -lt 64 ]; then rm -f "$b"; fi
    done
  done
  find "$work/out" -type f \( -name '*.o' -o -name '*.bin' \) | wc -l
fi
