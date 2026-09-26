#!/usr/bin/env bash
# Build bare-metal GCC cross compilers (C only, compile-to-object only) and
# compile the armgen C programs with them, producing ground-truth objects for
# scripts/build_corpus.py (--gen WORK/out).
#
#   scripts/gcc_matrix/build.sh WORK [toolchains|compile|all] [JOBS]
#
# Environment:
#   GCC_SRC       GCC source tree        (default: ~/hexrays/gcc, GCC 16)
#   BINUTILS_SRC  binutils source tree   (default: ~/hexrays/binutils-2.43)
#   ARMGEN        armgen checkout        (default: ../../../armgen from here)
#
# Classes, targets and flag variants are in variants.txt ("none" = no flags,
# commas separate flags). Output: WORK/out/<class>/<target>_<slug>_<Ox>/<set>__<program>.o
#
# Notes from getting this to build on macOS arm64 (Apple clang host):
# * rl78 and m32c are obsolete in GCC 16: --enable-obsolete.
# * No makeinfo: MAKEINFO=true.
# * GCC configures its in-tree gmp/mpfr/mpc/isl if present even with --with-*;
#   we configure from a symlink farm of the source that leaves them out.
# * --enable-host-pie, or libiberty is not built PIC and cc1 fails to link.
# * m32c's cc1 asserts in m32c_leaf_function_p on every function; apply
#   m32c-leaf-function.patch to the symlink farm's copy (the source tree is
#   not modified).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
work="${1:?usage: $0 WORK [toolchains|compile|all] [JOBS]}"
stage="${2:-all}"
jobs="${3:-4}"
gcc_src="${GCC_SRC:-$HOME/hexrays/gcc}"
binutils_src="${BINUTILS_SRC:-$HOME/hexrays/binutils-2.43}"
armgen="${ARMGEN:-$here/../../../armgen}"
stub="$here/../stubinc"
mkdir -p "$work"/{build,logs,out,prefix}
work="$(cd "$work" && pwd)"

# Symlink farm of the GCC source without in-tree support libraries.
farm="$work/gccsrc"
if [ ! -d "$farm" ]; then
  mkdir -p "$farm"
  for e in "$gcc_src"/*; do
    case "$(basename "$e")" in gmp|mpfr|mpc|isl|gcc) ;; *) ln -s "$e" "$farm/" ;; esac
  done
  # gcc/ needs a private copy of config/m32c/m32c.cc for the patch.
  mkdir -p "$farm/gcc"
  for e in "$gcc_src"/gcc/*; do [ "$(basename "$e")" = config ] || ln -s "$e" "$farm/gcc/"; done
  mkdir -p "$farm/gcc/config"
  for e in "$gcc_src"/gcc/config/*; do [ "$(basename "$e")" = m32c ] || ln -s "$e" "$farm/gcc/config/"; done
  cp -R "$gcc_src/gcc/config/m32c" "$farm/gcc/config/m32c"
  (cd "$farm" && patch -p1 < "$here/m32c-leaf-function.patch")
fi

build_target() {
  local t="$1" p="$work/prefix/$1"
  local log="$work/logs/$t.log"
  (
    export PATH="$p/bin:/opt/homebrew/opt/bison/bin:/opt/homebrew/opt/flex/bin:/usr/bin:/bin:/usr/sbin:/sbin"
    export CC=/usr/bin/clang CXX=/usr/bin/clang++ CFLAGS="-O2 -g0" CXXFLAGS="-O2 -g0"
    unset MAKEFLAGS MFLAGS
    set -e
    if [ ! -e "$work/build/$t/.binutils-done" ]; then
      rm -rf "$work/build/$t/binutils" && mkdir -p "$work/build/$t/binutils" && cd "$work/build/$t/binutils"
      "$binutils_src/configure" --target="$t" --prefix="$p" --disable-nls --disable-werror --without-zstd \
        --disable-gdb --disable-gdbserver --disable-sim --disable-gprofng --disable-gold --disable-ld
      make -j"$jobs" MAKEINFO=true all-gas all-binutils && make MAKEINFO=true install-gas install-binutils
      touch "$work/build/$t/.binutils-done"
    fi
    if [ ! -e "$work/build/$t/.gcc-done" ]; then
      rm -rf "$work/build/$t/gcc" && mkdir -p "$work/build/$t/gcc" && cd "$work/build/$t/gcc"
      "$farm/configure" --target="$t" --prefix="$p" --enable-languages=c --without-headers --with-newlib \
        --disable-libssp --disable-libgcc --disable-libquadmath --disable-shared --disable-threads --disable-nls \
        --disable-bootstrap --disable-multilib --enable-obsolete --disable-lto --disable-libcc1 --enable-host-pie \
        --disable-werror --without-zstd \
        --with-gmp=/opt/homebrew/opt/gmp --with-mpfr=/opt/homebrew/opt/mpfr \
        --with-mpc=/opt/homebrew/opt/libmpc --with-isl=/opt/homebrew/opt/isl
      make -j"$jobs" MAKEINFO=true all-gcc && make MAKEINFO=true install-gcc
      touch "$work/build/$t/.gcc-done"
    fi
  ) >> "$log" 2>&1 && echo "built $t" || echo "FAILED $t (see $log)"
}

if [ "$stage" = toolchains ] || [ "$stage" = all ]; then
  for t in $(awk '!/^#/ && NF {print $2}' "$here/variants.txt" | sort -u); do
    build_target "$t" &
    while [ "$(jobs -rp | wc -l)" -ge 4 ]; do sleep 5; done
  done
  wait
fi

if [ "$stage" = compile ] || [ "$stage" = all ]; then
  jobfile="$(mktemp)"
  while read -r cls t flags; do
    case "$cls" in ''|\#*) continue ;; esac
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
  find "$work/out" -name '*.o' -type f | wc -l
fi
