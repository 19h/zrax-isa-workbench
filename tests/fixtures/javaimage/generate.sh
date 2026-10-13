#!/usr/bin/env bash
set -euo pipefail

# Regenerate the jimage and JMOD fixtures in this directory.
# Usage: tests/fixtures/javaimage/generate.sh
# Requires a JDK 21 (javac, java with the jdk.jlink module, jmod). JAVA_HOME
# names it; otherwise the tools on PATH are used. See README.md for the
# version used.

cd "$(dirname "$0")"

bin="${JAVA_HOME:+$JAVA_HOME/bin/}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

module="zrax.sample"
classes="$work/$module"

# Compile the synthetic module; -g:none leaves out the debug attributes.
"${bin}javac" --release 21 -g:none -d "$classes" \
  src/zrax.sample/module-info.java src/zrax.sample/zrax/sample/Hello.java

# Two non-class resources: the synthetic ELF header from the compressed
# fixtures (a recognized format) and a line of text (not recognized).
cp ../compressed/payload.elf "$classes/zrax/sample/payload.elf"
printf 'Synthetic text resource for the Zrax Java image fixtures.\n' \
  > "$classes/zrax/sample/readme.txt"

# jimages written by the JDK's jimage writer (see GenerateImages.java).
"${bin}java" --add-modules jdk.jlink \
  --add-exports jdk.jlink/jdk.tools.jlink.internal=ALL-UNNAMED \
  --add-exports jdk.jlink/jdk.tools.jlink.internal.plugins=ALL-UNNAMED \
  --add-exports jdk.jlink/jdk.tools.jlink.builder=ALL-UNNAMED \
  --add-exports jdk.jlink/jdk.tools.jlink.plugin=ALL-UNNAMED \
  GenerateImages.java "$classes" "$module" .

# A JMOD with the classes, the ELF header as a native library and a fixed
# timestamp, so the archive is reproducible.
mkdir -p "$work/libs"
cp ../compressed/payload.elf "$work/libs/payload.elf"
rm -f sample.jmod
"${bin}jmod" create --class-path "$classes" --libs "$work/libs" \
  --date 2026-01-01T00:00:00Z sample.jmod

shasum -a 256 sample-le.jimage sample-be.jimage sample-zip.jimage \
  sample-compact-cp.jimage sample.jmod
