#!/usr/bin/env bash
set -euo pipefail
# Build a signed local macOS app and a drag-to-Applications disk image.
# Usage: ./build-macos.sh

if [[ "$(uname -s)" != Darwin ]]; then
  echo "The macOS package must be built on a Mac" >&2
  exit 1
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
desktop="$root/crates/zrax-desktop"
resources="$desktop/macos"
target="$root/crates/target"
output="$target/macos"
app_name="Zrax Workbench"
executable="zrax-desktop"
version="$(sed -n 's/^version = "\([0-9]*\.[0-9]*\.[0-9]*\)"$/\1/p' "$desktop/Cargo.toml")"
if [[ -z "$version" ]]; then
  echo "Missing a numeric desktop app version in $desktop/Cargo.toml" >&2
  exit 1
fi

# Compiling shaders at startup keeps the optional Xcode Metal compiler out
# of the packaging prerequisites. macOS provides Metal at runtime.
# Apeiron's xz2 must use the vendored static liblzma, even if pkg-config
# finds a copy installed on the build machine.
LZMA_API_STATIC=1 cargo build --locked --release --features runtime-shaders -p "$executable" \
  --manifest-path "$root/crates/Cargo.toml" --target-dir "$target"
arch="$(lipo -archs "$target/release/$executable")"
if [[ "$arch" != "$(uname -m)" ]]; then
  echo "Expected a native executable for $(uname -m), got $arch" >&2
  exit 1
fi
non_system_libraries="$(otool -L "$target/release/$executable" |
  awk 'NR > 1 && $1 !~ /^\/(System\/Library\/|usr\/lib\/)/ { print $1 }')"
if [[ -n "$non_system_libraries" ]]; then
  printf 'Unexpected non-system libraries in the app executable:\n%s\n' "$non_system_libraries" >&2
  exit 1
fi

mkdir -p "$output"
stage="$(mktemp -d "$output/.build.XXXXXXXX")"
trap 'rm -rf "$stage"' EXIT
image="$stage/image"
app="$image/$app_name.app"
contents="$app/Contents"
icons="$stage/AppIcon.iconset"
mkdir -p "$contents/MacOS" "$contents/Resources/Licenses" "$icons"

install -m 755 "$target/release/$executable" "$contents/MacOS/$executable"
cp "$resources/Info.plist" "$contents/Info.plist"
plutil -replace CFBundleShortVersionString -string "$version" "$contents/Info.plist"
plutil -replace CFBundleVersion -string "$version" "$contents/Info.plist"
plutil -lint "$contents/Info.plist"

swift "$resources/draw-icon.swift" "$stage/icon.png"
for size in 16 32 128 256 512; do
  sips -z "$size" "$size" "$stage/icon.png" \
    --out "$icons/icon_${size}x${size}.png" >/dev/null
  double_size="$((size * 2))"
  sips -z "$double_size" "$double_size" "$stage/icon.png" \
    --out "$icons/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil --convert icns --output "$contents/Resources/AppIcon.icns" "$icons"

licenses="$contents/Resources/Licenses"
cp "$root/LICENSE-MIT" "$root/LICENSE-APACHE" "$root"/web/fonts/*-OFL.txt "$licenses/"
cp "$root/crates/apeiron-core/LICENSE" "$licenses/Apeiron.txt"
cp "$root/docs/third-party-firmware-parsers.txt" "$licenses/"

identity="${ZRAX_MACOS_SIGN_IDENTITY:--}"
if [[ "$identity" == - ]]; then
  codesign --force --sign - "$app"
else
  codesign --force --options runtime --timestamp --sign "$identity" "$app"
fi
codesign --verify --strict "$app"

ln -s /Applications "$image/Applications"
dmg="zrax-workbench-$version-macos-$arch.dmg"
hdiutil create -quiet -srcfolder "$image" -volname "$app_name" -format UDZO "$stage/$dmg"
if [[ "$identity" != - ]]; then
  codesign --timestamp --sign "$identity" "$stage/$dmg"
fi
hdiutil verify -quiet "$stage/$dmg"

# Replace only the generated bundle, after its successor has been verified.
destination="$output/$app_name.app"
if [[ -e "$destination" ]]; then
  mv "$destination" "$stage/previous.app"
fi
if ! mv "$app" "$destination"; then
  if [[ -e "$stage/previous.app" ]]; then
    mv "$stage/previous.app" "$destination"
  fi
  exit 1
fi
mv -f "$stage/$dmg" "$output/$dmg"
printf '\n%s\n%s\n' "$destination" "$output/$dmg"
