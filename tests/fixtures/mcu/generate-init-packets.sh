#!/usr/bin/env bash
set -euo pipefail
# Encode the synthetic Nordic DFU init packets (`*.txtpb`, protobuf text
# format) in this directory into `*.dat` with protoc, against pc-nrfutil
# v6.1.7 `nordicsemi/dfu/dfu-cc.proto`. The .proto file is downloaded to a
# temporary directory and checked against its SHA-256; it is not committed.
#
# Usage: tests/fixtures/mcu/generate-init-packets.sh
# Needs: protoc, curl, shasum.

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

proto_url="https://raw.githubusercontent.com/NordicSemiconductor/pc-nrfutil/804bc0ffa9929d4c74238eb7abdfb62ad660e122/nordicsemi/dfu/dfu-cc.proto"
proto_sha256="d2b08647acc64a008452b5c78dd38f519fc0f9c960c19f65f5d68c40e18adb69"

curl -sSfL -o "${work}/dfu-cc.proto" "${proto_url}"
echo "${proto_sha256}  ${work}/dfu-cc.proto" | shasum -a 256 -c -

for name in nordic-init-signed nordic-init-unsigned; do
  protoc --proto_path="${work}" --encode=dfu.Packet dfu-cc.proto \
    < "${here}/${name}.txtpb" > "${here}/${name}.dat"
done
