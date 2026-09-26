#!/usr/bin/env bash
set -euo pipefail

# Build the ISA Classifier web app into dist/
# Output: dist/ folder containing index.html + JS glue + .wasm (ready to upload)

echo "Building WASM..."
wasm-pack build --target web --no-default-features --features wasm

echo "Assembling dist/..."
rm -rf dist
mkdir -p dist

cp pkg/isa_classifier.js dist/
cp pkg/isa_classifier_bg.wasm dist/

# Rewrite the import path so everything lives in one folder
sed "s|from '../pkg/isa_classifier.js'|from './isa_classifier.js'|" web/index.html > dist/index.html

echo ""
echo "Done. Contents of dist/:"
ls -lh dist/
echo ""
echo "Upload the dist/ folder as-is."
