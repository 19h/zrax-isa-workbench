#!/usr/bin/env bash
set -euo pipefail

# Build the ISA Classifier web app into dist/
# Output: dist/ folder containing index.html + JS glue + .wasm (ready to upload)

echo "Building WASM..."
wasm-pack build --release --target web --no-default-features --features wasm

echo "Assembling dist/..."
rm -rf dist
mkdir -p dist

cp pkg/isa_classifier.js dist/
cp pkg/isa_classifier_bg.wasm dist/

# Runtime files are native browser ES modules. No frontend bundler is required.
cp web/index.html web/workbench.css dist/
for source in web/*.js; do
    sed "s|from '../pkg/isa_classifier.js'|from './isa_classifier.js'|" "$source" > "dist/$(basename "$source")"
done
cp src/workbench/apeiron/LICENSE dist/APEIRON-LICENSE.txt
cp -R web/fonts dist/fonts

# Version the whole module graph and WASM together. A rebuilt page must never
# combine a cached worker protocol or JS wrapper with a different WASM binary.
python3 - <<'PY'
from pathlib import Path
import hashlib
import re
dist = Path('dist')
assets = sorted(dist.glob('*.js')) + sorted(dist.glob('*.wasm')) + [dist / 'workbench.css']
revision = hashlib.sha256(b''.join(p.read_bytes() for p in assets)).hexdigest()[:16]
names = {p.name for p in assets}
pattern = re.compile(r"(['\"])(\./)?([^/'\"?]+\.(?:js|wasm))\1")
for path in dist.glob('*.js'):
    path.write_text(pattern.sub(lambda m: f'{m[1]}{m[2] or ""}{m[3]}?v={revision}{m[1]}' if m[3] in names else m[0], path.read_text()))
page = dist / 'index.html'
page.write_text(page.read_text().replace('src="./workbench.js"', f'src="./workbench.js?v={revision}"')
    .replace('href="./workbench.css"', f'href="./workbench.css?v={revision}"'))
print(f'Asset revision: {revision}')
PY

echo ""
echo "Done. Contents of dist/:"
ls -lh dist/
echo ""
echo "Upload the dist/ folder as-is."
