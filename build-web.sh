#!/usr/bin/env bash
set -euo pipefail

# Build the Zrax workbench into dist/ and the classic classifier into dist/classic/
# Output: dist/ folder containing index.html + JS glue + .wasm (ready to upload)

echo "Building WASM..."
wasm-pack build --release --target web --no-default-features --features wasm

echo "Assembling dist/..."
rm -rf dist
mkdir -p dist

cp pkg/zrax.js dist/
cp pkg/zrax_bg.wasm dist/

# Runtime files are native browser ES modules. No frontend bundler is required.
cp web/index.html web/workbench.css dist/
for source in web/*.js; do
    sed "s|from '../pkg/zrax.js'|from './zrax.js'|" "$source" > "dist/$(basename "$source")"
done
cp src/workbench/apeiron/LICENSE dist/APEIRON-LICENSE.txt
cp -R web/fonts dist/fonts
cp -R web/classic dist/classic
sed "s|from '../../pkg/zrax.js'|from '../zrax.js'|" web/classic/classic.js > dist/classic/classic.js

# Version the whole module graph and WASM together. A rebuilt page must never
# combine a cached worker protocol or JS wrapper with a different WASM binary.
python3 - <<'PY'
from pathlib import Path
import hashlib
import re
dist = Path('dist')
assets = sorted(p for p in dist.rglob('*') if p.suffix in {'.js', '.wasm', '.css', '.ttf'})
revision = hashlib.sha256(b''.join(p.relative_to(dist).as_posix().encode() + b'\0' + p.read_bytes() for p in assets)).hexdigest()[:16]
paths = {p.resolve() for p in assets}
pattern = re.compile(r"(['\"])([^'\"\s?]+\.(?:js|wasm|css|ttf))\1")
for path in assets + sorted(dist.rglob('*.html')):
    if path.suffix not in {'.js', '.css', '.html'}:
        continue
    def version_url(url):
        return f'{url}?v={revision}' if (path.parent / url).resolve() in paths else url
    source = pattern.sub(lambda m: f'{m[1]}{version_url(m[2])}{m[1]}', path.read_text())
    # CSS font URLs use url(...) without quotes in the Google Fonts source.
    source = re.sub(r'url\(([^)\'"\s?]+\.ttf)\)', lambda m: f'url({version_url(m[1])})', source)
    path.write_text(source)
print(f'Asset revision: {revision}')
PY

echo ""
echo "Done. Contents of dist/:"
ls -lh dist/
echo ""
echo "Upload the dist/ folder as-is."
echo "Workbench: /  Classic classifier: /classic/"
