import assert from 'node:assert/strict';
import { before, after, test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { setup, teardown, openPage, load, elf, finished, selectEntry, holdRead, releaseRead } from './helpers.mjs';
before(setup); after(teardown);
const mapReady = page => page.waitForFunction(() => document.getElementById('entropy-map').dataset.state === 'ready');
const value = (page, type) => page.locator(`[data-value-type="${type}"] .value`).evaluate(el => el.firstChild.textContent);
async function goto(page, offset) { await page.locator('#goto-offset').fill(String(offset)); await page.locator('#goto-offset').press('Enter'); await page.waitForFunction(offset => document.getElementById('hex-location').textContent.includes('· ' + offset), offset); }
function patterned(name = 'pattern.o', size = 32768) { const file = elf(name, 62, size); for (let i = size / 2; i < size; i++) file.buffer[i] = i % 256; return file; }

test('WASM kernels return exact reference entropies, class fractions and a Hilbert permutation', async t => {
  const page = await openPage(t); await load(page);
  const data = await page.evaluate(async () => {
    const m = await import('/pkg/isa_classifier.js'); await m.default();
    const zero = new m.WorkbenchEngine(new Uint8Array(4096));
    const uniform = new m.WorkbenchEngine(Uint8Array.from({ length: 4096 }, (_, i) => i % 256));
    const binary = new m.WorkbenchEngine(Uint8Array.from({ length: 4096 }, (_, i) => i % 2));
    const stats = [zero, uniform, binary].map(e => JSON.parse(e.inspect(0, 4096)));
    const fractions = Array.from(uniform.cells(0, 4096, 256, 0, 1)).slice(1);
    const permutation = Array.from(m.hilbert_indices(64)).sort((a, b) => a - b);
    [zero, uniform, binary].forEach(e => e.free());
    return { stats, fractions, permutation };
  });
  assert.deepEqual(data.stats.map(s => s.entropy), [0, 8, 1]);
  assert.ok(data.stats[0].deflate_ratio < 0.02); assert.ok(Math.abs(data.fractions.reduce((a, b) => a + b) - 1) < 1e-6);
  assert.deepEqual(data.permutation, Array.from({ length: 4096 }, (_, i) => i));
});

test('entropy canvas, byte palette, exact probe, histogram and zoom are synchronized', async t => {
  const page = await openPage(t); await load(page); await page.locator('#fileinput').setInputFiles(patterned()); await finished(page, 1);
  await page.getByRole('tab', { name: 'entropy', exact: true }).click(); await mapReady(page);
  await page.getByRole('button', { name: 'linear', exact: true }).click();
  await mapReady(page);
  const canvas = page.locator('#entropy-map'), rect = await canvas.boundingBox();
  await canvas.click({ position: { x: (20000 % 256 + .5) / 256 * rect.width, y: (Math.floor(20000 / 256) + .5) / 256 * rect.height } });
  await page.waitForFunction(() => document.getElementById('probe-hex').textContent === '0x00004E20');
  assert.equal(await page.locator('#entropy-value').textContent(), '8.0000');
  await page.waitForFunction(() => document.getElementById('histogram-summary').textContent.includes('256 distinct'));
  assert.match(await page.locator('#complexity-value').textContent(), /\d+\.\d+%/);
  const entropyImage = await canvas.evaluate(c => c.toDataURL());
  await page.getByRole('button', { name: 'byte class', exact: true }).click();
  await page.waitForFunction(before => document.getElementById('entropy-map').toDataURL() !== before, entropyImage);
  assert.equal(await page.locator('#byte-legend').isVisible(), true);
  const range = await page.locator('#map-range').textContent();
  await page.getByRole('button', { name: '+ in', exact: true }).click(); await mapReady(page);
  assert.notEqual(await page.locator('#map-range').textContent(), range);
  await page.getByRole('button', { name: 'fit', exact: true }).click(); await mapReady(page);
  assert.equal(await page.locator('#map-range').textContent(), range);
  await page.getByRole('button', { name: 'hilbert', exact: true }).click();
  assert.equal(await page.locator('[data-curve="hilbert"]').getAttribute('class'), 'active');
});

test('failed architecture classification retains entropy and hex inspection', async t => {
  const page = await openPage(t); await load(page);
  await page.locator('#fileinput').setInputFiles({ name: 'zeros.bin', mimeType: 'application/octet-stream', buffer: Buffer.alloc(4096) }); await finished(page, 1);
  assert.equal(await page.locator('#file-status').textContent(), 'failed');
  await page.getByRole('tab', { name: 'entropy', exact: true }).click(); await mapReady(page);
  assert.equal(await page.locator('#entropy-value').textContent(), '0.0000');
  await page.getByRole('tab', { name: 'hex', exact: true }).click();
  await page.waitForFunction(() => document.querySelector('[data-value-type="u8"]'));
  assert.equal(await value(page, 'u8'), '0');
});

test('hex inspector decodes integers and endian overrides exactly, including EOF', async t => {
  const page = await openPage(t), file = elf('decode.o', 62, 256);
  file.buffer.set([1, 2, 3, 4, 5, 6, 7, 8], 64); file.buffer[255] = 42;
  await load(page); await page.locator('#fileinput').setInputFiles(file); await finished(page, 1); await page.getByRole('tab', { name: 'hex', exact: true }).click(); await goto(page, 64);
  await page.waitForFunction(() => document.querySelector('[data-value-type="u16"] .value')?.textContent.startsWith('513'));
  assert.equal(await value(page, 'u32'), '67305985'); assert.equal(await value(page, 'u64'), '578437695752307201');
  await page.getByRole('button', { name: 'be', exact: true }).click(); assert.equal(await value(page, 'u16'), '258'); assert.equal(await value(page, 'u64'), '72623859790382856');
  await goto(page, 255); await page.waitForFunction(() => document.querySelector('[data-value-type="u8"] .value')?.textContent.startsWith('42'));
  assert.equal(await value(page, 'u16'), '—'); assert.equal(await value(page, 'f64'), '—');
  await page.locator('#goto-offset').fill('invalid!'); await page.locator('#goto-offset').press('Enter'); assert.equal(await page.locator('#goto-offset').getAttribute('aria-invalid'), 'true');
});

test('virtual hex grid handles large offsets, paging, selection and selection download', async t => {
  const page = await openPage(t), file = patterned('large.o', 8 * 1024 ** 2);
  await load(page); await page.locator('#fileinput').setInputFiles(file); await finished(page, 1); await page.getByRole('tab', { name: 'hex', exact: true }).click();
  await goto(page, file.buffer.length - 1024);
  assert.ok(await page.locator('#hex-rows .hex-row').count() < 60);
  await page.locator('#hex-viewport').focus(); await page.keyboard.press('Shift+ArrowRight'); await page.keyboard.press('Shift+ArrowRight');
  await page.waitForFunction(() => document.getElementById('selection-size').textContent.startsWith('3 bytes'));
  await page.waitForFunction(() => document.getElementById('selection-entropy').textContent.startsWith('entropy '));
  const downloadEvent = page.waitForEvent('download'); await page.getByRole('button', { name: 'download', exact: true }).filter({ visible: true }).click();
  const download = await downloadEvent, bytes = await readFile(await download.path()); assert.equal(bytes.length, 3);
  await page.getByRole('button', { name: 'clear', exact: true }).filter({ visible: true }).last().click(); assert.equal(await page.locator('#selection-panel').isVisible(), false);
  await page.locator('#hex-columns').selectOption('32'); await page.locator('#hex-group').selectOption('8');
  await page.waitForFunction(() => document.querySelectorAll('#hex-head .hex-byte').length === 32);
  assert.ok(await page.locator('#hex-rows .hex-row').count() < 60);
});

test('hex encodings include complete EBCDIC, CP437 and UTF-16', async t => {
  const page = await openPage(t), file = elf('encodings.o', 62, 512);
  file.buffer.set([0xc1, 0x80, 0x41, 0x00, 0x00, 0x41], 64);
  await load(page); await page.locator('#fileinput').setInputFiles(file); await finished(page, 1); await page.getByRole('tab', { name: 'hex', exact: true }).click(); await goto(page, 64);
  await page.locator('#hex-encoding').selectOption('ebcdic'); await page.waitForFunction(() => document.querySelector('#hex-rows .hex-char[data-offset="64"]')?.textContent === 'A');
  await page.locator('#hex-encoding').selectOption('cp437'); await page.waitForFunction(() => document.querySelector('#hex-rows .hex-char[data-offset="65"]')?.textContent === 'Ç');
  await page.locator('#hex-encoding').selectOption('utf16le'); await page.waitForFunction(() => document.querySelector('#hex-rows .hex-char[data-offset="66"]')?.textContent === 'A');
  await page.locator('#hex-encoding').selectOption('utf16be'); await page.waitForFunction(() => document.querySelector('#hex-rows .hex-char[data-offset="68"]')?.textContent === 'A');
});

test('batch filters, sorts, tallies and JSON/CSV exports preserve actual results', async t => {
  const page = await openPage(t); await load(page);
  await page.locator('#fileinput').setInputFiles([elf('z,"first.o'), elf('a.o', 183), { name: 'empty.bin', mimeType: 'application/octet-stream', buffer: Buffer.alloc(0) }]); await finished(page, 3);
  await page.locator('#batch-sort').selectOption('name'); assert.deepEqual(await page.locator('.batch-file').allTextContents(), ['a.o', 'empty.bin', 'z,"first.o']);
  await page.locator('[data-filter="error"]').click(); assert.equal(await page.locator('#batch-rows tr:visible').count(), 1);
  await page.locator('[data-filter="done"]').click(); assert.equal(await page.locator('#batch-rows tr:visible').count(), 2);
  assert.match(await page.locator('#batch-tallies').textContent(), /aarch64 1/);
  let event = page.waitForEvent('download'); await page.locator('[data-action="export-json"]').click(); let downloaded = await event;
  const records = JSON.parse(await readFile(await downloaded.path(), 'utf8')); assert.equal(records.length, 3); assert.equal(records[1].payload.primary.isa, 'a_arch64'); assert.ok(records[2].error);
  event = page.waitForEvent('download'); await page.locator('[data-action="export-csv"]').click(); downloaded = await event;
  const csv = await readFile(await downloaded.path(), 'utf8'); assert.match(csv, /"z,""first.o"/); assert.match(csv, /mean_profile_entropy/);
});

test('tab shortcuts, cursor retention, log and UI preferences survive file switches', async t => {
  const page = await openPage(t); await load(page); await page.locator('#fileinput').setInputFiles([patterned('one.o'), patterned('two.o')]); await finished(page, 2); await selectEntry(page);
  await page.keyboard.press('3'); await goto(page, 1234); await page.locator('#hex-viewport').focus(); await page.keyboard.press('j'); await goto(page, 2048); await page.locator('#hex-viewport').focus(); await page.keyboard.press('k');
  await page.waitForFunction(() => document.getElementById('hex-location').textContent.includes('· 1234'));
  await page.keyboard.press('`'); assert.equal(await page.locator('#analysis-log').isVisible(), true); assert.match(await page.locator('#log-lines').textContent(), /one.o/);
  await page.keyboard.press('4'); assert.equal(await page.locator('#json-view').isVisible(), true); await page.keyboard.press('2'); await mapReady(page);
  await page.getByRole('button', { name: 'linear', exact: true }).click(); await page.reload(); await page.waitForFunction(() => document.getElementById('status-engine').textContent.includes('Apeiron/WASM'));
  assert.equal(await page.locator('.file-entry').count(), 0); await page.locator('#fileinput').setInputFiles(elf('again.o')); await finished(page, 1); assert.equal(await page.locator('[data-curve="linear"]').getAttribute('class'), 'active');
});

test('canvas context menu opens hex at the chosen cursor and closes accessibly', async t => {
  const page = await openPage(t); await load(page); await page.locator('#fileinput').setInputFiles(patterned()); await finished(page, 1); await page.getByRole('tab', { name: 'entropy', exact: true }).click(); await mapReady(page);
  await page.locator('#entropy-map').click({ button: 'right', position: { x: 50, y: 50 } }); assert.equal(await page.locator('#context-menu').isVisible(), true);
  await page.getByRole('menuitem', { name: 'open in hex' }).click(); assert.equal(await page.locator('#hex-view').isVisible(), true); assert.equal(await page.locator('#context-menu').isVisible(), false);
});

test('analysis runs in a worker while animation frames and controls remain active', async t => {
  const page = await openPage(t); await load(page);
  await page.evaluate(() => { window.frameCount = 0; const tick = () => { window.frameCount++; window.frameId = requestAnimationFrame(tick); }; window.frameId = requestAnimationFrame(tick); });
  const file = patterned('background.o', 16 * 1024 ** 2), start = await page.evaluate(() => window.frameCount);
  await page.locator('#fileinput').setInputFiles(file); await page.getByRole('button', { name: 'Analysis log' }).click(); await finished(page, 1);
  const frames = await page.evaluate(() => { cancelAnimationFrame(window.frameId); return window.frameCount; }); assert.ok(frames > start); assert.equal(await page.locator('#analysis-log').isVisible(), true);
  const requests = []; page.on('request', request => requests.push(request.url())); await page.reload(); await page.waitForFunction(() => document.getElementById('status-engine').textContent.includes('Apeiron/WASM'));
  assert.ok(requests.every(url => new URL(url).hostname === '127.0.0.1'), 'No external runtime dependencies');
});

async function watchRequests(page) {
  await page.addInitScript(() => {
    const Original = window.Worker;
    window.workbenchRequests = [];
    window.basePaints = 0;
    const paint = CanvasRenderingContext2D.prototype.putImageData;
    CanvasRenderingContext2D.prototype.putImageData = function(...args) { if (this.canvas.id === 'entropy-map') window.basePaints++; return paint.apply(this, args); };
    window.Worker = class extends Original {
      constructor(...args) { super(...args); window.testWorker = this; this.addEventListener('message', e => { if (e.data.type === 'test-detail-held') window.detailHeld = true; }); }
      postMessage(message, ...rest) { window.workbenchRequests.push({ type: message.type, id: message.id }); return super.postMessage(message, ...rest); }
    };
  });
}
const cameraState = page => page.locator('#map-frame').evaluate(el => ({ x: +el.dataset.x, y: +el.dataset.y, zoom: +el.dataset.zoom }));

test('continuous pointer-anchored zoom keeps the raster and byte location stable', async t => {
  const page = await openPage(t); await watchRequests(page); await load(page);
  await page.locator('#fileinput').setInputFiles(patterned('zoom.o', 8 * 1024 ** 2)); await finished(page, 1);
  await page.getByRole('tab', { name: 'entropy', exact: true }).click(); await mapReady(page);
  const beforeImage = await page.locator('#entropy-map').evaluate(c => ({ image: c.toDataURL(), width: c.width }));
  const frame = await page.locator('#map-frame').boundingBox(), ax = .271, ay = .637;
  const px = Math.round(frame.x + frame.width * ax), py = Math.round(frame.y + frame.height * ay);
  await page.evaluate(() => document.getElementById('map-frame').addEventListener('wheel', e => {
    const rect = e.currentTarget.getBoundingClientRect(); window.zoomAnchor = { x: (e.clientX - rect.left) / rect.width, y: (e.clientY - rect.top) / rect.height };
  }, { once: true }));
  await page.mouse.move(px, py);
  await page.waitForFunction(() => document.getElementById('probe-kind').textContent === 'hover');
  const offset = await page.locator('#probe-hex').textContent();
  await page.mouse.wheel(0, -12);
  await page.waitForFunction(() => +document.getElementById('map-frame').dataset.zoom > 1);
  const state = await cameraState(page);
  const anchor = await page.evaluate(() => window.zoomAnchor);
  assert.ok(state.zoom > 1 && state.zoom < 1.1, 'Small wheel deltas produce continuous zoom');
  assert.ok(Math.abs(state.x + anchor.x / state.zoom - anchor.x) < 1e-9);
  assert.ok(Math.abs(state.y + anchor.y / state.zoom - anchor.y) < 1e-9);
  assert.equal(await page.locator('#probe-hex').textContent(), offset, 'Zoom preserves the hover probe under the pointer');
  assert.deepEqual(await page.locator('#entropy-map').evaluate(c => ({ image: c.toDataURL(), width: c.width })), beforeImage, 'Zoom never clears or rebuilds the base raster');
  await page.mouse.click(px, py);
  await page.waitForFunction(offset => document.getElementById('probe-hex').textContent === offset, offset);
  assert.equal(await page.evaluate(() => window.workbenchRequests.filter(r => r.type === 'map').length), 1);
});

test('detail refinement, drag pan, minimap and history preserve spatial context and cached views', async t => {
  const page = await openPage(t); await watchRequests(page); await load(page);
  await page.locator('#fileinput').setInputFiles(patterned('detail.o', 8 * 1024 ** 2)); await finished(page, 1);
  await page.getByRole('tab', { name: 'entropy', exact: true }).click(); await mapReady(page);
  const base = await page.locator('#entropy-map').evaluate(c => c.toDataURL());
  const paints = await page.evaluate(() => window.basePaints);
  await page.getByRole('button', { name: '+ in', exact: true }).click(); await page.getByRole('button', { name: '+ in', exact: true }).click();
  await page.waitForFunction(() => +document.getElementById('map-frame').dataset.zoom === 4 && document.querySelector('.map-detail'));
  await page.keyboard.press(']');
  await page.waitForFunction(() => document.getElementById('probe-hex').textContent === '0x00000010');
  const before = await cameraState(page), cursor = await page.locator('#probe-hex').textContent(), frame = await page.locator('#map-frame').boundingBox();
  await page.mouse.move(frame.x + frame.width * .5, frame.y + frame.height * .5); await page.mouse.down();
  await page.mouse.move(frame.x + frame.width * .4, frame.y + frame.height * .4, { steps: 6 }); await page.mouse.up();
  const after = await cameraState(page); assert.ok(after.x > before.x || after.y > before.y);
  assert.equal(await page.locator('#probe-hex').textContent(), cursor, 'Panning does not select a different byte');
  await page.getByRole('button', { name: 'Previous view', exact: true }).click();
  await page.waitForFunction(before => { const el = document.getElementById('map-frame'); return Math.abs(+el.dataset.x - before.x) < 1e-9 && Math.abs(+el.dataset.y - before.y) < 1e-9; }, before);
  await page.keyboard.press('Alt+ArrowRight'); await page.waitForFunction(after => Math.abs(+document.getElementById('map-frame').dataset.x - after.x) < 1e-9, after);
  const overview = await page.locator('#map-overview').boundingBox();
  await page.mouse.click(overview.x + overview.width * .5, overview.y + overview.height * .5);
  await page.waitForFunction(() => Math.abs(+document.getElementById('map-frame').dataset.x - .375) < .015);
  await page.getByRole('button', { name: 'fit', exact: true }).click(); await page.waitForFunction(() => +document.getElementById('map-frame').dataset.zoom === 1);
  assert.equal(await page.locator('#entropy-map').evaluate(c => c.toDataURL()), base);
  assert.equal(await page.evaluate(() => window.basePaints), paints, 'Refinement, pan, history and fit never repaint the base raster');
  assert.equal(await page.evaluate(() => window.workbenchRequests.filter(r => r.type === 'map').length), 1);
});

test('per-file viewport and cached map survive switching files', async t => {
  const page = await openPage(t); await watchRequests(page); await load(page);
  await page.locator('#fileinput').setInputFiles([patterned('first.o'), patterned('second.o')]); await finished(page, 2); await selectEntry(page);
  await page.getByRole('tab', { name: 'entropy', exact: true }).click(); await mapReady(page);
  await page.getByRole('button', { name: '+ in', exact: true }).click(); await page.waitForFunction(() => +document.getElementById('map-frame').dataset.zoom === 2);
  const first = await cameraState(page); await page.locator('.file-entry').nth(1).click(); await mapReady(page); assert.equal((await cameraState(page)).zoom, 1);
  await page.locator('.file-entry').nth(0).click(); await mapReady(page); assert.deepEqual(await cameraState(page), first);
  assert.equal(await page.evaluate(() => window.workbenchRequests.filter(r => r.type === 'map').length), 2);
});

test('worker map exceptions replace pending progress with the actual error', async t => {
  const page = await openPage(t);
  await page.route('**/analysis-worker.js', async route => { const response = await route.fetch(); await route.fulfill({ response, body: (await response.text()).replace("const count = job.width * job.height;", "throw new Error('injected spatial failure'); const count = job.width * job.height;") }); });
  await load(page); await page.locator('#fileinput').setInputFiles(patterned()); await finished(page, 1);
  await page.getByRole('tab', { name: 'entropy', exact: true }).click();
  await page.waitForFunction(() => document.getElementById('entropy-map').dataset.state === 'error');
  assert.match(await page.locator('#map-progress').textContent(), /injected spatial failure/);
});

test('a mismatched worker protocol fails explicitly instead of leaving an empty map', async t => {
  const page = await openPage(t);
  await page.route('**/analysis-worker.js', async route => { const response = await route.fetch(); await route.fulfill({ response, body: (await response.text()).replace('protocol: WORKBENCH_PROTOCOL', 'protocol: -1') }); });
  await page.goto((await import('./helpers.mjs')).baseUrl + '/web/index.html');
  await page.waitForFunction(() => document.getElementById('status-engine').textContent === 'build mismatch');
  assert.match(await page.locator('#error').textContent(), /worker build mismatch/);
});

test('file switches clear stale hex values while the replacement read is held', async t => {
  const page = await openPage(t); await holdRead(page, 'held.o'); await load(page);
  await page.locator('#fileinput').setInputFiles(patterned('first.o')); await finished(page, 1);
  await page.getByRole('tab', { name: 'hex', exact: true }).click(); await page.waitForFunction(() => document.querySelector('[data-value-type="u8"]'));
  await page.locator('#fileinput').setInputFiles(elf('held.o'));
  await page.waitForFunction(() => window.readHeld);
  assert.equal(await page.locator('#hex-rows .hex-row').count(), 0); assert.equal(await page.locator('[data-value-type="u8"]').count(), 0);
  await releaseRead(page); await finished(page, 2); await page.waitForFunction(() => document.querySelector('[data-value-type="u8"]'));
  assert.equal(await value(page, 'u8'), '127');
});

test('fit cancels held refinement and removes its pending progress without clearing the raster', async t => {
  const page = await openPage(t); await watchRequests(page);
  await page.route('**/analysis-worker.js', async route => {
    const response = await route.fetch();
    const hook = "let releaseTestDetail; self.addEventListener('message', e => { if(e.data.type === 'test-release-detail') releaseTestDetail?.(); });\n";
    const body = (await response.text()).replace('const count = job.width * job.height;', "if(job.type === 'detail') { postMessage({type:'test-detail-held'}); await new Promise(resolve => releaseTestDetail = resolve); } const count = job.width * job.height;");
    await route.fulfill({ response, body: hook + body });
  });
  await load(page); await page.locator('#fileinput').setInputFiles(patterned('held-detail.o', 8 * 1024 ** 2)); await finished(page, 1);
  await page.getByRole('tab', { name: 'entropy', exact: true }).click(); await mapReady(page);
  const raster = await page.locator('#entropy-map').evaluate(c => c.toDataURL());
  await page.getByRole('button', { name: '+ in', exact: true }).click(); await page.waitForFunction(() => window.detailHeld);
  await page.getByRole('button', { name: 'fit', exact: true }).click(); await page.waitForFunction(() => document.getElementById('map-progress').hidden);
  assert.equal(await page.locator('#entropy-map').evaluate(c => c.toDataURL()), raster);
  await page.evaluate(() => window.testWorker.postMessage({ type: 'test-release-detail' }));
  await page.getByRole('tab', { name: 'hex', exact: true }).click(); await goto(page, 64);
  await page.waitForFunction(() => document.querySelector('[data-value-type="u8"] .value')?.textContent.startsWith('0'));
});
