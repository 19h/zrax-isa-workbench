import assert from 'node:assert/strict';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, elf, drop, finished, selectEntry, holdRead, releaseRead, baseUrl } from './helpers.mjs';
before(setup); after(teardown);

test('multi-file drop preserves order and isolates classification failure', async t => {
  const page = await openPage(t); await load(page);
  await drop(page, [elf('x86.o'), elf('arm.o', 183), { name: 'empty.bin', buffer: Buffer.alloc(0) }]); await finished(page, 3);
  assert.deepEqual(await page.locator('.batch-file').allTextContents(), ['x86.o', 'arm.o', 'empty.bin']);
  assert.deepEqual(await page.locator('.batch-status').allTextContents(), ['[+]', '[+]', '[-]']);
  assert.deepEqual(await page.locator('.batch-architecture').allTextContents(), ['x86_64', 'aarch64', '—']);
  await selectEntry(page); assert.equal(await page.locator('.hero-isa').textContent(), 'x86_64');
  await page.getByRole('tab', { name: 'json', exact: true }).click(); assert.equal(JSON.parse(await page.locator('#jsonRaw').textContent()).primary.isa, 'x86_64');
  await selectEntry(page, 1); assert.equal(JSON.parse(await page.locator('#jsonRaw').textContent()).primary.isa, 'a_arch64');
  await selectEntry(page, 2); await page.getByRole('tab', { name: 'classification', exact: true }).click();
  assert.match(await page.locator('#classification-content').textContent(), /classification failed/);
  assert.equal(await page.locator('#error').isVisible(), false);
});

test('picker appends duplicates, resets input and supports keyboard selection', async t => {
  const page = await openPage(t); await load(page);
  await page.locator('#fileinput').setInputFiles([elf('same.o'), elf('same.o', 183)]); await finished(page, 2);
  assert.equal(await page.locator('#fileinput').inputValue(), '');
  await page.locator('#fileinput').setInputFiles(elf('same.o')); await finished(page, 3);
  assert.equal(await page.locator('.file-entry').count(), 3);
  await page.locator('.file-entry').nth(1).focus(); await page.keyboard.press('Enter');
  assert.equal(await page.locator('.hero-isa').textContent(), 'aarch64'); assert.equal(await page.locator('.file-entry[aria-current="true"]').count(), 1);
});

test('additions during a held worker read join the queue', async t => {
  const page = await openPage(t); await holdRead(page, 'slow.o'); await load(page);
  await drop(page, [elf('slow.o')]); await page.waitForFunction(() => window.readHeld); await drop(page, [elf('later.o', 183)]);
  assert.deepEqual(await page.locator('.batch-status').allTextContents(), ['[*]', '[ ]']);
  await releaseRead(page); await finished(page, 2); assert.deepEqual(await page.locator('.batch-architecture').allTextContents(), ['x86_64', 'aarch64']);
});

test('clear during a worker read rejects stale results and runs a replacement', async t => {
  const page = await openPage(t); await holdRead(page, 'old.o'); await load(page);
  await drop(page, [elf('old.o'), elf('never-read.o')]); await page.waitForFunction(() => window.readHeld);
  await page.getByRole('button', { name: 'clear files', exact: true }).click(); assert.equal(await page.locator('#empty-view').isVisible(), true);
  await drop(page, [elf('new.o', 183)]); await releaseRead(page); await finished(page, 1);
  assert.deepEqual(await page.locator('.batch-file').allTextContents(), ['new.o']); assert.equal(await page.locator('.hero-isa').textContent(), 'aarch64');
  assert.equal(await page.locator('#batch-summary').textContent(), '1 file · 1 done · 0 failed');
});

test('remove an active file while a remaining file completes', async t => {
  const page = await openPage(t); await holdRead(page, 'remove.o'); await load(page);
  await drop(page, [elf('remove.o')]); await page.waitForFunction(() => window.readHeld); await page.getByRole('button', { name: 'Remove file' }).click();
  await drop(page, [elf('remain.o')]); await releaseRead(page); await finished(page, 1); assert.deepEqual(await page.locator('.batch-file').allTextContents(), ['remain.o']);
});

test('read errors stay local and hostile filenames stay literal', async t => {
  const page = await openPage(t), name = 'bad" onmouseover="window.injected=1"><img src=x>.o';
  await page.route('**/analysis-worker.js', async route => {
    const response = await route.fetch(), source = await response.text();
    await route.fulfill({ response, body: `const testOriginal = File.prototype.arrayBuffer; File.prototype.arrayBuffer = function() { return this.name === ${JSON.stringify(name)} ? Promise.reject(new Error('read failed <fixture>')) : testOriginal.call(this); };\n` + source });
  });
  await load(page); await drop(page, [elf(name), elf('good.o')]); await finished(page, 2);
  assert.deepEqual(await page.locator('.batch-status').allTextContents(), ['[-]', '[+]']); assert.equal(await page.locator('.batch-file').first().getAttribute('title'), name);
  assert.equal(await page.locator('[onmouseover], #file-list img, #classification-content img').count(), 0); assert.equal(await page.evaluate(() => window.injected), undefined);
});

test('files dropped before initialization wait and then classify', async t => {
  const page = await openPage(t); let release; const gate = new Promise(resolve => { release = resolve; });
  await page.route('**/isa_classifier_bg.wasm', async route => { await gate; await route.continue(); });
  await page.goto(baseUrl + '/web/index.html'); await drop(page, [elf('early.o'), elf('early-arm.o', 183)]);
  assert.deepEqual(await page.locator('.batch-status').allTextContents(), ['[ ]', '[ ]']); release(); await finished(page, 2);
});

test('initialization failure terminates pending entries and rejects additions', async t => {
  const page = await openPage(t); let release; const gate = new Promise(resolve => { release = resolve; });
  await page.route('**/isa_classifier_bg.wasm', async route => { await gate; await route.abort(); });
  await page.goto(baseUrl + '/web/index.html'); await drop(page, [elf('queued.o')]); release(); await finished(page, 1);
  assert.equal(await page.locator('.batch-status').textContent(), '[-]'); assert.match(await page.locator('#error').textContent(), /Failed to load classifier/);
  await drop(page, [elf('rejected.o')]); assert.equal(await page.locator('.batch-file').count(), 1);
});

test('nested drag overlay, default prevention and global file ingestion', async t => {
  const page = await openPage(t); await load(page);
  const actual = await page.evaluate(() => {
    const transfer = new DataTransfer(); transfer.items.add(new File(['x'], 'file.bin'));
    const dispatch = (target, type, dataTransfer = transfer) => { const e = new DragEvent(type, { dataTransfer, bubbles: true, cancelable: true }); target.dispatchEvent(e); return e.defaultPrevented; };
    dispatch(document.body, 'dragenter'); dispatch(document.querySelector('nav'), 'dragenter'); dispatch(document.querySelector('nav'), 'dragleave'); const nested = !document.getElementById('drag-overlay').hidden;
    dispatch(document.body, 'dragleave'); const left = !document.getElementById('drag-overlay').hidden; const prevented = dispatch(document.body, 'drop');
    const plain = new DataTransfer(); plain.setData('text/plain', 'text'); return { nested, left, prevented, textPrevented: dispatch(document.body, 'drop', plain) };
  });
  assert.deepEqual(actual, { nested: true, left: false, prevented: true, textPrevented: false }); await finished(page, 1);
});

test('100 files complete in packaged mobile UI with bounded document width', async t => {
  const page = await openPage(t, { viewport: { width: 390, height: 844 } }); await load(page, '/dist/index.html');
  await page.locator('#fileinput').setInputFiles(Array.from({ length: 100 }, (_, i) => elf(`file-${i}.o`, i % 2 ? 183 : 62))); await finished(page, 100);
  assert.equal(await page.locator('.batch-status.done').count(), 100); assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  await page.locator('.batch-file').last().click(); assert.equal(await page.locator('.hero-isa').textContent(), 'aarch64'); assert.equal(await page.locator('#batch').getAttribute('aria-busy'), 'false');
});
