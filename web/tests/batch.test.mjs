import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve, sep } from 'node:path';
import { chromium } from 'playwright';

// Test the real page and WASM exports; only file reads and startup timing are
// controlled in the race tests. Run ../build-web.sh before testing dist/.
const root = fileURLToPath(new URL('../../', import.meta.url));
let browser, server, baseUrl;

before(async () => {
  server = createServer(async (req, res) => {
    try {
      const path = resolve(root, `.${new URL(req.url, 'http://localhost').pathname}`);
      if (!path.startsWith(root.endsWith(sep) ? root : root + sep)) {
        res.writeHead(403).end();
        return;
      }
      const body = await readFile(path);
      const mime = path.endsWith('.wasm') ? 'application/wasm'
        : path.endsWith('.js') ? 'text/javascript' : 'text/html';
      res.writeHead(200, { 'Content-Type': mime }).end(body);
    } catch {
      res.writeHead(404).end();
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
  browser = await chromium.launch({
    headless: true,
    ...(process.env.BROWSER_PATH ? { executablePath: process.env.BROWSER_PATH } : {}),
  });
});

after(async () => {
  await browser?.close();
  if (server) await new Promise(resolve => server.close(resolve));
});

async function openPage(t, options = {}) {
  const page = await browser.newPage({ viewport: options.viewport });
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));
  // Keep external font availability out of the behavioral tests.
  await page.route('https://fonts.googleapis.com/**', route => route.abort());
  await page.route('https://fonts.gstatic.com/**', route => route.abort());
  t.after(async () => {
    await page.close();
    assert.deepEqual(errors, [], 'No uncaught browser errors');
  });
  return page;
}

async function load(page, path = '/web/index.html') {
  await page.goto(baseUrl + path);
  await page.waitForFunction(() => document.getElementById('version').textContent.startsWith('v'));
}

// Minimal ELF64 relocatable headers, with no program or section table.
function elf(name, machine = 62) {
  const buffer = Buffer.alloc(64);
  buffer.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]);
  buffer.writeUInt16LE(1, 16);
  buffer.writeUInt16LE(machine, 18);
  buffer.writeUInt32LE(1, 20);
  buffer.writeUInt16LE(64, 52);
  buffer.writeUInt16LE(56, 54);
  buffer.writeUInt16LE(64, 58);
  return { name, mimeType: 'application/octet-stream', buffer };
}

async function drop(page, files) {
  await page.evaluate(files => {
    const transfer = new DataTransfer();
    for (const file of files) {
      transfer.items.add(new File([new Uint8Array(file.bytes)], file.name));
    }
    const zone = document.getElementById('dropzone');
    for (const type of ['dragenter', 'dragover', 'drop']) {
      zone.dispatchEvent(new DragEvent(type, { dataTransfer: transfer, bubbles: true, cancelable: true }));
    }
  }, files.map(file => ({ name: file.name, bytes: [...file.buffer] })));
}

async function finished(page, total) {
  await page.waitForFunction(total => {
    const progress = document.getElementById('batch-progress');
    return progress.max === total && progress.value === total;
  }, total);
}

async function holdRead(page, name) {
  await page.evaluate(name => {
    const original = File.prototype.arrayBuffer;
    File.prototype.arrayBuffer = function () {
      if (this.name !== name) return original.call(this);
      const file = this;
      window.readHeld = true;
      return new Promise((resolve, reject) => {
        window.releaseRead = () => original.call(file).then(resolve, reject);
      });
    };
  }, name);
}

test('dropping a mixed batch preserves order, isolates errors and selects each result', async t => {
  const page = await openPage(t);
  await load(page);
  await drop(page, [elf('x86.o'), elf('arm.o', 183), { name: 'empty.bin', buffer: Buffer.alloc(0) }]);
  await finished(page, 3);
  assert.deepEqual(await page.locator('.batch-file').allTextContents(), ['x86.o', 'arm.o', 'empty.bin']);
  assert.deepEqual(await page.locator('.batch-status').allTextContents(), ['Done', 'Done', 'Failed']);
  assert.deepEqual(await page.locator('.batch-architecture').allTextContents(), ['x86-64', 'AArch64', '—']);
  assert.equal(await page.locator('.hero-isa').textContent(), 'x86-64');
  await page.getByRole('button', { name: 'Raw JSON' }).click();
  assert.equal(JSON.parse(await page.locator('#jsonRaw').textContent()).primary.isa, 'x86_64');
  await page.getByRole('button', { name: 'arm.o', exact: true }).click();
  assert.equal(await page.locator('.hero-isa').textContent(), 'AArch64');
  await page.getByRole('button', { name: 'Raw JSON' }).click();
  assert.equal(JSON.parse(await page.locator('#jsonRaw').textContent()).primary.isa, 'a_arch64');
  await page.getByRole('button', { name: 'empty.bin', exact: true }).click();
  assert.match(await page.locator('#results').textContent(), /Analysis failed:/);
  assert.equal(await page.locator('#loading').isVisible(), false);
  assert.equal(await page.locator('#error').isVisible(), false);
});

test('the multi-file picker appends repeated selections and resets its value', async t => {
  const page = await openPage(t);
  await load(page);
  await page.locator('#fileinput').setInputFiles([elf('same.o'), elf('same.o', 183)]);
  await finished(page, 2);
  assert.equal(await page.locator('#fileinput').inputValue(), '');
  await page.locator('#fileinput').setInputFiles(elf('same.o'));
  await finished(page, 3);
  assert.equal(await page.locator('.batch-file').count(), 3);
  await page.locator('.batch-file').nth(1).focus();
  await page.keyboard.press('Enter');
  assert.equal(await page.locator('.hero-isa').textContent(), 'AArch64');
  assert.equal(await page.locator('[aria-current="true"]').count(), 1);
});

test('files added during a pending read join the queue without losing selection', async t => {
  const page = await openPage(t);
  await load(page);
  await holdRead(page, 'slow.o');
  await drop(page, [elf('slow.o')]);
  await page.waitForFunction(() => window.readHeld);
  await drop(page, [elf('later.o', 183)]);
  assert.deepEqual(await page.locator('.batch-status').allTextContents(), ['Analyzing', 'Queued']);
  await page.getByRole('button', { name: 'later.o' }).click();
  assert.match(await page.locator('#results').textContent(), /Queued for analysis/);
  await page.evaluate(() => window.releaseRead());
  await finished(page, 2);
  assert.equal(await page.locator('.file-name').textContent(), 'later.o');
  assert.equal(await page.locator('.hero-isa').textContent(), 'AArch64');
});

test('clearing during a file read discards stale results before a new batch', async t => {
  const page = await openPage(t);
  await load(page);
  await holdRead(page, 'old.o');
  await drop(page, [elf('old.o'), elf('never-read.o')]);
  await page.waitForFunction(() => window.readHeld);
  await page.getByRole('button', { name: 'Clear files' }).click();
  assert.equal(await page.locator('#batch').isVisible(), false);
  assert.equal(await page.locator('#results').isVisible(), false);
  await drop(page, [elf('new.o', 183)]);
  await page.evaluate(() => window.releaseRead());
  await finished(page, 1);
  assert.deepEqual(await page.locator('.batch-file').allTextContents(), ['new.o']);
  assert.equal(await page.locator('.hero-isa').textContent(), 'AArch64');
  assert.equal(await page.locator('#batch-summary').textContent(), '1 file · 1 done · 0 failed');
});

test('read failures continue the batch and filenames remain literal text', async t => {
  const page = await openPage(t);
  await load(page);
  const name = 'bad" onmouseover="window.injected=1"><img src=x>.o';
  await page.evaluate(name => {
    const original = File.prototype.arrayBuffer;
    File.prototype.arrayBuffer = function () {
      return this.name === name ? Promise.reject(new Error('read failed <fixture>')) : original.call(this);
    };
  }, name);
  await drop(page, [elf(name), elf('good.o')]);
  await finished(page, 2);
  assert.deepEqual(await page.locator('.batch-status').allTextContents(), ['Failed', 'Done']);
  assert.equal(await page.locator('.batch-file').first().getAttribute('title'), name);
  assert.equal(await page.locator('[onmouseover], #file-list img, #results img').count(), 0);
  assert.match(await page.locator('#results').textContent(), /read failed <fixture>/);
  assert.equal(await page.evaluate(() => window.injected), undefined);
});

test('files dropped while the classifier initializes run once it is ready', async t => {
  const page = await openPage(t);
  let release;
  const gate = new Promise(resolve => { release = resolve; });
  await page.route('**/isa_classifier_bg.wasm', async route => {
    await gate;
    await route.continue();
  });
  await page.goto(baseUrl + '/web/index.html');
  await drop(page, [elf('early.o'), elf('early-arm.o', 183)]);
  assert.deepEqual(await page.locator('.batch-status').allTextContents(), ['Queued', 'Queued']);
  release();
  await finished(page, 2);
  assert.deepEqual(await page.locator('.batch-status').allTextContents(), ['Done', 'Done']);
});

test('initialization failure marks queued files failed and ends progress', async t => {
  const page = await openPage(t);
  let release;
  const gate = new Promise(resolve => { release = resolve; });
  await page.route('**/isa_classifier_bg.wasm', async route => {
    await gate;
    await route.abort();
  });
  await page.goto(baseUrl + '/web/index.html');
  await drop(page, [elf('queued.o')]);
  release();
  await finished(page, 1);
  assert.equal(await page.locator('.batch-status').textContent(), 'Failed');
  assert.equal(await page.locator('#loading').isVisible(), false);
  assert.match(await page.locator('#error').textContent(), /Failed to load classifier/);
  await drop(page, [elf('rejected.o')]);
  assert.equal(await page.locator('.batch-file').count(), 1);
});

test('nested drag targets keep highlighting and outside file drops prevent navigation', async t => {
  const page = await openPage(t);
  await load(page);
  const result = await page.evaluate(() => {
    const transfer = new DataTransfer();
    transfer.items.add(new File(['x'], 'file.bin'));
    const zone = document.getElementById('dropzone');
    const child = zone.querySelector('svg');
    const dispatch = (target, type) => {
      const e = new DragEvent(type, { dataTransfer: transfer, bubbles: true, cancelable: true });
      target.dispatchEvent(e);
      return e.defaultPrevented;
    };
    dispatch(zone, 'dragenter');
    dispatch(child, 'dragenter');
    dispatch(child, 'dragleave');
    const nestedHighlight = zone.classList.contains('dragover');
    dispatch(zone, 'dragleave');
    const leftHighlight = zone.classList.contains('dragover');
    const outsidePrevented = dispatch(document.body, 'drop');
    const textTransfer = new DataTransfer();
    textTransfer.setData('text/plain', 'ordinary text');
    const textEvent = new DragEvent('drop', { dataTransfer: textTransfer, bubbles: true, cancelable: true });
    document.body.dispatchEvent(textEvent);
    return { nestedHighlight, leftHighlight, outsidePrevented, textPrevented: textEvent.defaultPrevented };
  });
  assert.deepEqual(result, { nestedHighlight: true, leftHighlight: false, outsidePrevented: true, textPrevented: false });
});

test('a larger batch completes and the packaged UI fits a mobile viewport', async t => {
  const page = await openPage(t, { viewport: { width: 390, height: 844 } });
  await load(page, '/dist/index.html');
  await drop(page, Array.from({ length: 100 }, (_, i) => elf(`file-${i}.o`, i % 2 ? 183 : 62)));
  await finished(page, 100);
  assert.equal(await page.locator('.batch-status.done').count(), 100);
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true);
  assert.equal(await page.locator('#batch').getAttribute('aria-busy'), 'false');
  await page.getByRole('button', { name: 'file-99.o', exact: true }).click();
  assert.equal(await page.locator('.hero-isa').textContent(), 'AArch64');
});
