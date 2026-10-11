import assert from 'node:assert/strict';
import { before, after, test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { setup, teardown, openPage, elf, finished, baseUrl, root } from './helpers.mjs';
before(setup); after(teardown);

// Restore the historical queue/race regressions against the current WASM.
async function load(page, path = '/web/classic/index.html') {
  await page.goto(baseUrl + path);
  await page.waitForFunction(() => document.getElementById('version').textContent.startsWith('v'));
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
  await page.route('**/zrax_bg.wasm*', async route => {
    await gate;
    await route.continue();
  });
  await page.goto(baseUrl + '/web/classic/index.html');
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
  await page.route('**/zrax_bg.wasm*', async route => {
    await gate;
    await route.abort();
  });
  await page.goto(baseUrl + '/web/classic/index.html');
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
  await load(page, '/dist/classic/index.html');
  await drop(page, Array.from({ length: 100 }, (_, i) => elf(`file-${i}.o`, i % 2 ? 183 : 62)));
  await finished(page, 100);
  assert.equal(await page.locator('.batch-status.done').count(), 100);
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true);
  assert.equal(await page.locator('#batch').getAttribute('aria-busy'), 'false');
  await page.getByRole('button', { name: 'file-99.o', exact: true }).click();
  assert.equal(await page.locator('.hero-isa').textContent(), 'AArch64');
});

for (const path of ['/web/classic/', '/dist/classic/']) {
  test(`classic cards, local fonts and keyboard disclosures work at ${path}`, async t => {
    const page = await openPage(t);
    const requests = [], failures = [];
    page.on('request', request => requests.push(request.url()));
    page.on('response', response => { if (response.status() >= 400) failures.push(response.url()); });
    await load(page, path);
    await page.locator('#fileinput').setInputFiles(elf('classic.o'));
    await finished(page, 1);
    await page.evaluate(() => document.fonts.ready);
    assert.equal(await page.title(), 'ISA Classifier');
    assert.equal(await page.locator('.file-banner .file-name').textContent(), 'classic.o');
    assert.equal(await page.locator('.hero-isa').textContent(), 'x86-64');
    assert.match(await page.locator('.footer-bar').textContent(), /Analyzed 64 B.*\d+\.\d ms/s);
    assert.equal(await page.evaluate(() => document.fonts.check('400 16px Inter') && document.fonts.check('400 16px "JetBrains Mono"')), true);
    const disclosure = page.getByRole('button', { name: 'File Format', exact: true });
    await disclosure.focus(); await page.keyboard.press('Enter');
    assert.equal(await disclosure.getAttribute('aria-expanded'), 'false');
    assert.equal(await disclosure.locator('..').locator('.section-body').isVisible(), false);
    await page.keyboard.press('Space');
    assert.equal(await disclosure.getAttribute('aria-expanded'), 'true');
    const json = page.getByRole('button', { name: 'Raw JSON' });
    await json.focus(); await page.keyboard.press('Enter');
    assert.equal(await json.getAttribute('aria-expanded'), 'true');
    assert.equal(JSON.parse(await page.locator('#jsonRaw').textContent()).primary.isa, 'x86_64');
    assert.deepEqual(failures, []);
    assert.ok(requests.every(url => new URL(url).origin === baseUrl), 'All runtime assets are local');
    if (path.startsWith('/dist/')) {
      assert.ok(requests.every(url => new URL(url).pathname.startsWith('/dist/')), 'Assets respect the deployment prefix');
      const assets = requests.map(url => new URL(url)).filter(url => /\.(?:js|wasm|css|ttf)$/.test(url.pathname));
      const revisions = new Set(assets.map(url => url.searchParams.get('v')));
      assert.equal(revisions.size, 1); assert.ok(!revisions.has(null), 'One revision covers the whole classic asset graph');
      assert.equal(assets.filter(url => url.pathname.endsWith('.wasm')).length, 1);
      assert.equal(assets.find(url => url.pathname.endsWith('.wasm')).pathname, '/dist/zrax_bg.wasm');
    }
  });

  test(`classic firmware cards retain current D10 component labels at ${path}`, async t => {
    // Minimal valid D10 with two independent raw x86-64 components.
    const code = Buffer.from([0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20, 0x48, 0x89, 0x7d, 0xf8, 0x48, 0x89, 0x75, 0xf0, 0x48, 0x8b, 0x45, 0xf8, 0x48, 0x03, 0x45, 0xf0, 0x66, 0x0f, 0x38, 0xdc, 0xc1, 0x48, 0x89, 0xec, 0x5d, 0xc3]);
    const bytes = Buffer.concat(Array.from({ length: 128 }, () => code));
    const chunks = [Buffer.from('2504B     000243')];
    for (let section = 0; section < 6; section++) {
      for (let block = 0; block < 2; block++) {
        const data = block === 0 && (section === 1 || section === 5) ? bytes
          : section === 5 && block === 1 ? Buffer.alloc(128, 0xff) : Buffer.alloc(0);
        const header = Buffer.alloc(10); header[0] = section; header[1] = block;
        header.writeUInt32BE(0x100000 + section * 0x40000 + block * 0x3ffea, 2);
        header.writeUInt32BE(data.length, 6); chunks.push(header, data);
      }
    }
    const body = Buffer.concat(chunks), trailer = Buffer.alloc(2);
    let crc = 0xffff;
    for (const byte of body) { crc ^= byte; for (let bit = 0; bit < 8; bit++) crc = crc >>> 1 ^ (crc & 1 ? 0x8408 : 0); }
    trailer.writeUInt16LE(crc ^ 0xffff);
    const page = await openPage(t); await load(page, path);
    await page.locator('#fileinput').setInputFiles({ name: 'components.D10', mimeType: 'application/octet-stream', buffer: Buffer.concat([body, trailer]) });
    await finished(page, 1);
    const payload = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(payload.format.format, 'd10'); assert.equal(payload.primary.isa, 'x86_64');
    assert.deepEqual(payload.slices.map(s => s.label), ['CPU 5:0', 'DSP 1:0']);
    assert.equal(await page.locator('.hero-isa').textContent(), 'x86-64');
    assert.match(await page.locator('.hero-isa-sub').textContent(), /Multi-component container.*2 slices/);
    assert.deepEqual(await page.locator('.slice-isa').allTextContents(), ['CPU 5:0 · x86-64', 'DSP 1:0 · x86-64']);
    assert.match(await page.locator('.file-meta').textContent(), /AOR D10/);
    assert.match(await page.locator('#results').textContent(), /Heuristic Candidates/);
    assert.match(await page.locator('.cand-score').first().textContent(), /bits/);
  });
}

test('workbench and classic navigation remains within the deployment prefix', async t => {
  for (const prefix of ['/web', '/dist']) {
    const page = await openPage(t); await page.goto(baseUrl + prefix + '/index.html');
    const link = page.getByRole('link', { name: 'Classic classifier' });
    assert.equal(await link.textContent(), 'CLASSIC');
    for (const width of [320, 390, 1440, 1800]) {
      await page.setViewportSize({ width, height: 844 });
      const position = await link.evaluate(el => {
        const rect = el.getBoundingClientRect(), bar = el.parentElement.getBoundingClientRect();
        return { width: rect.width, right: rect.right, bottom: rect.bottom, barRight: bar.right, barBottom: bar.bottom, last: el === el.parentElement.lastElementChild, viewport: innerWidth };
      });
      assert.ok(position.width > 0); assert.equal(position.last, true);
      assert.ok(Math.abs(position.right - position.barRight) < 1);
      assert.ok(position.right <= position.viewport);
      assert.ok(Math.abs(position.bottom - position.barBottom) < 1);
    }
    await page.getByRole('link', { name: 'Classic classifier' }).click();
    await page.waitForFunction(() => document.getElementById('version').textContent.startsWith('v'));
    assert.equal(new URL(page.url()).pathname, prefix + '/classic/');
    await page.getByRole('link', { name: 'Workbench', exact: true }).click();
    await page.waitForFunction(() => document.getElementById('status-engine').textContent.includes('Apeiron/WASM'));
    assert.equal(new URL(page.url()).pathname, prefix + '/index.html');
  }
});

test('real D10 fixture retains RX and Blackfin components in packaged classic', { skip: !process.env.D10_FIXTURE }, async t => {
  const page = await openPage(t); await load(page, '/dist/classic/');
  await page.locator('#fileinput').setInputFiles(process.env.D10_FIXTURE); await finished(page, 1);
  const payload = JSON.parse(await page.locator('#jsonRaw').textContent());
  assert.equal(payload.primary.isa, 'rx'); assert.equal(payload.format.format, 'd10');
  assert.deepEqual(payload.slices.map(s => [s.label, s.isa]), [['CPU 5:0', 'rx'], ['DSP 1:0', 'blackfin'], ['DSP 2:0', 'blackfin']]);
  assert.equal(await page.locator('.hero-isa').textContent(), 'RX + Blackfin');
  assert.deepEqual(await page.locator('.slice-isa').allTextContents(), ['CPU 5:0 · RX', 'DSP 1:0 · Blackfin', 'DSP 2:0 · Blackfin']);
});

test('classic source and package expose the same current classifier payload', async t => {
  const file = { name: 'raw.bin', mimeType: 'application/octet-stream', buffer: await readFile(root + 'testbins/x86_64_x86_64-unknown-linux-musl_O0_cf_switch_dense.bin') };
  const results = [];
  for (const path of ['/web/classic/', '/dist/classic/']) {
    const page = await openPage(t); await load(page, path);
    await page.locator('#fileinput').setInputFiles(file); await finished(page, 1);
    results.push(JSON.parse(await page.locator('#jsonRaw').textContent()));
    assert.equal(results.at(-1).primary.isa, 'x86_64');
    assert.equal(await page.locator('.file-meta').textContent().then(text => text.includes('Raw Binary')), true);
  }
  assert.deepEqual(results[1], results[0]);
});
