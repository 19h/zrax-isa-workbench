import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, baseUrl, elf } from './helpers.mjs';

before(setup);
after(teardown);

const fixture = name => readFile(new URL(`../../tests/fixtures/apple/${name}`, import.meta.url));

// FTAB fixed header and one record: tag krnl, offset 0x40, byte length.
function ftab(payload) {
  const data = Buffer.alloc(0x40 + payload.length);
  data.writeUInt32LE(1, 0);
  data.writeUInt32LE(0xffffffff, 4);
  data.write('rkosftab', 0x20, 'ascii');
  data.writeUInt32LE(1, 0x28);
  data.write('krnl', 0x30, 'ascii');
  data.writeUInt32LE(0x40, 0x34);
  data.writeUInt32LE(payload.length, 0x38);
  payload.copy(data, 0x40);
  return data;
}

// FTAB fixed header followed by two records with the same four-byte tag.
// Their distinct stored ranges contain x86-64 and AArch64 ELF headers.
function duplicateTagFtab() {
  const payloads = [elf('x86', 62).buffer, elf('arm', 183).buffer];
  const headerSize = 0x50;
  const data = Buffer.alloc(headerSize + payloads.reduce((size, payload) => size + payload.length, 0));
  data.writeUInt32LE(1, 0);
  data.writeUInt32LE(0xffffffff, 4);
  data.write('rkosftab', 0x20, 'ascii');
  data.writeUInt32LE(payloads.length, 0x28);
  let offset = headerSize;
  payloads.forEach((payload, index) => {
    const record = 0x30 + index * 16;
    data.write('code', record, 'ascii');
    data.writeUInt32LE(offset, record + 4);
    data.writeUInt32LE(payload.length, record + 8);
    payload.copy(data, offset);
    offset += payload.length;
  });
  return data;
}

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`member extraction returns decoded bytes through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const data = [...await fixture('krnl.bvx2.im4p')];
    const result = await page.evaluate(async ({ module, data }) => {
      const wasm = await import(module);
      await wasm.default();
      const engine = new wasm.WorkbenchEngine(new Uint8Array(data));
      try {
        const files = JSON.parse(engine.subfiles());
        const kernel = files.find(file => file.label === 'krnl');
        return { kernel, bytes: [...engine.subfile(kernel.index)] };
      } finally { engine.free(); }
    }, { module, data });
    assert.equal(result.kernel.transform, 'LZFSE');
    assert.notEqual(result.kernel.stored_size, result.kernel.size);
    assert.deepEqual(result.bytes, [...await fixture('kernel.macho')]);
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`subfile tables show per-member evidence without mixing duplicate labels in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    await page.locator('#fileinput').setInputFiles([
      { name: 'mixed.ftab', buffer: duplicateTagFtab(), mimeType: 'application/octet-stream' },
    ]);
    await finished(page, 1);
    assert.equal(await page.locator('.hero-isa').textContent(), 'multiple ISAs');
    const table = page.getByRole('table', { name: 'subfiles', exact: true });
    const rows = table.locator('tbody tr');
    assert.equal(await rows.count(), 2);
    assert.deepEqual(await rows.nth(0).locator('td').allTextContents(),
      ['open code', 'x86-64', '64', 'little', '—', '—', '64 B', '64 B', '0x00000050', '—', 'available']);
    assert.deepEqual((await rows.nth(1).locator('td').allTextContents()).slice(0, 4),
      ['open code', 'AArch64', '64', 'little']);
    await rows.nth(0).getByRole('button', { name: 'open code', exact: true }).click();
    await finished(page, 2);
    await page.getByRole('navigation', { name: 'Container path' })
      .getByRole('button', { name: 'mixed.ftab', exact: true }).click();
    const cells = await rows.nth(0).locator('td').allTextContents();
    assert.equal(cells[4], 'ELF');
    assert.match(cells[5], /^\d+\.\d%$/);
    await page.setViewportSize({ width: 500, height: 800 });
    const bounds = await table.evaluate(element => ({
      scroll: element.parentElement.scrollWidth,
      width: element.parentElement.clientWidth,
      page: document.documentElement.scrollWidth,
      viewport: innerWidth,
    }));
    assert.ok(bounds.scroll > bounds.width, 'the table scrolls inside its panel');
    assert.ok(bounds.page <= bounds.viewport, 'the table does not widen the page');
  });

  test(`archive data and opaque members open in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const stored = await readFile(new URL('../../tests/fixtures/archives/stored.zip', import.meta.url));
    const encrypted = await readFile(new URL('../../tests/fixtures/archives/encrypted.zip', import.meta.url));
    await page.locator('#fileinput').setInputFiles([
      { name: 'stored.zip', buffer: stored, mimeType: 'application/zip' },
    ]);
    await finished(page, 1);
    await page.getByRole('button', { name: 'open notes.txt', exact: true }).click();
    await finished(page, 2);
    assert.equal(await page.locator('#file-name').textContent(), 'notes.txt');
    await page.getByRole('tab', { name: 'hex', exact: true }).click();
    await page.waitForFunction(() => document.querySelector('#hex-rows').textContent.includes('Synthetic'));
    await page.locator('#fileinput').setInputFiles([
      { name: 'encrypted.zip', buffer: encrypted, mimeType: 'application/zip' },
    ]);
    await finished(page, 3);
    await page.getByRole('tab', { name: 'classification', exact: true }).click();
    const opaque = page.getByRole('table', { name: 'subfiles', exact: true }).locator('tbody tr').first();
    assert.match(await opaque.textContent(), /not analyzed/);
    assert.equal(await opaque.locator('td').nth(2).textContent(), '—');
    await page.getByRole('button', { name: 'open bin/payload.elf', exact: true }).click();
    await finished(page, 4);
    assert.match(await page.locator('#classification-content').textContent(), /Opaque component; ISA analysis was not applied/);
    await page.getByRole('tab', { name: 'hex', exact: true }).click();
    await page.waitForFunction(() => document.querySelectorAll('#hex-rows .hex-byte').length > 0);
    await page.getByRole('navigation', { name: 'Container path' }).getByRole('button', { name: 'encrypted.zip' }).click();
    await page.getByRole('button', { name: 'Remove file', exact: true }).click();
    assert.equal(await page.locator('.file-entry').count(), 2, 'removing one tree retains the other');
  });

  test(`nested members retain their containers and full workbench in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const buffer = ftab(await fixture('krnl.bvx2.im4p'));
    await page.locator('#fileinput').setInputFiles([
      { name: 'umbrella.ftab', buffer, mimeType: 'application/octet-stream' },
    ]);
    await finished(page, 1);
    await page.getByRole('button', { name: 'open krnl', exact: true }).click();
    await finished(page, 2);
    assert.equal(await page.locator('#file-name').textContent(), 'krnl');
    assert.match(await page.locator('#classification-content').textContent(), /Apple IM4P/);
    await page.getByRole('button', { name: 'open krnl', exact: true }).click();
    await finished(page, 3);
    assert.match(await page.locator('#classification-content').textContent(), /Mach-O/);
    assert.equal(await page.locator('#subfile-breadcrumb button').count(), 2);
    assert.equal(await page.locator('.file-entry[data-parent-id]').count(), 2);
    await page.getByRole('tab', { name: 'hex', exact: true }).click();
    await page.waitForFunction(() => [...document.querySelectorAll('#hex-rows .hex-byte')].slice(0, 4).map(cell => cell.textContent).join(' ') === 'CF FA ED FE');
    await page.getByRole('tab', { name: 'entropy', exact: true }).click();
    await page.waitForFunction(() => document.querySelector('#entropy-map').dataset.state === 'ready');
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const payload = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(payload.format.format, 'macho');
    await page.getByRole('navigation', { name: 'Container path' }).getByRole('button', { name: 'umbrella.ftab' }).click();
    assert.equal(await page.locator('#file-name').textContent(), 'umbrella.ftab');
    await page.getByRole('tab', { name: 'classification', exact: true }).click();
    await page.getByRole('button', { name: 'open krnl', exact: true }).click();
    assert.equal(await page.locator('.file-entry').count(), 3, 'opening an existing member selects it');
    await page.getByRole('navigation', { name: 'Container path' }).getByRole('button', { name: 'umbrella.ftab' }).click();
    await page.getByRole('button', { name: 'Remove file', exact: true }).click();
    assert.equal(await page.locator('.file-entry').count(), 0, 'removal includes descendants');
  });
}
