import assert from 'node:assert/strict';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl, elf } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';

before(setup);
after(teardown);

// UARP: format version 3, fixed 44-byte header and one 40-byte payload
// record. All numeric fields are big-endian. The raw "CODE" tag and empty
// metadata precede an x86-64 ELF at byte offset 84.
function uarp() {
  const payload = elf('code').buffer;
  const data = Buffer.alloc(84 + payload.length);
  data.writeUInt32BE(3, 0);
  data.writeUInt32BE(44, 4);
  data.writeUInt32BE(data.length, 8);
  data.writeUInt32BE(44, 36);
  data.writeUInt32BE(40, 40);
  data.writeUInt32BE(40, 44);
  data.write('CODE', 48, 'ascii');
  data.writeUInt32BE(84, 76);
  data.writeUInt32BE(payload.length, 80);
  payload.copy(data, 84);
  return data;
}

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`UARP parses and classifies its child through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const results = await page.evaluate(async ({ module, inputs }) => {
      const wasm = await import(module);
      await wasm.default();
      return inputs.map(bytes => JSON.parse(wasm.classify(new Uint8Array(bytes))));
    }, { module, inputs: [[...uarp()]] });
    for (const payload of results) {
      assert.ok(!payload.error, payload.error);
      assert.equal(payload.format.format, 'uarp');
      assert.equal(payload.primary.isa, 'x86_64');
      const child = payload.slices.find(child => child.label === 'CODE');
      assert.ok(child);
      assert.equal(child.offset, 84);
      assert.equal(child.size, 64);
    }
    assert.equal(FORMAT_NAMES.uarp, 'UARP super binary');
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`UARP display and child coordinates in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    await page.locator('#fileinput').setInputFiles([
      { name: 'firmware.uarp', buffer: uarp(), mimeType: 'application/octet-stream' },
    ]);
    await finished(page, 1);
    await selectEntry(page, 0);
    assert.match(await page.locator('#classification-content').textContent(), /UARP super binary/);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const payload = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(payload.format.format, 'uarp');
    assert.equal(payload.slices.find(child => child.label === 'CODE').offset, 84);
  });
}
