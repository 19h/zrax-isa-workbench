import assert from 'node:assert/strict';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl, elf } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';

before(setup);
after(teardown);

// FTAB: generation=1, valid=all-ones, zero nonce/reserved fields; magic at
// 0x20 and one file at 0x28. The record at 0x30 holds tag "code", absolute
// payload offset 0x40, byte length, and reserved=0. Payload is an x86-64 ELF.
function ftab(magic = 'rkosftab') {
  const payload = elf('code').buffer;
  const data = Buffer.alloc(0x40 + payload.length);
  data.writeUInt32LE(1, 0);
  data.writeUInt32LE(0xffffffff, 4);
  data.write(magic, 0x20, 'ascii');
  data.writeUInt32LE(1, 0x28);
  data.write('code', 0x30, 'ascii');
  data.writeUInt32LE(0x40, 0x34);
  data.writeUInt32LE(payload.length, 0x38);
  payload.copy(data, 0x40);
  return data;
}

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`FTAB parses and classifies its child through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const results = await page.evaluate(async ({ module, inputs }) => {
      const wasm = await import(module);
      await wasm.default();
      return inputs.map(bytes => JSON.parse(wasm.classify(new Uint8Array(bytes))));
    }, { module, inputs: [[...ftab()], [...ftab('RKOSFTAB')], [...ftab().subarray(0, 0x28)]] });
    for (const payload of results.slice(0, 2)) {
      assert.ok(!payload.error, payload.error);
      assert.equal(payload.format.format, 'ftab');
      assert.equal(payload.primary.isa, 'x86_64');
      const child = payload.slices.find(child => child.label === 'code');
      assert.ok(child);
      assert.equal(child.offset, 0x40);
      assert.equal(child.size, 64);
    }
    assert.match(results[2].error, /FTAB parse error: Truncated FTAB header/);
    assert.equal(FORMAT_NAMES.ftab, 'Apple FTAB');
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`FTAB display and child coordinates in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    await page.locator('#fileinput').setInputFiles([
      { name: 'firmware.ftab', buffer: ftab(), mimeType: 'application/octet-stream' },
    ]);
    await finished(page, 1);
    await selectEntry(page, 0);
    assert.match(await page.locator('#classification-content').textContent(), /Apple FTAB/);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const payload = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(payload.format.format, 'ftab');
    assert.equal(payload.slices.find(child => child.label === 'code').offset, 0x40);
  });
}
