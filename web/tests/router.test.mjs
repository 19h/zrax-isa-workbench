import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup); after(teardown);

const fixture = name => readFile(new URL(`../../tests/fixtures/router/${name}`, import.meta.url));

// Each committed wrapper holds the synthetic big-endian MIPS kernel as a raw
// LZMA-alone stream (directly, or inside a nested wrapper).
const IMAGES = [
  ['image.trx', 'trx', 'Partition 2 (kernel)'],
  ['image-v2.trx', 'trx', 'Partition 2 (kernel)'],
  ['image.chk', 'netgearchk', 'Kernel'],
  ['image.seama', 'seama', 'Entity 1'],
  ['tplink-v1.bin', 'tplink', 'Kernel'],
  ['tplink-v2.bin', 'tplink', 'Kernel'],
  ['safeloader.bin', 'tplink', 'Partition os-image'],
];

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`router wrappers classify their kernels through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const fixtures = await Promise.all(IMAGES.map(async ([name]) => ({ name, bytes: [...await fixture(name)] })));
    const payloads = await page.evaluate(async ({ module, fixtures }) => {
      const wasm = await import(module);
      await wasm.default();
      return Object.fromEntries(fixtures.map(f => [f.name, JSON.parse(wasm.classify(new Uint8Array(f.bytes)))]));
    }, { module, fixtures });
    for (const [name, format, kernelLabel] of IMAGES) {
      const p = payloads[name];
      assert.ok(!p.error, `${name}: ${p.error}`);
      assert.equal(p.format.format, format, name);
      assert.ok(Object.hasOwn(FORMAT_NAMES, format), `${format} has a display name`);
      assert.deepEqual([p.primary.isa, p.primary.endianness], ['mips', 'big'], name);
      const kernel = p.slices.find(s => s.label === kernelLabel);
      assert.ok(kernel, `${name}: ${kernelLabel} slice`);
      assert.equal(kernel.isa, 'mips', name);
    }
    const trxKernel = payloads['image.trx'].slices.find(s => s.label === 'Partition 2 (kernel)');
    assert.equal(trxKernel.offset, 0x68);
    assert.deepEqual([trxKernel.decoded.transform, trxKernel.decoded.size], ['LZMA', 256]);
    const tplinkKernel = payloads['tplink-v1.bin'].slices.find(s => s.label === 'Kernel');
    assert.deepEqual([tplinkKernel.offset, tplinkKernel.size], [0x200, 79]);
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names router formats and keeps stored offsets in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const buffer = await fixture('image.trx');
    await page.locator('#fileinput').setInputFiles([{ name: 'openwrt.trx', buffer, mimeType: 'application/octet-stream' }]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes('Broadcom TRX'), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.primary.isa, 'mips');
    assert.ok(p.metadata.some(m => m.key?.custom === 'trx_image_size' && m.value === buffer.length));
  });
}
