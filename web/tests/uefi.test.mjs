import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup);
after(teardown);

const fixture = name => readFile(new URL(`../../tests/fixtures/uefi/${name}`, import.meta.url));

const IMAGE_FILE_MACHINE_ARM64 = 0xaa64;

// A TE image as EDK2 GenFw writes it: `VZ`, machine, one section, subsystem 11
// (boot service driver), stripped size 0x148 (the PE headers up to the end of
// the optional header), entry point and base of code RVA 0x180, then the kept
// `.text` section header (virtual size, RVA, raw size and raw pointer, code
// characteristics) and 16 B of code at TE offset 0x180 - 0x148 + 40 = 0x60.
function teImage(machine) {
  const image = Buffer.alloc(0x70);
  image.write('VZ', 0, 'latin1');
  image.writeUInt16LE(machine, 2);
  image[4] = 1;
  image[5] = 11;
  image.writeUInt16LE(0x148, 6);
  image.writeUInt32LE(0x180, 8);
  image.writeUInt32LE(0x180, 12);
  image.write('.text', 0x28, 'latin1');
  image.writeUInt32LE(16, 0x30);
  image.writeUInt32LE(0x180, 0x34);
  image.writeUInt32LE(16, 0x38);
  image.writeUInt32LE(0x180, 0x3c);
  image.writeUInt32LE(0x6000_0020, 0x4c);
  image.fill(0xc0, 0x60);
  return image;
}

const sliceIsas = payload => Object.fromEntries(payload.slices.map(s => [s.label, s.isa]));

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`UEFI volumes, TE images and flash descriptors classify through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const fixtures = [
      { name: 'sample.fd', bytes: [...await fixture('sample.fd')] },
      { name: 'flash.bin', bytes: [...await fixture('flash.bin')] },
      { name: 'arm64.te', bytes: [...teImage(IMAGE_FILE_MACHINE_ARM64)] },
    ];
    const payloads = await page.evaluate(async ({ module, fixtures }) => {
      const wasm = await import(module);
      await wasm.default();
      return fixtures.map(f => JSON.parse(wasm.classify(new Uint8Array(f.bytes))));
    }, { module, fixtures });
    const [volume, flash, te] = payloads;
    for (const p of payloads) {
      assert.ok(!p.error, p.error);
      assert.ok(Object.hasOwn(FORMAT_NAMES, p.format.format), `${p.format.format} has a display name`);
    }

    assert.equal(volume.format.format, 'uefifv');
    assert.equal(volume.primary.isa, 'x86_64');
    const isas = sliceIsas(volume);
    assert.equal(isas['X64Driver (5A1E7E57-0000-4000-8000-000000000001): PE32 image'], 'x86_64');
    assert.equal(isas['Aa64Driver (5A1E7E57-0000-4000-8000-000000000002): PE32 image'], 'a_arch64');
    assert.equal(isas['TePeim (5A1E7E57-0000-4000-8000-000000000003): TE image'], 'x86_64');
    const lzma = volume.slices.find(s => s.label.startsWith('LzmaDxe'));
    assert.equal(lzma.isa, 'x86_64');
    assert.equal(lzma.decoded.transform, 'LZMA');

    assert.equal(flash.format.format, 'intelifd');
    assert.equal(flash.primary.isa, 'x86_64');
    const bios = flash.slices.find(s => s.label === 'BIOS region firmware volume at 0x4000');
    assert.deepEqual([bios.offset, bios.size, bios.isa], [0x4000, 0x1000, 'x86_64']);
    // The ME region runs on a separate engine whose layout is not parsed.
    const me = flash.slices.find(s => s.label === 'ME region');
    assert.deepEqual(me.isa, { unknown: 0 });

    assert.equal(te.format.format, 'uefite');
    assert.equal(te.primary.isa, 'a_arch64');
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names UEFI firmware volumes in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const buffer = await fixture('sample.fd');
    await page.locator('#fileinput').setInputFiles([{ name: 'sample.fd', buffer, mimeType: 'application/octet-stream' }]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes(FORMAT_NAMES.uefifv), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.format.format, 'uefifv');
    assert.ok(p.metadata.some(m => m.key?.custom === 'uefi_volume_0'));
  });
}
