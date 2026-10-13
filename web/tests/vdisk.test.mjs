import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { gunzipSync } from 'node:zlib';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup);
after(teardown);

// qemu-img images of one 170 KiB MBR disk whose FAT12 partition holds a synthetic x86-64 ELF
// (tests/fixtures/vdisk/README.md).
const fixture = async name => gunzipSync(await readFile(new URL(`../../tests/fixtures/vdisk/${name}.gz`, import.meta.url)));

const DISK_SIZE = 340 * 512;

const IMAGES = [
  { name: 'qcow2-v3.qcow2', format: 'qcow2', variant: 'QCOW2 image', transform: 'QCOW2 clusters' },
  { name: 'qcow2-zstd.qcow2', format: 'qcow2', variant: 'QCOW2 image', transform: 'QCOW2 clusters' },
  { name: 'vmdk-stream.vmdk', format: 'vmdk', variant: 'VMDK sparse extent', transform: 'VMDK grains' },
  { name: 'vhd-fixed.vhd', format: 'vhd', variant: 'VHD image', offset: 0 },
  { name: 'vhd-dynamic.vhd', format: 'vhd', variant: 'VHD image', offset: 0xa00 },
  { name: 'vhdx-dynamic.vhdx', format: 'vhdx', variant: 'VHDX image', offset: 0x800000 },
  { name: 'vdi-static.vdi', format: 'vdi', variant: 'VDI image', offset: 0x400 },
];

const guestSlice = payload => payload.slices?.find(s => s.label === 'Guest disk');

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`virtual disks classify their guest disk through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const images = await Promise.all(IMAGES.map(async image => ({ ...image, base64: (await fixture(image.name)).toString('base64') })));
    const payloads = await page.evaluate(async ({ module, images }) => {
      const wasm = await import(module);
      await wasm.default();
      return images.map(image => {
        const bytes = Uint8Array.from(atob(image.base64), c => c.charCodeAt(0));
        return JSON.parse(wasm.classify(bytes));
      });
    }, { module, images });
    images.forEach(({ name, format, variant, transform, offset }, i) => {
      const p = payloads[i];
      assert.ok(!p.error, `${name}: ${p.error}`);
      assert.equal(p.format.format, format, name);
      assert.equal(p.format.variant_name, variant, name);
      assert.ok(Object.hasOwn(FORMAT_NAMES, format), `${format} has a display name`);
      assert.equal(p.primary.isa, 'x86_64', `${name}: from the ELF in the guest's FAT partition`);
      const slice = guestSlice(p);
      assert.ok(slice, `${name}: ${JSON.stringify(p.slices)}`);
      assert.equal(slice.isa, 'x86_64', name);
      if (transform) {
        assert.equal(slice.offset, 0, name);
        assert.equal(slice.decoded?.transform, transform, name);
        assert.equal(slice.decoded?.size, DISK_SIZE, name);
      } else {
        assert.equal(slice.offset, offset, name);
        assert.equal(slice.size, DISK_SIZE, name);
        assert.equal(slice.decoded, undefined, name);
      }
      assert.ok(p.notes.some(n => n.message === 'Virtual disk formats name no ISA; the guest disk is classified on its own'), name);
    });
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names virtual disks and keeps the guest disk offset in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const buffer = await fixture('vhd-fixed.vhd');
    await page.locator('#fileinput').setInputFiles([{ name: 'disk.vhd', buffer, mimeType: 'application/octet-stream' }]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes(FORMAT_NAMES.vhd), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.primary.isa, 'x86_64');
    const slice = guestSlice(p);
    assert.equal(slice.offset, 0);
    assert.deepEqual([...buffer.subarray(slice.offset + 510, slice.offset + 512)], [0x55, 0xaa], 'the stored offset holds the guest MBR');
    assert.ok(p.metadata.some(m => m.key?.custom === 'vdisk_virtual_size' && m.value === DISK_SIZE));
  });
}
