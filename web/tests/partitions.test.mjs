import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { gunzipSync } from 'node:zlib';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup);
after(teardown);

const fixture = name => readFile(new URL(`../../tests/fixtures/${name}`, import.meta.url));

// hdiutil images (tests/fixtures/partitions/README.md): 1 MiB disks with one empty partition each.
const hdiutil = async name => gunzipSync(await fixture(`partitions/hdiutil-${name}.img.gz`));

const SECTOR = 512;

// An MBR disk (UEFI 2.10 Table 5.1): no bootstrap code, the disk signature at 440, one Linux record (type 0x83)
// for sectors 8-519 at 446 (boot indicator, CHS placeholders, type, start and size, little-endian), 55 AA at
// 510, and the ext2 fixture in the partition.
async function mbrWithExt2() {
  const ext2 = await fixture('ext/ext2.img');
  const sectors = ext2.length / SECTOR;
  const disk = Buffer.alloc((8 + sectors) * SECTOR);
  disk.writeUInt32LE(0x12345678, 440);
  disk.set([0x00, 0xfe, 0xff, 0xff, 0x83, 0xfe, 0xff, 0xff], 446);
  disk.writeUInt32LE(8, 454);
  disk.writeUInt32LE(sectors, 458);
  disk.set([0x55, 0xaa], 510);
  disk.set(ext2, 8 * SECTOR);
  return disk;
}

const slice = (payload, label) => payload.slices?.find(s => s.label === label);

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`partition tables list their partitions through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const images = [
      { name: 'gpt', format: 'gpt', variant: 'GPT', bytes: [...await hdiutil('gpt')] },
      { name: 'apm', format: 'applepartitionmap', variant: 'Apple Partition Map', bytes: [...await hdiutil('apm')] },
      { name: 'mbr', format: 'mbr', variant: 'MBR', bytes: [...await hdiutil('mbr')] },
      { name: 'mbr+ext2', format: 'mbr', variant: 'MBR', bytes: [...await mbrWithExt2()] },
    ];
    const payloads = await page.evaluate(async ({ module, images }) => {
      const wasm = await import(module);
      await wasm.default();
      return images.map(image => JSON.parse(wasm.classify(new Uint8Array(image.bytes))));
    }, { module, images });
    images.forEach(({ name, format, variant }, i) => {
      const p = payloads[i];
      assert.ok(!p.error, `${name}: ${p.error}`);
      assert.equal(p.format.format, format, name);
      assert.equal(p.format.variant_name, variant, name);
      assert.ok(Object.hasOwn(FORMAT_NAMES, format), `${format} has a display name`);
    });
    const [gpt, apm, mbr, ext] = payloads;
    for (const p of [gpt, apm, mbr]) {
      assert.deepEqual(p.primary.isa, { unknown: 0 }, 'empty partitions carry no ISA');
      assert.equal(p.slices, undefined, 'an empty partition is not a recognized format');
    }
    assert.ok(gpt.notes.some(n => n.message.startsWith('Backup GPT header at LBA 2047 and its entry array verified')));
    assert.ok(gpt.metadata.some(m => m.key?.custom === 'partitions_gpt_usable_lbas' && m.value === '34-2014'));
    assert.ok(apm.metadata.some(m => m.key?.custom === 'partitions_apm_block_size' && m.value === 512));
    assert.ok(mbr.metadata.some(m => m.label === 'Partition 1 (HFS / HFS+, type 0xAF)'));
    const root = slice(ext, 'Partition 1 (Linux, type 0x83)');
    assert.ok(root, JSON.stringify(ext.slices));
    assert.equal(root.isa, 'x86_64');
    assert.equal(root.offset, 8 * SECTOR);
    assert.equal(ext.primary.isa, 'x86_64');
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names partition tables and keeps partition offsets in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const buffer = await mbrWithExt2();
    await page.locator('#fileinput').setInputFiles([{ name: 'sdcard.img', buffer, mimeType: 'application/octet-stream' }]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes(FORMAT_NAMES.mbr), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.primary.isa, 'x86_64');
    const root = slice(p, 'Partition 1 (Linux, type 0x83)');
    const superblock = buffer.subarray(root.offset + 1024, root.offset + 1024 + 64);
    assert.equal(superblock.readUInt16LE(0x38), 0xef53, 'the stored offset holds the ext superblock');
  });
}
