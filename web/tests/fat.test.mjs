import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { gunzipSync } from 'node:zlib';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup);
after(teardown);

const fixture = name => readFile(new URL(`../../tests/fixtures/fat/${name}`, import.meta.url));

// mkfs.fat and mtools volumes of the same tree (tests/fixtures/fat/README.md): the recognized members in walk
// order, then the boot code. mtools stores 8.3-compatible names as upper-case short names.
const FAT_CHILDREN = [
  '/PAYLOAD.ELF', '/Long File Name Payload.elf', '/BOOT/payload.elf.gz', '/FRAG/SPLIT.ELF', 'Volume boot code',
];
const EXFAT_MEMBERS = ['/payload.elf', '/Long File Name Payload.elf', '/boot/payload.elf.gz', '/frag/split.elf'];
// frag/split.elf: the 256 B ELF header and 60 lines of text (FAT), cut to 6000 B on exFAT.
const SPLIT_SIZE = 1396;
const EXFAT_SPLIT_SIZE = 6000;

const slice = (payload, label) => payload.slices.find(s => s.label === label);
const custom = (payload, key) => payload.metadata.find(m => m.key?.custom === key)?.value;

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`FAT and exFAT volumes list their boot code and members through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    // FAT16 and FAT32 travel gzip-compressed; the classifier decodes them.
    const inputs = [
      { name: 'fat12.img', bytes: [...await fixture('fat12.img')] },
      { name: 'fat16.img.gz', bytes: [...await fixture('fat16.img.gz')] },
      { name: 'fat32.img.gz', bytes: [...await fixture('fat32.img.gz')] },
      { name: 'exfat.img', bytes: [...gunzipSync(await fixture('exfat.img.gz'))] },
    ];
    const payloads = await page.evaluate(async ({ module, inputs }) => {
      const wasm = await import(module);
      await wasm.default();
      return inputs.map(input => JSON.parse(wasm.classify(new Uint8Array(input.bytes))));
    }, { module, inputs });
    const [fat12, fat16, fat32, exfat] = payloads;
    payloads.forEach((p, i) => assert.ok(!p.error, `${inputs[i].name}: ${p.error}`));

    assert.equal(fat12.format.format, 'fat');
    assert.equal(fat12.format.variant_name, 'FAT12');
    assert.deepEqual(fat12.slices.map(s => s.label), FAT_CHILDREN);
    assert.equal(fat12.primary.isa, 'x86_64');
    assert.equal(slice(fat12, 'Volume boot code').isa, 'x86');
    assert.equal(slice(fat12, 'Volume boot code').bitwidth, 16);
    assert.ok(fat12.slices.slice(0, -1).every(s => s.isa === 'x86_64'), 'members are classified on their own');
    const split = slice(fat12, '/FRAG/SPLIT.ELF');
    assert.equal(split.decoded.transform, 'FAT cluster chain');
    assert.equal(split.decoded.size, SPLIT_SIZE);
    assert.equal(custom(fat12, 'fat_member_count'), 4);
    assert.equal(custom(fat12, 'fat_deleted_entry_count'), 1);

    for (const [p, type] of [[fat16, 'FAT16'], [fat32, 'FAT32']]) {
      assert.equal(p.format.format, 'gzip', type);
      assert.deepEqual(p.slices.map(s => s.label), FAT_CHILDREN, type);
      assert.ok(p.notes.some(n => n.message === 'Decoded payload: FAT filesystem'), type);
      assert.ok(p.notes.some(n => n.message.startsWith(`${type} volume:`)), type);
    }

    assert.equal(exfat.format.format, 'exfat');
    assert.equal(exfat.format.variant_name, 'exFAT');
    assert.deepEqual(exfat.slices.map(s => s.label), EXFAT_MEMBERS);
    assert.equal(exfat.primary.isa, 'x86_64');
    const exfatSplit = slice(exfat, '/frag/split.elf');
    assert.equal(exfatSplit.decoded.transform, 'exFAT cluster chain');
    assert.equal(exfatSplit.decoded.size, EXFAT_SPLIT_SIZE);
    assert.ok(exfat.notes.some(n => n.message === 'Main boot region checksum verified (sectors 0-10)'));

    assert.ok(Object.hasOwn(FORMAT_NAMES, 'fat'), 'fat has a display name');
    assert.ok(Object.hasOwn(FORMAT_NAMES, 'exfat'), 'exfat has a display name');
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names FAT volumes and keeps stored member offsets in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const buffer = await fixture('fat12.img');
    const file = { name: 'floppy.img', buffer, mimeType: 'application/octet-stream' };
    await page.locator('#fileinput').setInputFiles([file]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes(FORMAT_NAMES.fat), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.format.format, 'fat');
    const member = slice(p, '/PAYLOAD.ELF');
    const elf = buffer.subarray(member.offset, member.offset + member.size);
    assert.deepEqual([...elf.subarray(0, 4)], [0x7f, 0x45, 0x4c, 0x46], 'the stored offset holds the ELF');
    const boot = slice(p, 'Volume boot code');
    assert.equal(boot.offset, 0x3e);
    assert.equal(boot.size, 0x1fe - 0x3e);
  });
}
