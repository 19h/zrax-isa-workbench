import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { gunzipSync } from 'node:zlib';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';

before(setup);
after(teardown);

// hdiutil images of 1 MiB disks whose volume holds a synthetic x86-64 ELF header
// (tests/fixtures/dmg/README.md).
const fixtureUrl = name => new URL(`../../tests/fixtures/dmg/${name}.gz`, import.meta.url);
const fixture = async name => gunzipSync(await readFile(fixtureUrl(name)));

const FAT_VOLUME = '(DOS_FAT_32 : 1)';
const FAT_VOLUME_SIZE = 2047 * 512;
const CRC_NOTE = 'Block table CRC-32 verified for every partition';
const ISA_NOTE = 'Disk images name no ISA; each partition is classified on its own';

const IMAGES = [
  { name: 'fat-udzo.dmg', variant: 'UDIF disk image', partitions: 2 },
  { name: 'hfs-udzo.dmg', variant: 'UDIF disk image', partitions: 8 },
  { name: 'hfs-udco.dmg', variant: 'UDIF disk image', partitions: 8 },
  { name: 'hfs-ulfo.dmg', variant: 'UDIF disk image', partitions: 8 },
  { name: 'encrypted.dmg', variant: 'Encrypted disk image (encrcdsa)' },
];

const hasNote = (payload, text) => payload.notes.some(n => n.message.includes(text));

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`Apple disk images classify their partitions through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const images = await Promise.all(IMAGES.map(async image => ({
      ...image,
      base64: (await fixture(image.name)).toString('base64'),
    })));
    const payloads = await page.evaluate(async ({ module, images }) => {
      const wasm = await import(module);
      await wasm.default();
      return images.map(image => {
        const bytes = Uint8Array.from(atob(image.base64), c => c.charCodeAt(0));
        return JSON.parse(wasm.classify(bytes));
      });
    }, { module, images });
    images.forEach(({ name, variant, partitions }, i) => {
      const p = payloads[i];
      assert.ok(!p.error, `${name}: ${p.error}`);
      assert.equal(p.format.format, 'appledmg', name);
      assert.equal(p.format.variant_name, variant, name);
      assert.ok(Object.hasOwn(FORMAT_NAMES, p.format.format), 'appledmg has a display name');
      if (partitions) {
        assert.ok(hasNote(p, `${CRC_NOTE} (${partitions})`), `${name}: ${JSON.stringify(p.notes)}`);
        assert.ok(hasNote(p, ISA_NOTE), name);
      }
    });

    const fat = payloads[0];
    assert.equal(fat.primary.isa, 'x86_64', 'from the ELF in the FAT volume');
    const volume = fat.slices.find(s => s.label === FAT_VOLUME);
    assert.ok(volume, JSON.stringify(fat.slices));
    assert.equal(volume.isa, 'x86_64');
    assert.equal(volume.offset, 0x1e);
    assert.equal(volume.decoded?.transform, 'UDIF zlib chunks');
    assert.equal(volume.decoded?.size, FAT_VOLUME_SIZE);

    const encrypted = payloads[4];
    assert.deepEqual(encrypted.primary.isa, { unknown: 0 });
    assert.ok(hasNote(encrypted, 'Encrypted Encoding version 2: AES-128'), JSON.stringify(encrypted.notes));
    assert.equal(encrypted.slices.find(s => s.label === 'Encrypted data').offset, 0x1de00);
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names Apple disk images and keeps the stored chunk offset in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const buffer = await fixture('fat-udzo.dmg');
    const file = { name: 'volume.dmg', buffer, mimeType: 'application/octet-stream' };
    await page.locator('#fileinput').setInputFiles([file]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes(FORMAT_NAMES.appledmg), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.primary.isa, 'x86_64');
    const volume = p.slices.find(s => s.label === FAT_VOLUME);
    // The stored offset holds the volume's zlib chunk (RFC 1950 header, method 8).
    assert.equal(buffer[volume.offset] & 0x0f, 8);
    assert.ok(p.metadata.some(m => m.key?.custom === 'dmg_sector_count' && m.value === 2048));
  });
}
