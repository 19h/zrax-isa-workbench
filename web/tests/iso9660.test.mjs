import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { gunzipSync } from 'node:zlib';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup);
after(teardown);

// The committed images are gzip-compressed (tests/fixtures/iso9660/README.md).
const fixture = async name => gunzipSync(await readFile(new URL(`../../tests/fixtures/iso9660/${name}.iso.gz`, import.meta.url)));

// The same synthetic tree written by bsdtar (Rock Ridge and Joliet, Joliet only) and by hdiutil (UDF bridge,
// Rock Ridge without NM entries): the El Torito boot image first, then the recognized members in walk order.
const BOOT = 'El Torito default entry (80x86, no emulation)';
const IMAGES = [
  {
    name: 'rockridge',
    names: 'Rock Ridge',
    members: ['/bin/payload-with-a-long-name.elf', '/deep/l1/l2/l3/l4/l5/l6/l7/l8/deep.elf'],
  },
  { name: 'joliet', names: 'Joliet', members: ['/bin/payload-with-a-long-name.elf'] },
  {
    name: 'hdiutil',
    names: 'Rock Ridge',
    members: ['/BIN/PAYLOAD-WITH-A-LONG-NAME.ELF', '/DEEP/L1/L2/L3/L4/L5/L6/L7/L8/DEEP.ELF'],
  },
];

const slice = (payload, label) => payload.slices.find(s => s.label === label);
const custom = (payload, key) => payload.metadata.find(m => m.key?.custom === key)?.value;

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`ISO 9660 images list their boot image and members through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const images = await Promise.all(IMAGES.map(async image => ({ ...image, bytes: [...await fixture(image.name)] })));
    const payloads = await page.evaluate(async ({ module, images }) => {
      const wasm = await import(module);
      await wasm.default();
      return images.map(image => JSON.parse(wasm.classify(new Uint8Array(image.bytes))));
    }, { module, images });
    images.forEach(({ name, names, members }, i) => {
      const p = payloads[i];
      assert.ok(!p.error, `${name}: ${p.error}`);
      assert.equal(p.format.format, 'iso9660', name);
      assert.equal(p.format.variant_name, 'ISO 9660', name);
      assert.deepEqual(p.slices.map(s => s.label), [...members, BOOT], name);
      const boot = slice(p, BOOT);
      assert.equal(boot.isa, 'x86', name);
      assert.equal(boot.bitwidth, 16, name);
      assert.ok(members.every(label => slice(p, label).isa === 'x86_64'), name);
      assert.equal(p.primary.isa, 'x86_64', name);
      assert.equal(custom(p, 'iso9660_names'), names, name);
      assert.equal(custom(p, 'iso9660_boot_entries'), 1, name);
    });
    assert.ok(payloads[2].notes.some(n => n.message.startsWith('UDF bridge: ECMA-167 recognition sequence BEA01')));
    assert.ok(Object.hasOwn(FORMAT_NAMES, 'iso9660'), 'iso9660 has a display name');
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names ISO 9660 images and keeps stored member offsets in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const buffer = await fixture('rockridge');
    const file = { name: 'install.iso', buffer, mimeType: 'application/octet-stream' };
    await page.locator('#fileinput').setInputFiles([file]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes(FORMAT_NAMES.iso9660), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    const member = slice(p, '/bin/payload-with-a-long-name.elf');
    const elf = buffer.subarray(member.offset, member.offset + member.size);
    assert.deepEqual([...elf.subarray(0, 4)], [0x7f, 0x45, 0x4c, 0x46], 'the stored offset holds the ELF');
    const boot = slice(p, BOOT);
    // boot.asm starts with cli; xor ax, ax.
    assert.deepEqual([...buffer.subarray(boot.offset, boot.offset + 3)], [0xfa, 0x31, 0xc0], 'the boot code');
  });
}
