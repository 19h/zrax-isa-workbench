import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { gunzipSync } from 'node:zlib';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup);
after(teardown);

// The volumes are committed gzip-compressed; the tests classify the volumes themselves.
const fixture = async name => gunzipSync(await readFile(new URL(`../../tests/fixtures/hfsplus/${name}.gz`, import.meta.url)));

// macOS volumes (tests/fixtures/hfsplus/README.md): the recognized members
// in walk order and the ISA each member classifies as.
const IMAGES = [
  {
    name: 'hfsplus.img',
    format: 'hfsplus',
    variant: 'HFS+',
    members: {
      '/payload.elf': 'x86_64',
      '/Applications/Zrax.app/Contents/MacOS/Zrax': 'a_arch64',
      '/bin/fragmented.elf': 'x86_64',
      '/Library/large.macho': 'a_arch64',
    },
  },
  {
    name: 'hfsx.img',
    format: 'hfsx',
    variant: 'HFSX',
    members: {
      '/CASE/payload.elf': 'x86_64',
      '/case/large.macho': 'a_arch64',
      '/case/payload.elf': 'a_arch64',
    },
  },
];

// Members that are decoded or reassembled: the transform and decoded size.
const DECODED = {
  '/Applications/Zrax.app/Contents/MacOS/Zrax': { transform: 'decmpfs LZVN', size: 24 * 1024 },
  '/Library/large.macho': { transform: 'decmpfs LZVN', size: 200 * 1024 },
  '/bin/fragmented.elf': { transform: 'HFS+ extents', size: 40 * 1024 },
  '/case/large.macho': { transform: 'decmpfs LZVN', size: 200 * 1024 },
};

const slice = (payload, label) => payload.slices.find(s => s.label === label);

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`HFS+ and HFSX volumes list their recognized files through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const images = await Promise.all(IMAGES.map(async image => ({ ...image, bytes: [...await fixture(image.name)] })));
    const payloads = await page.evaluate(async ({ module, images }) => {
      const wasm = await import(module);
      await wasm.default();
      return images.map(image => JSON.parse(wasm.classify(new Uint8Array(image.bytes))));
    }, { module, images });
    images.forEach(({ name, format, variant, members }, i) => {
      const p = payloads[i];
      assert.ok(!p.error, `${name}: ${p.error}`);
      assert.equal(p.format.format, format, name);
      assert.equal(p.format.variant_name, variant, name);
      assert.equal(p.primary.isa, 'x86_64', `${name}: the first member decides`);
      assert.deepEqual(p.slices.map(s => s.label), Object.keys(members), name);
      for (const [label, isa] of Object.entries(members)) {
        assert.equal(slice(p, label).isa, isa, `${name} ${label}`);
        const decoded = DECODED[label];
        if (decoded) {
          assert.equal(slice(p, label).decoded.transform, decoded.transform, label);
          assert.equal(slice(p, label).decoded.size, decoded.size, label);
        } else {
          assert.equal(slice(p, label).decoded, undefined, `${label}: stored in one extent`);
        }
      }
      assert.ok(Object.hasOwn(FORMAT_NAMES, format), `${format} has a display name`);
    });
    const journaled = payloads[0];
    assert.ok(journaled.notes.some(n => n.message.includes('Journaled volume') && n.message.includes('not replayed')));
    assert.ok(journaled.metadata.some(m => m.key?.custom === 'hfsplus_volume_name' && m.value === 'ZRAX'));
    assert.ok(payloads[1].notes.some(n => n.message.includes('case-sensitive names')));
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names HFS+ volumes and keeps stored member offsets in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const buffer = await fixture('hfsplus.img');
    const file = { name: 'volume.img', buffer, mimeType: 'application/octet-stream' };
    await page.locator('#fileinput').setInputFiles([file]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes(FORMAT_NAMES.hfsplus), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.primary.isa, 'x86_64');
    const member = slice(p, '/payload.elf');
    const elf = buffer.subarray(member.offset, member.offset + member.size);
    assert.deepEqual([...elf.subarray(0, 4)], [0x7f, 0x45, 0x4c, 0x46], 'the stored offset holds the ELF');
  });
}
