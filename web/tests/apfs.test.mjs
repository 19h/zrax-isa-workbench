import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { gunzipSync } from 'node:zlib';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup);
after(teardown);

// The containers are committed gzip-compressed; the tests classify the containers themselves.
const fixture = async name => gunzipSync(await readFile(new URL(`../../tests/fixtures/apfs/${name}.gz`, import.meta.url)));

// macOS containers (tests/fixtures/apfs/README.md): the members in walk
// order and the ISA each member classifies as.
const IMAGES = [
  {
    name: 'apfs.img',
    primary: 'x86_64',
    members: {
      '/ZRAX/payload.elf': 'x86_64',
      '/ZRAX/Applications/Zrax.app/Contents/MacOS/Zrax': 'a_arch64',
      '/ZRAX/Library/huge.macho': 'a_arch64',
      '/ZRAX/Library/large.macho': 'a_arch64',
      '/ZRAX/bin/fragmented.elf': 'x86_64',
    },
  },
  {
    name: 'apfs-cs.img',
    primary: 'x86_64',
    members: {
      '/ZRAXCS/payload.elf': 'x86_64',
      '/ZRAXCS/CASE/payload.elf': 'x86_64',
      '/ZRAXCS/case/payload.elf': 'a_arch64',
    },
  },
  {
    name: 'encrypted.img',
    primary: { unknown: 0 },
    members: { '/ZRAXENC': { unknown: 0 } },
  },
];

// Members that are decoded or reassembled: the transform and decoded size.
const DECODED = {
  '/ZRAX/Applications/Zrax.app/Contents/MacOS/Zrax': { transform: 'decmpfs LZVN', size: 24 * 1024 },
  '/ZRAX/Library/huge.macho': { transform: 'decmpfs LZVN', size: 70 * 1024 },
  '/ZRAX/Library/large.macho': { transform: 'decmpfs LZVN', size: 200 * 1024 },
  '/ZRAX/bin/fragmented.elf': { transform: 'APFS extents', size: 40 * 1024 },
};

const slice = (payload, label) => payload.slices.find(s => s.label === label);

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`APFS containers list their volumes' recognized files through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    // The 8 MiB containers are fetched and decompressed in the page rather
    // than passed through page.evaluate.
    const payloads = await page.evaluate(async ({ module, names }) => {
      const wasm = await import(module);
      await wasm.default();
      const results = [];
      for (const name of names) {
        const response = await fetch(`/tests/fixtures/apfs/${name}.gz`);
        const stream = response.body.pipeThrough(new DecompressionStream('gzip'));
        const bytes = new Uint8Array(await new Response(stream).arrayBuffer());
        results.push(JSON.parse(wasm.classify(bytes)));
      }
      return results;
    }, { module, names: IMAGES.map(image => image.name) });
    IMAGES.forEach(({ name, primary, members }, i) => {
      const p = payloads[i];
      assert.ok(!p.error, `${name}: ${p.error}`);
      assert.equal(p.format.format, 'apfs', name);
      assert.equal(p.format.variant_name, 'APFS container', name);
      assert.deepEqual(p.primary.isa, primary, name);
      assert.deepEqual(p.slices.map(s => s.label), Object.keys(members), name);
      for (const [label, isa] of Object.entries(members)) {
        assert.deepEqual(slice(p, label).isa, isa, `${name} ${label}`);
        const decoded = DECODED[label];
        if (decoded) {
          assert.equal(slice(p, label).decoded.transform, decoded.transform, label);
          assert.equal(slice(p, label).decoded.size, decoded.size, label);
        } else {
          assert.equal(slice(p, label).decoded, undefined, `${label}: stored in one extent`);
        }
      }
    });
    assert.ok(Object.hasOwn(FORMAT_NAMES, 'apfs'), 'apfs has a display name');
    const plain = payloads[0];
    assert.ok(plain.notes.some(n => n.message.includes('file-system tree of 704 records in 16 nodes, 2 levels')));
    assert.ok(plain.metadata.some(m => m.key?.custom === 'apfs_volume_0' && m.value.startsWith('"ZRAX"')));
    assert.ok(payloads[1].notes.some(n => n.message.includes('case-sensitive names')));
    assert.ok(payloads[2].notes.some(n => n.message.includes('/ZRAXENC: encrypted')));
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names APFS containers and keeps stored member offsets in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const buffer = await fixture('apfs.img');
    const file = { name: 'container.img', buffer, mimeType: 'application/octet-stream' };
    await page.locator('#fileinput').setInputFiles([file]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes(FORMAT_NAMES.apfs), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.primary.isa, 'x86_64');
    const member = slice(p, '/ZRAX/payload.elf');
    const elf = buffer.subarray(member.offset, member.offset + member.size);
    assert.deepEqual([...elf.subarray(0, 4)], [0x7f, 0x45, 0x4c, 0x46], 'the stored offset holds the ELF');
  });
}
