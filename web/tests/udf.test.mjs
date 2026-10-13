import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { gunzipSync } from 'node:zlib';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup);
after(teardown);

// The volumes are committed gzip-compressed (tests/fixtures/udf/README.md); the tests classify the volumes.
const fixture = async path => gunzipSync(await readFile(new URL(`../../tests/fixtures/${path}.gz`, import.meta.url)));

// The synthetic tree every fixture holds: the recognized members in walk order and the ISA each classifies as.
const TREE = {
  '/bin/payload.elf': 'x86_64',
  '/deep/a/b/c/kernel.macho': 'a_arch64',
  '/docs/café-€.elf': 'x86_64',
};

const IMAGES = [
  { path: 'udf/hdiutil-102.iso', variant: 'UDF', revision: '1.02', members: TREE },
  { path: 'udf/hdiutil-bridge.iso', variant: 'UDF bridge (UDF and ISO 9660)', revision: '1.50', members: TREE },
  {
    path: 'udf/newfs-201.img',
    variant: 'UDF',
    revision: '2.01',
    members: { '/fragmented.elf': 'x86_64', ...TREE },
  },
  { path: 'udf/newfs-250.img', variant: 'UDF', revision: '2.50', members: TREE },
  { path: 'udf/newfs-512.img', variant: 'UDF', revision: '2.01', members: TREE },
  // The ISO 9660 tests' hdiutil image is a UDF bridge disc with an El Torito boot record.
  {
    path: 'iso9660/hdiutil.iso',
    variant: 'UDF bridge (UDF and ISO 9660)',
    revision: '1.50',
    members: { '/bin/payload-with-a-long-name.elf': 'x86_64', '/deep/l1/l2/l3/l4/l5/l6/l7/l8/deep.elf': 'x86_64' },
  },
];

const slice = (payload, label) => payload.slices.find(s => s.label === label);
const custom = (payload, key) => payload.metadata.find(m => m.key?.custom === key)?.value;

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`UDF volumes list their recognized files through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const images = await Promise.all(IMAGES.map(async image => ({ ...image, bytes: [...await fixture(image.path)] })));
    const payloads = await page.evaluate(async ({ module, images }) => {
      const wasm = await import(module);
      await wasm.default();
      return images.map(image => JSON.parse(wasm.classify(new Uint8Array(image.bytes))));
    }, { module, images });
    images.forEach(({ path, variant, revision, members }, i) => {
      const p = payloads[i];
      assert.ok(!p.error, `${path}: ${p.error}`);
      assert.equal(p.format.format, 'udf', path);
      assert.equal(p.format.variant_name, variant, path);
      assert.equal(p.primary.isa, 'x86_64', `${path}: the first member decides`);
      assert.deepEqual(p.slices.map(s => s.label), Object.keys(members), path);
      for (const [label, isa] of Object.entries(members)) {
        assert.equal(slice(p, label).isa, isa, `${path} ${label}`);
      }
      assert.equal(custom(p, 'udf_revision'), revision, path);
    });
    // The fragmented file is reassembled from its extents; the slice keeps the first stored extent.
    const fragmented = slice(payloads[2], '/fragmented.elf');
    assert.equal(fragmented.decoded.transform, 'UDF extents');
    assert.equal(fragmented.decoded.size, 40 * 1024);
    assert.equal(fragmented.size, 4096);
    assert.equal(slice(payloads[0], '/bin/payload.elf').decoded, undefined, 'stored in one extent');
    assert.equal(custom(payloads[3], 'udf_partition_maps'), 'type 1, metadata');
    assert.equal(custom(payloads[4], 'udf_block_size'), 512);
    assert.ok(payloads[5].notes.some(n => n.message.includes('it holds an El Torito boot record at 0x8800')));
    assert.ok(Object.hasOwn(FORMAT_NAMES, 'udf'), 'udf has a display name');
  });
}

// The first 594 KiB of hdiutil-102.iso, which end inside the Mach-O's data: the ELFs before it are listed.
const TRUNCATED_END = 0x93800 + 4096;

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`a truncated UDF volume lists the files present through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const bytes = [...(await fixture('udf/hdiutil-102.iso')).subarray(0, TRUNCATED_END)];
    const p = await page.evaluate(async ({ module, bytes }) => {
      const wasm = await import(module);
      await wasm.default();
      return JSON.parse(wasm.classify(new Uint8Array(bytes)));
    }, { module, bytes });
    assert.ok(!p.error, p.error);
    assert.equal(p.format.format, 'udf');
    assert.deepEqual(p.slices.map(s => s.label), ['/bin/payload.elf', '/docs/café-€.elf']);
    assert.ok(p.slices.every(s => s.offset + s.size <= TRUNCATED_END), 'members lie inside the input');
    assert.ok(p.notes.some(n => n.message.startsWith('Volume truncated: ')));
    assert.ok(p.notes.some(n => n.message.startsWith('1 regular files were not listed')));
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names UDF volumes and keeps stored member offsets in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const buffer = await fixture('udf/newfs-250.img');
    const file = { name: 'disc.img', buffer, mimeType: 'application/octet-stream' };
    await page.locator('#fileinput').setInputFiles([file]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes(FORMAT_NAMES.udf), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    const member = slice(p, '/deep/a/b/c/kernel.macho');
    const macho = buffer.subarray(member.offset, member.offset + member.size);
    assert.deepEqual([...macho.subarray(0, 4)], [0xcf, 0xfa, 0xed, 0xfe], 'the stored offset holds the Mach-O');
    const elf = slice(p, '/bin/payload.elf');
    // Small files are recorded inside their extended file entries, not at a block boundary.
    assert.notEqual(elf.offset % 2048, 0);
    assert.deepEqual([...buffer.subarray(elf.offset, elf.offset + 4)], [0x7f, 0x45, 0x4c, 0x46], 'the ELF');
  });
}
