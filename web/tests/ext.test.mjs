import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup);
after(teardown);

const fixture = name => readFile(new URL(`../../tests/fixtures/ext/${name}`, import.meta.url));

// mke2fs images of the same tree (tests/fixtures/ext/README.md): the
// recognized members, in walk order, and how the sparse member is mapped.
const IMAGES = [
  { name: 'ext2.img', variant: 'ext2', transform: 'ext block map' },
  { name: 'ext4.img', variant: 'ext4', transform: 'ext extent map' },
];
const MEMBERS = ['/payload.elf', '/bin/sparse.elf', '/boot/payload.elf.gz', '/many/member-entry-160.elf'];
// bin/sparse.elf is 310 KiB with holes; it is reassembled from its blocks.
const SPARSE_SIZE = 310 * 1024;

const slice = (payload, label) => payload.slices.find(s => s.label === label);

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`ext images list their recognized members through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const images = await Promise.all(IMAGES.map(async image => ({ ...image, bytes: [...await fixture(image.name)] })));
    const payloads = await page.evaluate(async ({ module, images }) => {
      const wasm = await import(module);
      await wasm.default();
      return images.map(image => JSON.parse(wasm.classify(new Uint8Array(image.bytes))));
    }, { module, images });
    images.forEach(({ name, variant, transform }, i) => {
      const p = payloads[i];
      assert.ok(!p.error, `${name}: ${p.error}`);
      assert.equal(p.format.format, 'ext', name);
      assert.equal(p.format.variant_name, variant, name);
      assert.equal(p.primary.isa, 'x86_64', name);
      assert.deepEqual(p.slices.map(s => s.label), MEMBERS, name);
      assert.ok(p.slices.every(s => s.isa === 'x86_64'), name);
      const sparse = slice(p, '/bin/sparse.elf');
      assert.equal(sparse.decoded.transform, transform, name);
      assert.equal(sparse.decoded.size, SPARSE_SIZE, name);
      assert.equal(slice(p, '/payload.elf').decoded, undefined, `${name}: stored contiguously`);
      assert.ok(p.metadata.some(m => m.key?.custom === 'ext_member_count' && m.value === 4), name);
    });
    assert.ok(Object.hasOwn(FORMAT_NAMES, 'ext'), 'ext has a display name');
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names ext images and keeps stored member offsets in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const buffer = await fixture('ext4.img');
    const file = { name: 'rootfs.img', buffer, mimeType: 'application/octet-stream' };
    await page.locator('#fileinput').setInputFiles([file]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes(FORMAT_NAMES.ext), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.primary.isa, 'x86_64');
    const member = slice(p, '/payload.elf');
    const elf = buffer.subarray(member.offset, member.offset + member.size);
    assert.deepEqual([...elf.subarray(0, 4)], [0x7f, 0x45, 0x4c, 0x46], 'the stored offset holds the ELF');
  });
}
