import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup);
after(teardown);

const fixture = name => readFile(new URL(`../../tests/fixtures/erofs/${name}`, import.meta.url));

// mkfs.erofs images of the same tree (tests/fixtures/erofs/README.md) and how each stores lib/big.elf: as whole
// blocks plus an inline tail, in LZ4 big pclusters, or as a fragment of the MicroLZMA-compressed packed inode.
const IMAGES = [
  { name: 'plain.img', transform: 'EROFS tail packing' },
  { name: 'lz4.img', transform: 'EROFS LZ4' },
  { name: 'lzma-fragments.img', transform: 'EROFS fragment' },
];
const MEMBERS = ['/payload.elf', '/boot/payload.elf.gz', '/lib/big.elf', '/lib/mixed.elf'];
// lib/big.elf: the 256 B ELF header and 1000 lines of text.
const BIG_SIZE = 27256;

const slice = (payload, label) => payload.slices.find(s => s.label === label);

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`EROFS images list their recognized members through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const images = await Promise.all(IMAGES.map(async image => ({ ...image, bytes: [...await fixture(image.name)] })));
    const payloads = await page.evaluate(async ({ module, images }) => {
      const wasm = await import(module);
      await wasm.default();
      return images.map(image => JSON.parse(wasm.classify(new Uint8Array(image.bytes))));
    }, { module, images });
    images.forEach(({ name, transform }, i) => {
      const p = payloads[i];
      assert.ok(!p.error, `${name}: ${p.error}`);
      assert.equal(p.format.format, 'erofs', name);
      assert.equal(p.format.variant_name, 'EROFS', name);
      assert.equal(p.primary.isa, 'x86_64', name);
      assert.deepEqual(p.slices.map(s => s.label), MEMBERS, name);
      assert.ok(p.slices.every(s => s.isa === 'x86_64'), name);
      const big = slice(p, '/lib/big.elf');
      assert.equal(big.decoded.transform, transform, name);
      assert.equal(big.decoded.size, BIG_SIZE, name);
      assert.ok(p.metadata.some(m => m.key?.custom === 'erofs_member_count' && m.value === 4), name);
    });
    assert.equal(slice(payloads[0], '/payload.elf').decoded, undefined, 'stored contiguously');
    assert.ok(Object.hasOwn(FORMAT_NAMES, 'erofs'), 'erofs has a display name');
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names EROFS images and keeps stored member offsets in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const buffer = await fixture('plain.img');
    const file = { name: 'system.img', buffer, mimeType: 'application/octet-stream' };
    await page.locator('#fileinput').setInputFiles([file]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes(FORMAT_NAMES.erofs), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.primary.isa, 'x86_64');
    const member = slice(p, '/payload.elf');
    const elf = buffer.subarray(member.offset, member.offset + member.size);
    assert.deepEqual([...elf.subarray(0, 4)], [0x7f, 0x45, 0x4c, 0x46], 'the stored offset holds the ELF');
  });
}
