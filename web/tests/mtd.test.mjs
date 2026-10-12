import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';

before(setup);
after(teardown);

const fixture = name => readFile(new URL(`../../tests/fixtures/mtd/${name}`, import.meta.url));

// The mtd-utils fixtures (tests/fixtures/mtd/README.md): the same synthetic
// tree in each filesystem, and a UBI image whose volumes are a UBIFS image
// and a static ELF volume. Every ELF header names x86-64.
const IMAGES = [
  {
    name: 'rootfs-le-zlib.jffs2',
    format: 'jffs2',
    variant: 'JFFS2 image (little-endian)',
    slices: ['/bin/tool-link.elf', '/bin/tool.elf', '/boot/sparse.elf', '/lib/payload.elf'],
    transform: 'JFFS2 file',
  },
  {
    name: 'rootfs-be-lzo.jffs2',
    format: 'jffs2',
    variant: 'JFFS2 image (big-endian)',
    slices: ['/bin/tool-link.elf', '/bin/tool.elf', '/boot/sparse.elf', '/lib/payload.elf'],
    transform: 'JFFS2 file',
  },
  {
    name: 'rootfs-lzo.ubifs',
    format: 'ubifs',
    variant: 'UBIFS image',
    slices: ['/bin/tool-link.elf', '/bin/tool.elf', '/boot/sparse.elf', '/lib/payload.elf'],
    transform: 'UBIFS file',
  },
  {
    name: 'image.ubi',
    format: 'ubi',
    variant: 'UBI image',
    slices: ['rootfs', 'kernel'],
    transform: 'UBI volume',
  },
];

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`flash filesystem images list their files through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const withBytes = async image => ({ ...image, bytes: [...await fixture(image.name)] });
    const fixtures = await Promise.all(IMAGES.map(withBytes));
    const payloads = await page.evaluate(async ({ module, fixtures }) => {
      const wasm = await import(module);
      await wasm.default();
      return fixtures.map(f => JSON.parse(wasm.classify(new Uint8Array(f.bytes))));
    }, { module, fixtures });
    fixtures.forEach((image, i) => {
      const p = payloads[i];
      assert.ok(!p.error, `${image.name}: ${p.error}`);
      assert.equal(p.format.format, image.format, image.name);
      assert.equal(p.format.variant_name, image.variant, image.name);
      assert.ok(Object.hasOwn(FORMAT_NAMES, image.format), `${image.format} has a display name`);
      // The filesystems name no processor; the ISA comes from the files.
      assert.equal(p.primary.isa, 'x86_64', image.name);
      assert.deepEqual(p.slices.map(s => s.label), image.slices, image.name);
      for (const slice of p.slices) {
        assert.equal(slice.decoded?.transform, image.transform, `${image.name}: ${slice.label}`);
        const stored = slice.offset + slice.size <= image.bytes.length;
        assert.ok(stored, `${image.name}: ${slice.label} is stored in the file`);
      }
    });
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names UBI images and their volumes in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const buffer = await fixture('image.ubi');
    const file = { name: 'flash.ubi', buffer, mimeType: 'application/octet-stream' };
    await page.locator('#fileinput').setInputFiles([file]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes(FORMAT_NAMES.ubi), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.format.format, 'ubi');
    assert.ok(p.metadata.some(m => m.key?.custom === 'ubi_peb_size' && m.value === 16384));
    assert.ok(p.notes.some(n => n.message === 'rootfs: x86_64 (contained UBIFS)'));
  });
}
