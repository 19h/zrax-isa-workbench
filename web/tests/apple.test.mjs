import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup); after(teardown);

const fixture = name => readFile(new URL(`../../tests/fixtures/apple/${name}`, import.meta.url));

// Unslid address of file offset 0 in the cache below.
const CACHE_ADDRESS = 0x180000000n;

// mach_header_64 (magic 0xFEEDFACF, CPU_TYPE_ARM64, MH_DYLIB) with one
// 24-byte LC_UUID command.
function arm64Macho() {
  const header = Buffer.alloc(56);
  const fields = [0xfeedfacf, 0x0100000c, 0, 6, 1, 24, 0, 0, 0x1b, 24];
  fields.forEach((value, i) => header.writeUInt32LE(value, 4 * i));
  return header;
}

// dyld-1378 cache: magic "dyld_v1  arm64e" + NUL; mappingOffset 0x228 (the
// header size) with one mapping; imagesOffset/imagesCount at 0x1C0/0x1C4.
// The mapping (address, size, fileOffset, maxProt, initProt) covers the whole
// file; one dyld_cache_image_info (address, mtime, inode, pathFileOffset)
// points at the Mach-O header at 0x300 and its path at 0x268.
function dyldCache() {
  const file = Buffer.alloc(0x400);
  file.write('dyld_v1  arm64e\0', 0, 'latin1');
  file.writeUInt32LE(0x228, 0x10);
  file.writeUInt32LE(1, 0x14);
  file.writeUInt32LE(0x248, 0x1c0);
  file.writeUInt32LE(1, 0x1c4);
  file.writeBigUInt64LE(CACHE_ADDRESS, 0x228);
  file.writeBigUInt64LE(BigInt(file.length), 0x230);
  file.writeBigUInt64LE(0n, 0x238);
  file.writeUInt32LE(5, 0x240);
  file.writeUInt32LE(5, 0x244);
  file.writeBigUInt64LE(CACHE_ADDRESS + 0x300n, 0x248);
  file.writeUInt32LE(0x268, 0x248 + 0x18);
  file.write('/usr/lib/libSystem.B.dylib\0', 0x268, 'latin1');
  arm64Macho().copy(file, 0x300);
  return file;
}

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`Apple images classify from their payloads through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const inputs = [
      { name: 'krnl.bvx2.im4p', bytes: [...await fixture('krnl.bvx2.im4p')] },
      { name: 'krnl.img4', bytes: [...await fixture('krnl.img4')] },
      { name: 'dyld_shared_cache_arm64e', bytes: [...dyldCache()] },
    ];
    const payloads = await page.evaluate(async ({ module, inputs }) => {
      const wasm = await import(module);
      await wasm.default();
      return Object.fromEntries(inputs.map(f => [f.name, JSON.parse(wasm.classify(new Uint8Array(f.bytes)))]));
    }, { module, inputs });

    const im4p = payloads['krnl.bvx2.im4p'];
    assert.ok(!im4p.error, im4p.error);
    assert.equal(im4p.format.format, 'im4p');
    assert.equal(im4p.primary.isa, 'a_arch64');
    const kernel = im4p.slices.find(s => s.label === 'krnl');
    assert.ok(kernel, JSON.stringify(im4p.slices));
    assert.equal(kernel.decoded.transform, 'LZFSE');
    assert.equal(kernel.decoded.size, 8192);

    const img4 = payloads['krnl.img4'];
    assert.ok(!img4.error, img4.error);
    assert.equal(img4.format.format, 'img4');
    assert.equal(img4.primary.isa, 'a_arch64');
    assert.ok(img4.notes.some(n => n.message.includes('not verified')));
    assert.ok(img4.metadata.some(m => m.key?.custom === 'apple_im4r_nonce' && m.value === '8877665544332211'));

    const cache = payloads.dyld_shared_cache_arm64e;
    assert.ok(!cache.error, cache.error);
    assert.equal(cache.format.format, 'dyldcache');
    assert.equal(cache.primary.isa, 'a_arch64');
    assert.equal(cache.primary.bitwidth, 64);
    const image = cache.slices.find(s => s.label === '/usr/lib/libSystem.B.dylib');
    assert.ok(image, JSON.stringify(cache.slices));
    assert.equal(image.offset, 0x300);
    assert.equal(image.isa, 'a_arch64');

    for (const id of ['im4p', 'img4', 'dyldcache']) {
      assert.ok(Object.hasOwn(FORMAT_NAMES, id), `${id} has a display name`);
    }
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names Apple formats and keeps stored offsets in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const buffer = await fixture('krnl.complzss.im4p');
    await page.locator('#fileinput').setInputFiles([{ name: 'krnl.im4p', buffer, mimeType: 'application/octet-stream' }]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes(FORMAT_NAMES.im4p), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.primary.isa, 'a_arch64');
    const kernel = p.slices.find(s => s.label === 'krnl');
    assert.equal(kernel.offset, 0x30);
    assert.equal(kernel.size, buffer.length - 0x30);
    assert.equal(kernel.decoded.transform, 'Apple LZSS');
  });
}
