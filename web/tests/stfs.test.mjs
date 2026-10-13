import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup);
after(teardown);

// STFS layout (Free60 "STFS"; Velocity StfsPackage.cpp; xenia stfs_xbox.h).
const BLOCK = 0x1000;
const RECORD = 0x18;
const END_OF_CHAIN = 0xffffff;
const ALLOCATED = 0x80;
const READ_ONLY_FORMAT = 0x01;
const CONSECUTIVE = 0x40;
const DIRECTORY = 0x80;
const ROOT = 0xffff;
// Velocity's header size for one hash table copy: the first table at 0xB000.
const HEADER_SIZE = 0xad0e;
const FIRST_TABLE = 0xb000;
const BLOCKS = 8;

const sha1 = bytes => createHash('sha1').update(bytes).digest();

// An XEX2 header (the layout console.rs reads): `XEX2`, module flags 1,
// PE offset 0x40, security offset 0x20; then PowerPC nops up to `size`.
function xex(size) {
  const bytes = Buffer.alloc(size);
  for (let at = 0x40; at + 4 <= size; at += 4) {
    bytes.writeUInt32BE(0x60000000, at);
  }
  bytes.write('XEX2', 0, 'latin1');
  bytes.writeUInt32BE(1, 4);
  bytes.writeUInt32BE(0x40, 8);
  bytes.writeUInt32BE(0x20, 16);
  return bytes;
}

const writeUInt24LE = (buffer, value, at) => buffer.writeUIntLE(value, at, 3);
const writeUInt24BE = (buffer, value, at) => buffer.writeUIntBE(value, at, 3);

// A 64-byte file table entry: name, name length and flags (0x28), valid and
// allocated blocks (24-bit LE, 0x29 and 0x2C), first block (24-bit LE,
// 0x2F), parent directory index (BE, 0x32), size (BE, 0x34).
function fileEntry({ name, flags, start, blocks, parent, size }) {
  const entry = Buffer.alloc(0x40);
  entry.write(name, 0, 'latin1');
  entry[0x28] = name.length | flags;
  writeUInt24LE(entry, blocks, 0x29);
  writeUInt24LE(entry, blocks, 0x2c);
  writeUInt24LE(entry, start, 0x2f);
  entry.writeUInt16BE(parent, 0x32);
  entry.writeUInt32BE(size, 0x34);
  return entry;
}

// A read-only LIVE package of 8 blocks: the file table in block 0,
// default.xex in consecutive blocks 1-2, media/game.xex chained through
// blocks 6, 4, 5. Block b lies at FIRST_TABLE + (b + 1) * BLOCK, after the
// one level-0 table, which hashes every block and holds the chain.
function livePackage() {
  const blocks = Array.from({ length: BLOCKS }, () => Buffer.alloc(BLOCK));
  const next = new Array(BLOCKS).fill(END_OF_CHAIN);
  const store = (chain, contents, consecutive) => {
    chain.forEach((block, i) => {
      contents.copy(blocks[block], 0, i * BLOCK, Math.min(contents.length, (i + 1) * BLOCK));
      next[block] = consecutive ? 0 : (chain[i + 1] ?? END_OF_CHAIN);
    });
  };
  store([1, 2], xex(0x1800), true);
  store([6, 4, 5], xex(0x2100), false);
  const entries = [
    { name: 'default.xex', flags: CONSECUTIVE, start: 1, blocks: 2, parent: ROOT, size: 0x1800 },
    { name: 'media', flags: DIRECTORY, start: 0, blocks: 0, parent: ROOT, size: 0 },
    { name: 'game.xex', flags: 0, start: 6, blocks: 3, parent: 1, size: 0x2100 },
  ];
  entries.forEach((entry, i) => fileEntry(entry).copy(blocks[0], i * 0x40));
  const image = Buffer.alloc(FIRST_TABLE + (BLOCKS + 1) * BLOCK);
  const table = Buffer.alloc(BLOCK);
  blocks.forEach((block, b) => {
    block.copy(image, FIRST_TABLE + (b + 1) * BLOCK);
    sha1(block).copy(table, b * RECORD);
    table[b * RECORD + 0x14] = ALLOCATED;
    writeUInt24BE(table, next[b], b * RECORD + 0x15);
  });
  table.copy(image, FIRST_TABLE);
  // Header: magic, header size, content type 1, metadata version 2, title
  // ID, platform 2; volume descriptor at 0x379 (size 0x24, read-only
  // format, one file table block from block 0, top hash, 8 blocks); volume
  // type 0; the display name in UTF-16BE; the header SHA-1 at 0x32C.
  image.write('LIVE', 0, 'latin1');
  image.writeUInt32BE(HEADER_SIZE, 0x340);
  image.writeUInt32BE(1, 0x344);
  image.writeUInt32BE(2, 0x348);
  image.writeUInt32BE(0x4d5307e6, 0x360);
  image[0x364] = 2;
  image[0x379] = 0x24;
  image[0x37b] = READ_ONLY_FORMAT;
  image.writeUInt16LE(1, 0x37c);
  writeUInt24LE(image, 0, 0x37e);
  sha1(table).copy(image, 0x381);
  image.writeUInt32BE(BLOCKS, 0x395);
  Buffer.from('Zrax Test Pack', 'utf16le').swap16().copy(image, 0x411);
  sha1(image.subarray(0x344, FIRST_TABLE)).copy(image, 0x32c);
  return image;
}

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`Xbox 360 STFS packages list their XEX files by path through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const bytes = [...livePackage()];
    const p = await page.evaluate(async ({ module, bytes }) => {
      const wasm = await import(module);
      await wasm.default();
      return JSON.parse(wasm.classify(new Uint8Array(bytes)));
    }, { module, bytes });
    assert.ok(!p.error, p.error);
    assert.equal(p.format.format, 'xboxstfs');
    assert.equal(p.format.variant_name, 'Xbox 360 LIVE package');
    assert.equal(p.primary.isa, 'ppc');
    assert.deepEqual(p.slices.map(s => [s.label, s.isa, s.offset]), [
      ['/default.xex', 'ppc', FIRST_TABLE + 2 * BLOCK],
      ['/media/game.xex', 'ppc', FIRST_TABLE + 7 * BLOCK],
    ]);
    assert.equal(p.slices[1].decoded.transform, 'STFS data blocks');
    assert.ok(Object.hasOwn(FORMAT_NAMES, 'xboxstfs'), 'xboxstfs has a display name');
    assert.ok(p.notes.some(n => n.message === 'Package signature present (Microsoft-signed); not verified'));
    assert.ok(p.notes.some(n => n.message.startsWith('Header SHA-1 (content ID) over 0x344-0xAFFF matches')));
    assert.ok(p.metadata.some(m => m.key?.custom === 'stfs_display_name' && m.value === 'Zrax Test Pack'));
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names Xbox 360 STFS packages and keeps stored offsets in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const buffer = livePackage();
    const file = { name: 'package.live', buffer, mimeType: 'application/octet-stream' };
    await page.locator('#fileinput').setInputFiles([file]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes(FORMAT_NAMES.xboxstfs), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.primary.isa, 'ppc');
    const member = p.slices.find(s => s.label === '/default.xex');
    const magic = buffer.subarray(member.offset, member.offset + 4);
    assert.equal(magic.toString('latin1'), 'XEX2', 'the stored offset holds the XEX');
  });
}
