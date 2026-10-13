import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { before, after, test } from 'node:test';
import { deflateSync, deflateRawSync, gunzipSync } from 'node:zlib';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup);
after(teardown);

// The synthetic x86-64 ELF header of the compressed-stream fixtures.
const elf = () => readFile(new URL('../../tests/fixtures/compressed/payload.elf', import.meta.url));

// The committed bsdtar ISO 9660 image, stored with `gzip -9 -n`.
const isoImage = async () =>
  gunzipSync(await readFile(new URL('../../tests/fixtures/iso9660/joliet.iso.gz', import.meta.url)));

// PowerPC: stwu r1,-16(r1); mflr r0; lwz r0,20(r1); mtlr r0; addi r1,r1,16; blr.
const PPC_WORDS = [0x9421fff0, 0x7c0802a6, 0x80010014, 0x7c0803a6, 0x38210010, 0x4e800020];

// `size` bytes of repeated PowerPC code.
function ppcCode(size) {
  const bytes = Buffer.alloc(size);
  for (let at = 0; at + 4 <= size; at += 4) {
    bytes.writeUInt32BE(PPC_WORDS[(at / 4) % PPC_WORDS.length], at);
  }
  return bytes;
}

// A DOL: text section 0 at file 0x100 (PowerPC code at 0x80003100), data
// section 0 after it (0x40 B at 0x80100000), entry 0x80003100.
function dol(textSize) {
  const header = Buffer.alloc(0x100);
  header.writeUInt32BE(0x100, 0x00);
  header.writeUInt32BE(0x100 + textSize, 0x1c);
  header.writeUInt32BE(0x80003100, 0x48);
  header.writeUInt32BE(0x80100000, 0x64);
  header.writeUInt32BE(textSize, 0x90);
  header.writeUInt32BE(0x40, 0xac);
  header.writeUInt32BE(0x80003100, 0xe0);
  return Buffer.concat([header, ppcCode(textSize), Buffer.alloc(0x40, 0x5a)]);
}

// A GameCube image: game ID `GZRE01`, the magic at 0x1C, boot DOL at 0x3000
// (0x420), FST at 0x4000 (0x424, size at 0x428); apploader header at 0x2440
// (date, entry, code size 0x100, no trailer) and code; the FST holds the root
// (3 entries), `payload.elf` at 0x6000 and `opening.bnr` (zeros) at 0x5000.
async function gamecubeDisc() {
  const image = Buffer.alloc(0x6200);
  image.write('GZRE01', 0, 'latin1');
  image[7] = 1;
  image.write('ZRAX SYNTHETIC DISC', 0x20, 'latin1');
  image.writeUInt32BE(0xc2339f3d, 0x1c);
  image.write('2026/10/13', 0x2440, 'latin1');
  image.writeUInt32BE(0x81200000, 0x2450);
  image.writeUInt32BE(0x100, 0x2454);
  ppcCode(0x100).copy(image, 0x2460);
  dol(0x200).copy(image, 0x3000);
  const names = Buffer.from('\0payload.elf\0opening.bnr\0', 'latin1');
  const fst = Buffer.alloc(3 * 12);
  // Root: directory flag, name offset 0, parent 0, 3 entries.
  fst.writeUInt32BE(0x01000000, 0);
  fst.writeUInt32BE(3, 8);
  // Files: name offset, data offset, size.
  fst.writeUInt32BE(1, 12);
  fst.writeUInt32BE(0x6000, 16);
  fst.writeUInt32BE(256, 20);
  fst.writeUInt32BE(13, 24);
  fst.writeUInt32BE(0x5000, 28);
  fst.writeUInt32BE(0x40, 32);
  Buffer.concat([fst, names]).copy(image, 0x4000);
  image.writeUInt32BE(0x3000, 0x420);
  image.writeUInt32BE(0x4000, 0x424);
  image.writeUInt32BE(fst.length + names.length, 0x428);
  (await elf()).copy(image, 0x6000);
  return image;
}

// Adler-32 (RFC 1950, section 8.2).
function adler32(bytes) {
  let a = 1;
  let b = 0;
  for (const byte of bytes) {
    a = (a + byte) % 65521;
    b = (b + a) % 65521;
  }
  return ((b << 16) | a) >>> 0;
}

// Block `i` of `disc` in blocks of `size` bytes, zero-padded to the size.
function block(disc, i, size) {
  const padded = Buffer.alloc(size);
  disc.copy(padded, 0, i * size, Math.min((i + 1) * size, disc.length));
  return padded;
}

const blockCount = (length, size) => Math.ceil(length / size);

// GCZ: the 32-byte little-endian header (magic 0xB10BC001, sub-type 0,
// compressed data size, data size, block size, block count), a 64-bit
// pointer per block (offset from the data start), the Adler-32 of each
// block's stored bytes, then each 4 KiB block as a zlib stream.
function gcz(disc) {
  const size = 0x1000;
  const count = blockCount(disc.length, size);
  const streams = [];
  for (let i = 0; i < count; i++) {
    streams.push(deflateSync(block(disc, i, size), { level: 9 }));
  }
  const header = Buffer.alloc(0x20 + 12 * count);
  header.writeUInt32LE(0xb10bc001, 0);
  const total = streams.reduce((sum, s) => sum + s.length, 0);
  header.writeBigUInt64LE(BigInt(total), 8);
  header.writeBigUInt64LE(BigInt(disc.length), 0x10);
  header.writeUInt32LE(size, 0x18);
  header.writeUInt32LE(count, 0x1c);
  let offset = 0;
  streams.forEach((stream, i) => {
    header.writeBigUInt64LE(BigInt(offset), 0x20 + 8 * i);
    header.writeUInt32LE(adler32(stream), 0x20 + 8 * count + 4 * i);
    offset += stream.length;
  });
  return Buffer.concat([header, ...streams]);
}

// CISO: `CISO`, the block size (32 KiB, little-endian) and the block map
// (1 for each used block) in a 0x8000-byte header, then the used blocks.
function ciso(disc) {
  const size = 0x8000;
  const header = Buffer.alloc(0x8000);
  header.write('CISO', 0, 'latin1');
  header.writeUInt32LE(size, 4);
  const blocks = [];
  for (let i = 0; i < blockCount(disc.length, size); i++) {
    header[8 + i] = 1;
    blocks.push(block(disc, i, size));
  }
  return Buffer.concat([header, ...blocks]);
}

// WBFS with 512 B hd sectors and 256 KiB WBFS sectors: the head (`WBFS`, the
// partition size in hd sectors, big-endian; the shifts 9 and 18; version 1;
// slot 0 used), slot 0's disc info at 0x200 (the disc's first 0x100 bytes,
// then the big-endian WBFS sector of each block: block 0 in sector 1), and
// the block in sector 1.
function wbfs(disc) {
  const sector = 1 << 18;
  const image = Buffer.alloc(2 * sector);
  image.write('WBFS', 0, 'latin1');
  image.writeUInt32BE(image.length / 512, 4);
  image[8] = 9;
  image[9] = 18;
  image[10] = 1;
  image[0x0c] = 1;
  disc.copy(image, 0x200, 0, 0x100);
  image.writeUInt16BE(1, 0x300);
  block(disc, 0, sector).copy(image, sector);
  return image;
}

// An LZ4 block of literals only: the token's high nibble 15, the literal
// length's continuation bytes (255 while more follows), then the bytes.
function lz4Literals(bytes) {
  const lengths = [0xf0];
  let rest = bytes.length - 15;
  while (rest >= 255) {
    lengths.push(255);
    rest -= 255;
  }
  lengths.push(rest);
  return Buffer.concat([Buffer.from(lengths), bytes]);
}

// A PSP CSO (`CISO`, version 1, raw DEFLATE) or ZSO (`ZISO`, LZ4) image of
// 2 KiB blocks: the 0x18-byte little-endian header (magic, header size
// 0x18, uncompressed size, block size, version 1, index shift 0), one index
// entry per block plus the end, then the blocks.
function cso(iso, magic) {
  const size = 0x800;
  const count = blockCount(iso.length, size);
  const header = Buffer.alloc(0x18 + 4 * (count + 1));
  header.write(magic, 0, 'latin1');
  header.writeUInt32LE(0x18, 4);
  header.writeBigUInt64LE(BigInt(iso.length), 8);
  header.writeUInt32LE(size, 0x10);
  header[0x14] = 1;
  const blocks = [];
  let position = header.length;
  for (let i = 0; i < count; i++) {
    const bytes = iso.subarray(i * size, (i + 1) * size);
    const stored = magic === 'ZISO' ? lz4Literals(bytes) : deflateRawSync(bytes, { level: 9 });
    header.writeUInt32LE(position, 0x18 + 4 * i);
    blocks.push(stored);
    position += stored.length;
  }
  header.writeUInt32LE(position, 0x18 + 4 * count);
  return Buffer.concat([header, ...blocks]);
}

const IMAGES = [
  {
    name: 'game.gcz',
    build: async () => gcz(await gamecubeDisc()),
    format: 'gcz',
    variant: 'GCZ disc image',
    isa: 'ppc',
    slices: [['Disc image', 'ppc', 'GCZ']],
  },
  {
    name: 'game.ciso',
    build: async () => ciso(await gamecubeDisc()),
    format: 'ciso',
    variant: 'CISO disc image',
    isa: 'ppc',
    slices: [['Disc image', 'ppc', 'CISO']],
  },
  {
    name: 'games.wbfs',
    build: async () => wbfs(await gamecubeDisc()),
    format: 'wbfs',
    variant: 'WBFS image',
    isa: 'ppc',
    slices: [['Disc slot 0 (GZRE01)', 'ppc', 'WBFS']],
  },
  {
    name: 'game.cso',
    build: async () => cso(await isoImage(), 'CISO'),
    format: 'cso',
    variant: 'CSO v1 image',
    isa: 'x86_64',
    slices: [['Disc image', 'x86_64', 'CSO']],
  },
  {
    name: 'game.zso',
    build: async () => cso(await isoImage(), 'ZISO'),
    format: 'cso',
    variant: 'ZSO image',
    isa: 'x86_64',
    slices: [['Disc image', 'x86_64', 'ZSO']],
  },
];

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`disc image containers decode their discs through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const built = IMAGES.map(async image => ({ name: image.name, bytes: [...await image.build()] }));
    const images = await Promise.all(built);
    const payloads = await page.evaluate(async ({ module, images }) => {
      const wasm = await import(module);
      await wasm.default();
      return images.map(image => JSON.parse(wasm.classify(new Uint8Array(image.bytes))));
    }, { module, images });
    IMAGES.forEach(({ name, format, variant, isa, slices }, i) => {
      const p = payloads[i];
      assert.ok(!p.error, `${name}: ${p.error}`);
      assert.equal(p.format.format, format, name);
      assert.equal(p.format.variant_name, variant, name);
      assert.equal(p.primary.isa, isa, name);
      assert.deepEqual(p.slices.map(s => [s.label, s.isa, s.decoded?.transform]), slices, name);
      assert.ok(Object.hasOwn(FORMAT_NAMES, format), `${format} has a display name`);
    });
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names GCZ images and keeps stored offsets in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const buffer = gcz(await gamecubeDisc());
    const file = { name: 'game.gcz', buffer, mimeType: 'application/octet-stream' };
    await page.locator('#fileinput').setInputFiles([file]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes(FORMAT_NAMES.gcz), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.primary.isa, 'ppc');
    const disc = p.slices.find(s => s.label === 'Disc image');
    // The slice covers the stored zlib streams after the 32-byte header and
    // the 12-byte table entries of the seven blocks.
    assert.equal(disc.offset, 0x20 + 12 * 7);
    assert.equal(disc.offset + disc.size, buffer.length);
    assert.deepEqual([...buffer.subarray(disc.offset, disc.offset + 2)], [0x78, 0xda], 'a zlib stream starts there');
    assert.equal(disc.decoded.size, 0x6200);
  });
}
