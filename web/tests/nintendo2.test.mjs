import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup);
after(teardown);

const sha256 = bytes => createHash('sha256').update(bytes).digest();

// `value` rounded up to a multiple of `alignment`.
const align = (value, alignment) => Math.ceil(value / alignment) * alignment;

// Deterministic bytes that look encrypted (xorshift32).
function noise(size, seed) {
  const bytes = Buffer.alloc(size);
  let state = seed;
  for (let i = 0; i < size; i++) {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    bytes[i] = state & 0xff;
  }
  return bytes;
}

// ARM: push {r4, lr}; mov r0, #0; pop {r4, pc}; bx lr.
const ARM_WORDS = [0xe92d4010, 0xe3a00000, 0xe8bd8010, 0xe12fff1e];

function armCode(size) {
  const bytes = Buffer.alloc(size);
  for (let at = 0; at + 4 <= size; at += 4) {
    bytes.writeUInt32LE(ARM_WORDS[(at / 4) % ARM_WORDS.length], at);
  }
  return bytes;
}

// A NoCrypto CXI NCCH of 8 media units (3dbrew "NCCH"): `NCCH` at 0x100,
// content size at 0x104, platform CTR, form type 3 and NoCrypto in the
// flags at 0x188; a 0x400-byte ExHeader at 0x200 (uncompressed `.code`);
// an ExeFS at unit 6 of 2 units, hash region 1 unit, listing `.code`
// (0x100 B of ARM code at 0xE00) with its SHA-256, and the superblock
// SHA-256 at 0x1C0.
function cxi() {
  const ncch = Buffer.alloc(0x1000);
  ncch.fill(0xa5, 0, 0x100);
  ncch.write('NCCH', 0x100, 'latin1');
  ncch.writeUInt32LE(8, 0x104);
  ncch.write('CTR-P-ZRAX', 0x150, 'latin1');
  ncch.writeUInt32LE(0x400, 0x180);
  ncch[0x188 + 4] = 1;
  ncch[0x188 + 5] = 3;
  ncch[0x188 + 7] = 0x04;
  ncch.write('ZraxApp', 0x200, 'latin1');
  ncch.writeUInt32LE(0x00100000, 0x210);
  ncch.writeUInt32LE(1, 0x214);
  ncch.writeUInt32LE(0x100, 0x218);
  const code = armCode(0x100);
  ncch.write('.code', 0xc00, 'latin1');
  ncch.writeUInt32LE(0x100, 0xc0c);
  sha256(code).copy(ncch, 0xc00 + 0x1e0);
  code.copy(ncch, 0xe00);
  ncch.writeUInt32LE(6, 0x1a0);
  ncch.writeUInt32LE(2, 0x1a4);
  ncch.writeUInt32LE(1, 0x1a8);
  sha256(ncch.subarray(0xc00, 0xe00)).copy(ncch, 0x1c0);
  return ncch;
}

// A minimal NSO: `NSO0`, the text segment at 0x100 (0x40 B), then AArch64
// `nop` and `ret`, repeated.
function nso() {
  const bytes = Buffer.alloc(0x140);
  bytes.write('NSO0', 0, 'latin1');
  bytes.writeUInt32LE(0x100, 0x10);
  bytes.writeUInt32LE(0x40, 0x18);
  for (let at = 0x100; at < 0x140; at += 8) {
    bytes.writeUInt32LE(0xd503201f, at);
    bytes.writeUInt32LE(0xd65f03c0, at + 4);
  }
  return bytes;
}

// A CTR cart image (3dbrew "NCSD"): `NCSD` at 0x100, image size 0x30 units
// at 0x104, partition 0 (the CXI) at unit 0x20 for 8 units in the table at
// 0x120, flags at 0x188 (platform CTR, media type Card1), trimmed after the
// partition.
function cartImage() {
  const header = Buffer.alloc(0x4000);
  header.fill(0x5a, 0, 0x100);
  header.write('NCSD', 0x100, 'latin1');
  header.writeUInt32LE(0x30, 0x104);
  header.writeUInt32LE(0x20, 0x120);
  header.writeUInt32LE(8, 0x124);
  header[0x188 + 4] = 1;
  header[0x188 + 5] = 1;
  return Buffer.concat([header, cxi()]);
}

// A version 1 TMD (3dbrew "Title metadata"): RSA-2048 SHA-256 signature
// block (0x140 B), the header (version 1, title ID, content count, SHA-256
// of the info records at 0xA4), 64 info records (the first hashes every
// chunk record) and a chunk record (ID, index, type, size, SHA-256) per
// content.
function tmd(contents) {
  const chunks = Buffer.alloc(contents.length * 0x30);
  contents.forEach((content, i) => {
    chunks.writeUInt32BE(content.id, i * 0x30);
    chunks.writeUInt16BE(content.index, i * 0x30 + 4);
    chunks.writeUInt16BE(content.encrypted ? 1 : 0, i * 0x30 + 6);
    chunks.writeBigUInt64BE(BigInt(content.bytes.length), i * 0x30 + 8);
    sha256(content.bytes).copy(chunks, i * 0x30 + 0x10);
  });
  const info = Buffer.alloc(64 * 0x24);
  info.writeUInt16BE(contents.length, 2);
  sha256(chunks).copy(info, 4);
  const header = Buffer.alloc(0x140 + 0xc4);
  header.writeUInt32BE(0x00010004, 0);
  header[0x140 + 0x40] = 1;
  header.writeBigUInt64BE(0x00040000_00abcd00n, 0x140 + 0x4c);
  header.writeUInt16BE(contents.length, 0x140 + 0x9e);
  sha256(info).copy(header, 0x140 + 0xa4);
  return Buffer.concat([header, info, chunks]);
}

// A CIA (3dbrew "CIA"): the 0x2020-byte header (sizes and the content
// index bitmap), a certificate (RSA-4096 SHA-256 type, 0x400 B), a ticket
// (RSA-2048 SHA-256 type, 0x350 B), the TMD and the contents, each section
// 64-byte aligned and each content 16-byte aligned; no meta section.
function ciaArchive(contents) {
  const certificate = Buffer.alloc(0x400);
  certificate.writeUInt32BE(0x00010003, 0);
  const ticket = Buffer.alloc(0x350);
  ticket.writeUInt32BE(0x00010004, 0);
  const metadata = tmd(contents);
  let content = Buffer.alloc(0);
  for (const c of contents) {
    content = Buffer.concat([content, Buffer.alloc(align(content.length, 16) - content.length), c.bytes]);
  }
  content = Buffer.concat([content, Buffer.alloc(align(content.length, 16) - content.length)]);
  const header = Buffer.alloc(0x2020);
  header.writeUInt32LE(0x2020, 0);
  header.writeUInt32LE(certificate.length, 8);
  header.writeUInt32LE(ticket.length, 0xc);
  header.writeUInt32LE(metadata.length, 0x10);
  header.writeBigUInt64LE(BigInt(content.length), 0x18);
  for (const c of contents) {
    header[0x20 + (c.index >> 3)] |= 0x80 >> (c.index & 7);
  }
  let file = header;
  for (const section of [certificate, ticket, metadata, content]) {
    file = Buffer.concat([file, Buffer.alloc(align(file.length, 64) - file.length), section]);
  }
  return file;
}

// A PFS0 (switchbrew "NCA", PFS0): `PFS0`, entry count, string table size;
// 0x18-byte entries (offset after the string table, size, name offset);
// NUL-terminated names padded to 0x20; the files.
function pfs0(files) {
  const entries = Buffer.alloc(files.length * 0x18);
  let names = Buffer.alloc(0);
  let offset = 0;
  files.forEach(([name, bytes], i) => {
    entries.writeBigUInt64LE(BigInt(offset), i * 0x18);
    entries.writeBigUInt64LE(BigInt(bytes.length), i * 0x18 + 8);
    entries.writeUInt32LE(names.length, i * 0x18 + 0x10);
    names = Buffer.concat([names, Buffer.from(`${name}\0`, 'latin1')]);
    offset += bytes.length;
  });
  const headerEnd = 0x10 + entries.length + names.length;
  names = Buffer.concat([names, Buffer.alloc(align(headerEnd, 0x20) - headerEnd)]);
  const header = Buffer.alloc(0x10);
  header.write('PFS0', 0, 'latin1');
  header.writeUInt32LE(files.length, 4);
  header.writeUInt32LE(names.length, 8);
  return Buffer.concat([header, entries, names, ...files.map(([, bytes]) => bytes)]);
}

// An HFS0 (switchbrew "XCI"): like a PFS0 with `HFS0` and 0x40-byte entries
// adding the hashed region size (0x14) and its SHA-256 (0x20); the header
// is padded to 0x200. Returns the bytes and the header size.
function hfs0(files) {
  const entries = Buffer.alloc(files.length * 0x40);
  let names = Buffer.alloc(0);
  let offset = 0;
  files.forEach(([name, bytes, hashed], i) => {
    entries.writeBigUInt64LE(BigInt(offset), i * 0x40);
    entries.writeBigUInt64LE(BigInt(bytes.length), i * 0x40 + 8);
    entries.writeUInt32LE(names.length, i * 0x40 + 0x10);
    entries.writeUInt32LE(hashed, i * 0x40 + 0x14);
    sha256(bytes.subarray(0, hashed)).copy(entries, i * 0x40 + 0x20);
    names = Buffer.concat([names, Buffer.from(`${name}\0`, 'latin1')]);
    offset += bytes.length;
  });
  const headerEnd = 0x10 + entries.length + names.length;
  names = Buffer.concat([names, Buffer.alloc(align(headerEnd, 0x200) - headerEnd)]);
  const header = Buffer.alloc(0x10);
  header.write('HFS0', 0, 'latin1');
  header.writeUInt32LE(files.length, 4);
  header.writeUInt32LE(names.length, 8);
  const headerSize = 0x10 + entries.length + names.length;
  return { bytes: Buffer.concat([header, entries, names, ...files.map(([, bytes]) => bytes)]), headerSize };
}

// An XCI (switchbrew "XCI" CardHeader): `HEAD` at 0x100, ROM size 0xFA at
// 0x10D, the valid data end page at 0x118, the root HFS0 at 0xF000 (0x130),
// its header size (0x138) and SHA-256 (0x140); a secure partition with an
// encrypted NCA and an NSO, padded with 0xFF to a page.
function gamecardImage() {
  const secure = hfs0([['0123.nca', noise(0x1000, 3), 0x200], ['main', nso(), 0x140]]);
  const root = hfs0([['secure', secure.bytes, secure.headerSize]]);
  const header = Buffer.alloc(0xf000);
  header.write('HEAD', 0x100, 'latin1');
  header[0x10d] = 0xfa;
  header.writeBigUInt64LE(0xf000n, 0x130);
  header.writeBigUInt64LE(BigInt(root.headerSize), 0x138);
  sha256(root.bytes.subarray(0, root.headerSize)).copy(header, 0x140);
  const body = Buffer.concat([header, root.bytes]);
  const image = Buffer.concat([body, Buffer.alloc(align(body.length, 0x200) - body.length, 0xff)]);
  image.writeUInt32LE(image.length / 0x200 - 1, 0x118);
  return image;
}

const IMAGES = [
  {
    name: 'game.3ds',
    build: cartImage,
    format: 'ncsd',
    variant: '3DS NCSD',
    isa: 'arm',
    slices: [['Partition 0 (executable content)', 'arm', 0x4000]],
  },
  {
    name: 'game.cia',
    build: () => ciaArchive([
      { index: 0, id: 0, encrypted: false, bytes: cxi() },
      { index: 1, id: 1, encrypted: true, bytes: noise(0x200, 9) },
    ]),
    format: 'cia',
    variant: '3DS CIA',
    isa: 'arm',
    slices: [
      ['Certificate chain', { unknown: 0 }, 0x2040],
      ['Ticket', { unknown: 0 }, 0x2440],
      ['TMD', { unknown: 0 }, 0x27c0],
      ['Content 0 (ID 0x00000000)', 'arm', 0x3340],
      ['Content 1 (ID 0x00000001), encrypted', { unknown: 0 }, 0x4340],
    ],
  },
  {
    name: 'game.nsp',
    build: () => pfs0([['0123.nca', noise(0x1000, 1)], ['main', nso()]]),
    format: 'pfs0',
    variant: 'Switch PFS0',
    isa: 'a_arch64',
    slices: [['0123.nca', { unknown: 0 }, 0x60], ['main', 'a_arch64', 0x1060]],
  },
  {
    name: 'game.xci',
    build: gamecardImage,
    format: 'xci',
    variant: 'Switch XCI',
    isa: 'a_arch64',
    slices: [['secure/0123.nca', { unknown: 0 }, 0xf400], ['secure/main', 'a_arch64', 0x10400]],
  },
];

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`Nintendo 3DS and Switch containers classify their members through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const images = IMAGES.map(image => ({ name: image.name, bytes: [...image.build()] }));
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
      assert.deepEqual(p.primary.isa, isa, name);
      assert.deepEqual(p.slices.map(s => [s.label, s.isa, s.offset]), slices, name);
      assert.ok(Object.hasOwn(FORMAT_NAMES, format), `${format} has a display name`);
    });
    const cia = payloads[1];
    assert.ok(cia.notes.some(n => n.message.includes('AES-128-CBC encrypted with the ticket\'s title key')));
    const nsp = payloads[2];
    assert.ok(nsp.notes.some(n => n.message.startsWith('Opaque files named .nca: 1')));
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names Switch XCI images and keeps stored offsets in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const buffer = gamecardImage();
    await page.locator('#fileinput').setInputFiles([{ name: 'game.xci', buffer, mimeType: 'application/octet-stream' }]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes(FORMAT_NAMES.xci), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.primary.isa, 'a_arch64');
    const member = p.slices.find(s => s.label === 'secure/main');
    const bytes = buffer.subarray(member.offset, member.offset + 4);
    assert.equal(bytes.toString('latin1'), 'NSO0', 'the stored offset holds the NSO');
  });
}
