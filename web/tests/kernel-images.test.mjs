import assert from 'node:assert/strict';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup); after(teardown);

function crc32(bytes) {
  let crc = ~0;
  for (const b of bytes) {
    crc ^= b;
    for (let i = 0; i < 8; i++) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
  }
  return ~crc >>> 0;
}

// 64-byte ELF32 header: little- or big-endian, executable, machine 40 (Arm).
function armElf(bigEndian) {
  const elf = Buffer.alloc(64);
  elf.set([0x7f, 0x45, 0x4c, 0x46, 1, bigEndian ? 2 : 1, 1]);
  if (bigEndian) { elf.writeUInt16BE(2, 16); elf.writeUInt16BE(40, 18); } else { elf.writeUInt16LE(2, 16); elf.writeUInt16LE(40, 18); }
  return elf;
}

// uImage: magic, header CRC, size, load/entry, data CRC, Linux, Arm, kernel,
// no compression; then the payload.
function uimage(payload) {
  const header = Buffer.alloc(64);
  header.writeUInt32BE(0x27051956, 0);
  header.writeUInt32BE(payload.length, 12);
  header.writeUInt32BE(0x80008000, 16);
  header.writeUInt32BE(0x80008000, 20);
  header.writeUInt32BE(crc32(payload), 24);
  header.set([5, 2, 2, 0], 0x1c);
  header.writeUInt32BE(crc32(header), 4);
  return Buffer.concat([header, payload]);
}

// Arm zImage header: magic at 0x24, start 0, end = size, little-endian flag.
function zimage() {
  const image = Buffer.alloc(0x100);
  image.writeUInt32LE(0x016f2818, 0x24);
  image.writeUInt32LE(0x100, 0x2c);
  image.writeUInt32LE(0x04030201, 0x30);
  return image;
}

// bzImage setup header with protocol 2.15 and XLF_KERNEL_64.
function bzimage() {
  const image = Buffer.alloc(0x400);
  image[0x1f1] = 1;
  image.writeUInt16LE(0xaa55, 0x1fe);
  image.write('HdrS', 0x202);
  image.writeUInt16LE(0x020f, 0x206);
  image[0x211] = 1;
  image.writeUInt16LE(1, 0x236);
  return image;
}

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`kernel images report header and payload evidence through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const fixtures = [
      ['uimage-le', uimage(armElf(false))],
      ['uimage-be', uimage(armElf(true))],
      ['zimage', zimage()],
      ['bzimage', bzimage()],
    ].map(([name, bytes]) => ({ name, bytes: [...bytes] }));
    const payloads = await page.evaluate(async ({ module, fixtures }) => {
      const wasm = await import(module);
      await wasm.default();
      return Object.fromEntries(fixtures.map(f => [f.name, JSON.parse(wasm.classify(new Uint8Array(f.bytes)))]));
    }, { module, fixtures });
    for (const [name, p] of Object.entries(payloads)) {
      assert.ok(!p.error, `${name}: ${p.error}`);
      assert.ok(Object.hasOwn(FORMAT_NAMES, p.format.format), `${p.format.format} has a display name`);
    }
    assert.equal(payloads['uimage-le'].primary.endianness, 'little');
    assert.equal(payloads['uimage-be'].primary.endianness, 'big');
    assert.equal(payloads['uimage-be'].slices[0].offset, 64);
    assert.deepEqual([payloads.zimage.format.format, payloads.zimage.primary.isa], ['zimage', 'arm']);
    assert.deepEqual([payloads.bzimage.primary.isa, payloads.bzimage.primary.bitwidth], ['x86_64', 64]);
  });
}
