import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup);
after(teardown);

const repoFile = path => readFile(new URL(`../../${path}`, import.meta.url));

// Committed code fixtures: AArch64 and 32-bit Arm machine code.
const aarch64Code = async len => (await repoFile('tests/fixtures/transforms/aarch64.text.bin')).subarray(0, len);
const ARM_CODE = 'testbins/arm32_arm-unknown-linux-gnueabi_O0_int_crc32.bin';
const armCode = async len => (await repoFile(ARM_CODE)).subarray(0, len);

// `~sum` of little-endian words.
function wordChecksum(bytes) {
  let sum = 0;
  for (let at = 0; at < bytes.length; at += 4) {
    sum = (sum + bytes.readUInt32LE(at)) >>> 0;
  }
  return ~sum >>> 0;
}

// Image name: four characters per word, each word big-endian.
function putName(buffer, at, name) {
  for (let i = 0; i < name.length; i++) {
    buffer[at + (i & ~3) + (3 - (i & 3))] = name.charCodeAt(i);
  }
}

// ZynqMP BOOT.BIN as Bootgen lays it out: boot header (width detection
// word, XNLX, no key, FSBL execution address, source offset, FSBL length,
// attributes with CPU select A53 64-bit, checksum, table offsets), register
// table at 0xB8 with unused addresses, image header table at 0x8C0
// (version 1.2, checksum), one image header per partition at 0x900,
// partition headers at 0x980 (A53-0 FSBL, PL bitstream) and a null header,
// data from 0x1000.
function zynqmpBootBin(fsbl, bitstream) {
  const pht = 0x980;
  const fsblAt = 0x1000;
  const bitstreamAt = fsblAt + fsbl.length;
  const image = Buffer.alloc(bitstreamAt + bitstream.length);
  for (let i = 0; i < 8; i++) {
    image.writeUInt32LE(0x14000000, i * 4);
  }
  image.writeUInt32LE(0xaa995566, 0x20);
  image.write('XNLX', 0x24, 'latin1');
  image.writeUInt32LE(0xfffc0000, 0x2c);
  image.writeUInt32LE(fsblAt, 0x30);
  image.writeUInt32LE(fsbl.length, 0x3c);
  image.writeUInt32LE(fsbl.length, 0x40);
  image.writeUInt32LE(2 << 10, 0x44);
  image.writeUInt32LE(wordChecksum(image.subarray(0x20, 0x48)), 0x48);
  image.writeUInt32LE(0x8c0, 0x98);
  image.writeUInt32LE(pht, 0x9c);
  for (let pair = 0; pair < 256; pair++) {
    image.writeUInt32LE(0xffffffff, 0xb8 + pair * 8);
  }
  image.writeUInt32LE(0x01020000, 0x8c0);
  image.writeUInt32LE(2, 0x8c4);
  image.writeUInt32LE(pht / 4, 0x8c8);
  image.writeUInt32LE(0x900 / 4, 0x8cc);
  image.writeUInt32LE(wordChecksum(image.subarray(0x8c0, 0x8fc)), 0x8fc);
  const partitions = [
    // A53-0 (bits 11:8), destination device PS (6:4), EL3 (2:1).
    { name: 'fsbl.elf', at: fsblAt, length: fsbl.length, address: 0xfffc0000, attributes: 0x100 | 0x10 | 0x6 },
    { name: 'design.bit', at: bitstreamAt, length: bitstream.length, address: 0xffffffff, attributes: 2 << 4 },
  ];
  partitions.forEach((partition, i) => {
    const imageHeader = 0x900 + 0x40 * i;
    const header = pht + 0x40 * i;
    image.writeUInt32LE(i + 1 < partitions.length ? (imageHeader + 0x40) / 4 : 0, imageHeader);
    image.writeUInt32LE(header / 4, imageHeader + 4);
    image.writeUInt32LE(1, imageHeader + 0x0c);
    putName(image, imageHeader + 0x10, partition.name);
    image.writeUInt32LE(partition.length / 4, header);
    image.writeUInt32LE(partition.length / 4, header + 4);
    image.writeUInt32LE(partition.length / 4, header + 8);
    image.writeUInt32LE(i + 1 < partitions.length ? (header + 0x40) / 4 : 0, header + 0x0c);
    image.writeBigUInt64LE(BigInt(partition.address), header + 0x10);
    image.writeBigUInt64LE(BigInt(partition.address), header + 0x18);
    image.writeUInt32LE(partition.at / 4, header + 0x20);
    image.writeUInt32LE(partition.attributes, header + 0x24);
    image.writeUInt32LE(imageHeader / 4, header + 0x30);
    image.writeUInt32LE(wordChecksum(image.subarray(header, header + 0x3c)), header + 0x3c);
  });
  image.writeUInt32LE(0xffffffff, pht + 0x40 * partitions.length + 0x3c);
  fsbl.copy(image, fsblAt);
  bitstream.copy(image, bitstreamAt);
  return image;
}

// u-boot.imx: IVT (tag 0xD1, length 0x0020 big-endian, version 0x41, entry,
// boot data and self pointers), boot data (image start 0x400 before the
// IVT, size rounded to 4 KiB), the application 0xC00 after the IVT.
function ubootImx(app) {
  const self = 0x877ff400;
  const fileLength = 0x1000 * Math.ceil((0xc00 + app.length + 0x400) / 0x1000) - 0x400;
  const image = Buffer.alloc(fileLength);
  image.set([0xd1, 0x00, 0x20, 0x41], 0);
  image.writeUInt32LE(self + 0xc00, 0x04);
  image.writeUInt32LE(self + 0x20, 0x10);
  image.writeUInt32LE(self, 0x14);
  image.writeUInt32LE(self - 0x400, 0x20);
  image.writeUInt32LE(fileLength + 0x400, 0x24);
  app.copy(image, 0xc00);
  return image;
}

// Deterministic filler bytes.
function noise(length, seed) {
  const bytes = Buffer.alloc(length);
  let state = seed;
  for (let i = 0; i < length; i++) {
    state = (state * 1103515245 + 12345) >>> 0;
    bytes[i] = state >>> 24;
  }
  return bytes;
}

// SB3.1: header (sbv3, version 1.3, block count 2, block size 292,
// block 0 length, image type 6, certificate block offset 0x5C), the hash of
// data block 1, certificate block V2.1 (chdr, 64 B), a 64 B signature, then
// data blocks (number, hash of the next block, 256 B), hashed backwards.
function sb31() {
  const blocks = [];
  let nextHash = Buffer.alloc(32);
  for (let number = 2; number >= 1; number--) {
    const block = Buffer.concat([Buffer.alloc(4), nextHash, noise(256, number)]);
    block.writeUInt32LE(number, 0);
    nextHash = createHash('sha256').update(block).digest();
    blocks.unshift(block);
  }
  const block0 = Buffer.alloc(0x5c + 64 + 64);
  block0.write('sbv3', 0, 'latin1');
  block0.writeUInt16LE(1, 4);
  block0.writeUInt16LE(3, 6);
  block0.writeUInt32LE(blocks.length, 0x0c);
  block0.writeUInt32LE(292, 0x10);
  block0.writeUInt32LE(block0.length, 0x20);
  block0.writeUInt32LE(6, 0x24);
  block0.writeUInt32LE(0x5c, 0x28);
  nextHash.copy(block0, 0x3c);
  block0.write('chdr', 0x5c, 'latin1');
  block0.writeUInt32LE(64, 0x5c + 8);
  return Buffer.concat([block0, ...blocks]);
}

async function fixtures() {
  return [
    ['boot.bin', zynqmpBootBin(await aarch64Code(2048), noise(256, 7))],
    ['u-boot.imx', ubootImx(await armCode(2048))],
    ['update.sb3', sb31()],
  ].map(([name, bytes]) => ({ name, bytes: [...bytes] }));
}

const slice = (payload, label) => payload.slices.find(s => s.label === label);

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`SoC boot images report their targets and opaque parts through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const payloads = await page.evaluate(async ({ module, fixtures }) => {
      const wasm = await import(module);
      await wasm.default();
      return Object.fromEntries(fixtures.map(f => [f.name, JSON.parse(wasm.classify(new Uint8Array(f.bytes)))]));
    }, { module, fixtures: await fixtures() });
    for (const [name, p] of Object.entries(payloads)) {
      assert.ok(!p.error, `${name}: ${p.error}`);
      assert.ok(Object.hasOwn(FORMAT_NAMES, p.format.format), `${p.format.format} has a display name`);
    }
    const bootBin = payloads['boot.bin'];
    assert.equal(bootBin.format.format, 'xilinxbootbin');
    assert.deepEqual([bootBin.primary.isa, bootBin.primary.bitwidth], ['a_arch64', 64]);
    assert.equal(slice(bootBin, 'FSBL').isa, 'a_arch64');
    assert.equal(slice(bootBin, 'FSBL').offset, 0x1000);
    assert.deepEqual(slice(bootBin, 'Partition 1: design.bit').isa, { unknown: 0 });
    const imx = payloads['u-boot.imx'];
    assert.equal(imx.format.format, 'imximage');
    assert.equal(imx.primary.isa, 'arm');
    assert.equal(imx.primary.source, 'combined');
    assert.ok(imx.notes.some(n => n.message.includes('the IVT names no CPU or instruction set')));
    // The application bytes start after the IVT (32 B) and boot data (12 B).
    assert.equal(slice(imx, 'Application image').isa, 'arm');
    assert.equal(slice(imx, 'Application image').offset, 0x2c);
    const sb = payloads['update.sb3'];
    assert.equal(sb.format.format, 'nxpsb');
    assert.deepEqual(sb.primary.isa, { unknown: 0 });
    assert.ok(sb.notes.some(n => n.message.includes('SHA-256 block hash chain verified')));
    const blocks = slice(sb, 'Data blocks');
    assert.deepEqual([blocks.offset, blocks.size, blocks.isa], [0x5c + 64 + 64, 2 * 292, { unknown: 0 }]);
    for (const id of ['xilinxbootbin', 'imximage', 'nxpsb']) {
      assert.ok(Object.hasOwn(FORMAT_NAMES, id), `${id} has a display name`);
    }
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names BOOT.BIN images and keeps partition offsets in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const buffer = zynqmpBootBin(await aarch64Code(2048), noise(256, 7));
    const file = { name: 'BOOT.BIN', buffer, mimeType: 'application/octet-stream' };
    await page.locator('#fileinput').setInputFiles([file]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes('Xilinx BOOT.BIN'), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.primary.isa, 'a_arch64');
    assert.ok(p.metadata.some(m => m.key?.custom === 'zynq_partition_count' && m.value === 2));
  });
}
