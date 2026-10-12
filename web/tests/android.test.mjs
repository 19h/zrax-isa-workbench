import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { gzipSync } from 'node:zlib';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup);
after(teardown);

const fixture = path => readFile(new URL(`../../tests/fixtures/${path}`, import.meta.url));

// Zero bytes up to the next multiple of `size`.
function padTo(buffer, size) {
  const padded = Buffer.alloc(Math.ceil(buffer.length / size) * size);
  buffer.copy(padded);
  return padded;
}

// Linux arm64 Image: text_offset 0x80000 (u64 at 0x08), image_size (u64 at 0x10), magic ARM\x64 at 0x38; then code.
function arm64Image(code) {
  const header = Buffer.alloc(64);
  header.writeBigUInt64LE(0x80000n, 0x08);
  header.writeBigUInt64LE(BigInt(64 + code.length), 0x10);
  header.write('ARM\x64', 0x38, 'latin1');
  return Buffer.concat([header, code]);
}

// Boot image header v0 (mkbootimg bootimg.h): magic, kernel size and address, ramdisk size and address, no second
// stage, tags address, page size 2048, header version 0, OS version 0, board name at 0x30. The header takes one page;
// the kernel and the ramdisk each start on a page boundary.
function bootImage(kernel, ramdisk) {
  const header = Buffer.alloc(2048);
  header.write('ANDROID!', 0, 'latin1');
  header.writeUInt32LE(kernel.length, 0x08);
  header.writeUInt32LE(0x10008000, 0x0c);
  header.writeUInt32LE(ramdisk.length, 0x10);
  header.writeUInt32LE(0x11000000, 0x14);
  header.writeUInt32LE(0x10000100, 0x20);
  header.writeUInt32LE(2048, 0x24);
  header.write('zboard', 0x30, 'latin1');
  return Buffer.concat([header, padTo(kernel, 2048), padTo(ramdisk, 2048)]);
}

// Sparse image (libsparse sparse_format.h, little-endian): magic 0xED26FF3A, version 1.0, header sizes 28 and 12,
// block size 4096, total blocks, chunk count, image checksum 0; then a RAW chunk (0xCAC1: type, reserved, output
// blocks, input bytes with the header) holding `raw`, and a DONT_CARE chunk (0xCAC3) of one block.
function sparseImage(raw) {
  const header = Buffer.alloc(28);
  header.writeUInt32LE(0xed26ff3a, 0);
  header.writeUInt16LE(1, 4);
  header.writeUInt16LE(28, 8);
  header.writeUInt16LE(12, 10);
  header.writeUInt32LE(4096, 12);
  header.writeUInt32LE(raw.length / 4096 + 1, 16);
  header.writeUInt32LE(2, 20);
  const rawChunk = Buffer.alloc(12);
  rawChunk.writeUInt16LE(0xcac1, 0);
  rawChunk.writeUInt32LE(raw.length / 4096, 4);
  rawChunk.writeUInt32LE(12 + raw.length, 8);
  const dontCare = Buffer.alloc(12);
  dontCare.writeUInt16LE(0xcac3, 0);
  dontCare.writeUInt32LE(1, 4);
  dontCare.writeUInt32LE(12, 8);
  return Buffer.concat([header, rawChunk, raw, dontCare]);
}

// Protobuf varint (protobuf.dev encoding guide): 7 bits per byte, least significant group first.
function varint(value) {
  const bytes = [];
  let rest = value;
  while (rest >= 0x80) {
    bytes.push((rest % 0x80) | 0x80);
    rest = Math.floor(rest / 0x80);
  }
  bytes.push(rest);
  return Buffer.from(bytes);
}

// A varint field (wire type 0) and a length-delimited field (wire type 2).
const pbVarint = (field, value) => Buffer.concat([varint(field * 8), varint(value)]);
const pbBytes = (field, bytes) => Buffer.concat([varint(field * 8 + 2), varint(bytes.length), bytes]);

// OTA payload, major version 2 (update_engine update_metadata.proto): magic CrAU, major version and manifest size
// (u64 BE), metadata signature size 0 (u32 BE); the DeltaArchiveManifest has block size 4096 (field 3), minor version
// 0 (12) and one partition (13) named `name` (1) with one REPLACE operation (8: type 1, data offset 2, data length 3,
// destination extent 6 of start 1 and count 2). The blob follows the manifest.
function otaPayload(name, blob) {
  const extent = Buffer.concat([pbVarint(1, 0), pbVarint(2, blob.length / 4096)]);
  const operation = Buffer.concat([pbVarint(1, 0), pbVarint(2, 0), pbVarint(3, blob.length), pbBytes(6, extent)]);
  const partition = Buffer.concat([pbBytes(1, Buffer.from(name)), pbBytes(8, operation)]);
  const manifest = Buffer.concat([pbVarint(3, 4096), pbBytes(13, partition), pbVarint(12, 0)]);
  const header = Buffer.alloc(24);
  header.write('CrAU', 0, 'latin1');
  header.writeBigUInt64BE(2n, 4);
  header.writeBigUInt64BE(BigInt(manifest.length), 12);
  return Buffer.concat([header, manifest, blob]);
}

// FBPK version 2 (fbpack.py, little-endian): PackHeader of magic FBPK, version 2, header size 112, entry size 104,
// platform (16) at 0x10, pack version (64) at 0x20, slot type, data alignment 16, entry count, total size; then
// PackEntry records of type (0 partition table, 1 partition data), name (36), product (40), absolute data offset and
// size (u64), slotted and crc32. Each data block is aligned to 16 bytes.
function fbpk(entries) {
  const header = Buffer.alloc(112 + 104 * entries.length);
  header.write('FBPK', 0, 'latin1');
  header.writeUInt32LE(2, 4);
  header.writeUInt32LE(112, 8);
  header.writeUInt32LE(104, 12);
  header.write('zrax', 0x10, 'latin1');
  header.write('pack-1.0', 0x20, 'latin1');
  header.writeUInt32LE(16, 0x64);
  header.writeUInt32LE(entries.length, 0x68);
  const blocks = [];
  let offset = header.length;
  entries.forEach(({ type, name, data }, i) => {
    const entry = 112 + 104 * i;
    header.writeUInt32LE(type, entry);
    header.write(name, entry + 4, 'latin1');
    header.writeBigUInt64LE(BigInt(offset), entry + 0x50);
    header.writeBigUInt64LE(BigInt(data.length), entry + 0x58);
    const block = padTo(data, 16);
    blocks.push(block);
    offset += block.length;
  });
  header.writeUInt32LE(offset, 0x6c);
  return Buffer.concat([header, ...blocks]);
}

// The synthetic x86-64 ELF header of the compressed-stream fixtures and the AArch64 code of the transform fixtures.
async function fixtures() {
  const elf = await fixture('compressed/payload.elf');
  const code = await fixture('transforms/aarch64.text.bin');
  return [
    {
      name: 'boot.img',
      bytes: bootImage(gzipSync(arm64Image(code)), Buffer.from('070701 initramfs')),
      format: 'androidboot',
      isa: 'a_arch64',
      label: 'Kernel',
    },
    {
      name: 'system.sparse.img',
      bytes: sparseImage(padTo(elf, 4096)),
      format: 'androidsparse',
      isa: 'x86_64',
      label: 'Expanded image',
    },
    {
      name: 'payload.bin',
      bytes: otaPayload('system', padTo(elf, 4096)),
      format: 'androidota',
      isa: 'x86_64',
      label: 'system',
    },
    {
      name: 'bootloader.img',
      bytes: fbpk([{ type: 0, name: 'partition:0', data: Buffer.from('FBPT') }, { type: 1, name: 'abl', data: elf }]),
      format: 'androidbootloader',
      isa: 'x86_64',
      label: 'abl',
    },
  ];
}

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`Android images report their format and their members' ISAs through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const images = await fixtures();
    const payloads = await page.evaluate(async ({ module, images }) => {
      const wasm = await import(module);
      await wasm.default();
      return images.map(image => JSON.parse(wasm.classify(new Uint8Array(image.bytes))));
    }, { module, images: images.map(image => ({ name: image.name, bytes: [...image.bytes] })) });
    images.forEach(({ name, format, isa, label }, i) => {
      const p = payloads[i];
      assert.ok(!p.error, `${name}: ${p.error}`);
      assert.equal(p.format.format, format, name);
      assert.ok(Object.hasOwn(FORMAT_NAMES, format), `${format} has a display name`);
      assert.equal(p.primary.isa, isa, name);
      const member = p.slices.find(s => s.label === label);
      assert.ok(member, `${name}: slice ${label}`);
      assert.equal(member.isa, isa, `${name}: ${label}`);
    });
    const boot = payloads[images.findIndex(image => image.format === 'androidboot')];
    const kernel = boot.slices.find(s => s.label === 'Kernel');
    assert.equal(kernel.offset, 2048);
    assert.equal(kernel.decoded.transform, 'gzip');
    const sparse = payloads[images.findIndex(image => image.format === 'androidsparse')];
    assert.equal(sparse.slices[0].decoded.transform, 'Android sparse');
    assert.equal(sparse.slices[0].decoded.size, 8192);
    const pack = payloads[images.findIndex(image => image.format === 'androidbootloader')];
    assert.equal(pack.slices.find(s => s.label === 'partition:0').isa.unknown, 0);
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names Android boot images and keeps stored offsets in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const images = await fixtures();
    const boot = images.find(image => image.format === 'androidboot');
    const file = { name: boot.name, buffer: boot.bytes, mimeType: 'application/octet-stream' };
    await page.locator('#fileinput').setInputFiles([file]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes(FORMAT_NAMES.androidboot), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.primary.isa, 'a_arch64');
    assert.equal(p.slices.find(s => s.label === 'Kernel').offset, 2048);
    assert.ok(p.metadata.some(m => m.key?.custom === 'android_boot_header_version' && m.value === 0));
    assert.ok(p.notes.some(n => n.message === 'Android boot image, header v0; page size 2048 B'));
  });
}
