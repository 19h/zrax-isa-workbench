import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { crc32, deflateSync } from 'node:zlib';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup);
after(teardown);

// A 256-byte x86-64 ELF header and filler (tests/fixtures/compressed/README.md).
const payloadElf = () => readFile(new URL('../../tests/fixtures/compressed/payload.elf', import.meta.url));

const u16 = value => {
  const bytes = Buffer.alloc(2);
  bytes.writeUInt16LE(value);
  return bytes;
};
const u32 = value => {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32LE(value);
  return bytes;
};
const be32 = value => {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32BE(value);
  return bytes;
};

// --- MikroTik NPK ---

const NPK_MAGIC = 0xbad0f11e;
const NAME_INFO = 0x01;
const FILE_CONTAINER = 0x04;
const SIGNATURE = 0x09;
const MODE_FILE = 0x81ed;

// A part: type (2), payload size (4), payload; all little-endian.
const npkPart = (kind, payload) => Buffer.concat([u16(kind), u32(payload.length), payload]);

// NAME_INFO: name NUL-padded to 16, version bytes revision, build (102: final), minor, major (7.15.1), build time,
// then 12 zero bytes.
function nameInfo(name) {
  const payload = Buffer.alloc(36);
  payload.write(name, 0, 'latin1');
  payload.set([1, 102, 15, 7], 16);
  payload.writeUInt32LE(1700000000, 20);
  return payload;
}

// A file container entry: st_mode (2), user and group (6), modification time, version bytes, creation time, an
// unknown word, data size, name size (2), name, data.
function fileEntry(name, contents) {
  const header = Buffer.alloc(30);
  header.writeUInt16LE(MODE_FILE, 0);
  header.writeUInt32LE(contents.length, 24);
  header.writeUInt16LE(name.length, 28);
  return Buffer.concat([header, Buffer.from(name, 'latin1'), contents]);
}

// Magic, size after the size field, the name and file container parts, then the signature part: the SHA-1 of the
// parts and of the signature part's own header, a zero KCDSA signature (48 B) and a zero EdDSA signature (64 B).
function npk(elf) {
  const parts = [
    npkPart(NAME_INFO, nameInfo('zrax-test')),
    npkPart(FILE_CONTAINER, deflateSync(fileEntry('bin/payload.elf', elf))),
  ];
  const signatureHeader = Buffer.concat([u16(SIGNATURE), u32(20 + 48 + 64)]);
  const digest = createHash('sha1').update(Buffer.concat([...parts, signatureHeader])).digest();
  parts.push(Buffer.concat([signatureHeader, digest, Buffer.alloc(48 + 64)]));
  const body = Buffer.concat(parts);
  return { bytes: Buffer.concat([u32(NPK_MAGIC), u32(body.length), body]), containerOffset: 8 + parts[0].length + 6 };
}

// --- Ubiquiti ---

// Header: magic, version NUL-padded to 256, the CRC-32 of both (big-endian), a zero pad.
function ubntHeader(magic, version) {
  const header = Buffer.alloc(268);
  header.write(magic, 0, 'latin1');
  header.write(version, 4, 'latin1');
  header.writeUInt32BE(crc32(header.subarray(0, 260)), 260);
  return header;
}

// A PART record: magic, name NUL-padded to 16, 12 pad bytes, memory address, index, flash base, entry address, data
// size, partition size (big-endian), the data, the CRC-32 of header and data, a zero pad.
function ubntPart(name, index, data) {
  const header = Buffer.alloc(56);
  header.write('PART', 0, 'latin1');
  header.write(name, 4, 'latin1');
  header.writeUInt32BE(0x80002000, 32);
  header.writeUInt32BE(index, 36);
  header.writeUInt32BE(0x9f050000, 40);
  header.writeUInt32BE(0x80002000, 44);
  header.writeUInt32BE(data.length, 48);
  header.writeUInt32BE(0x100000, 52);
  const record = Buffer.concat([header, data]);
  return Buffer.concat([record, be32(crc32(record)), Buffer.alloc(4)]);
}

// Header, the kernel partition, then END. with the CRC-32 of everything before it and a zero pad.
function ubnt(elf) {
  const image = Buffer.concat([ubntHeader('UBNT', 'XM.ar7240.v6.0.0-zrax'), ubntPart('kernel', 1, elf)]);
  return Buffer.concat([image, Buffer.from('END.', 'latin1'), be32(crc32(image)), Buffer.alloc(4)]);
}

// --- ChromeOS kernel partition ---

const BODY_LOAD_ADDRESS = 0x100000;
const PAGE = 4096;
const VBLOCK_SIZE = 64 << 10;
const RSA2048_SIGNATURE = 256;

// A vb2_signature at `at`: data offset from the structure, data size, signed size (each followed by a reserved word).
function putSignature(block, at, dataAt, size, signed) {
  block.writeUInt32LE(dataAt - at, at);
  block.writeUInt32LE(size, at + 8);
  block.writeUInt32LE(signed, at + 16);
}

// The keyblock: CHROMEOS, version 2.1, size, the signature at 24, the SHA-512 hash at 48, flags 0x5 at 72, the data
// key at 80 (offset from the key structure, size, algorithm 4 = RSA2048 SHA256, version 1), the key bytes, the hash of
// header and key, a zero RSA-2048 signature.
function keyblock() {
  const key = Buffer.from('zrax-data-key-16', 'latin1');
  const hashAt = 112 + key.length;
  const signatureAt = hashAt + 64;
  const block = Buffer.alloc(signatureAt + RSA2048_SIGNATURE);
  block.write('CHROMEOS', 0, 'latin1');
  block.writeUInt32LE(2, 8);
  block.writeUInt32LE(1, 12);
  block.writeUInt32LE(block.length, 16);
  putSignature(block, 24, signatureAt, RSA2048_SIGNATURE, hashAt);
  putSignature(block, 48, hashAt, 64, hashAt);
  block.writeUInt32LE(0x5, 72);
  block.writeUInt32LE(112 - 80, 80);
  block.writeUInt32LE(key.length, 88);
  block.writeUInt32LE(4, 96);
  block.writeUInt32LE(1, 104);
  key.copy(block, 112);
  createHash('sha512').update(block.subarray(0, hashAt)).digest().copy(block, hashAt);
  return block;
}

// The 2.2 kernel preamble padded to fill the 64 KiB vblock: size, the preamble signature at 8, version 2.2 at 32,
// kernel version 1, body load address, bootloader address and size, the body signature at 72 (signing the whole
// blob), no vmlinuz header, flags 0, then the signature data.
function preamble(size, bootloaderOffset, bodySize) {
  const bodySignatureAt = 116;
  const signatureAt = bodySignatureAt + RSA2048_SIGNATURE;
  const block = Buffer.alloc(size);
  block.writeUInt32LE(size, 0);
  putSignature(block, 8, signatureAt, RSA2048_SIGNATURE, signatureAt);
  block.writeUInt32LE(2, 32);
  block.writeUInt32LE(2, 36);
  block.writeUInt32LE(1, 40);
  block.writeBigUInt64LE(BigInt(BODY_LOAD_ADDRESS), 48);
  block.writeBigUInt64LE(BigInt(BODY_LOAD_ADDRESS + bootloaderOffset), 56);
  putSignature(block, 72, bodySignatureAt, RSA2048_SIGNATURE, bodySize);
  return block;
}

// An AArch64 Image (magic ARM\x64 at 0x38) in the kernel slot (4 KiB), the command line and boot parameter pages,
// and no bootloader: futility's blob layout.
function chromeos() {
  const blob = Buffer.alloc(3 * PAGE);
  blob.write('ARM\x64', 0x38, 'latin1');
  blob.write('console=ttyS0', PAGE, 'latin1');
  const block = keyblock();
  const bootloaderOffset = 3 * PAGE;
  return Buffer.concat([block, preamble(VBLOCK_SIZE - block.length, bootloaderOffset, blob.length), blob]);
}

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`firmware package wrappers classify through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const elf = await payloadElf();
    const npkFixture = npk(elf);
    const inputs = [npkFixture.bytes, ubnt(elf), chromeos()];
    const payloads = await page.evaluate(async ({ module, inputs }) => {
      const wasm = await import(module);
      await wasm.default();
      return inputs.map(bytes => JSON.parse(wasm.classify(new Uint8Array(bytes))));
    }, { module, inputs: inputs.map(input => [...input]) });
    const [npkPayload, ubntPayload, chromeosPayload] = payloads;

    assert.ok(!npkPayload.error, npkPayload.error);
    assert.equal(npkPayload.format.format, 'mikrotiknpk');
    assert.equal(npkPayload.primary.isa, 'x86_64');
    const file = npkPayload.slices.find(s => s.label === 'bin/payload.elf');
    assert.ok(file, 'bin/payload.elf slice');
    assert.deepEqual([file.isa, file.offset, file.decoded.transform, file.decoded.size],
      ['x86_64', npkFixture.containerOffset, 'zlib', elf.length]);
    const digest = 'Package zrax-test: SHA-1 digest verified; '
      + 'KCDSA (48 B) and EdDSA (64 B) signatures present, not verified';
    assert.ok(npkPayload.notes.some(n => n.message === digest), digest);

    assert.ok(!ubntPayload.error, ubntPayload.error);
    assert.equal(ubntPayload.format.format, 'ubiquitifw');
    assert.equal(ubntPayload.primary.isa, 'x86_64');
    const kernel = ubntPayload.slices.find(s => s.label === 'kernel');
    assert.deepEqual([kernel.isa, kernel.offset, kernel.size], ['x86_64', 268 + 56, elf.length]);

    assert.ok(!chromeosPayload.error, chromeosPayload.error);
    assert.equal(chromeosPayload.format.format, 'chromeoskernel');
    assert.equal(chromeosPayload.primary.isa, 'a_arch64');
    const image = chromeosPayload.slices.find(s => s.label === 'Kernel');
    assert.deepEqual([image.isa, image.offset, image.size], ['a_arch64', VBLOCK_SIZE, PAGE]);
    assert.ok(chromeosPayload.notes.some(n => n.message.includes('keyblock SHA-512 hash verified')));

    for (const id of ['mikrotiknpk', 'ubiquitifw', 'chromeoskernel']) {
      assert.ok(Object.hasOwn(FORMAT_NAMES, id), `${id} has a display name`);
    }
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names firmware package wrappers in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const buffer = ubnt(await payloadElf());
    const upload = { name: 'XM.v6.0.0.bin', buffer, mimeType: 'application/octet-stream' };
    await page.locator('#fileinput').setInputFiles([upload]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes(FORMAT_NAMES.ubiquitifw), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.primary.isa, 'x86_64');
    assert.ok(p.metadata.some(m => m.key?.custom === 'ubnt_image_size' && m.value === buffer.length));
  });
}
