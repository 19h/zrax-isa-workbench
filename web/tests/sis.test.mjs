import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { deflateSync } from 'node:zlib';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup);
after(teardown);

// Compiled little-endian 32-bit Arm code from the repository's testbins.
const ARM_CODE = '../../testbins/arm32_arm-unknown-linux-gnueabi_O0_call_nested.bin';
const armCode = () => readFile(new URL(ARM_CODE, import.meta.url));

// SISField types (Symbian OS v9 SIS File Format Specification, Appendix A).
const SIS_STRING = 1;
const SIS_ARRAY = 2;
const SIS_COMPRESSED = 3;
const SIS_VERSION = 4;
const SIS_DATE = 6;
const SIS_TIME = 7;
const SIS_DATE_TIME = 8;
const SIS_UID = 9;
const SIS_LANGUAGE = 11;
const SIS_CONTENTS = 12;
const SIS_CONTROLLER = 13;
const SIS_INFO = 14;
const SIS_SUPPORTED_LANGUAGES = 15;
const SIS_SUPPORTED_OPTIONS = 16;
const SIS_PREREQUISITES = 17;
const SIS_DEPENDENCY = 18;
const SIS_PROPERTIES = 19;
const SIS_PROPERTY = 20;
const SIS_FILE_DESCRIPTION = 24;
const SIS_HASH = 25;
const SIS_IF = 26;
const SIS_INSTALL_BLOCK = 28;
const SIS_DATA = 30;
const SIS_DATA_UNIT = 31;
const SIS_FILE_DATA = 32;
const SIS_SUPPORTED_OPTION = 33;
const SIS_CONTROLLER_CHECKSUM = 34;
const SIS_DATA_CHECKSUM = 35;
const SIS_BLOB = 37;
const SIS_DATA_INDEX = 40;

const SISX_UID1 = 0x10201a7a;
const COMPRESS_NONE = 0;
const COMPRESS_DEFLATE = 1;
const HASH_SHA1 = 1;
const OP_INSTALL = 1;
const ENGLISH = 1;
const PACKAGE_UID = 0xa0001234;
const EXE_TARGET = '!:\\sys\\bin\\hello.exe';
const RSC_TARGET = '!:\\resource\\apps\\hello.rsc';

const u8 = value => Buffer.from([value]);
const u16 = value => {
  const word = Buffer.alloc(2);
  word.writeUInt16LE(value);
  return word;
};
const u32 = value => {
  const word = Buffer.alloc(4);
  word.writeUInt32LE(value);
  return word;
};
const u64 = value => {
  const word = Buffer.alloc(8);
  word.writeBigUInt64LE(BigInt(value));
  return word;
};
const utf16 = text => Buffer.from(text, 'utf16le');
const sha1 = bytes => createHash('sha1').update(bytes).digest();

// CRC-16 with polynomial 0x1021, initial value 0, no reflection and no final XOR (MakeSIS `DoTheCrc`).
function crc16(bytes) {
  let crc = 0;
  for (const byte of bytes) {
    crc ^= byte << 8;
    for (let bit = 0; bit < 8; bit++) {
      crc = crc & 0x8000 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
    }
  }
  return crc;
}

// A SISArray element: 31-bit length, value and zero padding to 4 bytes, without the type.
function element(value) {
  const padding = Buffer.alloc((4 - (value.length % 4)) % 4);
  return Buffer.concat([u32(value.length), value, padding]);
}
// A SISField: 32-bit type, then the element form.
const field = (kind, ...parts) => Buffer.concat([u32(kind), element(Buffer.concat(parts))]);
// A SISArray: the element type, then each element's value without its type.
const array = (elementType, values) => field(SIS_ARRAY, u32(elementType), ...values.map(element));
const string = text => field(SIS_STRING, utf16(text));
// SISCompressed: algorithm, uncompressed size (u64), stored bytes (zlib streams for deflate, as MakeSIS writes).
function compressed(algorithm, contents) {
  const stored = algorithm === COMPRESS_DEFLATE ? deflateSync(contents) : contents;
  return field(SIS_COMPRESSED, u32(algorithm), u64(contents.length), stored);
}

// The UID checksum: CRC-16 of the UIDs' odd bytes in the high half, of their even bytes in the low half.
function fileHeader(uid3) {
  const uids = Buffer.concat([u32(SISX_UID1), u32(0), u32(uid3)]);
  const even = Buffer.from(uids.filter((_, i) => i % 2 === 0));
  const odd = Buffer.from(uids.filter((_, i) => i % 2 === 1));
  return Buffer.concat([uids, u32(((crc16(odd) << 16) | crc16(even)) >>> 0)]);
}

// A synthetic E32 executable: UID1 0x1000007A, UID2 0x100039CE, UID3, zero UID checksum, `EPOC` at 0x10, zero
// header words to 0x40, then the code.
function e32Image(code) {
  const header = Buffer.alloc(0x40);
  header.writeUInt32LE(0x1000007a, 0);
  header.writeUInt32LE(0x100039ce, 4);
  header.writeUInt32LE(PACKAGE_UID, 8);
  header.write('EPOC', 0x10, 'latin1');
  return Buffer.concat([header, code]);
}

// SISFileDescription: target, MIME type, SISHash (SHA-1 in a SISBlob), operation, options, stored and uncompressed
// lengths, file index.
const description = (target, file, index) => Buffer.concat([
  string(target), string(''), field(SIS_HASH, u32(HASH_SHA1), field(SIS_BLOB, sha1(file))),
  u32(OP_INSTALL), u32(0), u64(file.length), u64(file.length), u32(index),
]);

// SISController: SISInfo (UID, vendor, names, vendor names, version 1.2.3, creation time, install type and flags),
// options, languages, prerequisites, properties, install block, no signatures, data index 0.
function controller(files) {
  const dateTime = field(SIS_DATE_TIME, field(SIS_DATE, u16(2024), u8(2), u8(5)), field(SIS_TIME, u8(6), u8(7), u8(8)));
  const info = field(SIS_INFO, field(SIS_UID, u32(PACKAGE_UID)), string('Example Vendor'),
    array(SIS_STRING, [utf16('Hello')]), array(SIS_STRING, [utf16('Vendor-EN')]),
    field(SIS_VERSION, u32(1), u32(2), u32(3)), dateTime, u8(0), u8(0));
  return field(SIS_CONTROLLER, info,
    field(SIS_SUPPORTED_OPTIONS, array(SIS_SUPPORTED_OPTION, [])),
    field(SIS_SUPPORTED_LANGUAGES, array(SIS_LANGUAGE, [u32(ENGLISH)])),
    field(SIS_PREREQUISITES, array(SIS_DEPENDENCY, []), array(SIS_DEPENDENCY, [])),
    field(SIS_PROPERTIES, array(SIS_PROPERTY, [])),
    field(SIS_INSTALL_BLOCK, array(SIS_FILE_DESCRIPTION, files), array(SIS_CONTROLLER, []), array(SIS_IF, [])),
    field(SIS_DATA_INDEX, u32(0)));
}

// A package with a deflated executable and a stored resource file. SISContents holds both CRC-16s (of the whole
// compressed controller and data fields), the zlib-compressed controller and the data unit.
function sisPackage(code) {
  const exe = e32Image(code);
  const rsc = Buffer.concat([u32(0x101f4a6b), Buffer.from('resource strings', 'latin1').map(b => b ^ 0x5a)]);
  const descriptions = [description(EXE_TARGET, exe, 0), description(RSC_TARGET, rsc, 1)];
  const controllerField = compressed(COMPRESS_DEFLATE, controller(descriptions));
  const files = [compressed(COMPRESS_DEFLATE, exe), compressed(COMPRESS_NONE, rsc)];
  const dataField = field(SIS_DATA, array(SIS_DATA_UNIT, [array(SIS_FILE_DATA, files)]));
  const contents = field(SIS_CONTENTS, field(SIS_CONTROLLER_CHECKSUM, u16(crc16(controllerField))),
    field(SIS_DATA_CHECKSUM, u16(crc16(dataField))), controllerField, dataField);
  const file = Buffer.concat([fileHeader(PACKAGE_UID), contents]);
  const stream = deflateSync(exe);
  return { file, exe, streamOffset: file.indexOf(stream), streamSize: stream.length };
}

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`Symbian SIS packages classify through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const sis = sisPackage(await armCode());
    const p = await page.evaluate(async ({ module, bytes }) => {
      const wasm = await import(module);
      await wasm.default();
      return JSON.parse(wasm.classify(new Uint8Array(bytes)));
    }, { module, bytes: [...sis.file] });
    assert.ok(!p.error, p.error);
    assert.equal(p.format.format, 'symbiansis');
    assert.equal(p.format.variant_name, 'Symbian OS v9 SIS package');
    assert.ok(Object.hasOwn(FORMAT_NAMES, 'symbiansis'), 'symbiansis has a display name');
    assert.deepEqual([p.primary.isa, p.primary.bitwidth, p.primary.endianness], ['arm', 32, 'little']);
    assert.equal(p.slices.length, 1);
    const exe = p.slices.find(s => s.label === EXE_TARGET);
    assert.ok(exe, `${EXE_TARGET} slice`);
    assert.deepEqual([exe.isa, exe.offset, exe.size], ['arm', sis.streamOffset, sis.streamSize]);
    assert.deepEqual(exe.decoded, { transform: 'zlib', offset: 0, size: sis.exe.length });
    const packageNote = 'Package "Hello"; UID 0xA0001234; version 1.2.3; vendor "Example Vendor"';
    assert.ok(p.notes.some(n => n.message === packageNote));
    assert.ok(p.notes.some(n => n.message === 'SHA-1 of 1 listed file matches the SISHash'));
    const crcNote = /^Controller CRC-16 0x[0-9A-F]{4} matches; data CRC-16 0x[0-9A-F]{4} matches$/;
    assert.ok(p.notes.some(n => crcNote.test(n.message)));
    assert.ok(p.metadata.some(m => m.key?.custom === 'sis_package_uid' && m.value === '0xA0001234'));
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names Symbian SIS packages in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const { file } = sisPackage(await armCode());
    const upload = { name: 'hello.sisx', buffer: file, mimeType: 'application/octet-stream' };
    await page.locator('#fileinput').setInputFiles([upload]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes(FORMAT_NAMES.symbiansis), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.primary.isa, 'arm');
    assert.ok(p.metadata.some(m => m.key?.custom === 'sis_image_size' && m.value === file.length));
  });
}
