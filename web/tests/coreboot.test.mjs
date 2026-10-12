import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';

before(setup);
after(teardown);

const fixture = path => readFile(new URL(`../../tests/fixtures/${path}`, import.meta.url));

const TYPE_CBFSHEADER = 0x02;
const TYPE_STAGE = 0x11;
const TYPE_NULL = 0xffffffff;
const COMPRESS_LZMA = 1;
const ARCHITECTURE_AARCH64 = 0xaa64;

// `struct fmap`, little-endian: `__FMAP__`, version 1.1, flash base address
// (u64, 0 here), image size (u32), 32-byte name, area count (u16); then one
// 42-byte area each: offset, size, 32-byte name, flags (0 here).
function fmap(imageSize, name, areas) {
  const map = Buffer.alloc(56 + 42 * areas.length);
  map.write('__FMAP__', 0, 'latin1');
  map[8] = 1;
  map[9] = 1;
  map.writeUInt32LE(imageSize, 18);
  map.write(name, 22, 'latin1');
  map.writeUInt16LE(areas.length, 54);
  areas.forEach((area, i) => {
    const at = 56 + 42 * i;
    map.writeUInt32LE(area.offset, at);
    map.writeUInt32LE(area.size, at + 4);
    map.write(area.name, at + 8, 'latin1');
  });
  return map;
}

// `struct cbfs_file`, big-endian: `LARCHIVE`, data length, type, attributes
// offset (0 for none), data offset; then the name NUL-padded to a multiple
// of 4 bytes, the attributes and the data.
function cbfsFile(type, name, attributes, data) {
  const nameSize = Math.ceil((name.length + 1) / 4) * 4;
  const header = Buffer.alloc(24 + nameSize);
  header.write('LARCHIVE', 0, 'latin1');
  header.writeUInt32BE(data.length, 8);
  header.writeUInt32BE(type, 12);
  header.writeUInt32BE(attributes.length > 0 ? 24 + nameSize : 0, 16);
  header.writeUInt32BE(24 + nameSize + attributes.length, 20);
  header.write(name, 24, 'latin1');
  return Buffer.concat([header, attributes, data]);
}

// Compression attribute: tag `BCZL`, length 16, algorithm, decoded size;
// big-endian.
function compressionAttribute(algorithm, decodedSize) {
  const attribute = Buffer.alloc(16);
  attribute.write('BCZL', 0, 'latin1');
  attribute.writeUInt32BE(16, 4);
  attribute.writeUInt32BE(algorithm, 8);
  attribute.writeUInt32BE(decodedSize, 12);
  return attribute;
}

// Stage-header attribute: tag `StgH`, length 24, load address (u64), entry
// offset (0 here), memory size; big-endian.
function stageAttribute(loadAddress, memorySize) {
  const attribute = Buffer.alloc(24);
  attribute.write('StgH', 0, 'latin1');
  attribute.writeUInt32BE(24, 4);
  attribute.writeBigUInt64BE(loadAddress, 8);
  attribute.writeUInt32BE(memorySize, 20);
  return attribute;
}

// `struct cbfs_header`, big-endian: `ORBC`, version `1112`, ROM size,
// bootblock size 4, alignment 64, first entry 0, architecture, padding.
function masterHeader(romSize, architecture) {
  const header = Buffer.alloc(32);
  header.write('ORBC1112', 0, 'latin1');
  header.writeUInt32BE(romSize, 8);
  header.writeUInt32BE(4, 12);
  header.writeUInt32BE(64, 16);
  header.writeUInt32BE(architecture, 24);
  return header;
}

// A CBFS region of `size` bytes: the files on 64-byte boundaries, then a
// `NULL` entry with an empty name and 0xFF data up to the end.
function cbfsRegion(files, size) {
  const parts = [];
  let length = 0;
  const alignTo64 = () => {
    const padding = Math.ceil(length / 64) * 64 - length;
    parts.push(Buffer.alloc(padding, 0xff));
    length += padding;
  };
  for (const file of files) {
    alignTo64();
    parts.push(file);
    length += file.length;
  }
  alignTo64();
  const free = size - length - 28;
  parts.push(cbfsFile(TYPE_NULL, '', Buffer.alloc(0), Buffer.alloc(free, 0xff)));
  return Buffer.concat(parts);
}

// The COREBOOT region: an AArch64 master header and an LZMA stage holding
// the committed AArch64 code sample.
async function corebootRegion(size) {
  const code = await fixture('transforms/aarch64.text.bin');
  const romstage = await fixture('coreboot/romstage.lzma');
  const attributes = Buffer.concat([
    compressionAttribute(COMPRESS_LZMA, code.length),
    stageAttribute(0x40000000n, 0x2000),
  ]);
  return cbfsRegion([
    cbfsFile(TYPE_CBFSHEADER, 'cbfs master header', Buffer.alloc(0), masterHeader(size, ARCHITECTURE_AARCH64)),
    cbfsFile(TYPE_STAGE, 'fallback/romstage', attributes, romstage),
  ], size);
}

// A 64 KiB AP image: the FMAP at 0, a GBB, the COREBOOT CBFS at 0x2000 and
// an erased area, with RO_SECTION as the parent of the first three.
async function apImage() {
  const areas = [
    { offset: 0x0000, size: 0xc000, name: 'RO_SECTION' },
    { offset: 0x0000, size: 0x1000, name: 'FMAP' },
    { offset: 0x1000, size: 0x100, name: 'GBB' },
    { offset: 0x2000, size: 0xa000, name: 'COREBOOT' },
    { offset: 0xc000, size: 0x4000, name: 'RW_UNUSED' },
  ];
  const image = Buffer.alloc(0x10000, 0xff);
  fmap(image.length, 'FLASH', areas).copy(image, 0);
  Buffer.from('$GBB\x01\x00\x01\x00', 'latin1').copy(image, 0x1000);
  (await corebootRegion(0xa000)).copy(image, 0x2000);
  return image;
}

// A 16 KiB EC image: RISC-V code in EC_RO and EC_RW, with the version string
// and the FMAP (at 0x1040) nested in EC_RO.
async function ecImage() {
  const code = await fixture('transforms/riscv64.text.bin');
  const areas = [
    { offset: 0x0000, size: 0x2000, name: 'EC_RO' },
    { offset: 0x1000, size: 0x20, name: 'RO_FRID' },
    { offset: 0x1040, size: 0x200, name: 'FMAP' },
    { offset: 0x2000, size: 0x2000, name: 'EC_RW' },
  ];
  const image = Buffer.alloc(0x4000, 0xff);
  code.copy(image, 0);
  Buffer.from('ec_test_v1.0.0\0', 'latin1').copy(image, 0x1000);
  fmap(image.length, 'EC_FMAP', areas).copy(image, 0x1040);
  code.copy(image, 0x2000);
  return image;
}

const slice = (payload, label) => payload.slices.find(s => s.label === label);

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`flash maps and CBFS regions classify their components through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const fixtures = [
      ['ap', await apImage()],
      ['cbfs', await corebootRegion(0xa000)],
      ['ec', await ecImage()],
    ].map(([name, bytes]) => ({ name, bytes: [...bytes] }));
    const payloads = await page.evaluate(async ({ module, fixtures }) => {
      const wasm = await import(module);
      await wasm.default();
      const entries = fixtures.map(f => [f.name, JSON.parse(wasm.classify(new Uint8Array(f.bytes)))]);
      return Object.fromEntries(entries);
    }, { module, fixtures });
    for (const [name, payload] of Object.entries(payloads)) {
      assert.ok(!payload.error, `${name}: ${payload.error}`);
      assert.ok(Object.hasOwn(FORMAT_NAMES, payload.format.format), `${payload.format.format} has a display name`);
    }

    const ap = payloads.ap;
    assert.equal(ap.format.format, 'fmap');
    assert.equal(ap.primary.isa, 'a_arch64');
    assert.deepEqual(ap.slices.map(s => s.label), ['FMAP', 'GBB', 'COREBOOT']);
    assert.equal(slice(ap, 'COREBOOT').offset, 0x2000);
    assert.equal(slice(ap, 'COREBOOT').isa, 'a_arch64');
    assert.deepEqual(slice(ap, 'GBB').isa, { unknown: 0 });

    const cbfs = payloads.cbfs;
    const code = await fixture('transforms/aarch64.text.bin');
    assert.equal(cbfs.format.format, 'cbfs');
    assert.equal(cbfs.primary.isa, 'a_arch64');
    const romstage = slice(cbfs, 'fallback/romstage');
    assert.equal(romstage.decoded.transform, 'LZMA');
    assert.equal(romstage.decoded.size, code.length);
    assert.equal(romstage.isa, 'a_arch64');

    const ec = payloads.ec;
    assert.equal(ec.format.format, 'fmap');
    assert.equal(ec.format.variant_name, 'FMAP flash image (map found by search)');
    assert.equal(ec.primary.isa, 'risc_v64');
    assert.equal(slice(ec, 'EC_RO').isa, 'risc_v64');
    assert.ok(Object.hasOwn(FORMAT_NAMES, 'cbfs'));
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names FMAP images and lists their areas in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const buffer = await apImage();
    const file = { name: 'image.bin', buffer, mimeType: 'application/octet-stream' };
    await page.locator('#fileinput').setInputFiles([file]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes('Chromium FMAP'), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const payload = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(payload.primary.isa, 'a_arch64');
    const coreboot = payload.metadata.find(m => m.key?.custom === 'fmap_area_3');
    assert.equal(coreboot?.value, '0x2000 + 40960 B; flags none; classified');
  });
}
