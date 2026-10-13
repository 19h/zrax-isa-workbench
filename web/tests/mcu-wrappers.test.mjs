import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';

before(setup);
after(teardown);

const WRAPPER_IDS = ['dfusuffix', 'silabsebl', 'nordicinitpacket'];

// Cortex-M4 Thumb-2 code from tests/fixtures/mcu/generate.sh and the init
// packet that tests/fixtures/mcu/generate-init-packets.sh encodes with protoc.
const fixture = name => readFile(new URL(`../../tests/fixtures/mcu/${name}`, import.meta.url));

// CRC-32 register over `bytes` (reflected polynomial 0xEDB88320, initial
// value 0xFFFFFFFF, no final inversion).
function crc32Register(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) {
      crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
    }
  }
  return crc >>> 0;
}

// zlib CRC-32: the register, inverted.
const crc32 = bytes => ~crc32Register(bytes) >>> 0;

// USB DFU 1.1 file: the firmware, then bcdDevice, idProduct, idVendor,
// bcdDFU 0x0100, "UFD", bLength 16 (little-endian) and the CRC register over
// everything before it.
function dfuFile(firmware) {
  const suffix = Buffer.alloc(12);
  suffix.writeUInt16LE(0x0102, 0);
  suffix.writeUInt16LE(0x0001, 2);
  suffix.writeUInt16LE(0x1209, 4);
  suffix.writeUInt16LE(0x0100, 6);
  suffix.write('UFD', 8);
  suffix[11] = 16;
  const body = Buffer.concat([firmware, suffix]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32LE(crc32Register(body), 0);
  return Buffer.concat([body, crc]);
}

// One EBL tag: big-endian tag ID and length, then the payload.
function eblTag(id, payload) {
  const header = Buffer.alloc(4);
  header.writeUInt16BE(id, 0);
  header.writeUInt16BE(payload.length, 2);
  return Buffer.concat([header, payload]);
}

// EBL file: header tag (version 0x0201, signature 0xE350, flashAddr 0x4000,
// aatCrc, 128-byte AAT with type 0x0AA7, platform 4 CortexM3 and micro 24
// efr32, little-endian), one erase-then-program tag at 0x4080 and the end
// tag whose little-endian CRC is the zlib CRC-32 of everything before it.
function eblFile(code) {
  const aat = Buffer.alloc(128);
  aat.writeUInt32LE(0x20008000, 0);
  aat.writeUInt32LE(0x000040c1, 4);
  aat.writeUInt16LE(0x0aa7, 16);
  aat[24] = 4;
  aat[25] = 24;
  const fields = Buffer.alloc(12);
  fields.writeUInt16BE(0x0201, 0);
  fields.writeUInt16BE(0xe350, 2);
  fields.writeUInt32BE(0x00004000, 4);
  fields.writeUInt32BE(0x12345678, 8);
  const address = Buffer.alloc(4);
  address.writeUInt32BE(0x00004080, 0);
  const endHeader = Buffer.alloc(4);
  endHeader.writeUInt16BE(0xfc04, 0);
  endHeader.writeUInt16BE(4, 2);
  const body = Buffer.concat([
    eblTag(0x0000, Buffer.concat([fields, aat])),
    eblTag(0xfd03, Buffer.concat([address, code])),
    endHeader,
  ]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32LE(crc32(body), 0);
  return Buffer.concat([body, crc]);
}

const custom = (p, key) => p.metadata.find(m => m.key?.custom === key)?.value;

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`MCU update wrappers report their format, ISA and slices through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const thumb = await fixture('thumbv7em.text.bin');
    const fixtures = [
      ['dfusuffix', dfuFile(thumb)],
      ['silabsebl', eblFile(thumb)],
      ['nordicinitpacket', await fixture('nordic-init-signed.dat')],
    ].map(([name, bytes]) => ({ name, bytes: [...bytes] }));
    const payloads = await page.evaluate(async ({ module, fixtures }) => {
      const wasm = await import(module);
      await wasm.default();
      return Object.fromEntries(fixtures.map(f => [f.name, JSON.parse(wasm.classify(new Uint8Array(f.bytes)))]));
    }, { module, fixtures });
    for (const id of WRAPPER_IDS) {
      const p = payloads[id];
      assert.ok(!p.error, `${id}: ${p.error}`);
      assert.equal(p.format.format, id);
      assert.ok(Object.hasOwn(FORMAT_NAMES, id), `${id} has a display name`);
    }
    const dfu = payloads.dfusuffix;
    assert.equal(dfu.primary.isa, 'arm');
    assert.equal(dfu.slices.length, 1);
    assert.equal(dfu.slices[0].label, 'DFU firmware');
    assert.equal(dfu.slices[0].offset, 0);
    assert.equal(dfu.slices[0].size, thumb.length);
    assert.equal(custom(dfu, 'dfu_vendor_id'), '0x1209');
    const ebl = payloads.silabsebl;
    assert.equal(ebl.primary.isa, 'arm');
    assert.equal(ebl.primary.source, 'file_format');
    assert.equal(custom(ebl, 'ebl_platform'), '4 (CortexM3)');
    assert.equal(custom(ebl, 'ebl_section_0'), `file 0x98; destination 0x4080; ${thumb.length} B`);
    const nordic = payloads.nordicinitpacket;
    assert.deepEqual(nordic.primary.isa, { unknown: 0 });
    assert.equal(nordic.slices?.length ?? 0, 0);
    assert.equal(custom(nordic, 'nordic_fw_type'), 'APPLICATION');
    assert.ok(nordic.notes.some(n => n.message.includes('64 B signature; not verified')));
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names EBL files and keeps the AAT platform in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const buffer = eblFile(await fixture('thumbv7em.text.bin'));
    const file = { name: 'app.ebl', buffer, mimeType: 'application/octet-stream' };
    await page.locator('#fileinput').setInputFiles([file]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes(FORMAT_NAMES.silabsebl), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.primary.isa, 'arm');
    assert.equal(custom(p, 'ebl_micro'), '24 (efr32)');
  });
}
