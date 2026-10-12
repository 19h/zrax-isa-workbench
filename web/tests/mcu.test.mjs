import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup);
after(teardown);

const MCU_IDS = ['uf2', 'dfuse', 'gbl', 'cyacd'];

// Cortex-M4 Thumb-2 and RV32IMAC code from tests/fixtures/mcu/generate.sh.
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

const UF2_FLAG_FAMILY_ID_PRESENT = 0x2000;
const RP2350_ARM_S = 0xe48bff59;
const RP2350_RISCV = 0xe48bff5a;

// UF2 blocks of 256 payload bytes: magicStart0, magicStart1, flags,
// targetAddr, payloadSize, blockNo, numBlocks, familyID, data[476],
// magicEnd; every field little-endian.
function uf2(code, address, family) {
  const count = Math.ceil(code.length / 256);
  const blocks = [];
  for (let i = 0; i < count; i++) {
    const payload = code.subarray(i * 256, (i + 1) * 256);
    const block = Buffer.alloc(512);
    block.writeUInt32LE(0x0a324655, 0);
    block.writeUInt32LE(0x9e5d5157, 4);
    block.writeUInt32LE(UF2_FLAG_FAMILY_ID_PRESENT, 8);
    block.writeUInt32LE(address + i * 256, 12);
    block.writeUInt32LE(payload.length, 16);
    block.writeUInt32LE(i, 20);
    block.writeUInt32LE(count, 24);
    block.writeUInt32LE(family, 28);
    payload.copy(block, 32);
    block.writeUInt32LE(0x0ab16f30, 508);
    blocks.push(block);
  }
  return Buffer.concat(blocks);
}

// DfuSe: prefix ("DfuSe", bVersion 1, DFUImageSize, bTargets 1), one
// target prefix ("Target", alternate 0, named, name, dwTargetSize,
// dwNbElements 1), one element (address, size, data), and the DFU suffix
// (bcdDevice, idProduct, idVendor, bcdDFU 0x011A, "UFD", bLength 16, CRC
// register).
function dfuse(code, address) {
  const element = Buffer.alloc(8);
  element.writeUInt32LE(address, 0);
  element.writeUInt32LE(code.length, 4);
  const target = Buffer.alloc(274);
  target.write('Target', 0);
  target.writeUInt32LE(1, 7);
  target.write('Internal Flash', 11);
  target.writeUInt32LE(element.length + code.length, 266);
  target.writeUInt32LE(1, 270);
  const prefix = Buffer.alloc(11);
  prefix.write('DfuSe', 0);
  prefix[5] = 1;
  prefix.writeUInt32LE(11 + target.length + element.length + code.length, 6);
  prefix[10] = 1;
  const suffix = Buffer.alloc(12);
  suffix.writeUInt16LE(0x0200, 0);
  suffix.writeUInt16LE(0xdf11, 2);
  suffix.writeUInt16LE(0x0483, 4);
  suffix.writeUInt16LE(0x011a, 6);
  suffix.write('UFD', 8);
  suffix[11] = 16;
  const body = Buffer.concat([prefix, target, element, code, suffix]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32LE(crc32Register(body), 0);
  return Buffer.concat([body, crc]);
}

// One GBL tag: tagId and length (little-endian), then the payload.
function gblTag(id, payload) {
  const header = Buffer.alloc(8);
  header.writeUInt32LE(id, 0);
  header.writeUInt32LE(payload.length, 4);
  return Buffer.concat([header, payload]);
}

// GBL v3: header tag (version 0x03000000, type 0), one program data tag
// (flashStartAddress, data) and the end tag whose gblCrc is the zlib CRC-32
// of everything before it.
function gbl(code, address) {
  const version = Buffer.alloc(8);
  version.writeUInt32LE(0x03000000, 0);
  const flashAddress = Buffer.alloc(4);
  flashAddress.writeUInt32LE(address, 0);
  const endHeader = Buffer.alloc(8);
  endHeader.writeUInt32LE(0xfc0404fc, 0);
  endHeader.writeUInt32LE(4, 4);
  const body = Buffer.concat([
    gblTag(0x03a617eb, version),
    gblTag(0xfe0101fe, Buffer.concat([flashAddress, code])),
    endHeader,
  ]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32LE(crc32(body), 0);
  return Buffer.concat([body, crc]);
}

const hex = bytes => Buffer.from(bytes).toString('hex').toUpperCase();

// .cyacd: header (silicon ID big-endian, revision, checksum type 0), then
// rows ':' array 0, row number and data length (big-endian), 128 data
// bytes, and the two's complement of the byte sum; CRLF line endings.
function cyacd(code) {
  const lines = ['0490119311' + '00'];
  for (let row = 0; row * 128 < code.length; row++) {
    const data = code.subarray(row * 128, (row + 1) * 128);
    const record = Buffer.alloc(5 + data.length + 1);
    record[0] = 0;
    record.writeUInt16BE(row, 1);
    record.writeUInt16BE(data.length, 3);
    data.copy(record, 5);
    let sum = 0;
    for (const byte of record.subarray(0, record.length - 1)) {
      sum = (sum + byte) & 0xff;
    }
    record[record.length - 1] = (0x100 - sum) & 0xff;
    lines.push(':' + hex(record));
  }
  return Buffer.from(lines.join('\r\n') + '\r\n');
}

const hasCustom = (p, key) => p.metadata.some(m => m.key?.custom === key);

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`MCU update images report their format, ISA and slices through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const thumb = await fixture('thumbv7em.text.bin');
    const riscv = await fixture('riscv32.text.bin');
    const fixtures = [
      ['uf2', Buffer.concat([uf2(thumb, 0x10000000, RP2350_ARM_S), uf2(riscv, 0x10000000, RP2350_RISCV)])],
      ['dfuse', dfuse(thumb, 0x08000000)],
      ['gbl', gbl(thumb, 0x00004000)],
      ['cyacd', cyacd(thumb)],
    ].map(([name, bytes]) => ({ name, bytes: [...bytes] }));
    const payloads = await page.evaluate(async ({ module, fixtures }) => {
      const wasm = await import(module);
      await wasm.default();
      return Object.fromEntries(fixtures.map(f => [f.name, JSON.parse(wasm.classify(new Uint8Array(f.bytes)))]));
    }, { module, fixtures });
    for (const id of MCU_IDS) {
      const p = payloads[id];
      assert.ok(!p.error, `${id}: ${p.error}`);
      assert.equal(p.format.format, id);
      assert.ok(Object.hasOwn(FORMAT_NAMES, id), `${id} has a display name`);
    }
    const uf2Slices = payloads.uf2.slices;
    assert.deepEqual(uf2Slices.map(s => s.isa).sort(), ['arm', 'risc_v32']);
    const armSlice = uf2Slices.find(s => s.isa === 'arm');
    assert.equal(armSlice.label, 'RP2350_ARM_S (Raspberry Pi RP2350, Secure Arm image)');
    assert.equal(armSlice.offset, 0);
    assert.equal(armSlice.decoded.transform, 'UF2 blocks');
    assert.equal(armSlice.decoded.size, thumb.length);
    assert.equal(payloads.dfuse.primary.isa, 'arm');
    assert.ok(hasCustom(payloads.dfuse, 'dfuse_vendor_id'));
    assert.equal(payloads.gbl.primary.isa, 'arm');
    assert.ok(payloads.gbl.notes.some(n => n.message.includes('end-tag CRC-32 verified')));
    assert.equal(payloads.cyacd.primary.isa, 'arm');
    assert.ok(hasCustom(payloads.cyacd, 'cyacd_silicon_id'));
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names UF2 files and keeps the family ID in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const buffer = uf2(await fixture('thumbv7em.text.bin'), 0x10000000, RP2350_ARM_S);
    const file = { name: 'firmware.uf2', buffer, mimeType: 'application/octet-stream' };
    await page.locator('#fileinput').setInputFiles([file]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes(FORMAT_NAMES.uf2), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.primary.isa, 'arm');
    assert.ok(p.metadata.some(m => m.key?.custom === 'uf2_family_id' && m.value === '0xE48BFF59'));
  });
}
