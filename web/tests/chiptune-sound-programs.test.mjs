import assert from 'node:assert/strict';
import { deflateSync, crc32 } from 'node:zlib';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup);
after(teardown);

// MOVEM.L D0-A6,-(SP); MOVEQ #0,D0; NOP; MOVEM.L (SP)+,D0-A6; RTS.
const DRIVER_68000 = [0x48, 0xe7, 0xff, 0xfe, 0x70, 0x00, 0x4e, 0x71, 0x4c, 0xdf, 0x7f, 0xff, 0x4e, 0x75];

// LD A,7; OUT ($A0),A; LD A,$38; OUT ($A1),A; RET.
const DRIVER_Z80 = [0x3e, 0x07, 0xd3, 0xa0, 0x3e, 0x38, 0xd3, 0xa1, 0xc9];

// LDA #$00; STA $D208; LDX #$0F; DEX; BNE; RTS.
const DRIVER_6502 = [0xa9, 0x00, 0x8d, 0x08, 0xd2, 0xa2, 0x0f, 0xca, 0xd0, 0xfd, 0x60];

// PSF: 'PSF', version byte, reserved size, compressed program size and the
// CRC-32 of the compressed program (little-endian), reserved area, zlib program.
function psf(version, reserved, program) {
  const compressed = program.length ? deflateSync(Buffer.from(program)) : Buffer.alloc(0);
  const header = Buffer.alloc(16);
  header.write('PSF', 0, 'latin1');
  header[3] = version;
  header.writeUInt32LE(reserved.length, 4);
  header.writeUInt32LE(compressed.length, 8);
  header.writeUInt32LE(compressed.length ? crc32(compressed) : 0, 12);
  return Buffer.concat([header, Buffer.from(reserved), compressed]);
}

// SSF program: 4-byte little-endian load address, then 68000 code.
function ssf() {
  const load = Buffer.alloc(4);
  load.writeUInt32LE(0x1000, 0);
  return psf(0x11, [], [...load, ...DRIVER_68000]);
}

// NCSF: a 4-byte sequence number in the reserved area and a zlib SDAT whose
// size is at SDAT bytes 8-11.
function ncsf() {
  const sdat = Buffer.alloc(64);
  sdat.write('SDAT', 0, 'latin1');
  sdat.writeUInt32LE(64, 8);
  const sequence = Buffer.alloc(4);
  sequence.writeUInt32LE(3, 0);
  return psf(0x25, [...sequence], [...sdat]);
}

// HES: 'HESM', version 0, start song, init address, MPR0-MPR7; 'DATA', size,
// load address, reserved; data.
function hes() {
  const header = Buffer.alloc(0x20);
  header.write('HESM', 0, 'latin1');
  header.writeUInt16LE(0xe000, 6);
  header.set([0xff, 0xf8], 8);
  header.write('DATA', 0x10, 'latin1');
  header.writeUInt32LE(DRIVER_6502.length, 0x14);
  return Buffer.concat([header, Buffer.from(DRIVER_6502)]);
}

// KSCC: magic, load address, initial data length, init and play addresses,
// first bank, bank count, reserved byte, device flags; initial data.
function kss() {
  const header = Buffer.alloc(0x10);
  header.write('KSCC', 0, 'latin1');
  header.writeUInt16LE(0x4000, 4);
  header.writeUInt16LE(DRIVER_Z80.length, 6);
  header.writeUInt16LE(0x4000, 8);
  header.writeUInt16LE(0x4003, 10);
  return Buffer.concat([header, Buffer.from(DRIVER_Z80)]);
}

// SAP: text header lines (CR/LF), then FF FF, first and last address, data.
function sap() {
  const header = Buffer.from('SAP\r\nNAME "Inside"\r\nTYPE B\r\nINIT 0F80\r\nPLAYER 0F83\r\n', 'latin1');
  const block = Buffer.alloc(6);
  block.set([0xff, 0xff], 0);
  block.writeUInt16LE(0x0f80, 2);
  block.writeUInt16LE(0x0f80 + DRIVER_6502.length - 1, 4);
  return Buffer.concat([header, block, Buffer.from(DRIVER_6502)]);
}

// SNDH: bra.w INIT, EXIT and PLAY to the code, 'SNDH', a title tag, 'HDNS', code.
function sndh() {
  const tags = Buffer.from('SNDHTITLTune\0HDNS', 'latin1');
  const codeAt = 12 + tags.length;
  const entries = Buffer.alloc(12);
  for (const slot of [0, 4, 8]) {
    entries.writeUInt16BE(0x6000, slot);
    entries.writeInt16BE(codeAt + slot - (slot + 2), slot + 2);
  }
  return Buffer.concat([entries, tags, Buffer.from(DRIVER_68000)]);
}

// Pack-Ice: 'ICE!', packed size including the 12-byte header, unpacked size
// (big-endian), packed data.
function packIce() {
  const header = Buffer.alloc(12);
  header.write('ICE!', 0, 'latin1');
  header.writeUInt32BE(12 + 16, 4);
  header.writeUInt32BE(64, 8);
  return Buffer.concat([header, Buffer.alloc(16, 0x55)]);
}

const FIXTURES = [
  ['ssf', ssf(), 'psf', 'm68k'],
  ['ncsf', ncsf(), 'psf', null],
  ['hes', hes(), 'hes', 'mcs6502'],
  ['kss', kss(), 'kss', 'z80'],
  ['sap', sap(), 'sap', 'mcs6502'],
  ['sndh', sndh(), 'sndh', 'm68k'],
  ['packice', packIce(), 'packice', null],
];

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`chiptune and sound-program formats name their CPU through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const fixtures = FIXTURES.map(([name, bytes]) => ({ name, bytes: [...bytes] }));
    const payloads = await page.evaluate(async ({ module, fixtures }) => {
      const wasm = await import(module);
      await wasm.default();
      return fixtures.map(f => JSON.parse(wasm.classify(new Uint8Array(f.bytes))));
    }, { module, fixtures });
    FIXTURES.forEach(([name, , format, isa], i) => {
      const p = payloads[i];
      assert.ok(!p.error, `${name}: ${p.error}`);
      assert.equal(p.format.format, format, name);
      if (isa) {
        assert.equal(p.primary.isa, isa, name);
      } else {
        assert.deepEqual(p.primary.isa, { unknown: 0 }, name);
      }
      assert.ok(Object.hasOwn(FORMAT_NAMES, format), `${format} has a display name`);
    });
    const byName = name => payloads[FIXTURES.findIndex(([fixture]) => fixture === name)];
    const sdat = byName('ncsf').slices.find(s => s.label === 'SDAT sound data');
    assert.equal(sdat.offset, 20);
    assert.deepEqual([sdat.decoded.transform, sdat.decoded.size], ['zlib', 64]);
    const packed = byName('packice').slices.find(s => s.label === 'Packed data');
    assert.deepEqual([packed.offset, packed.size], [12, 16]);
    assert.ok(byName('ssf').notes.some(n => n.message.includes('68000) program loaded at 0x1000')));
  });
}
