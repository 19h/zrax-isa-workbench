import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup);
after(teardown);

// Compiled code from the repository's testbins: 32-bit Arm (little-endian)
// and 64-bit MIPS (big-endian).
const testbin = name => readFile(new URL(`../../testbins/${name}`, import.meta.url));
const ARM_CODE = 'arm32_arm-unknown-linux-gnueabi_O0_min_float_add.bin';
const MIPS_CODE = 'mips64_be_mips64-unknown-linux-gnuabi64_O0_int_crc32.bin';

// The 156-byte Nintendo logo of the DS and GBA headers (gbafix.c), 16
// bytes per row.
const NINTENDO_LOGO = Buffer.from([
  '24FFAE51699AA2213D84820A84E409AD',
  '11248B98C0817F21A352BE199309CE20',
  '10464A4AF82731EC58C7E83382E3CEBF',
  '85F4DF94CE4B09C194568AC01372A7FC',
  '9F844D73A3CA9A615897A327FC039876',
  '231DC7610304AE56BF38840040A70EFD',
  'FF52FE036F9530F197FBC08560D68025',
  'A963BE03014E38E2F9A234FFBB3E0344',
  '780090CB88113A9465C07C6387F03CAF',
  'D625E48B380AAC7221D4F807',
].join(''), 'hex');

// The 48-byte Game Boy logo (Pan Docs).
const GB_LOGO = Buffer.from(
  'CEED6666CC0D000B03730083000C000D0008111F8889000EDCCC6EE6DDDDD999BBBB67636E0EECCCDDDC999FBBB9333E',
  'hex',
);

// CRC-16/MODBUS: reflected polynomial 0xA001, initial value 0xFFFF.
function crc16Modbus(bytes) {
  let crc = 0xffff;
  for (const b of bytes) {
    crc ^= b;
    for (let i = 0; i < 8; i++) {
      crc = crc & 1 ? (crc >>> 1) ^ 0xa001 : crc >>> 1;
    }
  }
  return crc;
}

// A homebrew-style DS image: title and game code, the ARM9 area at 0x020
// (offset 0x200, entry and RAM address 0x02000000, size) and the ARM7 area
// at 0x030 (after the ARM9 binary, ARM7 WRAM 0x037F8000), the logo at
// 0x0C0, its CRC-16 at 0x15C and the header CRC-16 at 0x15E.
function nds(code) {
  const arm9Offset = 0x200;
  const arm7Offset = arm9Offset + code.length;
  const image = Buffer.alloc(arm7Offset + code.length);
  image.write('ZRAXTEST', 0x000, 'latin1');
  image.write('AZRE', 0x00c, 'latin1');
  image.writeUInt32LE(arm9Offset, 0x020);
  image.writeUInt32LE(0x02000000, 0x024);
  image.writeUInt32LE(0x02000000, 0x028);
  image.writeUInt32LE(code.length, 0x02c);
  image.writeUInt32LE(arm7Offset, 0x030);
  image.writeUInt32LE(0x037f8000, 0x034);
  image.writeUInt32LE(0x037f8000, 0x038);
  image.writeUInt32LE(code.length, 0x03c);
  NINTENDO_LOGO.copy(image, 0x0c0);
  image.writeUInt16LE(crc16Modbus(image.subarray(0x0c0, 0x15c)), 0x15c);
  image.writeUInt16LE(crc16Modbus(image.subarray(0, 0x15e)), 0x15e);
  code.copy(image, arm9Offset);
  code.copy(image, arm7Offset);
  return image;
}

// A GBA image: entry branch `B 0x0C0`, logo, title, fixed 0x96 at 0x0B2,
// the complement of 0x0A0-0x0BC at 0x0BD, then the code.
function gba(code) {
  const header = Buffer.alloc(0xc0);
  header.writeUInt32LE(0xea00002e, 0x000);
  NINTENDO_LOGO.copy(header, 0x004);
  header.write('ZRAXTEST', 0x0a0, 'latin1');
  header[0x0b2] = 0x96;
  const sum = header.subarray(0x0a0, 0x0bd).reduce((total, b) => total + b, 0);
  header[0x0bd] = -(0x19 + sum) & 0xff;
  return Buffer.concat([header, code]);
}

// A 32 KiB Game Boy Color ROM: `nop; jp $0150` at 0x100, logo at 0x104,
// title, CGB flag 0x80 at 0x143, header checksum over 0x134-0x14C at 0x14D.
function gbc() {
  const rom = Buffer.alloc(0x8000);
  rom.set([0x00, 0xc3, 0x50, 0x01], 0x100);
  GB_LOGO.copy(rom, 0x104);
  rom.write('ZRAXTEST', 0x134, 'latin1');
  rom[0x143] = 0x80;
  let checksum = 0;
  for (let i = 0x134; i <= 0x14c; i++) {
    checksum = (checksum - rom[i] - 1) & 0xff;
  }
  rom[0x14d] = checksum;
  return rom;
}

// An iNES NROM image: one 16 KiB PRG-ROM bank of 6502 code ending with the
// vectors (reset 0xC000) and one 8 KiB CHR-ROM bank of pattern data.
function ines() {
  const header = Buffer.from([0x4e, 0x45, 0x53, 0x1a, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
  const code = [0x78, 0xd8, 0xa2, 0xff, 0x9a, 0xa9, 0x00, 0x8d, 0x00, 0x20, 0x4c, 0x0b, 0xc0];
  const prg = Buffer.alloc(16 << 10);
  for (let i = 0; i < prg.length; i++) {
    prg[i] = code[i % code.length];
  }
  prg.set([0x00, 0xc0, 0x00, 0xc0, 0x00, 0xc0], prg.length - 6);
  const chr = Buffer.alloc(8 << 10, 0x33);
  return Buffer.concat([header, prg, chr]);
}

// A 32 KiB SNES LoROM: 65816 code at ROM 0 (CPU 0x8000), the internal
// header at 0x7FC0 with title, map mode 0x20, the emulation-mode reset
// vector 0x8000 at 0x7FFC, and the 16-bit byte sum with its complement.
function snesLoRom() {
  const rom = Buffer.alloc(0x8000);
  const code = [0x78, 0x18, 0xfb, 0xc2, 0x30, 0xa9, 0x34, 0x12, 0x8d, 0x00, 0x21, 0x80, 0xfe];
  for (let i = 0; i < 0x1000; i++) {
    rom[i] = code[i % code.length];
  }
  rom.write('ZRAX TEST            ', 0x7fc0, 'latin1');
  rom[0x7fd5] = 0x20;
  rom.writeUInt16LE(0xffff, 0x7fdc);
  rom.writeUInt16LE(0x0000, 0x7fde);
  rom.writeUInt16LE(0x8000, 0x7ffc);
  const checksum = rom.reduce((total, b) => total + b, 0) & 0xffff;
  rom.writeUInt16LE(checksum ^ 0xffff, 0x7fdc);
  rom.writeUInt16LE(checksum, 0x7fde);
  return rom;
}

// An N64 ROM in native order: first word 80 37 12 40, clock rate
// 0x0000000F, boot address 0x80000400, title, game code NZRE, IPL3 filler,
// then MIPS code from 0x1000; stored as .v64 (16-bit byte swap).
function n64v64(code) {
  const rom = Buffer.alloc(0x2000);
  rom.writeUInt32BE(0x80371240, 0x00);
  rom.writeUInt32BE(0x0000000f, 0x04);
  rom.writeUInt32BE(0x80000400, 0x08);
  rom.write('ZRAX TEST           ', 0x20, 'latin1');
  rom.write('NZRE', 0x3b, 'latin1');
  for (let i = 0x1000; i < rom.length; i++) {
    rom[i] = code[(i - 0x1000) % code.length];
  }
  return Buffer.from(rom).swap16();
}

async function fixtures() {
  const arm = await testbin(ARM_CODE);
  const mips = await testbin(MIPS_CODE);
  return {
    'test.nds': nds(arm),
    'test.gba': gba(arm),
    'test.gbc': gbc(),
    'test.nes': ines(),
    'test.sfc': snesLoRom(),
    'test.v64': n64v64(mips),
  };
}

const variantName = classification => classification.variant?.name;

test('the logo fixture has the DS logo checksum', () => {
  assert.equal(NINTENDO_LOGO.length, 156);
  assert.equal(crc16Modbus(NINTENDO_LOGO), 0xcf56);
  assert.equal(GB_LOGO.length, 48);
});

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`Nintendo ROMs report their platform CPUs and slices through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const files = Object.entries(await fixtures()).map(([name, bytes]) => ({ name, bytes: [...bytes] }));
    const payloads = await page.evaluate(async ({ module, files }) => {
      const wasm = await import(module);
      await wasm.default();
      return Object.fromEntries(files.map(f => [f.name, JSON.parse(wasm.classify(new Uint8Array(f.bytes)))]));
    }, { module, files });
    const expected = {
      'test.nds': ['ndsrom', 'arm', 'ARMv5TE (ARM946E-S)'],
      'test.gba': ['gbarom', 'arm', 'ARMv4T (ARM7TDMI)'],
      'test.gbc': ['gbrom', 'z80', 'SM83'],
      'test.nes': ['nesrom', 'mcs6502', 'Ricoh 2A03 (6502 without decimal mode)'],
      'test.sfc': ['snesrom', 'w65816', '65C816 (Ricoh 5A22)'],
      'test.v64': ['n64rom', 'mips64', 'VR4300 (MIPS III)'],
    };
    for (const [name, [format, isa, variant]] of Object.entries(expected)) {
      const p = payloads[name];
      assert.ok(!p.error, `${name}: ${p.error}`);
      assert.equal(p.format.format, format, name);
      assert.equal(p.primary.isa, isa, name);
      assert.equal(variantName(p.primary), variant, name);
      assert.ok(Object.hasOwn(FORMAT_NAMES, format), `${format} has a display name`);
    }
    const slice = (name, label) => payloads[name].slices.find(s => s.label === label);
    assert.equal(variantName(slice('test.nds', 'ARM9 binary')), 'ARMv5TE (ARM946E-S)');
    assert.equal(variantName(slice('test.nds', 'ARM7 binary')), 'ARMv4T (ARM7TDMI)');
    assert.equal(slice('test.nds', 'ARM9 binary').offset, 0x200);
    assert.equal(slice('test.nes', 'PRG-ROM').isa, 'mcs6502');
    assert.deepEqual(slice('test.nes', 'CHR-ROM').isa, { unknown: 0 });
    const n64 = payloads['test.v64'];
    assert.equal(n64.primary.endianness, 'big');
    const gameCode = n64.metadata.find(m => m.key?.custom === 'n64_section_1');
    const gameCodeRange = 'file 0x1000; destination 0x80000400; 4096 B stored; 4096 B decoded (N64 byte swap)';
    assert.equal(gameCode.value, gameCodeRange);
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names Nintendo ROM formats in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const buffer = nds(await testbin(ARM_CODE));
    const file = { name: 'test.nds', buffer, mimeType: 'application/octet-stream' };
    await page.locator('#fileinput').setInputFiles([file]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes('Nintendo DS ROM'), content);
  });
}
