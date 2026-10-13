import assert from 'node:assert/strict';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup); after(teardown);

// Text padded with `pad` to `length` bytes.
function putText(buffer, at, length, text, pad = 0x20) {
  buffer.fill(pad, at, at + length);
  buffer.write(text, at, 'latin1');
}

// `size` bytes of a repeated instruction pattern.
function code(pattern, size) {
  const bytes = Buffer.alloc(size);
  for (let at = 0; at < size; at++) {
    bytes[at] = pattern[at % pattern.length];
  }
  return bytes;
}

// Z80: ld a,1; ld (0xc000),a; ld hl,0xc000; ld a,(hl); inc hl; ret.
const Z80 = [0x3e, 0x01, 0x32, 0x00, 0xc0, 0x21, 0x00, 0xc0, 0x7e, 0x23, 0xc9, 0x00];
// 68000: link a6,#0; moveq #1,d0; unlk a6; rts.
const M68K = [0x4e, 0x56, 0x00, 0x00, 0x70, 0x01, 0x4e, 0x5e, 0x4e, 0x75];
// SH-2: mov #1,r0; rts; nop.
const SH2 = [0xe0, 0x01, 0x00, 0x0b, 0x00, 0x09];
// 6502: lda #1; sta $0200; nop; rts.
const MOS6502 = [0xa9, 0x01, 0x8d, 0x00, 0x02, 0xea, 0x60];
// 16-bit x86: mov ax,0x1234; nop; ret.
const X86 = [0xb8, 0x34, 0x12, 0x90, 0xc3];
// TLCS-900: nop; ret.
const TLCS900 = [0x00, 0x0e];

// Master System export ROM of 32 KiB: Z80 code, TMR SEGA header at 0x7FF0
// with product 7026, region 4 and size code 0xC, checksum over 0-0x7FFF
// without the header.
function smsRom() {
  const rom = code(Z80, 0x8000);
  rom.write('TMR SEGA', 0x7ff0, 'latin1');
  rom.fill(0, 0x7ff8, 0x7ffc);
  rom[0x7ffc] = 0x26;
  rom[0x7ffd] = 0x70;
  rom[0x7ffe] = 0x01;
  rom[0x7fff] = 0x4c;
  let sum = 0;
  for (let at = 0; at < 0x7ff0; at++) {
    sum = (sum + rom[at]) & 0xffff;
  }
  rom.writeUInt16LE(sum, 0x7ffa);
  return rom;
}

// 32X ROM: 68000 vectors (PC 0x3F0), SEGA 32X header, user header at 0x3C0
// (MARS CHECK MODE, source 0x800, destination 0, size 0x100, master and
// slave starts in SDRAM), security text at 0x512, SH-2 code at 0x800.
function rom32x() {
  const rom = code(M68K, 0x1000);
  rom.fill(0, 0, 0x200);
  rom.writeUInt32BE(0x00fffe00, 0);
  rom.writeUInt32BE(0x3f0, 4);
  putText(rom, 0x100, 16, 'SEGA 32X');
  putText(rom, 0x1f0, 16, 'JUE');
  putText(rom, 0x3c0, 16, 'MARS CHECK MODE');
  rom.writeUInt32BE(0, 0x3d0);
  rom.writeUInt32BE(0x800, 0x3d4);
  rom.writeUInt32BE(0, 0x3d8);
  rom.writeUInt32BE(0x100, 0x3dc);
  rom.writeUInt32BE(0x06000000, 0x3e0);
  rom.writeUInt32BE(0x06000004, 0x3e4);
  rom.writeUInt32BE(0x06000000, 0x3e8);
  rom.writeUInt32BE(0x06000000, 0x3ec);
  rom.write('MARS Initial & Security Program', 0x512, 'latin1');
  code(SH2, 0x100).copy(rom, 0x800);
  return rom;
}

// Saturn IP.BIN of 4 KiB: hardware ID, product, areas, IP size 0x1000 at
// 0xE0 (big-endian), SH-2 code from 0x100.
function saturnIp() {
  const ip = code(SH2, 0x1000);
  ip.fill(0x20, 0, 0xd0);
  ip.fill(0, 0xd0, 0x100);
  ip.write('SEGA SEGASATURN ', 0, 'latin1');
  putText(ip, 0x20, 10, 'T-99901G');
  putText(ip, 0x40, 10, 'JUE');
  ip.writeUInt32BE(0x1000, 0xe0);
  return ip;
}

// Sega CD system area of 4 KiB: SEGADISCSYSTEM, IP at 0x200 (0x600 B) and
// SP at 0x800 (0x800 B), Mega Drive disc ID with region JUE, 68000 code.
function segaCd() {
  const disc = code(M68K, 0x1000);
  disc.fill(0x20, 0, 0x200);
  disc.write('SEGADISCSYSTEM', 0, 'latin1');
  disc.writeUInt32BE(0x200, 0x30);
  disc.writeUInt32BE(0x600, 0x34);
  disc.writeUInt32BE(0, 0x38);
  disc.writeUInt32BE(0, 0x3c);
  disc.writeUInt32BE(0x800, 0x40);
  disc.writeUInt32BE(0x800, 0x44);
  disc.writeUInt32BE(0, 0x48);
  disc.writeUInt32BE(0, 0x4c);
  putText(disc, 0x100, 16, 'SEGA MEGA DRIVE');
  putText(disc, 0x1f0, 16, 'JUE');
  return disc;
}

// MSX cartridge of 16 KiB at 0x4000: AB, INIT 0x4010, zero header words and
// reserved bytes, Z80 code.
function msxRom() {
  const rom = code(Z80, 0x4000);
  rom.fill(0, 0, 0x10);
  rom.write('AB', 0, 'latin1');
  rom.writeUInt16LE(0x4010, 2);
  return rom;
}

// LNX image: LYNX, bank 0 page size 0x100, bank 1 unused, version 1, names,
// then 4 KiB of 6502 code.
function lynx() {
  const header = Buffer.alloc(64);
  header.write('LYNX', 0, 'latin1');
  header.writeUInt16LE(0x100, 4);
  header.writeUInt16LE(1, 8);
  header.write('ZRAXLYNX', 0x0a, 'latin1');
  return Buffer.concat([header, code(MOS6502, 0x1000)]);
}

// A78 image: version 3, ATARI7800, ROM size 0x8000 (big-endian), plain cart
// type, end text; then 32 KiB of 6502 code with the reset vector 0x8000 at
// 0xFFFC.
function a78() {
  const header = Buffer.alloc(128);
  header[0] = 3;
  header.write('ATARI7800', 1, 'latin1');
  header.writeUInt32BE(0x8000, 0x31);
  header.write('ACTUAL CART DATA STARTS HERE', 0x64, 'latin1');
  const rom = code(MOS6502, 0x8000);
  rom.writeUInt16LE(0x8000, 0x7ffc);
  return Buffer.concat([header, rom]);
}

// C64 CRT: signature, header length 0x40, version 1.00, GAME 1, one 8 KiB
// ROM CHIP packet at 0x8000.
function crt() {
  const header = Buffer.alloc(0x40);
  header.write('C64 CARTRIDGE   ', 0, 'latin1');
  header.writeUInt32BE(0x40, 0x10);
  header.writeUInt16BE(0x0100, 0x14);
  header[0x19] = 1;
  header.write('ZRAX CART', 0x20, 'latin1');
  const chip = Buffer.alloc(0x10);
  chip.write('CHIP', 0, 'latin1');
  chip.writeUInt32BE(0x2010, 4);
  chip.writeUInt16BE(0x8000, 0xc);
  chip.writeUInt16BE(0x2000, 0xe);
  return Buffer.concat([header, chip, code(MOS6502, 0x2000)]);
}

// GEMDOS program: 0x601A, TEXT 0x200 B, BSS 0x100 B, TEXT of 68000 code and
// a relocation table with fixups at 4 and 264.
function gemdos() {
  const header = Buffer.alloc(0x1c);
  header.writeUInt16BE(0x601a, 0);
  header.writeUInt32BE(0x200, 2);
  header.writeUInt32BE(0x100, 0xa);
  return Buffer.concat([header, code(M68K, 0x200), Buffer.from([0, 0, 0, 4, 1, 6, 0])]);
}

// .z80 version 3 48K snapshot: PC 0 in the main header, interrupt mode 1,
// additional header of 54 B with PC 0x8000 and hardware mode 0, then pages
// 4, 5 and 8 stored uncompressed (length 0xFFFF).
function z80() {
  const header = Buffer.alloc(32 + 54);
  header.writeUInt16LE(0xff00, 8);
  header[29] = 1;
  header.writeUInt16LE(54, 30);
  header.writeUInt16LE(0x8000, 32);
  const pages = [4, 5, 8].map(page => {
    const block = Buffer.alloc(3);
    block.writeUInt16LE(0xffff, 0);
    block[2] = page;
    return Buffer.concat([block, code(Z80, 0x4000)]);
  });
  return Buffer.concat([header, ...pages]);
}

// 512 KiB WonderSwan Color ROM: x86 code, zero byte and footer (publisher 1,
// color, game 0x23, size code 2, 8 KiB SRAM, 1-cycle ROM) with the byte sum.
function wonderswan() {
  const rom = code(X86, 512 << 10);
  const end = rom.length;
  rom[end - 11] = 0;
  Buffer.from([0x01, 0x01, 0x23, 0x00, 0x02, 0x01, 0x04, 0x00]).copy(rom, end - 10);
  let sum = 0;
  for (let at = 0; at < end - 2; at++) {
    sum = (sum + rom[at]) & 0xffff;
  }
  rom.writeUInt16LE(sum, end - 2);
  return rom;
}

// 32 KiB Neo Geo Pocket Color ROM: SNK code, startup 0x200040, ID 0x0042,
// color, title ZRAXNGP, TLCS-900 code from 0x40.
function ngp() {
  const rom = code(TLCS900, 0x8000);
  rom.fill(0, 0, 0x40);
  rom.write('COPYRIGHT BY SNK CORPORATION', 0, 'latin1');
  rom.writeUInt32LE(0x200040, 0x1c);
  rom.writeUInt16LE(0x0042, 0x20);
  rom[0x23] = 0x10;
  putText(rom, 0x24, 12, 'ZRAXNGP');
  return rom;
}

const FIXTURES = [
  ['sms', smsRom(), 'smsrom', 'z80'],
  ['32x', rom32x(), 'sega32xrom', 'm68k'],
  ['saturn', saturnIp(), 'saturnip', 'sh'],
  ['segacd', segaCd(), 'segacdip', 'm68k'],
  ['msx', msxRom(), 'msxrom', 'z80'],
  ['lynx', lynx(), 'lynxrom', 'mcs6502'],
  ['a78', a78(), 'atari7800rom', 'mcs6502'],
  ['crt', crt(), 'c64crt', 'mcs6502'],
  ['st', gemdos(), 'ataristprg', 'm68k'],
  ['z80', z80(), 'zxsnapshot', 'z80'],
  ['ws', wonderswan(), 'wonderswanrom', 'x86'],
  ['ngp', ngp(), 'ngprom', 'tlcs900'],
];

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`console and home-computer images report their platform CPU through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const fixtures = FIXTURES.map(([name, bytes]) => ({ name, bytes: [...bytes] }));
    const payloads = await page.evaluate(async ({ module, fixtures }) => {
      const wasm = await import(module);
      await wasm.default();
      const classify = f => [f.name, JSON.parse(wasm.classify(new Uint8Array(f.bytes)))];
      return Object.fromEntries(fixtures.map(classify));
    }, { module, fixtures });
    for (const [name, , format, isa] of FIXTURES) {
      const p = payloads[name];
      assert.ok(!p.error, `${name}: ${p.error}`);
      assert.equal(p.format.format, format, name);
      assert.equal(p.primary.isa, isa, name);
      assert.ok(Object.hasOwn(FORMAT_NAMES, format), `${format} has a display name`);
    }
    const sh2 = payloads['32x'].slices.find(s => s.label === '32X SH-2 program');
    assert.deepEqual([sh2.isa, sh2.endianness, sh2.offset, sh2.size], ['sh', 'big', 0x800, 0x100]);
    const subCpu = payloads.segacd.slices.find(s => s.label === 'System program (sub-CPU)');
    assert.deepEqual([subCpu.isa, subCpu.offset, subCpu.size], ['m68k', 0x800, 0x800]);
    const chip = payloads.crt.slices.find(s => s.label === 'CHIP bank 0 at 0x8000 (ROM)');
    assert.deepEqual([chip.isa, chip.offset, chip.size], ['mcs6502', 0x50, 0x2000]);
    assert.equal(payloads.ws.primary.bitwidth, 16);
    assert.ok(payloads.msx.format.confidence < 1, 'MSX headers are weak');
    const page4 = payloads.z80.metadata.find(m => m.key?.custom === 'zxsnap_section_0');
    assert.equal(page4.value, 'file 0x59; destination 0x8000; 16384 B');
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names the 32X and reports its user header in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const file = { name: 'game.32x', buffer: rom32x(), mimeType: 'application/octet-stream' };
    await page.locator('#fileinput').setInputFiles([file]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes('Sega 32X ROM'), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.format.format, 'sega32xrom');
    assert.equal(p.primary.isa, 'm68k');
    assert.ok(p.metadata.some(m => m.key?.custom === 'sega32x_module_name' && m.value === 'MARS CHECK MODE'));
  });
}
