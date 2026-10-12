import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { deflateSync } from 'node:zlib';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup); after(teardown);

const sha256 = bytes => createHash('sha256').update(bytes).digest();

// Space-padded ASCII field.
function putText(buffer, at, length, text) {
  buffer.fill(0x20, at, at + length);
  buffer.write(text, at, 'latin1');
}

// Little-endian 32-bit words, repeated to `size` bytes.
function words(values, size, bigEndian = false) {
  const code = Buffer.alloc(size);
  for (let at = 0; at < size; at += 4) {
    const value = values[(at / 4) % values.length];
    if (bigEndian) {
      code.writeUInt32BE(value, at);
    } else {
      code.writeUInt32LE(value, at);
    }
  }
  return code;
}

// MIPS I: addiu sp,-8; sw ra,4(sp); lw ra,4(sp); jr ra; addiu sp,8; nop.
const mipsCode = size => words([0x27bdfff8, 0xafbf0004, 0x8fbf0004, 0x03e00008, 0x27bd0008, 0], size);

// ARM: push {r4, lr}; mov r0, #0; pop {r4, pc}; bx lr.
const armCode = size => words([0xe92d4010, 0xe3a00000, 0xe8bd8010, 0xe12fff1e], size);

// PowerPC: stwu r1,-16(r1); mflr r0; lwz r0,20(r1); mtlr r0; addi r1,r1,16; blr.
const ppcCode = size => words([0x9421fff0, 0x7c0802a6, 0x80010014, 0x7c0803a6, 0x38210010, 0x4e800020], size, true);

// Mega Drive ROM: SSP and PC vectors, header at 0x100 (system type, ROM
// range, RAM range, region), 68000 NOPs from 0x200, checksum at 0x18E.
function genesisRom() {
  const rom = Buffer.alloc(0x400);
  rom.writeUInt32BE(0x00fffe00, 0);
  rom.writeUInt32BE(0x200, 4);
  putText(rom, 0x100, 16, 'SEGA MEGA DRIVE');
  rom.writeUInt32BE(rom.length - 1, 0x1a4);
  rom.writeUInt32BE(0xff0000, 0x1a8);
  rom.writeUInt32BE(0xffffff, 0x1ac);
  putText(rom, 0x1f0, 16, 'JUE');
  let checksum = 0;
  for (let at = 0x200; at < rom.length; at += 2) {
    rom.writeUInt16BE(0x4e71, at);
    checksum = (checksum + 0x4e71) & 0xffff;
  }
  rom.writeUInt16BE(checksum, 0x18e);
  return rom;
}

// PS-X EXE: ID, pc0 and t_addr 0x80010000, t_size 0x800, text at 0x800.
function psxExe() {
  const header = Buffer.alloc(0x800);
  header.write('PS-X EXE', 0, 'latin1');
  header.writeUInt32LE(0x80010000, 0x10);
  header.writeUInt32LE(0x80010000, 0x18);
  header.writeUInt32LE(0x800, 0x1c);
  header.write('Sony Computer Entertainment Inc. for Europe area', 0x4c, 'latin1');
  return Buffer.concat([header, mipsCode(0x800)]);
}

// Dreamcast IP.BIN: hardware and maker IDs, boot file name, SH-4 code
// (rts; nop) in the license screen and bootstrap areas.
function ipBin() {
  const ip = Buffer.alloc(0x8000);
  putText(ip, 0x00, 16, 'SEGA SEGAKATANA');
  putText(ip, 0x10, 16, 'SEGA ENTERPRISES');
  putText(ip, 0x60, 16, '1ST_READ.BIN');
  for (let at = 0x300; at < 0x8000; at += 4) {
    if (at < 0x3700 || at >= 0x3800) {
      ip.writeUInt32LE(0x0009000b, at);
    }
  }
  return ip;
}

// Wii U RPX: Cafe OS e_ident (OSABI 0xCA, ABI version 0xFE), e_type
// 0xFE01, EM_PPC, section headers at 0x40 (null, .text deflated with a
// big-endian inflated size, .shstrtab), then the section data.
function rpx() {
  const text = ppcCode(0x200);
  const size = Buffer.alloc(4);
  size.writeUInt32BE(text.length);
  const stored = Buffer.concat([size, deflateSync(text)]);
  const names = Buffer.from('\0.text\0.shstrtab\0', 'latin1');
  const header = Buffer.alloc(0x40 + 3 * 0x28);
  header.set([0x7f, 0x45, 0x4c, 0x46, 1, 2, 1, 0xca, 0xfe]);
  header.writeUInt16BE(0xfe01, 0x10);
  header.writeUInt16BE(20, 0x12);
  header.writeUInt32BE(1, 0x14);
  header.writeUInt32BE(0x02000000, 0x18);
  header.writeUInt32BE(0x40, 0x20);
  header.writeUInt16BE(0x34, 0x28);
  header.writeUInt16BE(0x28, 0x2e);
  header.writeUInt16BE(3, 0x30);
  header.writeUInt16BE(2, 0x32);
  const textHeader = 0x40 + 0x28;
  header.writeUInt32BE(1, textHeader);
  header.writeUInt32BE(1, textHeader + 4);
  header.writeUInt32BE(0x08000006, textHeader + 8);
  header.writeUInt32BE(0x02000000, textHeader + 0xc);
  header.writeUInt32BE(header.length, textHeader + 0x10);
  header.writeUInt32BE(stored.length, textHeader + 0x14);
  const namesHeader = 0x40 + 2 * 0x28;
  header.writeUInt32BE(7, namesHeader);
  header.writeUInt32BE(3, namesHeader + 4);
  header.writeUInt32BE(header.length + stored.length, namesHeader + 0x10);
  header.writeUInt32BE(names.length, namesHeader + 0x14);
  return Buffer.concat([header, stored, names]);
}

// 3DS NCCH CXI of 8 media units: NCCH at 0x100, content size, product
// code, ExHeader size 0x400, flags (CTR, executable, NoCrypto), ExeFS at
// unit 5 of 2 units with a 1-unit hash region and its superblock hash; the
// ExHeader title with .code not compressed; the ExeFS header with .code
// and its SHA-256 at 0x1E0, then the code.
function ncch() {
  const code = armCode(0x100);
  const exefs = Buffer.alloc(0x400);
  exefs.write('.code', 0, 'latin1');
  exefs.writeUInt32LE(code.length, 12);
  sha256(code).copy(exefs, 0x1e0);
  code.copy(exefs, 0x200);
  const head = Buffer.alloc(0xa00);
  head.fill(0xa5, 0, 0x100);
  head.write('NCCH', 0x100, 'latin1');
  head.writeUInt32LE(7, 0x104);
  head.write('CTR-P-ZRAX', 0x150, 'latin1');
  head.writeUInt32LE(0x400, 0x180);
  head[0x18c] = 1;
  head[0x18d] = 3;
  head[0x18f] = 4;
  head.writeUInt32LE(5, 0x1a0);
  head.writeUInt32LE(2, 0x1a4);
  head.writeUInt32LE(1, 0x1a8);
  sha256(exefs.subarray(0, 0x200)).copy(head, 0x1c0);
  head.write('CtrApp', 0x200, 'latin1');
  head.writeUInt32LE(0x00100000, 0x210);
  head.writeUInt32LE(code.length, 0x218);
  return Buffer.concat([head, exefs]);
}

// 3DSX: magic, header size 32, relocation header size 8, code 0x40 B,
// three empty relocation headers, then the code segment.
function homebrew3dsx() {
  const header = Buffer.alloc(32 + 24);
  header.write('3DSX', 0, 'latin1');
  header.writeUInt16LE(32, 4);
  header.writeUInt16LE(8, 6);
  header.writeUInt32LE(0x40, 0x10);
  return Buffer.concat([header, armCode(0x40)]);
}

// EBOOT.PBP: \0PBP, version 0x00010000, eight offsets (only DATA.PSP is
// present: a 52-byte MIPS little-endian ELF32 header and MIPS code).
function pbp() {
  const elf = Buffer.alloc(52);
  elf.set([0x7f, 0x45, 0x4c, 0x46, 1, 1, 1]);
  elf.writeUInt16LE(2, 16);
  elf.writeUInt16LE(8, 18);
  const dataPsp = Buffer.concat([elf, mipsCode(0x100)]);
  const header = Buffer.alloc(0x28);
  header.write('\0PBP', 0, 'latin1');
  header.writeUInt32LE(0x00010000, 4);
  for (let index = 0; index < 8; index++) {
    const offset = index <= 6 ? 0x28 : 0x28 + dataPsp.length;
    header.writeUInt32LE(offset, 8 + 4 * index);
  }
  return Buffer.concat([header, dataPsp]);
}

const FIXTURES = [
  ['genesis', genesisRom(), 'genesisrom', 'm68k'],
  ['psx', psxExe(), 'psxexe', 'mips'],
  ['dreamcast', ipBin(), 'dreamcastip', 'sh4'],
  ['rpx', rpx(), 'wiiurpx', 'ppc'],
  ['ncch', ncch(), 'n3dsncch', 'arm'],
  ['3dsx', homebrew3dsx(), 'n3ds3dsx', 'arm'],
  ['pbp', pbp(), 'psppbp', 'mips'],
];

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`console images report their platform CPU through ${module}`, async t => {
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
    const code = payloads.ncch.slices.find(s => s.label === '.code');
    assert.deepEqual([code.isa, code.offset, code.size], ['arm', 0xc00, 0x100]);
    const dataPsp = payloads.pbp.slices.find(s => s.label === 'DATA.PSP');
    assert.equal(dataPsp.isa, 'mips');
    const text = payloads.rpx.metadata.find(m => m.key?.custom === 'wiiu_section_0');
    assert.ok(text.value.includes('512 B decoded (zlib)'), text.value);
    const region = 'Region marker: Sony Computer Entertainment Inc. for Europe area';
    assert.ok(payloads.psx.notes.some(n => n.message === region));
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names 3DS NCCH and reports its product code in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const buffer = ncch();
    const file = { name: 'title.cxi', buffer, mimeType: 'application/octet-stream' };
    await page.locator('#fileinput').setInputFiles([file]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes('3DS NCCH'), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.format.format, 'n3dsncch');
    assert.equal(p.primary.isa, 'arm');
    assert.ok(p.metadata.some(m => m.key?.custom === 'n3ds_product_code' && m.value === 'CTR-P-ZRAX'));
  });
}
