import assert from 'node:assert/strict';
import { deflateRawSync } from 'node:zlib';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup);
after(teardown);

// Cabinet layout (Cabinet SDK "Microsoft Cabinet Format"; [MS-MCI];
// [MS-PATCH]; libmspack cabd.c and lzxd.c).
const CFHEADER_SIZE = 36;
const CFFOLDER_SIZE = 8;
const CFFILE_SIZE = 16;
const CFDATA_SIZE = 8;
const TYPE_NONE = 0;
const TYPE_MSZIP = 1;
const TYPE_LZX = 3;
const LZX_WINDOW_BITS = 15;
const A_ARCH = 0x20;

// An x86-64 ELF header (magic, class 2, little-endian, version 1, type 2,
// machine 62) followed by `fill` up to `size` bytes.
function elf(size, fill) {
  const bytes = Buffer.alloc(size, fill);
  bytes.fill(0, 0, 64);
  bytes.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]);
  bytes.writeUInt16LE(2, 16);
  bytes.writeUInt16LE(62, 18);
  return bytes;
}

// CSUMCompute (SDK "Checksum Method"): little-endian words XORed into the
// seed, then the 1-3 remaining bytes, the first of them most significant.
function csum(bytes, seed) {
  let sum = seed;
  const words = Math.floor(bytes.length / 4);
  for (let i = 0; i < words; i++) {
    sum = (sum ^ bytes.readUInt32LE(4 * i)) >>> 0;
  }
  let tail = 0;
  for (let i = 4 * words; i < bytes.length; i++) {
    tail = ((tail << 8) | bytes[i]) >>> 0;
  }
  return (sum ^ tail) >>> 0;
}

// Writes 16-bit little-endian words, most significant bit first (LZX).
class LzxBits {
  constructor() {
    this.bytes = [];
    this.word = 0;
    this.count = 0;
  }

  put(value, n) {
    for (let i = n - 1; i >= 0; i--) {
      this.word = (this.word << 1) | ((value >>> i) & 1);
      this.count++;
      if (this.count === 16) {
        this.bytes.push(this.word & 0xff, this.word >>> 8);
        this.word = 0;
        this.count = 0;
      }
    }
  }

  align() {
    if (this.count > 0) this.put(0, 16 - this.count);
  }
}

// One LZX verbatim block (window 2^15: 30 position slots) coding every byte
// as a literal, for at most 32 KiB: no E8 translation; block type 1 and
// size; the first 256 main-tree lengths as pretree code 9 (length 8 from
// 0) with a pretree of codes 0 and 9; the 240 match symbols and the 249
// length-tree symbols as runs of zeros (code 18 with 5 bits, 20-51 each)
// with a pretree of codes 0 and 18; then each byte as its 8-bit literal
// code, which equals the byte.
function lzxLiterals(data) {
  const w = new LzxBits();
  const pretree = (one, other) => {
    for (let code = 0; code < 20; code++) w.put(code === one || code === other ? 1 : 0, 4);
  };
  const zeros = count => {
    for (let left = count; left > 0;) {
      const run = Math.min(left, 51);
      w.put(1, 1);
      w.put(run - 20, 5);
      left -= run;
    }
  };
  w.put(0, 1);
  w.put(1, 3);
  w.put(data.length, 24);
  pretree(0, 9);
  for (let i = 0; i < 256; i++) w.put(1, 1);
  pretree(0, 18);
  zeros(240);
  pretree(0, 18);
  zeros(249);
  for (const b of data) w.put(b, 8);
  w.align();
  return Buffer.from(w.bytes);
}

// A cabinet of one file per folder: CFHEADER (MSCF, reserved1, cbCabinet,
// reserved2, coffFiles, reserved3, version 1.3, cFolders, cFiles, flags,
// setID, iCabinet), CFFOLDER entries (coffCabStart, cCFData,
// typeCompress), CFFILE entries (cbFile, uoffFolderStart, iFolder, date,
// time, attribs, name), then one CFDATA block per folder (csum, cbData,
// cbUncomp, data).
function cabinet(folders) {
  const names = folders.map(f => Buffer.from(f.name + '\0', 'latin1'));
  const filesOffset = CFHEADER_SIZE + folders.length * CFFOLDER_SIZE;
  const dataStart = filesOffset + names.reduce((n, name) => n + CFFILE_SIZE + name.length, 0);
  const blocks = folders.map(f => f.block);
  const total = dataStart + blocks.reduce((n, b) => n + CFDATA_SIZE + b.length, 0);
  const out = Buffer.alloc(total);
  out.write('MSCF', 0, 'latin1');
  out.writeUInt32LE(total, 8);
  out.writeUInt32LE(filesOffset, 16);
  out.set([3, 1], 24);
  out.writeUInt16LE(folders.length, 26);
  out.writeUInt16LE(folders.length, 28);
  out.writeUInt16LE(0x0622, 32);
  let at = filesOffset;
  folders.forEach((f, i) => {
    out.writeUInt32LE(f.data.length, at);
    out.writeUInt16LE(i, at + 8);
    out.writeUInt16LE(0x226c, at + 10);
    out.writeUInt16LE(0x59ba, at + 12);
    out.writeUInt16LE(A_ARCH, at + 14);
    names[i].copy(out, at + CFFILE_SIZE);
    at += CFFILE_SIZE + names[i].length;
  });
  const offsets = [];
  folders.forEach((f, i) => {
    offsets.push(at);
    const entry = CFHEADER_SIZE + i * CFFOLDER_SIZE;
    out.writeUInt32LE(at, entry);
    out.writeUInt16LE(1, entry + 4);
    out.writeUInt16LE(f.type, entry + 6);
    const sizes = Buffer.alloc(4);
    sizes.writeUInt16LE(f.block.length, 0);
    sizes.writeUInt16LE(f.data.length, 2);
    out.writeUInt32LE(csum(sizes, csum(f.block, 0)), at);
    sizes.copy(out, at + 4);
    f.block.copy(out, at + CFDATA_SIZE);
    at += CFDATA_SIZE + f.block.length;
  });
  return { bytes: out, offsets };
}

// A stored, an MSZIP and an LZX folder, each holding one ELF file.
function threeFolders() {
  const stored = elf(300, 0x90);
  const zipped = elf(5000, 0xc3);
  const packed = elf(2000, 0xcc);
  return cabinet([
    { name: 'tools\\stored.elf', type: TYPE_NONE, data: stored, block: stored },
    {
      name: 'tools\\mszip.elf',
      type: TYPE_MSZIP,
      data: zipped,
      block: Buffer.concat([Buffer.from('CK', 'latin1'), deflateRawSync(zipped)]),
    },
    { name: 'tools\\lzx.elf', type: TYPE_LZX | (LZX_WINDOW_BITS << 8), data: packed, block: lzxLiterals(packed) },
  ]);
}

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`Microsoft cabinets list stored, MSZIP and LZX files by name through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const { bytes, offsets } = threeFolders();
    const p = await page.evaluate(async ({ module, bytes }) => {
      const wasm = await import(module);
      await wasm.default();
      return JSON.parse(wasm.classify(new Uint8Array(bytes)));
    }, { module, bytes: [...bytes] });
    assert.ok(!p.error, p.error);
    assert.equal(p.format.format, 'mscab');
    assert.equal(p.format.variant_name, 'MSCF cabinet');
    assert.equal(p.primary.isa, 'x86_64');
    assert.deepEqual(p.slices.map(s => [s.label, s.isa, s.offset, s.decoded?.transform ?? null]), [
      ['tools\\stored.elf', 'x86_64', offsets[0] + CFDATA_SIZE, null],
      ['tools\\mszip.elf', 'x86_64', offsets[1] + CFDATA_SIZE, 'MSZIP'],
      ['tools\\lzx.elf', 'x86_64', offsets[2] + CFDATA_SIZE, 'LZX'],
    ]);
    assert.ok(Object.hasOwn(FORMAT_NAMES, 'mscab'), 'mscab has a display name');
    assert.ok(p.notes.some(n => n.message === 'CFDATA checksums verified for 3 of 3 blocks'));
    const summary = 'Cabinet format 1.3; 3 folders: 1 stored, 1 MSZIP, 1 LZX (2^15 B window); 3 files';
    assert.ok(p.notes.some(n => n.message === summary));
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names Microsoft cabinets and keeps stored offsets in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const { bytes } = threeFolders();
    const file = { name: 'drivers.cab', buffer: bytes, mimeType: 'application/vnd.ms-cab-compressed' };
    await page.locator('#fileinput').setInputFiles([file]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes(FORMAT_NAMES.mscab), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.primary.isa, 'x86_64');
    const member = p.slices.find(s => s.label === 'tools\\stored.elf');
    const magic = bytes.subarray(member.offset, member.offset + 4);
    assert.equal(magic.toString('latin1'), '\x7fELF', 'the stored offset holds the ELF header');
  });
}
