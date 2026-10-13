import assert from 'node:assert/strict';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup);
after(teardown);

// The linear EXE page size (IBM LX specification, PAGE SIZE).
const PAGE_SIZE = 4096;
// The builders write the 196-byte VxD header of winnt.h (IMAGE_VXD_HEADER);
// the object table follows it.
const HEADER_SIZE = 0xC4;
// Object table entry: virtual size, relocation base, flags, page table
// index, page count, reserved.
const OBJECT_ENTRY_SIZE = 24;
// A 32-bit x86 function: push ebp; mov ebp, esp; mov eax, [ebp+8];
// add eax, [ebp+12]; pop ebp; ret.
const X86_CODE = [0x55, 0x89, 0xE5, 0x8B, 0x45, 0x08, 0x03, 0x45, 0x0C, 0x5D, 0xC3];

// An LE or LX header at offset 0 without an MZ stub: an OS/2 80386 program
// with one code object holding X86_CODE on one page. Header fields
// (Figure 2): byte and word order 0, format level 0, CPU type 2, OS type 1,
// module flags 0 (program), one page, EIP object 1 at 0, ESP object 1, page
// size 4096, then the LX page offset shift 0 or the LE last page size, the
// object table and its count, the object page table and the data pages
// offset (file-relative). The data pages end the file.
function bareLinear(signature) {
  const lx = signature === 'LX';
  const objectTable = HEADER_SIZE;
  const pageTable = objectTable + OBJECT_ENTRY_SIZE;
  const dataPages = 0x100;
  const file = Buffer.alloc(dataPages + X86_CODE.length);
  file.write(signature, 0, 'latin1');
  file.writeUInt16LE(2, 0x08);
  file.writeUInt16LE(1, 0x0A);
  file.writeUInt32LE(1, 0x14);
  file.writeUInt32LE(1, 0x18);
  file.writeUInt32LE(1, 0x20);
  file.writeUInt32LE(0x1000, 0x24);
  file.writeUInt32LE(PAGE_SIZE, 0x28);
  file.writeUInt32LE(lx ? 0 : X86_CODE.length, 0x2C);
  file.writeUInt32LE(objectTable, 0x40);
  file.writeUInt32LE(1, 0x44);
  file.writeUInt32LE(pageTable, 0x48);
  file.writeUInt32LE(dataPages, 0x80);
  // The code object: readable, executable, 32-bit (2005h), page 1.
  file.writeUInt32LE(0x1000, objectTable);
  file.writeUInt32LE(0x10000, objectTable + 4);
  file.writeUInt32LE(0x2005, objectTable + 8);
  file.writeUInt32LE(1, objectTable + 12);
  file.writeUInt32LE(1, objectTable + 16);
  if (lx) {
    // Page data offset 0 from the data pages, data size, flags 0.
    file.writeUInt32LE(0, pageTable);
    file.writeUInt16LE(X86_CODE.length, pageTable + 4);
  } else {
    // 24-bit page number 1, most significant byte first, flags 0.
    file[pageTable + 2] = 1;
  }
  // The 4- or 8-byte page table entry ends before the data pages.
  file.set(X86_CODE, dataPages);
  return file;
}

// A PE image whose DOS header starts with ZM: e_lfanew 0x80, the PE
// signature and an i386 COFF header with one section.
function zmPe() {
  const file = Buffer.alloc(0x100);
  file.write('ZM', 0, 'latin1');
  file.writeUInt32LE(0x80, 0x3C);
  file.write('PE\0\0', 0x80, 'latin1');
  file.writeUInt16LE(0x014C, 0x84);
  file.writeUInt16LE(1, 0x86);
  return file;
}

const ZM_NOTE = 'DOS header signature is ZM, the byte-swapped MZ that the MS-DOS loader also accepts; '
  + 'whether PE loaders accept it is not verified';

const FIXTURES = [
  { name: 'nostub.lx', build: () => bareLinear('LX'), format: 'lx', note: 'No MZ stub; the LX header starts at offset 0x0' },
  { name: 'nostub.le', build: () => bareLinear('LE'), format: 'le', note: 'No MZ stub; the LE header starts at offset 0x0' },
  { name: 'zm.exe', build: zmPe, format: 'pe', note: ZM_NOTE },
];

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`LE/LX without a stub and ZM PE images classify through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const fixtures = FIXTURES.map(f => ({ name: f.name, bytes: [...f.build()] }));
    const payloads = await page.evaluate(async ({ module, fixtures }) => {
      const wasm = await import(module);
      await wasm.default();
      return Object.fromEntries(fixtures.map(f => [f.name, JSON.parse(wasm.classify(new Uint8Array(f.bytes)))]));
    }, { module, fixtures });
    for (const { name, format, note } of FIXTURES) {
      const p = payloads[name];
      assert.ok(!p.error, `${name}: ${p.error}`);
      assert.equal(p.format.format, format, name);
      assert.ok(Object.hasOwn(FORMAT_NAMES, format), `${format} has a display name`);
      assert.deepEqual([p.primary.isa, p.primary.bitwidth, p.primary.source], ['x86', 32, 'file_format'], name);
      assert.ok(p.notes.some(n => n.message === note), name);
    }
    assert.equal(payloads['nostub.lx'].format.variant_name, 'BareLx { cpu: 2, os: 1 }');
    assert.equal(payloads['nostub.lx'].format.confidence, 0.85);
    assert.equal(payloads['nostub.lx'].primary.variant.name, 'OS/2 80386');
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names an LX module without a stub in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const buffer = bareLinear('LX');
    await page.locator('#fileinput').setInputFiles([{ name: 'module.dll', buffer, mimeType: 'application/octet-stream' }]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes(FORMAT_NAMES.lx), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.format.format, 'lx');
    assert.equal(p.primary.isa, 'x86');
  });
}
