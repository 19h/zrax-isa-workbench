import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl, elf } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup);
after(teardown);

// clang-generated A32 code from tests/fixtures/socboot2/generate.sh.
const armCode = () => readFile(new URL('../../tests/fixtures/socboot2/arm.text.bin', import.meta.url));

const ROM_SIGNATURE = 0x43454345;
const MACHINE_ARM = 0x01c0;
// IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ.
const CODE_FLAGS = 0x60000020;
const PHYS_FIRST = 0x80000000;

// Layout of the synthetic ROM, as offsets from physfirst.
const SIGNATURE_AT = 0x40;
const ROMHDR_AT = 0x100;
const ROMHDR_SIZE = 84;
const TOC_AT = ROMHDR_AT + ROMHDR_SIZE;
const FILES_AT = TOC_AT + 32;
const NAMES_AT = 0x200;
const E32_AT = 0x240;
const O32_AT = 0x2c0;
const CODE_AT = 0x400;
const CODE_SIZE = 0x300;
const ELF_AT = 0x700;
const IMAGE_SIZE = 0x800;
const CODE_LABEL = 'nk.exe o32 0 (RVA 0x1000)';

// An XIP region with one module (nk.exe, one A32 code section) and one
// file (boot.elf, an x86-64 ELF header). Pointers are runtime addresses.
// ROMHDR: physfirst (8), physlast (0xC), nummods (0x10), numfiles (0x30),
// usCPUType (0x44). TOCentry: lpszFileName (16), ulE32Offset (20),
// ulO32Offset (24). FILESentry: nRealFileSize (12), nCompFileSize (16),
// lpszFileName (20), ulLoadOffset (24). e32_rom: e32_objcnt (0),
// e32_entryrva (4), e32_vbase (8), e32_vsize (20). o32_rom: o32_vsize,
// o32_rva, o32_psize, o32_dataptr, o32_realaddr, o32_flags.
function romImage(code) {
  const image = Buffer.alloc(IMAGE_SIZE);
  const at = offset => PHYS_FIRST + offset;
  image.writeUInt32LE((0xea000000 | ((CODE_AT - 8) >> 2)) >>> 0, 0);
  image.writeUInt32LE(ROM_SIGNATURE, SIGNATURE_AT);
  image.writeUInt32LE(at(ROMHDR_AT), SIGNATURE_AT + 4);
  image.writeUInt32LE(PHYS_FIRST, ROMHDR_AT + 0x08);
  image.writeUInt32LE(at(IMAGE_SIZE), ROMHDR_AT + 0x0c);
  image.writeUInt32LE(1, ROMHDR_AT + 0x10);
  image.writeUInt32LE(1, ROMHDR_AT + 0x30);
  image.writeUInt16LE(MACHINE_ARM, ROMHDR_AT + 0x44);
  image.write('nk.exe\0', NAMES_AT, 'latin1');
  image.write('boot.elf\0', NAMES_AT + 0x10, 'latin1');
  image.writeUInt32LE(at(NAMES_AT), TOC_AT + 16);
  image.writeUInt32LE(at(E32_AT), TOC_AT + 20);
  image.writeUInt32LE(at(O32_AT), TOC_AT + 24);
  image.writeUInt32LE(64, FILES_AT + 12);
  image.writeUInt32LE(64, FILES_AT + 16);
  image.writeUInt32LE(at(NAMES_AT + 0x10), FILES_AT + 20);
  image.writeUInt32LE(at(ELF_AT), FILES_AT + 24);
  image.writeUInt16LE(1, E32_AT);
  image.writeUInt32LE(0x1000, E32_AT + 4);
  image.writeUInt32LE(0x10000, E32_AT + 8);
  image.writeUInt32LE(0x2000, E32_AT + 20);
  image.writeUInt32LE(CODE_SIZE, O32_AT);
  image.writeUInt32LE(0x1000, O32_AT + 4);
  image.writeUInt32LE(CODE_SIZE, O32_AT + 8);
  image.writeUInt32LE(at(CODE_AT), O32_AT + 12);
  image.writeUInt32LE(at(CODE_AT), O32_AT + 16);
  image.writeUInt32LE(CODE_FLAGS, O32_AT + 20);
  code.copy(image, CODE_AT, 0, CODE_SIZE);
  elf('boot.elf').buffer.copy(image, ELF_AT);
  return image;
}

// Record checksum: the unsigned byte sum, 32 bits.
const checksum = bytes => bytes.reduce((sum, b) => (sum + b) >>> 0, 0);

// BIN file: "B000FF\n", image address, image length, then records
// (address, length, checksum, data) and the terminator (address 0, entry
// point, checksum 0). The signature and ROMHDR records come last, as
// romimage writes them. Returns the file and the file offset of the code.
function binFile(image) {
  const ranges = [
    [0, SIGNATURE_AT],
    [TOC_AT, FILES_AT + 28],
    [NAMES_AT, NAMES_AT + 0x20],
    [E32_AT, O32_AT + 24],
    [CODE_AT, CODE_AT + CODE_SIZE],
    [ELF_AT, ELF_AT + 64],
    [SIGNATURE_AT, SIGNATURE_AT + 8],
    [ROMHDR_AT, ROMHDR_AT + ROMHDR_SIZE],
  ];
  const header = Buffer.alloc(15);
  header.write('B000FF\n', 0, 'latin1');
  header.writeUInt32LE(PHYS_FIRST, 7);
  header.writeUInt32LE(IMAGE_SIZE, 11);
  const parts = [header];
  let size = header.length;
  let codeOffset = 0;
  for (const [start, end] of ranges) {
    const data = image.subarray(start, end);
    const fields = Buffer.alloc(12);
    fields.writeUInt32LE(PHYS_FIRST + start, 0);
    fields.writeUInt32LE(data.length, 4);
    fields.writeUInt32LE(checksum(data), 8);
    if (start === CODE_AT) {
      codeOffset = size + 12;
    }
    parts.push(fields, data);
    size += 12 + data.length;
  }
  const terminator = Buffer.alloc(12);
  terminator.writeUInt32LE(PHYS_FIRST + CODE_AT, 4);
  parts.push(terminator);
  return { file: Buffer.concat(parts), codeOffset };
}

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`Windows CE BIN and raw ROM images classify through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const image = romImage(await armCode());
    const { file, codeOffset } = binFile(image);
    const fixtures = [
      { name: 'nk.bin', bytes: [...file], variant: 'Windows CE BIN image', codeOffset },
      { name: 'nk.nb0', bytes: [...image], variant: 'Windows CE raw ROM image', codeOffset: CODE_AT },
    ];
    const payloads = await page.evaluate(async ({ module, fixtures }) => {
      const wasm = await import(module);
      await wasm.default();
      return Object.fromEntries(fixtures.map(f => [f.name, JSON.parse(wasm.classify(new Uint8Array(f.bytes)))]));
    }, { module, fixtures });
    assert.ok(Object.hasOwn(FORMAT_NAMES, 'winceimage'), 'winceimage has a display name');
    for (const { name, variant, codeOffset: offset } of fixtures) {
      const p = payloads[name];
      assert.ok(!p.error, `${name}: ${p.error}`);
      assert.equal(p.format.format, 'winceimage', name);
      assert.equal(p.format.variant_name, variant, name);
      assert.deepEqual([p.primary.isa, p.primary.endianness], ['arm', 'little'], name);
      const code = p.slices.find(s => s.label === CODE_LABEL);
      assert.ok(code, `${name}: ${CODE_LABEL} slice`);
      assert.deepEqual([code.isa, code.offset, code.size], ['arm', offset, CODE_SIZE], name);
      const boot = p.slices.find(s => s.label === 'boot.elf');
      assert.equal(boot?.isa, 'x86_64', name);
      assert.ok(p.notes.some(n => n.message.startsWith('ROMHDR at 0x80000100: usCPUType 0x01C0')), name);
    }
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names Windows CE images in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const { file } = binFile(romImage(await armCode()));
    const upload = { name: 'nk.bin', buffer: file, mimeType: 'application/octet-stream' };
    await page.locator('#fileinput').setInputFiles([upload]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes('Windows CE image'), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.primary.isa, 'arm');
    assert.ok(p.metadata.some(m => m.key?.custom === 'wince_image_size' && m.value === file.length));
  });
}
