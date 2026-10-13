import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup);
after(teardown);

// Compiled little-endian MIPS32 code from the repository's testbins.
const MIPS_CODE = '../../testbins/mips32_le_mipsel-unknown-linux-gnu_O0_call_nested.bin';
const mipsCode = () => readFile(new URL(MIPS_CODE, import.meta.url));

// Record opcodes (PCSX-Redux PsyqOpcode) and the PlayStation processor type (psy-k cputype).
const END = 0;
const BYTES = 2;
const SWITCH = 6;
const RELOCATION = 10;
const SECTION = 16;
const PROGRAMTYPE = 46;
const MIPS_R3000 = 7;
// Relocation type HI16 and the expression operators `+`, sectbase and constant.
const HI16 = 82;
const EXPR_ADD = 44;
const EXPR_SECTION_BASE = 4;
const EXPR_CONSTANT = 0;

const TEXT = 2;
const DATA = 3;
const TEXT_LABEL = '.text (section 0x0002)';
const DATA_LABEL = '.data (section 0x0003)';

// Little-endian record fields; strings are a length byte and the bytes.
const u8 = value => Buffer.from([value]);
const u16 = value => {
  const field = Buffer.alloc(2);
  field.writeUInt16LE(value);
  return field;
};
const u32 = value => {
  const field = Buffer.alloc(4);
  field.writeUInt32LE(value);
  return field;
};
const string = text => Buffer.concat([u8(text.length), Buffer.from(text, 'latin1')]);

// An LNK object: `LNK`, version 2, PROGRAMTYPE 7, SECTION records (u16 ID, u16 group, u8 alignment, name) for
// .text and .data, the code in two BYTES records (u16 size, bytes) with a HI16 RELOCATION (u8 type, u16 offset,
// `sectbase(.data) + 0`) between them, the .data bytes, END. Returns the file and the payload offsets.
function lnkObject(code) {
  const parts = [Buffer.from('LNK'), u8(2), u8(PROGRAMTYPE), u8(MIPS_R3000)];
  let size = 6;
  const push = (...fields) => {
    for (const field of fields) {
      parts.push(field);
      size += field.length;
    }
  };
  const bytes = payload => {
    push(u8(BYTES), u16(payload.length));
    const offset = size;
    push(payload);
    return offset;
  };
  push(u8(SECTION), u16(TEXT), u16(0), u8(8), string('.text'));
  push(u8(SECTION), u16(DATA), u16(0), u8(8), string('.data'));
  push(u8(SWITCH), u16(TEXT));
  const half = code.length >> 1;
  const first = bytes(code.subarray(0, half));
  push(u8(RELOCATION), u8(HI16), u16(0x10), u8(EXPR_ADD), u8(EXPR_SECTION_BASE), u16(DATA), u8(EXPR_CONSTANT), u32(0));
  const second = bytes(code.subarray(half));
  push(u8(SWITCH), u16(DATA));
  const data = bytes(Buffer.from('Hello\0\0\0', 'latin1'));
  push(u8(END));
  return { file: Buffer.concat(parts), first, textEnd: second + code.length - half, data };
}

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`Psy-Q LNK objects classify through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const code = await mipsCode();
    const object = lnkObject(code);
    const p = await page.evaluate(async ({ module, bytes }) => {
      const wasm = await import(module);
      await wasm.default();
      return JSON.parse(wasm.classify(new Uint8Array(bytes)));
    }, { module, bytes: [...object.file] });
    assert.ok(!p.error, p.error);
    assert.equal(p.format.format, 'psyqobject');
    assert.equal(p.format.variant_name, 'PsyQ LNK object');
    assert.ok(Object.hasOwn(FORMAT_NAMES, 'psyqobject'), 'psyqobject has a display name');
    assert.deepEqual([p.primary.isa, p.primary.bitwidth, p.primary.endianness], ['mips', 32, 'little']);
    const text = p.slices.find(s => s.label === TEXT_LABEL);
    assert.ok(text, `${TEXT_LABEL} slice`);
    assert.deepEqual([text.isa, text.offset, text.size], ['mips', object.first, object.textEnd - object.first]);
    assert.deepEqual(text.decoded, { transform: 'LNK BYTES records', offset: 0, size: code.length });
    const data = p.slices.find(s => s.label === DATA_LABEL);
    assert.deepEqual([data.isa, data.offset, data.size], [{ unknown: 0 }, object.data, 8]);
    assert.ok(p.notes.some(n => n.message === 'LNK version 2 object; processor type 7: MIPS R3000 (PlayStation)'));
    assert.ok(p.metadata.some(m => m.key?.custom === 'psyq_relocations' && m.value === 1));
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names Psy-Q objects in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const { file } = lnkObject(await mipsCode());
    const upload = { name: 'MAIN.OBJ', buffer: file, mimeType: 'application/octet-stream' };
    await page.locator('#fileinput').setInputFiles([upload]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes(FORMAT_NAMES.psyqobject), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.primary.isa, 'mips');
    assert.ok(p.metadata.some(m => m.key?.custom === 'psyq_image_size' && m.value === file.length));
  });
}
