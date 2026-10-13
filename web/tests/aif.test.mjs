import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup);
after(teardown);

// Little-endian ARMv4T code in ARM state (tests/fixtures/aif/README.md).
const armCode = () => readFile(new URL('../../tests/fixtures/aif/arm-le.text.bin', import.meta.url));

// AIF header values (ARM DUI 0041C, Table 13-1): the 128-byte header, MOV r0, r0 as NOP, armlink's default exit
// instruction SWI 0x11, debug type 3 (low-level and source-level), address mode 32, and the image base.
const HEADER_SIZE = 0x80;
const NOP = 0xe1a00000;
const SWI_EXIT = 0xef000011;
const DEBUG_BOTH = 3;
const ADDRESS_MODE_32 = 32;
const IMAGE_BASE = 0x8000;
// The zero-init BL lands on the debug initialization NOP at 0x40.
const ZERO_INIT_CODE = 0x40;

// BL at `from` to `to`: condition AL and the signed word offset from `from + 8`.
const bl = (from, to) => (0xeb000000 | (((to - from - 8) >> 2) & 0xffffff)) >>> 0;

// An executable AIF image: header words 0x00 NOP (not compressed), 0x04 NOP (not self-relocating), 0x08 BL zero-init,
// 0x0C BL entry (the code at 0x80), 0x10 SWI 0x11, 0x14 read-only size (header included), 0x18 read-write size,
// 0x1C debug size, 0x20 zero-init size, 0x24 debug type, 0x28 image base, 0x2C work space, 0x30 address mode,
// 0x34 data base, two reserved words, then NOPs where the zero-init code would be; the code, a 64-byte read-write
// area and 32 bytes of debugging data follow. Returns the file and the debugging data offset.
function aifImage(code) {
  const readWrite = Buffer.alloc(64, 0x5a);
  const debug = Buffer.alloc(32, 0xd0);
  const words = [
    NOP, NOP, bl(0x08, ZERO_INIT_CODE), bl(0x0c, HEADER_SIZE), SWI_EXIT, HEADER_SIZE + code.length,
    readWrite.length, debug.length, 0x100, DEBUG_BOTH, IMAGE_BASE, 0, ADDRESS_MODE_32, 0, 0, 0,
  ];
  const header = Buffer.alloc(HEADER_SIZE);
  for (let i = 0; i < HEADER_SIZE / 4; i++) {
    header.writeUInt32LE(i < words.length ? words[i] : NOP, i * 4);
  }
  const file = Buffer.concat([header, code, readWrite, debug]);
  return { file, debug: HEADER_SIZE + code.length + readWrite.length };
}

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`ARM AIF images classify through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const image = aifImage(await armCode());
    const p = await page.evaluate(async ({ module, bytes }) => {
      const wasm = await import(module);
      await wasm.default();
      return JSON.parse(wasm.classify(new Uint8Array(bytes)));
    }, { module, bytes: [...image.file] });
    assert.ok(!p.error, p.error);
    assert.equal(p.format.format, 'armaif');
    assert.equal(p.format.variant_name, 'Executable AIF');
    assert.ok(Object.hasOwn(FORMAT_NAMES, 'armaif'), 'armaif has a display name');
    assert.deepEqual([p.primary.isa, p.primary.bitwidth, p.primary.endianness], ['arm', 32, 'little']);
    assert.equal(p.metadata.find(m => m.key === 'entry_point').value, IMAGE_BASE + HEADER_SIZE);
    const debug = p.slices.find(s => s.label === 'Debugging data');
    assert.ok(debug, 'debugging data slice');
    assert.deepEqual([debug.isa, debug.offset, debug.size], [{ unknown: 0 }, image.debug, 32]);
    assert.ok(p.notes.some(n => n.message === 'Linked for 32-bit ARM mode'));
    assert.ok(p.metadata.some(m => m.key?.custom === 'aif_image_base' && m.value === IMAGE_BASE));
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names ARM AIF images in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const { file } = aifImage(await armCode());
    const upload = { name: 'image.axf', buffer: file, mimeType: 'application/octet-stream' };
    await page.locator('#fileinput').setInputFiles([upload]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes(FORMAT_NAMES.armaif), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.primary.isa, 'arm');
    assert.ok(p.metadata.some(m => m.key?.custom === 'aif_image_size' && m.value === file.length));
  });
}
