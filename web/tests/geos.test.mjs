import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup);
after(teardown);

// nasm-assembled 16-bit real-mode code (tests/fixtures/geos/code.asm).
const x86Code = () => readFile(new URL('../../tests/fixtures/geos/code.bin', import.meta.url));

// Sizes and values from the PC/GEOS sources (Tools/include/geode.h, os90File.h, Include/heap.def).
const FILE_HEADER_SIZE = { 2: 256, 1: 200 };
const EXECUTABLE_HEADER_SIZE = 24;
const CORE_BLOCK_SIZE = 64;
const RESOURCE_ENTRY_SIZE = 10;
const PARAGRAPH = 16;
const GA_LIBRARY = 0x4000;
const GEODE_TYPE_LIBRARY = 2;
// Resource flags: core block, dgroup, code (HAF_CODE set) and an LMem block.
const FLAGS = { core: 0x0880, dgroup: 0x0080, code: 0x0a72, lmem: 0x001a };

const paragraphAlign = n => (n + PARAGRAPH - 1) & ~(PARAGRAPH - 1);

// File header. 2.0 (256 B): signature C7 45 C1 53, long name (0x04), file type 1 (0x28), token (0x38),
// creator (0x3E). 1.x (200 B): signature C7 45 CF 53, file type 0 (0x04), token (0x14), creator (0x1A),
// long name (0x20).
function fileHeader(version) {
  const header = Buffer.alloc(FILE_HEADER_SIZE[version]);
  if (version === 2) {
    header.set([0xc7, 0x45, 0xc1, 0x53]);
    header.write('Test Library', 0x04, 'latin1');
    header.writeUInt16LE(1, 0x28);
    header.write('TEST', 0x38, 'latin1');
    header.write('GEOS', 0x3e, 'latin1');
  } else {
    header.set([0xc7, 0x45, 0xcf, 0x53]);
    header.writeUInt16LE(0, 0x04);
    header.write('TEST', 0x14, 'latin1');
    header.write('GEOS', 0x1a, 'latin1');
    header.write('Test Library', 0x20, 'latin1');
  }
  return header;
}

// Executable header (24 B): attributes, geode type, heap space, unused, resource, imported library and
// exported entry counts, udata size, process class, application object.
function executableHeader(resourceCount) {
  const header = Buffer.alloc(EXECUTABLE_HEADER_SIZE);
  header.writeUInt16LE(GA_LIBRARY, 0);
  header.writeUInt16LE(GEODE_TYPE_LIBRARY, 2);
  header.writeUInt16LE(resourceCount, 8);
  return header;
}

// Core block (64 B): copies of the attributes and type, permanent name `testlib` and extension `lib`
// (blank padded, at 20 and 28), and the exported entry, imported library and resource counts (50, 52, 56).
function coreBlock(resourceCount) {
  const core = Buffer.alloc(CORE_BLOCK_SIZE);
  core.writeUInt16LE(GA_LIBRARY, 2);
  core.writeUInt16LE(GEODE_TYPE_LIBRARY, 4);
  core.write('testlib ', 20, 'latin1');
  core.write('lib ', 28, 'latin1');
  core.writeUInt16LE(resourceCount, 56);
  return core;
}

// A library geode with the core block (resource 0, empty), dgroup, one code resource and an LMem block:
// headers, the four resource arrays (sizes, positions, relocation sizes, flags), then each resource padded
// to a paragraph. 2.0 positions exclude the 256-byte file header; 1.x positions are file offsets. Returns
// the file and the file offset of the code.
function geode(version, code) {
  const resources = [
    { data: Buffer.alloc(0), flags: FLAGS.core },
    { data: Buffer.alloc(16, 0x11), flags: FLAGS.dgroup },
    { data: code, flags: FLAGS.code },
    { data: Buffer.alloc(40, 0x22), flags: FLAGS.lmem },
  ];
  const head = Buffer.concat([fileHeader(version), executableHeader(resources.length), coreBlock(resources.length)]);
  const base = version === 2 ? FILE_HEADER_SIZE[2] : 0;
  const table = Buffer.alloc(resources.length * RESOURCE_ENTRY_SIZE);
  const offsets = [];
  let cursor = head.length + table.length;
  resources.forEach((resource, i) => {
    offsets.push(cursor);
    table.writeUInt16LE(resource.data.length, 2 * i);
    table.writeUInt32LE(cursor - base, 2 * resources.length + 4 * i);
    table.writeUInt16LE(0, 6 * resources.length + 2 * i);
    table.writeUInt16LE(resource.flags, 8 * resources.length + 2 * i);
    cursor += paragraphAlign(resource.data.length);
  });
  const file = Buffer.alloc(cursor);
  head.copy(file, 0);
  table.copy(file, head.length);
  resources.forEach((resource, i) => resource.data.copy(file, offsets[i]));
  return { bytes: file, codeOffset: offsets[2] };
}

// The resources with data, as the classifier labels them; resource 0 (the core block) is empty.
const SLICES = ['Resource 1 (dgroup)', 'Resource 2 (code)', 'Resource 3 (LMem block)'];

const slice = (payload, label) => payload.slices.find(s => s.label === label);

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`PC/GEOS geodes list code resources as 16-bit x86 through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const code = await x86Code();
    const fixtures = [2, 1].map(version => ({ version, ...geode(version, code) }));
    const payloads = await page.evaluate(async ({ module, inputs }) => {
      const wasm = await import(module);
      await wasm.default();
      return inputs.map(bytes => JSON.parse(wasm.classify(new Uint8Array(bytes))));
    }, { module, inputs: fixtures.map(f => [...f.bytes]) });
    const variants = { 2: 'PC/GEOS 2.0+ geode', 1: 'PC/GEOS 1.x geode' };
    fixtures.forEach(({ version, codeOffset }, i) => {
      const p = payloads[i];
      assert.ok(!p.error, `${version}: ${p.error}`);
      assert.equal(p.format.format, 'geosgeode', `${version}`);
      assert.equal(p.format.variant_name, variants[version]);
      assert.equal(p.primary.isa, 'x86');
      assert.equal(p.primary.bitwidth, 16);
      assert.deepEqual(p.slices.map(s => s.label), SLICES);
      const codeSlice = slice(p, 'Resource 2 (code)');
      assert.equal(codeSlice.isa, 'x86');
      assert.equal(codeSlice.bitwidth, 16);
      assert.equal(codeSlice.offset, codeOffset);
      assert.equal(codeSlice.size, code.length);
      assert.deepEqual(slice(p, 'Resource 1 (dgroup)').isa, { unknown: 0 });
      assert.ok(p.notes.some(n => n.message.startsWith('Library geode "Test Library"')), `${version}`);
    });
    assert.ok(Object.hasOwn(FORMAT_NAMES, 'geosgeode'), 'geosgeode has a display name');
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names PC/GEOS geodes and keeps resource offsets in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const code = await x86Code();
    const { bytes, codeOffset } = geode(2, code);
    const file = { name: 'testlib.geo', buffer: bytes, mimeType: 'application/octet-stream' };
    await page.locator('#fileinput').setInputFiles([file]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes(FORMAT_NAMES.geosgeode), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.primary.isa, 'x86');
    const codeSlice = slice(p, 'Resource 2 (code)');
    assert.equal(codeSlice.offset, codeOffset);
    assert.deepEqual([...bytes.subarray(codeSlice.offset, codeSlice.offset + 8)], [...code.subarray(0, 8)]);
  });
}
