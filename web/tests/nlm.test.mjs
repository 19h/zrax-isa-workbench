import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup);
after(teardown);

// Compiled code from the repository's testbins: i686 and big-endian SPARC.
const testbin = name => readFile(new URL(`../../testbins/${name}`, import.meta.url));
const X86_CODE = 'x86_i686-unknown-linux-gnu_O0_call_nested.bin';
const SPARC_CODE = 'sparc32_sparc-unknown-linux-gnu_O0_call_nested.bin';

// Two binutils NLM targets (bfd/nlm32-i386.c, bfd/nlm32-sparc.c): the
// signature, the header byte order and the padding after the module name
// (include/nlm/i386-ext.h, sparc32-ext.h).
const I386 = { signature: 'NetWare Loadable Module\x1a', bigEndian: false, namePadding: 0 };
const SPARC = { signature: 'NetWare SPARC Module   \x1a', bigEndian: true, namePadding: 2 };

// Signature, version word and the 14-byte module name field.
const FIXED_PREFIX_SIZE = 24 + 4 + 14;
// Words of the fixed header after the module name (codeImageOffset to flags).
const FIXED_HEADER_WORDS = 22;

// Words in the target's byte order.
function words(target, values) {
  const bytes = Buffer.alloc(4 * values.length);
  values.forEach((value, i) => {
    if (target.bigEndian) {
      bytes.writeUInt32BE(value, 4 * i);
    } else {
      bytes.writeUInt32LE(value, 4 * i);
    }
  });
  return bytes;
}

// A length byte, the text and a NUL terminator.
function terminated(text) {
  return Buffer.concat([Buffer.from([text.length]), Buffer.from(text, 'latin1'), Buffer.from([0])]);
}

// The fixed header: signature, version 4, module name (length byte,
// "TEST.NLM", NUL fill), pad1, then code image offset and size, data image
// offset and size, uninitialized data size, custom data offset and size,
// module dependency offset and count, then offset and count of the
// relocation fixups, external references, publics and debug records (all
// empty), the start, exit and check-unload procedure offsets, module type
// and flags.
function fixedHeader(target, layout) {
  const prefix = Buffer.alloc(FIXED_PREFIX_SIZE + target.namePadding);
  prefix.write(target.signature, 0, 'latin1');
  words(target, [4]).copy(prefix, 24);
  prefix[28] = 8;
  prefix.write('TEST.NLM', 29, 'latin1');
  const fields = words(target, [
    layout.codeOffset, layout.codeSize,
    layout.end, 0,
    0,
    0, 0,
    layout.dependencyOffset, 1,
    0, 0,
    0, 0,
    0, 0,
    0, 0,
    0, 0, 0,
    0,
    0,
  ]);
  return Buffer.concat([prefix, fields]);
}

// The variable header: description, stack size, reserved word, " LONG",
// screen name and thread name.
function variableHeader(target) {
  return Buffer.concat([
    terminated('Browser test module'),
    words(target, [8192, 0]),
    Buffer.from(' LONG', 'latin1'),
    terminated('Test'),
    terminated('test'),
  ]);
}

// A VeRsIoN# header: major, minor, revision, year, month, day.
function versionHeader(target) {
  return Buffer.concat([Buffer.from('VeRsIoN#', 'latin1'), words(target, [1, 2, 0, 2026, 10, 13])]);
}

// A module whose stored parts are the code image and a one-entry module
// dependency list ("CLIB", length-prefixed). Returns the file and the
// file offset of the code image.
function nlm(target, code) {
  const variable = variableHeader(target);
  const version = versionHeader(target);
  const fixedSize = FIXED_PREFIX_SIZE + target.namePadding + 4 * FIXED_HEADER_WORDS;
  const codeOffset = fixedSize + variable.length + version.length;
  const dependencyOffset = codeOffset + code.length;
  const dependencies = Buffer.from('\x04CLIB', 'latin1');
  const end = dependencyOffset + dependencies.length;
  const fixed = fixedHeader(target, { codeOffset, codeSize: code.length, dependencyOffset, end });
  return { file: Buffer.concat([fixed, variable, version, code, dependencies]), codeOffset };
}

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`NetWare modules name their processor through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const i386 = nlm(I386, await testbin(X86_CODE));
    const sparc = nlm(SPARC, await testbin(SPARC_CODE));
    const fixtures = [
      {
        name: 'i386.nlm',
        bytes: [...i386.file],
        variant: 'NetWare NLM (i386)',
        isa: 'x86',
        endianness: 'little',
        codeOffset: i386.codeOffset,
      },
      {
        name: 'sparc.nlm',
        bytes: [...sparc.file],
        variant: 'NetWare NLM (SPARC)',
        isa: 'sparc',
        endianness: 'big',
        codeOffset: sparc.codeOffset,
      },
    ];
    const payloads = await page.evaluate(async ({ module, fixtures }) => {
      const wasm = await import(module);
      await wasm.default();
      return Object.fromEntries(fixtures.map(f => [f.name, JSON.parse(wasm.classify(new Uint8Array(f.bytes)))]));
    }, { module, fixtures });
    assert.ok(Object.hasOwn(FORMAT_NAMES, 'netwarenlm'), 'netwarenlm has a display name');
    for (const { name, variant, isa, endianness, codeOffset } of fixtures) {
      const p = payloads[name];
      assert.ok(!p.error, `${name}: ${p.error}`);
      assert.equal(p.format.format, 'netwarenlm', name);
      assert.equal(p.format.variant_name, variant, name);
      assert.deepEqual([p.primary.isa, p.primary.endianness], [isa, endianness], name);
      assert.ok(p.notes.some(n => n.message === 'Module TEST.NLM: Browser test module'), name);
      assert.ok(p.notes.some(n => n.message === '1 module dependency: CLIB'), name);
      const section = p.metadata.find(m => m.key?.custom === 'nlm_section_0');
      assert.ok(section?.value.startsWith(`file 0x${codeOffset.toString(16).toUpperCase()}; destination 0x0;`), name);
    }
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names NetWare modules in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const { file } = nlm(I386, await testbin(X86_CODE));
    const upload = { name: 'test.nlm', buffer: file, mimeType: 'application/octet-stream' };
    await page.locator('#fileinput').setInputFiles([upload]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes('NetWare NLM'), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.primary.isa, 'x86');
    assert.ok(p.metadata.some(m => m.key?.custom === 'nlm_image_size' && m.value === file.length));
    assert.ok(p.metadata.some(m => m.key?.custom === 'nlm_module_name' && m.value === 'TEST.NLM'));
  });
}
