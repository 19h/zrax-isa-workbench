import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { deflateRawSync, deflateSync } from 'node:zlib';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup);
after(teardown);

const fixture = path => readFile(new URL(`../../tests/fixtures/${path}`, import.meta.url));

// The committed ASAR fixture (tests/fixtures/appbundle/README.md): header_size 1376, so file data starts at 1384.
const sampleAsar = () => fixture('appbundle/sample.asar');
const ASAR_DATA_START = 8 + 1376;

// 256-byte ELF headers with filler: x86-64 (compressed/README.md) and AArch64 (archives/README.md).
const x86Elf = () => fixture('compressed/payload.elf');
const armElf = () => fixture('archives/payload.elf');

const be32 = value => {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32BE(value);
  return bytes;
};
const le32 = value => {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32LE(value);
  return bytes;
};
const le64 = value => {
  const bytes = Buffer.alloc(8);
  bytes.writeBigInt64LE(BigInt(value));
  return bytes;
};
const align16 = value => Math.ceil(value / 16) * 16;

// --- PyInstaller ---

const COOKIE_MAGIC = Buffer.from([0x4d, 0x45, 0x49, 0x0c, 0x0b, 0x0a, 0x0b, 0x0e]);

// A CArchive as CArchiveWriter writes it: entry data from offset 0, the TOC (entry length, offset, stored length,
// uncompressed length, all big-endian; compression flag, type code, NUL-terminated name padded to 16), then the
// cookie (magic, package length, TOC offset and length, Python version 312, library name padded to 64).
function carchive(entries, libname) {
  const blobs = [];
  const records = [];
  let offset = 0;
  for (const { name, typecode, contents, compress } of entries) {
    const stored = compress ? deflateSync(contents, { level: 9 }) : contents;
    const length = align16(18 + name.length + 1);
    const record = Buffer.alloc(length);
    record.writeUInt32BE(length, 0);
    record.writeUInt32BE(offset, 4);
    record.writeUInt32BE(stored.length, 8);
    record.writeUInt32BE(contents.length, 12);
    record[16] = compress ? 1 : 0;
    record.write(typecode, 17, 'latin1');
    record.write(name, 18, 'latin1');
    blobs.push(stored);
    records.push(record);
    offset += stored.length;
  }
  const toc = Buffer.concat(records);
  const name = Buffer.alloc(64);
  name.write(libname, 0, 'latin1');
  const lengths = [be32(offset + toc.length + 88), be32(offset), be32(toc.length), be32(312)];
  const cookie = Buffer.concat([COOKIE_MAGIC, ...lengths, name]);
  return Buffer.concat([...blobs, toc, cookie]);
}

// A one-file archive: the entry script (marshalled code stands in as opaque bytes), the x86-64 Python library
// (compressed) and an AArch64 extension module (stored).
function pyinstaller(x86, arm) {
  const code = Buffer.from('\xe3zrax python code object', 'latin1');
  const script = { name: 'main', typecode: 's', contents: code, compress: true };
  const library = { name: 'libpython3.12.so.1.0', typecode: 'b', contents: x86, compress: true };
  const extension = { name: '_ssl.so', typecode: 'b', contents: arm, compress: false };
  const libraryOffset = deflateSync(code, { level: 9 }).length;
  const extensionOffset = libraryOffset + deflateSync(x86, { level: 9 }).length;
  return { bytes: carchive([script, library, extension], 'libpython3.12.so.1.0'), libraryOffset, extensionOffset };
}

// --- .NET single-file bundle ---

const BUNDLE_SIGNATURE = Buffer.from('8b1202b96a612038727b930214d7a03213f5b9e6efae3318ee3b2dce24b36aae', 'hex');
const MARKER_AT = 0x80;

// A BinaryWriter string shorter than 128 bytes: a one-byte length, then the bytes.
const text = value => Buffer.concat([Buffer.from([value.length]), Buffer.from(value, 'latin1')]);

// The host with the bundle marker (header offset, signature) at 0x80, a native AArch64 library compressed with raw
// DEFLATE and deps.json, then the version 6.0 header (major, minor, count, bundle ID, the deps.json and
// runtimeconfig.json locations, flags) and the entries (offset, size, compressed size, type, path).
function dotnetBundle(host, arm) {
  const deps = Buffer.from('{"runtimeTarget":{}}', 'latin1');
  const compressed = deflateRawSync(arm);
  const nativeAt = host.length;
  const depsAt = nativeAt + compressed.length;
  const headerAt = depsAt + deps.length;
  const header = Buffer.concat([
    le32(6), le32(0), le32(2), text('zraxbundleid'),
    le64(depsAt), le64(deps.length), le64(0), le64(0), le64(0),
  ]);
  const entries = Buffer.concat([
    le64(nativeAt), le64(arm.length), le64(compressed.length), Buffer.from([2]), text('libzrax.so'),
    le64(depsAt), le64(deps.length), le64(0), Buffer.from([3]), text('zrax.deps.json'),
  ]);
  const bytes = Buffer.concat([host, compressed, deps, header, entries]);
  le64(headerAt).copy(bytes, MARKER_AT);
  BUNDLE_SIGNATURE.copy(bytes, MARKER_AT + 8);
  return bytes;
}

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`application bundles classify through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const [asar, x86, arm] = await Promise.all([sampleAsar(), x86Elf(), armElf()]);
    const archive = pyinstaller(x86, arm);
    const inputs = [asar, archive.bytes, dotnetBundle(x86, arm)];
    const payloads = await page.evaluate(async ({ module, inputs }) => {
      const wasm = await import(module);
      await wasm.default();
      return inputs.map(bytes => JSON.parse(wasm.classify(new Uint8Array(bytes))));
    }, { module, inputs: inputs.map(input => [...input]) });
    const [asarPayload, pyiPayload, dotnetPayload] = payloads;

    assert.ok(!asarPayload.error, asarPayload.error);
    assert.equal(asarPayload.format.format, 'asar');
    assert.equal(asarPayload.primary.isa, 'a_arch64');
    const armModule = asarPayload.slices.find(s => s.label === 'native/aarch64.node');
    assert.deepEqual([armModule.isa, armModule.offset, armModule.size], ['a_arch64', ASAR_DATA_START + 67, 256]);
    const x86Module = asarPayload.slices.find(s => s.label === 'native/x86_64.node');
    assert.deepEqual([x86Module.isa, x86Module.offset], ['x86_64', ASAR_DATA_START + 323]);
    const integrity = 'Integrity: 4 of 4 declared SHA-256 file hashes verified; block hashes not verified';
    assert.ok(asarPayload.notes.some(n => n.message === integrity), integrity);

    assert.ok(!pyiPayload.error, pyiPayload.error);
    assert.equal(pyiPayload.format.format, 'pyinstaller');
    assert.equal(pyiPayload.primary.isa, 'x86_64');
    const library = pyiPayload.slices.find(s => s.label === 'libpython3.12.so.1.0');
    assert.deepEqual([library.isa, library.offset, library.decoded.transform, library.decoded.size],
      ['x86_64', archive.libraryOffset, 'zlib', x86.length]);
    const extension = pyiPayload.slices.find(s => s.label === '_ssl.so');
    assert.deepEqual([extension.isa, extension.offset], ['a_arch64', archive.extensionOffset]);
    assert.ok(pyiPayload.notes.some(n => n.message === 'Python 3.12; Python library libpython3.12.so.1.0'));

    // A .NET bundle lives in its apphost: the host keeps its own format and ISA.
    assert.ok(!dotnetPayload.error, dotnetPayload.error);
    assert.equal(dotnetPayload.format.format, 'elf');
    assert.equal(dotnetPayload.primary.isa, 'x86_64');

    for (const id of ['pyinstaller', 'asar', 'dotnetbundle']) {
      assert.ok(Object.hasOwn(FORMAT_NAMES, id), `${id} has a display name`);
    }
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names ASAR archives in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const buffer = await sampleAsar();
    const upload = { name: 'app.asar', buffer, mimeType: 'application/octet-stream' };
    await page.locator('#fileinput').setInputFiles([upload]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes(FORMAT_NAMES.asar), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.primary.isa, 'a_arch64');
    assert.ok(p.metadata.some(m => m.key?.custom === 'asar_image_size' && m.value === buffer.length));
  });
}
