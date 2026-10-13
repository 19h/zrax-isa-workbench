import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl, elf } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';

before(setup);
after(teardown);

// Committed fixtures (tests/fixtures/wim/README.md): a stored WIM written by
// 7-Zip and synthetic XPRESS, LZX and LZMS WIMs, each holding the x86-64 PE
// Windows/System32/driver.efi and the AArch64 ELF payload.elf.
const fixture = name => readFile(new URL(`../../tests/fixtures/wim/${name}`, import.meta.url));

const FIXTURES = [
  { name: '7zip-stored.wim', isa: 'a_arch64', first: '/1/payload.elf' },
  { name: 'xpress.wim', isa: 'x86_64', first: '/1/Windows/System32/driver.efi', transform: 'XPRESS' },
  { name: 'lzx.wim', isa: 'x86_64', first: '/1/Windows/System32/driver.efi', transform: 'LZX' },
  { name: 'solid-lzx.wim', isa: 'x86_64', first: '/1/Windows/System32/driver.efi', transform: 'LZX' },
  { name: 'solid-lzms.wim', isa: 'x86_64', first: '/1/Windows/System32/driver.efi', transform: 'LZMS' },
];

const sha1 = bytes => createHash('sha1').update(bytes).digest();
const utf16 = text => Buffer.from(text, 'utf16le');
const align8 = n => (n + 7) & ~7;

// Wire constants (wimlib `include/wimlib/header.h`, `resource.h`, `dentry.h`).
const HEADER_SIZE = 208;
const WIM_VERSION = 0x10d00;
// The resource header flag that marks metadata, including the lookup table.
const RESOURCE_METADATA = 0x02;
const FILE_ATTRIBUTE_DIRECTORY = 0x10;
const FILE_ATTRIBUTE_ARCHIVE = 0x20;
const END_OF_LIST = Buffer.alloc(8);

// A resource header: stored size (7 bytes), flags, offset, uncompressed size.
function reshdr(size, flags, offset) {
  const out = Buffer.alloc(24);
  out.writeUIntLE(size, 0, 6);
  out[7] = flags;
  out.writeBigUInt64LE(BigInt(offset), 8);
  out.writeBigUInt64LE(BigInt(size), 16);
  return out;
}

// A directory entry (wimlib `wim_dentry_on_disk`, 102 bytes and the name):
// length, attributes, security ID, subdirectory offset, the SHA-1 of the
// unnamed stream at 0x40 and the name size at 0x64.
function dentry(name, attributes, subdir, hash) {
  const nameBytes = utf16(name);
  const size = align8(102 + (nameBytes.length ? nameBytes.length + 2 : 0));
  const out = Buffer.alloc(size);
  out.writeBigUInt64LE(BigInt(size), 0);
  out.writeUInt32LE(attributes, 8);
  out.writeUInt32LE(0xffffffff, 12);
  out.writeBigUInt64LE(BigInt(subdir), 16);
  hash?.copy(out, 0x40);
  out.writeUInt16LE(nameBytes.length, 0x64);
  nameBytes.copy(out, 102);
  return out;
}

// A lookup table entry: resource header, part number 1, reference count 1
// and the SHA-1 of the uncompressed data.
const lookupEntry = (header, hash) => Buffer.concat([header, Buffer.from([1, 0, 1, 0, 0, 0]), hash]);

// An image's metadata resource: empty security data (total length 8), the
// root directory entry and its end of list, then the root's list (one file)
// and its end of list. The root's subdirectory offset is relative to the
// resource.
function metadataResource(fileName, data) {
  const security = Buffer.from([8, 0, 0, 0, 0, 0, 0, 0]);
  const root = dentry('', FILE_ATTRIBUTE_DIRECTORY, 0, null);
  const listOffset = security.length + root.length + END_OF_LIST.length;
  root.writeBigUInt64LE(BigInt(listOffset), 16);
  const file = dentry(fileName, FILE_ATTRIBUTE_ARCHIVE, 0, sha1(data));
  return Buffer.concat([security, root, END_OF_LIST, file, END_OF_LIST]);
}

// A stored WIM of one image named "Browser" whose root holds `fileName`, laid
// out as the header, the file resource, the metadata resource, the lookup
// table and the UTF-16LE XML data. Header: magic, header size (0x08),
// version (0x0C), part number (0x28), total parts (0x2A), image count
// (0x2C), lookup table resource (0x30), XML resource (0x48).
function storedWim(fileName, data) {
  const metadata = metadataResource(fileName, data);
  const fileOffset = HEADER_SIZE;
  const metadataOffset = fileOffset + data.length;
  const tableOffset = metadataOffset + metadata.length;
  const table = Buffer.concat([
    lookupEntry(reshdr(data.length, 0, fileOffset), sha1(data)),
    lookupEntry(reshdr(metadata.length, RESOURCE_METADATA, metadataOffset), sha1(metadata)),
  ]);
  const xmlOffset = tableOffset + table.length;
  const xmlText = '<WIM><IMAGE INDEX="1"><NAME>Browser</NAME></IMAGE></WIM>';
  const xml = Buffer.concat([Buffer.from([0xff, 0xfe]), utf16(xmlText)]);
  const header = Buffer.alloc(HEADER_SIZE);
  header.write('MSWIM\0\0\0', 0, 'latin1');
  header.writeUInt32LE(HEADER_SIZE, 0x08);
  header.writeUInt32LE(WIM_VERSION, 0x0c);
  header.writeUInt16LE(1, 0x28);
  header.writeUInt16LE(1, 0x2a);
  header.writeUInt32LE(1, 0x2c);
  reshdr(table.length, RESOURCE_METADATA, tableOffset).copy(header, 0x30);
  reshdr(xml.length, 0, xmlOffset).copy(header, 0x48);
  return { bytes: Buffer.concat([header, data, metadata, table, xml]), fileOffset };
}

const hasNote = (payload, text) => payload.notes.some(n => n.message.includes(text));

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`WIM images list their files through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const built = storedWim('tool.elf', elf('tool.elf', 62, 256).buffer);
    const inputs = [
      ...await Promise.all(FIXTURES.map(async f => ({ ...f, base64: (await fixture(f.name)).toString('base64') }))),
      { name: 'built', isa: 'x86_64', first: '/1/tool.elf', base64: built.bytes.toString('base64') },
    ];
    const payloads = await page.evaluate(async ({ module, inputs }) => {
      const wasm = await import(module);
      await wasm.default();
      return inputs.map(input => {
        const bytes = Uint8Array.from(atob(input.base64), c => c.charCodeAt(0));
        return JSON.parse(wasm.classify(bytes));
      });
    }, { module, inputs });
    inputs.forEach(({ name, isa, first, transform }, i) => {
      const p = payloads[i];
      assert.ok(!p.error, `${name}: ${p.error}`);
      assert.equal(p.format.format, 'wim', name);
      assert.equal(p.format.variant_name, 'WIM image', name);
      assert.equal(p.primary.isa, isa, name);
      assert.equal(p.slices[0].label, first, `${name}: ${JSON.stringify(p.slices)}`);
      assert.ok(hasNote(p, 'SHA-1 verified for'), `${name}: ${JSON.stringify(p.notes)}`);
      if (transform) {
        const tools = p.slices.find(s => s.label === '/1/tools.elf');
        assert.equal(tools?.decoded?.transform, transform, `${name}: ${JSON.stringify(p.slices)}`);
        assert.equal(tools.decoded.size, 20000, name);
      }
    });
    assert.ok(Object.hasOwn(FORMAT_NAMES, 'wim'), 'wim has a display name');
    const builtPayload = payloads[FIXTURES.length];
    assert.equal(builtPayload.slices[0].offset, built.fileOffset, 'a stored file keeps its offset');
    assert.ok(builtPayload.metadata.some(m => m.key?.custom === 'wim_image_1_name' && m.value === 'Browser'));
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names WIM images and their LZMS files in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const buffer = await fixture('solid-lzms.wim');
    const file = { name: 'install.esd', buffer, mimeType: 'application/octet-stream' };
    await page.locator('#fileinput').setInputFiles([file]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes(FORMAT_NAMES.wim), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.primary.isa, 'x86_64');
    assert.ok(p.metadata.some(m => m.key?.custom === 'wim_compression' && m.value === 'LZMS'));
    assert.ok(p.metadata.some(m => m.key?.custom === 'wim_image_1_name' && m.value === 'Fixture'));
  });
}
