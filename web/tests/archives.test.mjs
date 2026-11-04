import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup);
after(teardown);

const fixture = name => readFile(new URL(`../../tests/fixtures/archives/${name}`, import.meta.url));

// Each committed archive holds the synthetic AArch64 ELF `bin/payload.elf`
// and a text member; the fixture, its format ID and the codec named on the
// ELF member's slice (null when it is stored).
const ARCHIVES = [
  ['stored.zip', 'zip', null],
  ['deflate.zip', 'zip', 'DEFLATE'],
  ['descriptor.zip', 'zip', 'DEFLATE'],
  ['zip64.zip', 'zip', 'DEFLATE'],
  ['bzip2.zip', 'zip', 'bzip2'],
  ['lzma.zip', 'zip', 'LZMA'],
  ['xz.zip', 'zip', 'xz'],
  ['zstd.zip', 'zip', 'Zstandard'],
  ['ustar.tar', 'tar', null],
  ['pax.tar', 'tar', null],
  ['gnu.tar', 'tar', null],
  ['newc.cpio', 'cpio', null],
  ['odc.cpio', 'cpio', null],
  ['binary.cpio', 'cpio', null],
];

const OPAQUE = ['encrypted.zip', 'aes.zip', 'deflate64.zip'];

async function classifyAll(page, module, names) {
  const fixtures = await Promise.all(names.map(async name => ({ name, bytes: [...await fixture(name)] })));
  return page.evaluate(async ({ module, fixtures }) => {
    const wasm = await import(module);
    await wasm.default();
    return fixtures.map(f => JSON.parse(wasm.classify(new Uint8Array(f.bytes))));
  }, { module, fixtures });
}

// A StuffIt 5 archive is built here from the layout in
// src/formats/archives/stuffit.rs (The Unarchiver XADMaster 7cb9ee0a,
// XADStuffIt5Parser.m): no archiver on this platform writes one.

/** CRC-16/ARC: reflected polynomial 0xA001, initial value 0. */
function crc16Arc(bytes) {
  let crc = 0;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) {
      crc = crc & 1 ? (crc >>> 1) ^ 0xa001 : crc >>> 1;
    }
  }
  return crc;
}

const be16 = value => [(value >>> 8) & 0xff, value & 0xff];
const be32 = value => [(value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff];

/**
 * Entry header: magic A5A5A5A5, version 1, 0, header size (2), 0, flags
 * (0x40 folder), dates and previous/next entry offsets (16 zero bytes),
 * parent folder offset (4), name length (2), header CRC (2, over the header
 * with the field zeroed), two 32-bit fields (a file's data length and
 * stored length), data CRC (2), 0 (2), two tail bytes (a file's method and
 * password data length, a folder's entry count) and the name.
 */
function sitHeader(flags, parent, fields, dataCrc, tail, name) {
  const nameBytes = [...Buffer.from(name, 'latin1')];
  const header = [
    ...be32(0xa5a5a5a5), 1, 0, ...be16(48 + nameBytes.length), 0, flags,
    ...new Array(16).fill(0),
    ...be32(parent), ...be16(nameBytes.length), 0, 0,
    ...be32(fields[0]), ...be32(fields[1]), ...be16(dataCrc), 0, 0,
    ...tail, ...nameBytes,
  ];
  header.splice(32, 2, ...be16(crc16Arc(header)));
  return header;
}

/**
 * Second block without a resource fork: fork flags 0 (2), 0 (2), file type
 * and creator (4 each), Finder flags (2) and 22 B for an entry of version 1.
 */
const SIT_SECOND_BLOCK = [0, 0, 0, 0, ...Buffer.from('BINAzrax'), 0, 0, ...new Array(22).fill(0)];

/**
 * Archive of one folder holding stored files: the signature text, 1A 00,
 * version 5, flags 0x10, archive size (4), 0 (4), one root entry (2), the
 * first entry at 114 (4), a header CRC (2, not checked) and the 14 bytes of
 * flag 0x10; then the folder, the unnamed entry that follows every folder
 * (data length 0xFFFFFFFF) and each file's header, second block and data.
 */
function stuffit5(folder, files) {
  const signature = 'StuffIt (c)1997-2002 Aladdin Systems, Inc., http://www.aladdinsys.com/StuffIt/\r\n';
  const out = [...Buffer.from(signature, 'latin1'), 0x1a, 0x00, 5, 0x10];
  out.push(...be32(0), ...be32(0), ...be16(1), ...be32(114), 0, 0, ...new Array(14).fill(0));
  const folderAt = out.length;
  out.push(...sitHeader(0x40, 0, [0, 0], 0, be16(files.length), folder), ...SIT_SECOND_BLOCK);
  out.push(...sitHeader(0x40, 0, [0xffffffff, 0], 0, [0, 0], ''));
  for (const [name, bytes] of files) {
    out.push(...sitHeader(0, folderAt, [bytes.length, bytes.length], crc16Arc(bytes), [0, 0], name));
    out.push(...SIT_SECOND_BLOCK, ...bytes);
  }
  out.splice(84, 4, ...be32(out.length));
  return out;
}

async function classifyBytes(page, module, bytes) {
  return page.evaluate(async ({ module, bytes }) => {
    const wasm = await import(module);
    await wasm.default();
    return JSON.parse(wasm.classify(new Uint8Array(bytes)));
  }, { module, bytes });
}

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`archive members are classified on their own bytes through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const payloads = await classifyAll(page, module, ARCHIVES.map(([name]) => name));
    ARCHIVES.forEach(([name, format, transform], i) => {
      const p = payloads[i];
      assert.ok(!p.error, `${name}: ${p.error}`);
      assert.equal(p.format.format, format, name);
      assert.ok(Object.hasOwn(FORMAT_NAMES, format), `${format} has a display name`);
      assert.equal(p.primary.isa, 'a_arch64', name);
      const member = p.slices.find(s => s.label === 'bin/payload.elf');
      assert.ok(member, `${name}: ${JSON.stringify(p.slices)}`);
      assert.equal(member.isa, 'a_arch64', name);
      assert.equal(member.decoded?.transform ?? null, transform, name);
      assert.ok(!p.slices.some(s => s.label === 'notes.txt'), `${name}: text members are not listed`);
    });
  });

  test(`StuffIt 5 stored data forks are classified on their own bytes through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const payload = [...await fixture('payload.elf')];
    const text = [...Buffer.from('not a recognized format\n')];
    const archive = stuffit5('bin', [['payload.elf', payload], ['notes.txt', text]]);
    const p = await classifyBytes(page, module, archive);
    assert.ok(!p.error, p.error);
    assert.equal(p.format.format, 'stuffit');
    assert.equal(FORMAT_NAMES.stuffit, 'StuffIt');
    assert.equal(p.primary.isa, 'a_arch64');
    const member = p.slices.find(s => s.label === 'bin/payload.elf');
    assert.ok(member, JSON.stringify(p.slices));
    assert.equal(member.size, payload.length);
    assert.ok(!p.slices.some(s => s.label === 'bin/notes.txt'), 'text members are not listed');
    assert.ok(p.notes.some(n => n.message === 'Data fork CRC-16 verified for 2 of 2 stored files'));
  });

  test(`encrypted and Deflate64 ZIP members stay opaque through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const payloads = await classifyAll(page, module, OPAQUE);
    OPAQUE.forEach((name, i) => {
      const p = payloads[i];
      assert.equal(p.format.format, 'zip', name);
      assert.deepEqual(p.primary.isa, { unknown: 0 }, name);
      assert.deepEqual(p.slices ?? [], [], name);
      assert.ok(p.notes.some(n => /opaque/.test(n.message)), `${name}: ${JSON.stringify(p.notes)}`);
    });
  });

  test(`a gzip-compressed CPIO keeps the stored range and the decoded offset through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const [p] = await classifyAll(page, module, ['initramfs.cpio.gz']);
    const stored = await fixture('initramfs.cpio.gz');
    assert.equal(p.format.format, 'gzip');
    assert.equal(p.primary.isa, 'a_arch64');
    const member = p.slices.find(s => s.label === 'bin/payload.elf');
    assert.equal(member.offset, 0);
    assert.equal(member.size, stored.length);
    assert.equal(member.decoded.transform, 'gzip');
    assert.equal(member.decoded.size, 256);
    assert.ok(p.notes.some(n => n.message === 'Decoded payload: CPIO'));
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names archive formats and lists the member in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const buffer = await fixture('deflate.zip');
    await page.locator('#fileinput').setInputFiles([{ name: 'firmware.zip', buffer, mimeType: 'application/zip' }]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes(FORMAT_NAMES.zip), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.format.format, 'zip');
    assert.equal(p.primary.isa, 'a_arch64');
    assert.ok(p.metadata.some(m => m.key?.custom === 'zip_crc_verified' && m.value === 2));
  });
}
