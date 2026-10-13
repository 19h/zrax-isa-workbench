import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { gzipSync } from 'node:zlib';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup);
after(teardown);

// Synthetic payloads (tests/fixtures/rpm/README.md): a newc cpio archive holding ./usr/bin/hello, a 256-byte
// x86-64 ELF header, and a text file, plus its compressed copies.
const fixture = name => readFile(new URL(`../../tests/fixtures/${name}`, import.meta.url));

// --- RPM header structures (rpm docs/manual/format_header.md, LSB 5.0 section 25.2.2); all big-endian ---

const HEADER_MAGIC = Buffer.from([0x8e, 0xad, 0xe8, 0x01, 0, 0, 0, 0]);
const LEAD_MAGIC = [0xed, 0xab, 0xee, 0xdb];
const LEAD_SIZE = 96;

const RPM_INT32_TYPE = 4;
const RPM_STRING_TYPE = 6;
const RPM_BIN_TYPE = 7;
const RPM_STRING_ARRAY_TYPE = 8;

const HEADER_SIGNATURES = 62;
const HEADER_IMMUTABLE = 63;
const RPMSIGTAG_SHA256 = 272;
const RPMSIGTAG_SIZE = 1000;
const RPMSIGTAG_MD5 = 1004;
const RPMTAG_NAME = 1000;
const RPMTAG_VERSION = 1001;
const RPMTAG_RELEASE = 1002;
const RPMTAG_OS = 1021;
const RPMTAG_ARCH = 1022;
const RPMTAG_SOURCERPM = 1044;
const RPMTAG_PAYLOADFORMAT = 1124;
const RPMTAG_PAYLOADCOMPRESSOR = 1125;
const RPMTAG_PAYLOADSHA256 = 5092;

const be32 = value => {
  const bytes = Buffer.alloc(4);
  bytes.writeInt32BE(value);
  return bytes;
};
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const md5 = bytes => createHash('md5').update(bytes).digest();

// Entries: a STRING (text and NUL), a STRING_ARRAY of one string, an INT32 and a BIN value.
const stringTag = (tag, text) => ({ tag, kind: RPM_STRING_TYPE, count: 1, data: Buffer.from(`${text}\0`, 'latin1') });
const stringsTag = (tag, text) => ({ ...stringTag(tag, text), kind: RPM_STRING_ARRAY_TYPE });
const int32Tag = (tag, value) => ({ tag, kind: RPM_INT32_TYPE, count: 1, data: be32(value) });
const binTag = (tag, bytes) => ({ tag, kind: RPM_BIN_TYPE, count: bytes.length, data: bytes });

// A header structure: magic, entry count, store size, the region entry and the entries (tag, type, offset, count)
// sorted by tag, then the store with INT32 values aligned to 4 and the region trailer (the region tag, BIN, offset
// -16 * entries, count 16) at its end.
function header(regionTag, tags) {
  const sorted = [...tags].sort((a, b) => a.tag - b.tag);
  const index = [];
  const store = [];
  let size = 0;
  for (const t of sorted) {
    const pad = t.kind === RPM_INT32_TYPE ? (4 - (size % 4)) % 4 : 0;
    store.push(Buffer.alloc(pad));
    size += pad;
    index.push([t.tag, t.kind, size, t.count]);
    store.push(t.data);
    size += t.data.length;
  }
  const entries = sorted.length + 1;
  index.unshift([regionTag, RPM_BIN_TYPE, size, 16]);
  store.push(Buffer.concat([be32(regionTag), be32(RPM_BIN_TYPE), be32(-16 * entries), be32(16)]));
  size += 16;
  const intro = Buffer.concat([HEADER_MAGIC, be32(entries), be32(size)]);
  return Buffer.concat([intro, ...index.map(fields => Buffer.concat(fields.map(be32))), ...store]);
}

// An RPM v4 binary package: the lead (magic, version 3.0, binary, name, signature type 5), the signature header
// (header and payload size, header SHA-256, header and payload MD5) zero-padded to 8 bytes, the main header
// (identity, architecture, payload format, compressor and payload SHA-256) and the payload.
function rpm(arch, compressor, payload) {
  const main = header(HEADER_IMMUTABLE, [
    stringTag(RPMTAG_NAME, 'hello'),
    stringTag(RPMTAG_VERSION, '1.0'),
    stringTag(RPMTAG_RELEASE, '1'),
    stringTag(RPMTAG_OS, 'linux'),
    stringTag(RPMTAG_ARCH, arch),
    stringTag(RPMTAG_SOURCERPM, 'hello-1.0-1.src.rpm'),
    stringTag(RPMTAG_PAYLOADFORMAT, 'cpio'),
    stringTag(RPMTAG_PAYLOADCOMPRESSOR, compressor),
    stringsTag(RPMTAG_PAYLOADSHA256, sha256(payload)),
  ]);
  const covered = Buffer.concat([main, payload]);
  const signature = header(HEADER_SIGNATURES, [
    int32Tag(RPMSIGTAG_SIZE, covered.length),
    stringTag(RPMSIGTAG_SHA256, sha256(main)),
    binTag(RPMSIGTAG_MD5, md5(covered)),
  ]);
  const lead = Buffer.alloc(LEAD_SIZE);
  lead.set(LEAD_MAGIC);
  lead[4] = 3;
  lead.write('hello-1.0-1', 10, 'latin1');
  lead.writeUInt16BE(5, 78);
  const padding = Buffer.alloc((8 - ((LEAD_SIZE + signature.length) % 8)) % 8);
  const bytes = Buffer.concat([lead, signature, padding, covered]);
  return { bytes, payloadOffset: bytes.length - payload.length, payloadSize: payload.length };
}

// --- Debian packages (dpkg man/deb.pod): an ar archive of debian-binary, control.tar.gz and data.tar.gz ---

// A ustar header (name, mode, uid, gid, size, mtime in octal, checksum, typeflag 0, magic ustar\0 and version 00 at
// 257), then the data padded to 512 bytes; two zero blocks end the archive.
function tar(name, contents) {
  const block = Buffer.alloc(512);
  block.write(name, 0, 'latin1');
  block.write('0000755\0', 100, 'latin1');
  block.write('0000000\0', 108, 'latin1');
  block.write('0000000\0', 116, 'latin1');
  block.write(`${contents.length.toString(8).padStart(11, '0')}\0`, 124, 'latin1');
  block.write('00000000000\0', 136, 'latin1');
  block.write('        ', 148, 'latin1');
  block.write('0', 156, 'latin1');
  block.write('ustar\x0000', 257, 'latin1');
  const sum = block.reduce((total, b) => total + b, 0);
  block.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 'latin1');
  const padded = Buffer.alloc(Math.ceil(contents.length / 512) * 512);
  contents.copy(padded);
  return Buffer.concat([block, padded, Buffer.alloc(1024)]);
}

// `!<arch>\n`, then per member a 60-byte header (name with a trailing slash, mtime, uid, gid, mode, decimal size,
// "`\n") and the data, padded to an even offset with "\n".
function ar(members) {
  const parts = [Buffer.from('!<arch>\n', 'latin1')];
  for (const [name, contents] of members) {
    const fields = [`${name}/`.padEnd(16), '0'.padEnd(12), '0'.padEnd(6), '0'.padEnd(6), '100644'.padEnd(8),
      String(contents.length).padEnd(10), '`\n'];
    parts.push(Buffer.from(fields.join(''), 'latin1'), contents);
    if (contents.length % 2 === 1) parts.push(Buffer.from('\n', 'latin1'));
  }
  return Buffer.concat(parts);
}

const deb = elf => ar([
  ['debian-binary', Buffer.from('2.0\n', 'latin1')],
  ['control.tar.gz', gzipSync(tar('./control', Buffer.from('Package: hello\n', 'latin1')))],
  ['data.tar.gz', gzipSync(tar('./usr/bin/hello', elf))],
]);

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`RPM and Debian packages classify from their payload files through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const elf = await fixture('compressed/payload.elf');
    const packages = [
      rpm('x86_64', 'gzip', await fixture('rpm/payload.cpio.gz')),
      rpm('aarch64', 'xz', await fixture('rpm/payload.cpio.xz')),
      rpm('noarch', 'zstd', await fixture('rpm/payload.cpio.zst')),
    ];
    const inputs = [...packages.map(p => p.bytes), deb(elf)];
    const payloads = await page.evaluate(async ({ module, inputs }) => {
      const wasm = await import(module);
      await wasm.default();
      return inputs.map(bytes => JSON.parse(wasm.classify(new Uint8Array(bytes))));
    }, { module, inputs: inputs.map(input => [...input]) });

    const transforms = ['gzip', 'xz', 'Zstandard'];
    packages.forEach((fixtureInfo, i) => {
      const p = payloads[i];
      assert.ok(!p.error, p.error);
      assert.equal(p.format.format, 'rpm');
      // The header architecture is not ISA evidence: the payload's ELF decides.
      assert.equal(p.primary.isa, 'x86_64');
      const hello = p.slices.find(s => s.label === './usr/bin/hello');
      assert.ok(hello, './usr/bin/hello slice');
      assert.deepEqual([hello.isa, hello.offset, hello.size, hello.decoded.transform, hello.decoded.size],
        ['x86_64', fixtureInfo.payloadOffset, fixtureInfo.payloadSize, transforms[i], elf.length]);
      assert.ok(p.notes.some(n => n.message.startsWith('Digests verified: header SHA-256, payload SHA-256, '
        + 'header and payload MD5')), JSON.stringify(p.notes));
    });

    const debPayload = payloads[3];
    assert.ok(!debPayload.error, debPayload.error);
    assert.equal(debPayload.format.format, 'archive');
    assert.equal(debPayload.primary.isa, 'x86_64');
    assert.equal(debPayload.slices.find(s => s.label === 'data.tar.gz').isa, 'x86_64');
    assert.ok(Object.hasOwn(FORMAT_NAMES, 'rpm'), 'rpm has a display name');
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names RPM packages in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const { bytes: buffer } = rpm('x86_64', 'gzip', await fixture('rpm/payload.cpio.gz'));
    const upload = { name: 'hello-1.0-1.x86_64.rpm', buffer, mimeType: 'application/octet-stream' };
    await page.locator('#fileinput').setInputFiles([upload]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes(FORMAT_NAMES.rpm), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.primary.isa, 'x86_64');
    assert.ok(p.metadata.some(m => m.key?.custom === 'rpm_image_size' && m.value === buffer.length));
    assert.ok(p.metadata.some(m => m.key?.custom === 'rpm_arch' && m.value === 'x86_64'));
  });
}
