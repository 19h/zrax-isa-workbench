import assert from 'node:assert/strict';
import { gzipSync } from 'node:zlib';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl, elf } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup);
after(teardown);

// QNX `sys/startup.h` and `sys/image.h`; every field little-endian here.
const STARTUP_HDR_SIGNATURE = 0x00ff7eeb;
const STARTUP_HEADER_SIZE = 0x100;
const FLAGS1_VIRTUAL = 0x01;
const COMPRESS_NONE = 0x00;
const COMPRESS_ZLIB = 0x04;
const IMAGE_FLAGS_INO_BITS = 0x04;
const IMAGE_HEADER_SIZE = 0x58;
const IMAGE_ATTR_SIZE = 24;
const S_IFDIR = 0x4000;
const S_IFREG = 0x8000;
const EM_AARCH64 = 183;
const IMAGE_PADDR = 0x80000000;

const align = (size, to) => Math.ceil(size / to) * to;

// The 32-bit word sum mkifs keeps; a region that ends with its trailer
// sums to zero.
function wordSum(bytes) {
  let sum = 0;
  for (let i = 0; i + 4 <= bytes.length; i += 4) {
    sum = (sum + bytes.readUInt32LE(i)) >>> 0;
  }
  return sum;
}

// Store the trailer at the end of `region` so its word sum is zero.
function seal(region) {
  region.writeUInt32LE(0, region.length - 4);
  region.writeUInt32LE((0x100000000 - wordSum(region)) % 0x100000000, region.length - 4);
}

// Directory entry: `struct image_attr` (size, extattr_offset, ino, mode,
// gid, uid, mtime), then `extra` (a file's offset and size), the
// NUL-terminated path, padded to four bytes.
function dirent(ino, mode, extra, path) {
  const entry = Buffer.alloc(align(IMAGE_ATTR_SIZE + extra.length + path.length + 1, 4));
  entry.writeUInt16LE(entry.length, 0);
  entry.writeUInt32LE(ino, 4);
  entry.writeUInt32LE(mode, 8);
  extra.copy(entry, IMAGE_ATTR_SIZE);
  entry.write(path, IMAGE_ATTR_SIZE + extra.length);
  return entry;
}

// Image filesystem (mkifs layout): header (signature, flags, image_size,
// hdr_dir_size, dir_offset, mountpoint `/`), the root directory, one entry
// per file, the zero-size terminator, the file data at four-byte
// boundaries, and the trailer.
function imagefs(files) {
  const dirOffset = align(IMAGE_HEADER_SIZE + 2, 4);
  const fileEntrySize = path => align(IMAGE_ATTR_SIZE + 8 + path.length + 1, 4);
  const root = dirent(1, S_IFDIR | 0o755, Buffer.alloc(0), '');
  const hdrDirSize = dirOffset + root.length + files.reduce((sum, [path]) => sum + fileEntrySize(path), 0) + 4;
  let position = hdrDirSize;
  const entries = [root];
  const data = [];
  files.forEach(([path, bytes], i) => {
    position = align(position, 4);
    const extra = Buffer.alloc(8);
    extra.writeUInt32LE(position, 0);
    extra.writeUInt32LE(bytes.length, 4);
    entries.push(dirent(i + 2, S_IFREG | 0o755, extra, path));
    data.push([position, bytes]);
    position += bytes.length;
  });
  const image = Buffer.alloc(align(position, 4) + 4);
  image.write('imagefs', 0);
  image[7] = IMAGE_FLAGS_INO_BITS;
  image.writeUInt32LE(image.length, 0x08);
  image.writeUInt32LE(hdrDirSize, 0x0c);
  image.writeUInt32LE(dirOffset, 0x10);
  image.write('/', IMAGE_HEADER_SIZE);
  Buffer.concat(entries).copy(image, dirOffset);
  for (const [at, bytes] of data) bytes.copy(image, at);
  seal(image);
  return image;
}

// Bootable image: the startup header (signature, version 1, flags1,
// header_size, machine, startup_vaddr, image_paddr, ram_paddr, ram_size,
// startup_size, stored_size, imagefs_size), AArch64 NOPs as the startup
// program and the startup trailer, then the image filesystem stored or as a
// gzip stream padded to four bytes with an image trailer.
function bootable(fs, compression) {
  const code = Buffer.alloc(64);
  for (let i = 0; i < code.length; i += 4) code.writeUInt32LE(0xd503201f, i);
  const startupSize = align(STARTUP_HEADER_SIZE + code.length + 4, 4);
  let region = fs;
  if (compression === COMPRESS_ZLIB) {
    const stream = gzipSync(fs);
    region = Buffer.alloc(align(stream.length, 4) + 4);
    stream.copy(region, 0);
    seal(region);
  }
  const startup = Buffer.alloc(startupSize);
  startup.writeUInt32LE(STARTUP_HDR_SIGNATURE, 0);
  startup.writeUInt16LE(1, 0x04);
  startup[0x06] = FLAGS1_VIRTUAL | compression;
  startup.writeUInt16LE(STARTUP_HEADER_SIZE, 0x08);
  startup.writeUInt16LE(EM_AARCH64, 0x0a);
  startup.writeUInt32LE(IMAGE_PADDR + STARTUP_HEADER_SIZE, 0x0c);
  startup.writeUInt32LE(IMAGE_PADDR, 0x14);
  startup.writeUInt32LE(IMAGE_PADDR, 0x18);
  startup.writeUInt32LE(startupSize + region.length, 0x1c);
  startup.writeUInt32LE(startupSize, 0x20);
  startup.writeUInt32LE(startupSize + region.length, 0x24);
  startup.writeUInt32LE(fs.length, 0x2c);
  code.copy(startup, STARTUP_HEADER_SIZE);
  seal(startup);
  return Buffer.concat([startup, region]);
}

const FILES = [
  ['proc/boot/procnto', elf('procnto', EM_AARCH64, 256).buffer],
  ['etc/motd', Buffer.from('plain words for a qnx image filesystem fixture\n'.repeat(3))],
];

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`QNX images report the startup machine and list ELF members through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const fs = imagefs(FILES);
    const fixtures = [
      ['stored', bootable(fs, COMPRESS_NONE)],
      ['gzip', bootable(fs, COMPRESS_ZLIB)],
      ['imagefs', fs],
    ].map(([name, bytes]) => ({ name, bytes: [...bytes] }));
    const payloads = await page.evaluate(async ({ module, fixtures }) => {
      const wasm = await import(module);
      await wasm.default();
      return fixtures.map(f => JSON.parse(wasm.classify(new Uint8Array(f.bytes))));
    }, { module, fixtures });
    const byName = Object.fromEntries(fixtures.map(({ name }, i) => [name, payloads[i]]));
    for (const [name, p] of Object.entries(byName)) {
      assert.ok(!p.error, `${name}: ${p.error}`);
      assert.equal(p.format.format, 'qnxifs', name);
      assert.equal(p.primary.isa, 'a_arch64', name);
      const procnto = p.slices.find(s => s.label === '/proc/boot/procnto');
      assert.ok(procnto, `${name}: ${p.slices.map(s => s.label)}`);
      assert.equal(procnto.isa, 'a_arch64', name);
      assert.ok(!p.slices.some(s => s.label === '/etc/motd'), name);
    }
    assert.ok(Object.hasOwn(FORMAT_NAMES, 'qnxifs'), 'qnxifs has a display name');
    // The stored member is listed where it is stored; the gzip member at the
    // compressed stream with its decoded size.
    const stored = byName.stored.slices.find(s => s.label === '/proc/boot/procnto');
    const startupSize = STARTUP_HEADER_SIZE + 64 + 4;
    assert.equal(stored.offset, startupSize + fs.indexOf(FILES[0][1]));
    assert.equal(stored.decoded, undefined);
    const decoded = byName.gzip.slices.find(s => s.label === '/proc/boot/procnto');
    assert.equal(decoded.offset, startupSize);
    assert.equal(decoded.decoded.transform, 'gzip');
    assert.equal(decoded.decoded.size, 256);
    assert.ok(byName.stored.notes.some(n => n.message === 'Startup program machine 183 (ELF e_machine): AArch64 (ARM64)'));
    assert.ok(byName.imagefs.notes.some(n => n.message.startsWith('Image filesystem without a startup header')));
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names QNX IFS images and their metadata in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const buffer = bootable(imagefs(FILES), COMPRESS_NONE);
    await page.locator('#fileinput').setInputFiles([{ name: 'boot.ifs', buffer, mimeType: 'application/octet-stream' }]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes('QNX IFS'), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.primary.isa, 'a_arch64');
    assert.ok(p.metadata.some(m => m.key?.custom === 'qnx_machine' && m.value === EM_AARCH64));
    assert.ok(p.metadata.some(m => m.key?.custom === 'qnx_mountpoint' && m.value === '/'));
  });
}
