import assert from 'node:assert/strict';
import { deflateSync } from 'node:zlib';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl, elf } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup);
after(teardown);

// SquashFS 4.0 (Linux v6.11 `fs/squashfs/squashfs_fs.h`).
const SQUASHFS_METADATA_STORED = 0x8000;
const SQUASHFS_BLOCK_STORED = 1 << 24;
const SQUASHFS_INVALID = 0xffffffffffffffffn;
const SQUASHFS_NO_FRAGMENT = 0xffffffff;
const SQUASHFS_DIR_TYPE = 1;
const SQUASHFS_REG_TYPE = 2;
const SQUASHFS_ZLIB = 1;
const SQUASHFS_BLOCK_SIZE = 4096;
const SQUASHFS_BLOCK_LOG = 12;

// CramFS (Linux v6.11 `include/uapi/linux/cramfs_fs.h`).
const CRAMFS_MAGIC = 0x28cd3d45;
const CRAMFS_FSID_VERSION_2_AND_SORTED_DIRS = 0x3;
const CRAMFS_PAGE = 4096;
const S_IFDIR_755 = 0o040755;
const S_IFREG_755 = 0o100755;

// romfs (Linux v6.11 `include/uapi/linux/romfs_fs.h`).
const ROMFH_HRD = 0;
const ROMFH_DIR = 1;
const ROMFH_REG = 2;
const ROMFH_EXEC = 8;
const ROMFS_CHECKSUM_SPAN = 512;

function crc32(bytes) {
  let crc = ~0;
  for (const b of bytes) {
    crc ^= b;
    for (let i = 0; i < 8; i++) {
      crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
    }
  }
  return ~crc >>> 0;
}

const align = (size, to) => Math.ceil(size / to) * to;
const zeroPad = (bytes, to) => Buffer.concat([bytes, Buffer.alloc(align(bytes.length, to) - bytes.length)]);

// A 64-byte x86-64 ELF header and 192 B of text, so the member spans more
// than its header.
function appElf() {
  const text = Buffer.from('zrax read-only filesystem fixture text '.repeat(5)).subarray(0, 192);
  return Buffer.concat([elf('app.elf').buffer, text]);
}

const README = Buffer.from('plain words for a read only filesystem fixture\n'.repeat(4));

// SquashFS metadata block: a 2-byte header with bit 15 set (stored), then
// the bytes.
function metadataBlock(bytes) {
  const block = Buffer.alloc(2 + bytes.length);
  block.writeUInt16LE(SQUASHFS_METADATA_STORED | bytes.length, 0);
  bytes.copy(block, 2);
  return block;
}

// Basic regular file inode: type 2, mode, uid and gid indexes, mtime, inode
// number; start block, no fragment, fragment offset 0, file size; one
// block list entry with the stored bit.
function regularInode(number, start, size) {
  const inode = Buffer.alloc(36);
  inode.writeUInt16LE(SQUASHFS_REG_TYPE, 0);
  inode.writeUInt16LE(0o755, 2);
  inode.writeUInt32LE(number, 12);
  inode.writeUInt32LE(start, 16);
  inode.writeUInt32LE(SQUASHFS_NO_FRAGMENT, 20);
  inode.writeUInt32LE(size, 28);
  inode.writeUInt32LE(SQUASHFS_BLOCK_STORED | size, 32);
  return inode;
}

// Root directory listing: one header (count - 1, inode block 0, base inode
// number 1) and one entry per file (inode offset, number delta, type 2,
// name size - 1, name).
function rootListing(files, inodeSize) {
  const header = Buffer.alloc(12);
  header.writeUInt32LE(files.length - 1, 0);
  header.writeUInt32LE(1, 8);
  const entries = files.map(([name], i) => {
    const entry = Buffer.alloc(8 + name.length);
    entry.writeUInt16LE(inodeSize * i, 0);
    entry.writeInt16LE(i, 2);
    entry.writeUInt16LE(SQUASHFS_REG_TYPE, 4);
    entry.writeUInt16LE(name.length - 1, 6);
    entry.write(name, 8);
    return entry;
  });
  return Buffer.concat([header, ...entries]);
}

// Root directory inode: type 1, number, start block 0, link count 2, file
// size (listing + 3), listing offset 0, parent.
function rootInode(number, listingSize) {
  const root = Buffer.alloc(32);
  root.writeUInt16LE(SQUASHFS_DIR_TYPE, 0);
  root.writeUInt16LE(0o755, 2);
  root.writeUInt32LE(number, 12);
  root.writeUInt32LE(2, 20);
  root.writeUInt16LE(listingSize + 3, 24);
  return root;
}

// SquashFS 4.0, little-endian, everything stored: the superblock, one data
// block per file, then the inode, directory and id tables, padded to 4 KiB.
// Superblock: magic, inode count, block size, compressor, block log, id
// count, version 4.0, root inode reference, bytes used, then the id, xattr,
// inode, directory, fragment and export table starts.
function squashfs(files) {
  const inodeSize = 36;
  const blocks = [];
  const inodes = [];
  let position = 96;
  files.forEach(([, bytes], i) => {
    inodes.push(regularInode(i + 1, position, bytes.length));
    blocks.push(bytes);
    position += bytes.length;
  });
  const listing = rootListing(files, inodeSize);
  const inodeTable = metadataBlock(Buffer.concat([...inodes, rootInode(files.length + 1, listing.length)]));
  const directoryTable = metadataBlock(listing);
  const idTable = metadataBlock(Buffer.alloc(4));
  const inodeStart = position;
  const directoryStart = inodeStart + inodeTable.length;
  const idBlock = directoryStart + directoryTable.length;
  const idIndex = Buffer.alloc(8);
  idIndex.writeBigUInt64LE(BigInt(idBlock));
  const idStart = idBlock + idTable.length;
  const bytesUsed = idStart + idIndex.length;
  const superblock = Buffer.alloc(96);
  superblock.write('hsqs', 0);
  superblock.writeUInt32LE(files.length + 1, 4);
  superblock.writeUInt32LE(SQUASHFS_BLOCK_SIZE, 12);
  superblock.writeUInt16LE(SQUASHFS_ZLIB, 20);
  superblock.writeUInt16LE(SQUASHFS_BLOCK_LOG, 22);
  superblock.writeUInt16LE(1, 26);
  superblock.writeUInt16LE(4, 28);
  superblock.writeBigUInt64LE(BigInt(inodeSize * files.length), 32);
  superblock.writeBigUInt64LE(BigInt(bytesUsed), 40);
  superblock.writeBigUInt64LE(BigInt(idStart), 48);
  superblock.writeBigUInt64LE(SQUASHFS_INVALID, 56);
  superblock.writeBigUInt64LE(BigInt(inodeStart), 64);
  superblock.writeBigUInt64LE(BigInt(directoryStart), 72);
  superblock.writeBigUInt64LE(BigInt(idBlock), 80);
  superblock.writeBigUInt64LE(SQUASHFS_INVALID, 88);
  return zeroPad(Buffer.concat([superblock, ...blocks, inodeTable, directoryTable, idTable, idIndex]), 4096);
}

// CramFS inode, little-endian: mode and uid; size (24 bits) and gid; name
// length / 4 (6 bits) and offset / 4 (26 bits).
function cramInode(mode, size, nameLength, offset) {
  const inode = Buffer.alloc(12);
  inode.writeUInt16LE(mode, 0);
  inode.writeUInt32LE(size, 4);
  inode.writeUInt32LE((nameLength / 4) | ((offset / 4) << 6), 8);
  return inode;
}

// CramFS file data at file offset `position`: one u32 pointer per page (the
// file offset where that page's zlib stream ends), then the streams,
// padded to 4 bytes.
function cramData(bytes, position) {
  const pages = [];
  for (let i = 0; i < bytes.length; i += CRAMFS_PAGE) {
    pages.push(deflateSync(bytes.subarray(i, i + CRAMFS_PAGE)));
  }
  const table = Buffer.alloc(4 * pages.length);
  let end = position + table.length;
  pages.forEach((page, i) => {
    end += page.length;
    table.writeUInt32LE(end, 4 * i);
  });
  return zeroPad(Buffer.concat([table, ...pages]), 4);
}

// CramFS (mkfs.cramfs layout), little-endian: superblock (magic, size,
// flags, signature, CRC, file count, name, root inode), the root's entries
// (inode and name padded to 4), each file's data, padding to 4 KiB. The
// CRC-32 covers the image with the CRC field zero.
function cramfs(files) {
  const entrySize = name => 12 + align(name.length, 4);
  let position = 76 + files.reduce((sum, [name]) => sum + entrySize(name), 0);
  const entries = [];
  const data = [];
  for (const [name, bytes] of files) {
    const stored = cramData(bytes, position);
    const entry = Buffer.alloc(entrySize(name));
    cramInode(S_IFREG_755, bytes.length, align(name.length, 4), position).copy(entry, 0);
    entry.write(name, 12);
    entries.push(entry);
    data.push(stored);
    position += stored.length;
  }
  const directory = Buffer.concat(entries);
  const image = zeroPad(Buffer.concat([Buffer.alloc(76), directory, ...data]), CRAMFS_PAGE);
  image.writeUInt32LE(CRAMFS_MAGIC, 0);
  image.writeUInt32LE(image.length, 4);
  image.writeUInt32LE(CRAMFS_FSID_VERSION_2_AND_SORTED_DIRS, 8);
  image.write('Compressed ROMFS', 16);
  image.writeUInt32LE(files.length + 1, 44);
  image.write('Compressed', 48);
  cramInode(S_IFDIR_755, directory.length, 0, 76).copy(image, 64);
  image.writeUInt32LE(crc32(image), 32);
  return image;
}

// Sum of big-endian words; a romfs region sums to 0.
function wordSum(bytes) {
  let sum = 0;
  for (let i = 0; i + 4 <= bytes.length; i += 4) {
    sum = (sum + bytes.readUInt32BE(i)) >>> 0;
  }
  return sum;
}

// The checksum word that makes a region sum to 0 (mod 2^32).
const balancing = sum => (0x100000000 - sum) % 0x100000000;

// romfs file header: next and type (0), spec (4), size (8), checksum (12),
// name NUL-terminated and padded to 16; the data follows, padded to 16.
// The checksum covers the header and padded name.
function romHeader(name, type, spec, contents) {
  const meta = align(16 + name.length + 1, 16);
  const header = Buffer.alloc(meta + align(contents.length, 16));
  header.writeUInt32BE(type, 0);
  header.writeUInt32BE(spec, 4);
  header.writeUInt32BE(contents.length, 8);
  header.write(name, 16);
  contents.copy(header, meta);
  return { header, meta };
}

// romfs (genromfs layout), big-endian: superblock (-rom1fs-, size,
// checksum, volume name), the root listing: `.` (a directory pointing at
// itself), `..` (a hard link to it), then the files, chained by `next`.
// The superblock checksum covers the first 512 bytes.
function romfs(files) {
  const superblock = Buffer.alloc(32);
  superblock.write('-rom1fs-', 0);
  superblock.write('zrax', 16);
  const dot = superblock.length;
  const headers = [romHeader('.', ROMFH_DIR, dot, Buffer.alloc(0)), romHeader('..', ROMFH_HRD, dot, Buffer.alloc(0))];
  for (const [name, bytes] of files) {
    headers.push(romHeader(name, ROMFH_REG | ROMFH_EXEC, 0, bytes));
  }
  let position = dot;
  const offsets = headers.map(({ header }) => {
    const at = position;
    position += header.length;
    return at;
  });
  headers.forEach(({ header, meta }, i) => {
    const next = i + 1 < headers.length ? offsets[i + 1] : 0;
    header.writeUInt32BE((next | header.readUInt32BE(0)) >>> 0, 0);
    header.writeUInt32BE(balancing(wordSum(header.subarray(0, meta))), 12);
  });
  const image = Buffer.concat([superblock, ...headers.map(({ header }) => header)]);
  image.writeUInt32BE(image.length, 8);
  const checked = image.subarray(0, Math.min(image.length, ROMFS_CHECKSUM_SPAN));
  image.writeUInt32BE(balancing(wordSum(checked)), 12);
  return zeroPad(image, 1024);
}

const FILES = [['app.elf', appElf()], ['readme.txt', README]];

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`read-only filesystems list their recognized members through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const fixtures = [
      ['squashfs', squashfs(FILES)],
      ['cramfs', cramfs(FILES)],
      ['romfs', romfs(FILES)],
    ].map(([format, bytes]) => ({ format, bytes: [...bytes] }));
    const payloads = await page.evaluate(async ({ module, fixtures }) => {
      const wasm = await import(module);
      await wasm.default();
      return fixtures.map(f => JSON.parse(wasm.classify(new Uint8Array(f.bytes))));
    }, { module, fixtures });
    const byFormat = Object.fromEntries(fixtures.map(({ format }, i) => [format, payloads[i]]));
    for (const [format, p] of Object.entries(byFormat)) {
      assert.ok(!p.error, `${format}: ${p.error}`);
      assert.equal(p.format.format, format);
      assert.ok(Object.hasOwn(FORMAT_NAMES, format), `${format} has a display name`);
      assert.equal(p.primary.isa, 'x86_64', format);
      assert.deepEqual(p.slices.map(s => s.label), ['/app.elf'], format);
      assert.equal(p.slices[0].isa, 'x86_64', format);
      assert.ok(p.notes.some(n => n.message.includes('2 regular files; 1 recognized members listed')), format);
    }
    // Stored SquashFS blocks and romfs data are listed where they are stored.
    const squash = byFormat.squashfs.slices[0];
    assert.deepEqual([squash.offset, squash.size, squash.decoded], [96, 256, undefined]);
    assert.equal(byFormat.romfs.slices[0].decoded, undefined);
    // CramFS blocks are zlib streams: the stored range and the decoded size.
    const cram = byFormat.cramfs.slices[0];
    assert.equal(cram.decoded.transform, 'zlib');
    assert.equal(cram.decoded.size, 256);
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names SquashFS and lists member paths in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const buffer = squashfs(FILES);
    const file = { name: 'rootfs.squashfs', buffer, mimeType: 'application/octet-stream' };
    await page.locator('#fileinput').setInputFiles([file]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes('SquashFS'), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.primary.isa, 'x86_64');
    assert.deepEqual(p.slices.map(s => s.label), ['/app.elf']);
    assert.ok(p.metadata.some(m => m.key?.custom === 'squashfs_regular_files' && m.value === 2));
  });
}
