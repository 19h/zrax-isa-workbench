import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { crc32 } from 'node:zlib';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';

before(setup);
after(teardown);

// Synthetic Full Flash Update images built from the documented layout (Microsoft "FFU image format", in
// img2ffu's write order; tests/ffu.rs builds the same images): a 320-sector GPT disk whose EFI system partition
// is tests/fixtures/fat/fat12.img, a FAT12 volume that holds a synthetic x86-64 ELF header.
const SECTOR = 512;
const BLOCK = 4096;
const CHUNK_KIB = 4;
const DISK_SECTORS = 320;
const FAT_FIRST_LBA = 8;
const STORE_HEADER_SIZE = 248;
const CALG_SHA_256 = 0x800c;
const DISK_BEGIN = 0;
const DISK_END = 2;
const EFI_SYSTEM = 'C12A7328-F81F-11D2-BA4B-00A0C93EC93B';
const DISK_GUID = '5A524158-4646-5544-4953-4B0000000001';
const ISA_NOTE = "FFU images name no ISA; each store's disk is classified on its own";

const fixture = path => readFile(new URL(`../../tests/fixtures/${path}`, import.meta.url));

/** `bytes` padded with zeros to a multiple of `unit`. */
const padded = (bytes, unit) => Buffer.concat([bytes, Buffer.alloc((unit - (bytes.length % unit)) % unit)]);

/** A 32-bit little-endian value. */
function u32(value) {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32LE(value);
  return bytes;
}

/** `EFI_GUID` bytes of a text GUID: the first three fields little-endian. */
function guid(text) {
  const bytes = Buffer.from(text.replaceAll('-', ''), 'hex');
  return Buffer.concat([
    Buffer.from(bytes.subarray(0, 4)).reverse(),
    Buffer.from(bytes.subarray(4, 6)).reverse(),
    Buffer.from(bytes.subarray(6, 8)).reverse(),
    bytes.subarray(8),
  ]);
}

/**
 * A GPT header (UEFI 2.10, Table 5.5) at `lba`: signature, revision 1.0, header size 92, header CRC (16),
 * MyLBA (24), AlternateLBA (32), usable LBAs (40, 48), disk GUID (56), entry array LBA (72), 4 entries (80) of
 * 128 B (84) and the array CRC (88).
 */
function gptHeader(lba, alternate, entryLba, array) {
  const header = Buffer.alloc(SECTOR);
  header.write('EFI PART', 0, 'latin1');
  header.writeUInt32LE(0x00010000, 8);
  header.writeUInt32LE(92, 12);
  header.writeBigUInt64LE(BigInt(lba), 24);
  header.writeBigUInt64LE(BigInt(alternate), 32);
  header.writeBigUInt64LE(3n, 40);
  header.writeBigUInt64LE(BigInt(DISK_SECTORS - 3), 48);
  guid(DISK_GUID).copy(header, 56);
  header.writeBigUInt64LE(BigInt(entryLba), 72);
  header.writeUInt32LE(4, 80);
  header.writeUInt32LE(128, 84);
  header.writeUInt32LE(crc32(array), 88);
  header.writeUInt32LE(crc32(header.subarray(0, 92)), 16);
  return header;
}

/**
 * The GPT disk: a protective MBR (one type 0xEE record from LBA 1), the primary header at LBA 1 and its entry
 * array at LBA 2 (entry 0 is the EFI system partition "EFIESP" over the FAT volume: type GUID, unique GUID, first
 * and last LBA, attributes, UTF-16LE name), the volume from LBA 8, and the backup array and header at the end.
 */
function gptDisk(volume) {
  const disk = Buffer.alloc(DISK_SECTORS * SECTOR);
  disk[446 + 4] = 0xee;
  disk.writeUInt32LE(1, 446 + 8);
  disk.writeUInt32LE(DISK_SECTORS - 1, 446 + 12);
  disk[510] = 0x55;
  disk[511] = 0xaa;
  const array = Buffer.alloc(4 * 128);
  guid(EFI_SYSTEM).copy(array, 0);
  guid('5A524158-0000-4000-8000-000000000001').copy(array, 16);
  array.writeBigUInt64LE(BigInt(FAT_FIRST_LBA), 32);
  array.writeBigUInt64LE(BigInt(FAT_FIRST_LBA + volume.length / SECTOR - 1), 40);
  array.write('EFIESP', 56, 'utf16le');
  array.copy(disk, 2 * SECTOR);
  array.copy(disk, (DISK_SECTORS - 2) * SECTOR);
  gptHeader(1, DISK_SECTORS - 1, 2, array).copy(disk, SECTOR);
  gptHeader(DISK_SECTORS - 1, 1, DISK_SECTORS - 2, array).copy(disk, (DISK_SECTORS - 1) * SECTOR);
  volume.copy(disk, FAT_FIRST_LBA * SECTOR);
  return disk;
}

/**
 * The write descriptors img2ffu writes for a disk: an empty block over both GPTs (block 0 and the last block
 * from the end), the primary GPT block, every other non-empty block, the primary GPT block again and the backup
 * GPT block from the end. Each is `{ blocks, locations: [[method, block index]] }`.
 */
function img2ffuWrites(disk) {
  const blocks = [];
  for (let at = 0; at < disk.length; at += BLOCK) {
    blocks.push(disk.subarray(at, at + BLOCK));
  }
  const last = blocks.length - 1;
  const writes = [
    { blocks: Buffer.alloc(BLOCK), locations: [[DISK_BEGIN, 0], [DISK_END, 0]] },
    { blocks: blocks[0], locations: [[DISK_BEGIN, 0]] },
  ];
  for (let i = 1; i < last; i++) {
    if (blocks[i].some(b => b !== 0)) {
      writes.push({ blocks: blocks[i], locations: [[DISK_BEGIN, i]] });
    }
  }
  writes.push({ blocks: blocks[0], locations: [[DISK_BEGIN, 0]] });
  writes.push({ blocks: blocks[last], locations: [[DISK_END, 0]] });
  return writes;
}

/** An img2ffu-style manifest: `[FullFlash]`, then one `[Store]` per entry of `stores` (`{ mainOs, sectors }`). */
function manifest(stores) {
  const lines = ['[FullFlash]', 'Version           = 2.0', 'DevicePlatformId0 = Zrax.Test.Platform', ''];
  for (const { mainOs, sectors } of stores) {
    lines.push('[Store]', `IsMainOSStore  = ${mainOs ? 'True' : 'False'}`, `MinSectorCount = ${sectors}`);
    lines.push('SectorSize     = 512', '');
  }
  return Buffer.from(lines.join('\r\n'), 'latin1');
}

/**
 * A store header (248 B: update type 0, store and full flash versions at 4-10, platform ID at 12, block size at
 * 204, write descriptor count and length at 208 and 212, no validation entries), the V2 fields when `version` is
 * 2 (store count, 1-based index, payload size, device path length and UTF-16LE path), and the write descriptors
 * (location count, block count, then each location's access method and block index).
 */
function storeRegion(version, index, count, store) {
  const writes = [];
  for (const { blocks, locations } of store.writes) {
    writes.push(u32(locations.length), u32(blocks.length / BLOCK));
    for (const [method, block] of locations) {
      writes.push(u32(method), u32(block));
    }
  }
  const descriptors = Buffer.concat(writes);
  const header = Buffer.alloc(STORE_HEADER_SIZE);
  header.writeUInt16LE(version, 4);
  header.writeUInt16LE(2, 8);
  header.write('Zrax.Test.Platform', 12, 'latin1');
  header.writeUInt32LE(BLOCK, 204);
  header.writeUInt32LE(store.writes.length, 208);
  header.writeUInt32LE(descriptors.length, 212);
  const parts = [header];
  if (version === 2) {
    const path = Buffer.from(store.devicePath, 'utf16le');
    const fields = Buffer.alloc(14);
    fields.writeUInt16LE(count, 0);
    fields.writeUInt16LE(index + 1, 2);
    fields.writeBigUInt64LE(BigInt(store.writes.reduce((sum, w) => sum + w.blocks.length, 0)), 4);
    fields.writeUInt16LE(path.length / 2, 12);
    parts.push(fields, path);
  }
  parts.push(descriptors);
  return padded(Buffer.concat(parts), BLOCK);
}

/**
 * An FFU in the documented order: security header (`cbSize` 32, `SignedImage `, chunk size in KiB, SHA-256,
 * catalog and hash table sizes), a stand-in catalog and the SHA-256 of every 4 KiB chunk from the image header
 * on, padded to a chunk; the image header (24 B, `ImageFlash  `, manifest length, chunk size) and manifest,
 * padded; the store regions; and the payload blocks in store order.
 */
function buildFfu(version, manifestText, stores) {
  const signature = Buffer.from('ImageFlash  ', 'latin1');
  const imageHeader = Buffer.concat([u32(24), signature, u32(manifestText.length), u32(CHUNK_KIB)]);
  const regions = [padded(Buffer.concat([imageHeader, manifestText]), BLOCK)];
  stores.forEach((store, i) => regions.push(storeRegion(version, i, stores.length, store)));
  const headerSize = regions.reduce((sum, region) => sum + region.length, 0);
  const payload = stores.flatMap(store => store.writes.map(write => write.blocks));
  const image = Buffer.concat([...regions, ...payload]);
  const hashes = [];
  for (let at = 0; at < image.length; at += BLOCK) {
    hashes.push(createHash('sha256').update(image.subarray(at, at + BLOCK)).digest());
  }
  const table = Buffer.concat(hashes);
  const catalog = Buffer.alloc(64, 0x5a);
  const security = Buffer.concat([
    u32(32), Buffer.from('SignedImage ', 'latin1'), u32(CHUNK_KIB), u32(CALG_SHA_256), u32(catalog.length),
    u32(table.length), catalog, table,
  ]);
  const head = padded(security, BLOCK);
  return { file: Buffer.concat([head, image]), payloadOffset: head.length + headerSize };
}

/** The V1 image of the FAT GPT disk, and a V2 image whose store 1 is a one-block AArch64 ELF "disk" and store 2,
 * the main OS store, the FAT GPT disk. */
async function images() {
  const disk = gptDisk(await fixture('fat/fat12.img'));
  const v1 = buildFfu(1, manifest([{ mainOs: true, sectors: DISK_SECTORS }]), [{ writes: img2ffuWrites(disk) }]);
  const elf = padded(await fixture('compressed/payload.elf'), BLOCK);
  elf.writeUInt16LE(183, 18);
  const v2Manifest = manifest([{ mainOs: false, sectors: BLOCK / SECTOR }, { mainOs: true, sectors: DISK_SECTORS }]);
  const v2 = buildFfu(2, v2Manifest, [
    {
      writes: [{ blocks: elf, locations: [[DISK_BEGIN, 0]] }],
      devicePath: 'VenHw(860845C1-BE09-4355-8BC1-30D64FF8E63A)',
    },
    { writes: img2ffuWrites(disk), devicePath: 'PciRoot(0x0)/Pci(0x1D,0x0)' },
  ]);
  return { v1, v2 };
}

const slice = (payload, label) => payload.slices?.find(s => s.label === label);

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`FFU images classify each store's disk through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const { v1, v2 } = await images();
    const inputs = [v1.file.toString('base64'), v2.file.toString('base64')];
    const [p1, p2] = await page.evaluate(async ({ module, inputs }) => {
      const wasm = await import(module);
      await wasm.default();
      return inputs.map(base64 => JSON.parse(wasm.classify(Uint8Array.from(atob(base64), c => c.charCodeAt(0)))));
    }, { module, inputs });
    for (const p of [p1, p2]) {
      assert.ok(!p.error, p.error);
      assert.equal(p.format.format, 'ffu');
      assert.equal(p.format.variant_name, 'FFU image');
      assert.equal(p.primary.isa, 'x86_64', 'from the ELF in the GPT disk\'s FAT partition');
      assert.ok(p.notes.some(n => n.message === ISA_NOTE));
    }
    assert.ok(Object.hasOwn(FORMAT_NAMES, 'ffu'), 'ffu has a display name');
    const disk = slice(p1, 'Store 1 disk');
    assert.ok(disk, JSON.stringify(p1.slices));
    assert.equal(disk.isa, 'x86_64');
    assert.equal(disk.offset, v1.payloadOffset);
    assert.equal(disk.size, v1.file.length - v1.payloadOffset);
    assert.equal(disk.decoded?.transform, 'FFU blocks');
    assert.equal(disk.decoded?.size, DISK_SECTORS * SECTOR);
    assert.deepEqual(p2.slices.map(s => s.label), ['Store 2 disk', 'Store 1 disk'], 'the main OS store first');
    assert.equal(slice(p2, 'Store 1 disk').isa, 'a_arch64');
    assert.equal(slice(p2, 'Store 1 disk').offset, v2.payloadOffset);
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names FFU images and keeps the store payload offset in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const { v1 } = await images();
    const file = { name: 'flash.ffu', buffer: v1.file, mimeType: 'application/octet-stream' };
    await page.locator('#fileinput').setInputFiles([file]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes(FORMAT_NAMES.ffu), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.primary.isa, 'x86_64');
    assert.equal(slice(p, 'Store 1 disk').offset, v1.payloadOffset);
    assert.ok(p.metadata.some(m => m.key?.custom === 'ffu_chunk_hashes' && m.value === 'match'));
  });
}
