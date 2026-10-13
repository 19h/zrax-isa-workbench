import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup);
after(teardown);

const fixture = path => readFile(new URL(`../../tests/fixtures/${path}`, import.meta.url));
const sha256 = bytes => createHash('sha256').update(bytes).digest();

// A NUL-padded 36-byte name field.
function name36(name) {
  const field = Buffer.alloc(36);
  field.write(name, 'latin1');
  return field;
}

// liblp LpMetadataGeometry in its 4096-byte block (little-endian): magic 0x616C4467, struct_size 52, SHA-256 of the
// 52 bytes with the checksum zeroed (8), metadata_max_size 4096 (40), one metadata slot (44), logical block size 4096.
function geometry() {
  const block = Buffer.alloc(4096);
  block.writeUInt32LE(0x616c4467, 0);
  block.writeUInt32LE(52, 4);
  block.writeUInt32LE(4096, 40);
  block.writeUInt32LE(1, 44);
  block.writeUInt32LE(4096, 48);
  sha256(block.subarray(0, 52)).copy(block, 8);
  return block;
}

// LpMetadataHeader v10.2 (256 B): magic 0x414C5030, version 10.2, header size, header SHA-256 (12), tables size (44),
// tables SHA-256 (48), table descriptors (offset, count, entry size) at 80, 92, 104, 116. Tables: one partition
// `system` (52 B: name, readonly, first extent 0, one extent, group 0), one linear extent of 8 sectors at sector 64
// (24 B), group `default` (48 B), block device `super` of 36864 B whose first logical sector is 64 (64 B).
function metadata() {
  const partition = Buffer.alloc(52);
  name36('system').copy(partition, 0);
  partition.writeUInt32LE(1, 36);
  partition.writeUInt32LE(1, 44);
  const extent = Buffer.alloc(24);
  extent.writeBigUInt64LE(8n, 0);
  extent.writeBigUInt64LE(64n, 12);
  const group = Buffer.alloc(48);
  name36('default').copy(group, 0);
  const device = Buffer.alloc(64);
  device.writeBigUInt64LE(64n, 0);
  device.writeBigUInt64LE(36864n, 16);
  name36('super').copy(device, 24);
  const tables = [partition, extent, group, device];
  const header = Buffer.alloc(256);
  header.writeUInt32LE(0x414c5030, 0);
  header.writeUInt16LE(10, 4);
  header.writeUInt16LE(2, 6);
  header.writeUInt32LE(256, 8);
  let offset = 0;
  tables.forEach((table, k) => {
    header.writeUInt32LE(offset, 80 + 12 * k);
    header.writeUInt32LE(1, 84 + 12 * k);
    header.writeUInt32LE(table.length, 88 + 12 * k);
    offset += table.length;
  });
  header.writeUInt32LE(offset, 44);
  const body = Buffer.concat(tables);
  sha256(body).copy(header, 48);
  sha256(header).copy(header, 12);
  return Buffer.concat([header, body]);
}

// A full super image: 4096 reserved bytes, the geometry and its backup, the metadata slot and its backup (4096 B each),
// and `system` at sector 64; the file is the 36864-byte block device.
function superImage(system) {
  const slot = Buffer.alloc(4096);
  metadata().copy(slot);
  const image = Buffer.concat([Buffer.alloc(4096), geometry(), geometry(), slot, slot, Buffer.alloc(36864 - 20480)]);
  system.copy(image, 64 * 512);
  return image;
}

// A flattened device tree (big-endian): header (magic D00DFEED, total size, structure at 56, strings, reservation map
// at 40, version 17, last compatible 16, strings and structure sizes), an empty reservation map, a root node with a
// `model` property, and the strings block.
function fdt(model) {
  const value = Buffer.from(model + '\0');
  const padded = Buffer.alloc(Math.ceil(value.length / 4) * 4);
  value.copy(padded);
  const prop = Buffer.alloc(12);
  prop.writeUInt32BE(3, 0);
  prop.writeUInt32BE(value.length, 4);
  const end = Buffer.alloc(8);
  end.writeUInt32BE(2, 0);
  end.writeUInt32BE(9, 4);
  const begin = Buffer.alloc(8);
  begin.writeUInt32BE(1, 0);
  const structure = Buffer.concat([begin, prop, padded, end]);
  const strings = Buffer.from('model\0');
  const header = Buffer.alloc(56);
  header.writeUInt32BE(0xd00dfeed, 0);
  header.writeUInt32BE(56 + structure.length + strings.length, 4);
  header.writeUInt32BE(56, 8);
  header.writeUInt32BE(56 + structure.length, 12);
  header.writeUInt32BE(40, 16);
  header.writeUInt32BE(17, 20);
  header.writeUInt32BE(16, 24);
  header.writeUInt32BE(strings.length, 32);
  header.writeUInt32BE(structure.length, 36);
  return Buffer.concat([header, structure, strings]);
}

// libufdt dt_table_header (big-endian): magic 0xD7B7AB1E, total size, header size 32, entry size 32, one entry at 32,
// page size 2048, version 0; the entry (blob size and offset, id 1, rev 0, custom words 0); then the blob.
function dtbo(blob) {
  const header = Buffer.alloc(64);
  header.writeUInt32BE(0xd7b7ab1e, 0);
  header.writeUInt32BE(64 + blob.length, 4);
  header.writeUInt32BE(32, 8);
  header.writeUInt32BE(32, 12);
  header.writeUInt32BE(1, 16);
  header.writeUInt32BE(32, 20);
  header.writeUInt32BE(2048, 24);
  header.writeUInt32BE(blob.length, 32);
  header.writeUInt32BE(64, 36);
  header.writeUInt32BE(1, 40);
  return Buffer.concat([header, blob]);
}

// libavb AvbVBMetaImageHeader (256 B, big-endian): magic AVB0, required libavb 1.0, authentication block 64 B,
// auxiliary block 64 B, algorithm NONE, descriptors at auxiliary offset 0, release string; the auxiliary block holds
// one property descriptor (tag 0, 32 B following: key and value sizes, `ro.zrax\0`, `1\0`, padding).
function vbmeta() {
  const descriptor = Buffer.alloc(48);
  descriptor.writeBigUInt64BE(0n, 0);
  descriptor.writeBigUInt64BE(32n, 8);
  descriptor.writeBigUInt64BE(7n, 16);
  descriptor.writeBigUInt64BE(1n, 24);
  descriptor.write('ro.zrax\x001\0', 32, 'latin1');
  const header = Buffer.alloc(256);
  header.write('AVB0', 0, 'latin1');
  header.writeUInt32BE(1, 4);
  header.writeBigUInt64BE(64n, 12);
  header.writeBigUInt64BE(64n, 20);
  header.writeBigUInt64BE(BigInt(descriptor.length), 104);
  header.write('avbtool 1.3.0', 128, 'latin1');
  const auxiliary = Buffer.alloc(64);
  descriptor.copy(auxiliary);
  return Buffer.concat([header, Buffer.alloc(64), auxiliary]);
}

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`super, DTBO and vbmeta images report their format and members through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const elf = await fixture('compressed/payload.elf');
    const images = [
      { name: 'super.img', bytes: superImage(elf), format: 'androidsuper' },
      { name: 'dtbo.img', bytes: dtbo(fdt('zrax board')), format: 'androiddtbo' },
      { name: 'vbmeta.img', bytes: vbmeta(), format: 'androidvbmeta' },
    ];
    const payloads = await page.evaluate(async ({ module, images }) => {
      const wasm = await import(module);
      await wasm.default();
      return images.map(image => JSON.parse(wasm.classify(new Uint8Array(image.bytes))));
    }, { module, images: images.map(image => ({ name: image.name, bytes: [...image.bytes] })) });
    images.forEach(({ name, format }, i) => {
      const p = payloads[i];
      assert.ok(!p.error, `${name}: ${p.error}`);
      assert.equal(p.format.format, format, name);
      assert.ok(Object.hasOwn(FORMAT_NAMES, format), `${format} has a display name`);
    });
    const [lp, table, avb] = payloads;
    assert.equal(lp.primary.isa, 'x86_64');
    const system = lp.slices.find(s => s.label === 'system');
    assert.equal(system.isa, 'x86_64');
    assert.equal(system.offset, 32768);
    assert.equal(system.size, 4096);
    const tree = table.slices.find(s => s.label === 'DT entry 0 (id 0x1, rev 0x0)');
    assert.equal(tree.offset, 64);
    assert.equal(tree.isa.unknown, 0);
    assert.equal(avb.primary.isa.unknown, 0);
    assert.ok(!avb.slices?.length, 'a vbmeta image has no members');
    assert.ok(avb.notes.some(n => n.message === 'Property ro.zrax = 1'), JSON.stringify(avb.notes));
  });
}
