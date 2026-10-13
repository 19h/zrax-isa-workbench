import assert from 'node:assert/strict';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup);
after(teardown);

// Intel SDM Vol. 3A Table 12-7: header version and loader revision 1; 18 July
// 2023 as BCD mmddyyyy; a synthetic processor signature and platform flags.
const MICROCODE_DATE = 0x07182023;
const SIGNATURE = 0x000906ea;
const PLATFORM_FLAGS = 0x22;
// coreboot ifdtool: the flash descriptor signature; an unused FLREG.
const FLVALSIG = 0x0ff0a55a;
const FLREG_UNUSED = 0x00007fff;
// coreboot amdfwtool.h: the EFS signature and where amdfwread finds it.
const EFS_SIGNATURE = 0x55aa55aa;
const EFS_OFFSET = 0x20000;
// Address modes in bits 63:62 of a directory entry address.
const MODE_IMAGE = 1n;

const sum32 = bytes => {
  let sum = 0;
  for (let i = 0; i < bytes.length; i += 4) sum = (sum + bytes.readUInt32LE(i)) >>> 0;
  return sum;
};
const sum8 = bytes => bytes.reduce((sum, b) => (sum + b) & 0xff, 0);
const synthetic = (length, seed) => Buffer.from(Array.from({ length }, (_, i) => (i * 31 + seed) & 0xff));

// A 1 KiB microcode update: version 1, revision 0xF0, the BCD date, the
// signature, a checksum that makes header and data sum to 0, loader revision
// 1, the flags, 976 B of data and a 1024 B total size.
function intelMicrocode() {
  const update = Buffer.alloc(1024);
  update.writeUInt32LE(1, 0x00);
  update.writeUInt32LE(0xf0, 0x04);
  update.writeUInt32LE(MICROCODE_DATE, 0x08);
  update.writeUInt32LE(SIGNATURE, 0x0c);
  update.writeUInt32LE(1, 0x14);
  update.writeUInt32LE(PLATFORM_FLAGS, 0x18);
  update.writeUInt32LE(976, 0x1c);
  update.writeUInt32LE(1024, 0x20);
  synthetic(976, 3).copy(update, 48);
  update.writeUInt32LE((0x100000000 - sum32(update)) % 0x100000000, 0x10);
  return update;
}

// An AMD microcode container (Linux amd.c): magic DMA\0, equivalence table
// type 0 with one entry and the all-zero terminator, then one patch section
// (type 1, 256 B) whose header holds patch ID 0x0A201016 and equivalence ID
// 0xA210.
function amdMicrocode() {
  const header = Buffer.alloc(12 + 32);
  header.write('DMA\0', 0, 'latin1');
  header.writeUInt32LE(0, 4);
  header.writeUInt32LE(32, 8);
  header.writeUInt32LE(0x00a20f10, 12);
  header.writeUInt16LE(0xa210, 24);
  const section = Buffer.alloc(8 + 256);
  section.writeUInt32LE(1, 0);
  section.writeUInt32LE(256, 4);
  section.writeUInt32LE(0x0a201016, 8 + 4);
  section.writeUInt16LE(0xa210, 8 + 0x18);
  synthetic(192, 9).copy(section, 8 + 64);
  return Buffer.concat([header, section]);
}

// A version 1 code partition directory (coreboot ifwitool): $CPD, two
// entries, versions 1, header length 0x10, the 8-bit checksum, name FTPR;
// entries FTPR.man (a $MN2 manifest with version 11.8.50.3399) and rbe.
function codePartition() {
  const manifest = synthetic(0x100, 0x41);
  manifest.write('$MN2', 0x1c, 'latin1');
  [11, 8, 50, 3399].forEach((part, i) => manifest.writeUInt16LE(part, 0x24 + 2 * i));
  const rbe = synthetic(0x80, 0x22);
  const table = Buffer.alloc(0x40);
  table.write('$CPD', 0, 'latin1');
  table.writeUInt32LE(2, 4);
  table[8] = 1;
  table[9] = 1;
  table[10] = 0x10;
  table.write('FTPR', 0x0c, 'latin1');
  table.write('FTPR.man', 0x10, 'latin1');
  table.writeUInt32LE(0x40, 0x10 + 0x0c);
  table.writeUInt32LE(manifest.length, 0x10 + 0x10);
  table.write('rbe', 0x28, 'latin1');
  table.writeUInt32LE(0x140, 0x28 + 0x0c);
  table.writeUInt32LE(rbe.length, 0x28 + 0x10);
  table[0x0b] = (0x100 - sum8(table.subarray(0, 0x40))) & 0xff;
  return Buffer.concat([table, manifest, rbe]);
}

// An ME region: zero ROM bypass vector, $FPT at 0x10 (one entry, header
// version 0x20, entry version 0x10, header length 0x20, the 8-bit checksum at
// 0x1B), the FTPR code entry (offset 0x1000), then the code partition.
function meRegion() {
  const region = Buffer.alloc(0x2000, 0xff);
  region.fill(0, 0, 0x50);
  region.write('$FPT', 0x10, 'latin1');
  region.writeUInt32LE(1, 0x14);
  region[0x18] = 0x20;
  region[0x19] = 0x10;
  region[0x1a] = 0x20;
  region[0x1b] = (0x100 - sum8(region.subarray(0x10, 0x30))) & 0xff;
  const partition = codePartition();
  region.write('FTPR', 0x30, 'latin1');
  region.writeUInt32LE(0x1000, 0x30 + 0x08);
  region.writeUInt32LE(partition.length, 0x30 + 0x0c);
  region.writeUInt32LE(0, 0x30 + 0x1c);
  partition.copy(region, 0x1000);
  return region;
}

// A flash descriptor image: FLVALSIG at 0x10, FLMAP0 (FCBA 0x30, FRBA 0x40),
// FLMAP1 (FMBA 0x80, FPSBA 0x100), FLREG registers at 0x40 (descriptor
// 0x0-0xFFF, ME 0x1000-0x2FFF, BIOS 0x3000-0x3FFF erased), then the regions.
function flashWithMe() {
  const image = Buffer.alloc(0x4000, 0xff);
  image.writeUInt32LE(FLVALSIG, 0x10);
  image.writeUInt32LE(0x00040003, 0x14);
  image.writeUInt32LE(0x00100008, 0x18);
  for (let i = 0; i < 16; i++) image.writeUInt32LE(FLREG_UNUSED, 0x40 + 4 * i);
  image.writeUInt32LE(0, 0x40);
  image.writeUInt32LE(3 | (3 << 16), 0x44);
  image.writeUInt32LE(1 | (2 << 16), 0x48);
  meRegion().copy(image, 0x1000);
  return image;
}

// amdfwtool fletcher32: 16-bit words into two registers that start at 0xFFFF,
// folded after every 359 words and at the end.
function fletcher32(bytes) {
  const fold = sum => (sum & 0xffff) + (sum >>> 16);
  let c0 = 0xffff;
  let c1 = 0xffff;
  for (let block = 0; block < bytes.length; block += 718) {
    const end = Math.min(block + 718, bytes.length & ~1);
    for (let i = block; i < end; i += 2) {
      c0 = (c0 + bytes.readUInt16LE(i)) >>> 0;
      c1 = (c1 + c0) >>> 0;
    }
    c0 = fold(c0);
    c1 = fold(c1);
  }
  return ((fold(c1) << 16) | fold(c0)) >>> 0;
}

// A 0x20400 B AMD flash image: erased flash, the EFS at 0x20000 (signature,
// psp_directory 0x20100, efs_gen second generation, the rest erased) and a
// $PSP directory (Fletcher-32 checksum, one entry, address mode 1) whose
// PSP boot loader entry (type 0x01, 0x40 B) points to 0x20200.
function amdImage() {
  const image = Buffer.alloc(0x20400, 0xff);
  image.writeUInt32LE(EFS_SIGNATURE, EFS_OFFSET);
  image.writeUInt32LE(0x20100, EFS_OFFSET + 0x10);
  image.writeUInt32LE(0, EFS_OFFSET + 0x14);
  image.writeUInt32LE(0xfffffffe, EFS_OFFSET + 0x24);
  const directory = Buffer.alloc(32, 0);
  directory.write('$PSP', 0, 'latin1');
  directory.writeUInt32LE(1, 8);
  directory.writeUInt32LE(1 << 29, 12);
  directory[16] = 0x01;
  directory.writeUInt32LE(0x40, 20);
  directory.writeBigUInt64LE(0x20200n | (MODE_IMAGE << 62n), 24);
  directory.writeUInt32LE(fletcher32(directory.subarray(8)), 4);
  directory.copy(image, 0x20100);
  synthetic(0x40, 0x51).copy(image, 0x20200);
  return image;
}

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`PC firmware blobs classify as opaque containers through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const fixtures = [
      { name: 'ucode.bin', format: 'intelmicrocode', bytes: [...intelMicrocode()] },
      { name: 'amd.bin', format: 'amdmicrocode', bytes: [...amdMicrocode()] },
      { name: 'me.bin', format: 'intelme', bytes: [...meRegion()] },
      { name: 'amd-flash.bin', format: 'amdpsp', bytes: [...amdImage()] },
    ];
    const payloads = await page.evaluate(async ({ module, fixtures }) => {
      const wasm = await import(module);
      await wasm.default();
      return fixtures.map(f => JSON.parse(wasm.classify(new Uint8Array(f.bytes))));
    }, { module, fixtures });
    fixtures.forEach(({ name, format }, i) => {
      const p = payloads[i];
      assert.ok(!p.error, `${name}: ${p.error}`);
      assert.equal(p.format.format, format, name);
      assert.ok(Object.hasOwn(FORMAT_NAMES, format), `${format} has a display name`);
      assert.deepEqual(p.primary.isa, { unknown: 0 }, name);
      assert.deepEqual(p.candidates, [], name);
      assert.ok(p.slices.length > 0, name);
      for (const slice of p.slices) assert.deepEqual(slice.isa, { unknown: 0 }, `${name} ${slice.label}`);
    });
    const [ucode, amd, me, flash] = payloads;
    assert.ok(ucode.notes.some(n => n.message.startsWith('Microcode update data: encrypted')));
    const updateLabel = 'Microcode update 1 (processor signature 0x000906EA, revision 0xF0)';
    const update = ucode.slices.find(s => s.label === updateLabel);
    assert.deepEqual([update.offset, update.size], [0, 1024]);
    const patch = amd.slices.find(s => s.label === 'Microcode patch 0x0A201016 (equivalence ID 0xA210)');
    assert.deepEqual([patch.offset, patch.size], [0x34, 256]);
    const ftpr = me.slices.find(s => s.label === 'FTPR partition (code)');
    assert.equal(ftpr.offset, 0x1000);
    assert.ok(me.notes.some(n => n.message.includes('$CPD "FTPR" (header version 1), 2 modules: FTPR.man, rbe')));
    const boot = flash.slices.find(s => s.label === 'PSP L1 entry 0x01 (AMD_FW_PSP_BOOTLOADER)');
    assert.deepEqual([boot.offset, boot.size], [0x20200, 0x40]);
  });

  test(`a flash descriptor's ME region with a partition table is Intel ME through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const bytes = [...flashWithMe()];
    const p = await page.evaluate(async ({ module, bytes }) => {
      const wasm = await import(module);
      await wasm.default();
      return JSON.parse(wasm.classify(new Uint8Array(bytes)));
    }, { module, bytes });
    assert.equal(p.format.format, 'intelifd');
    const me = p.slices.find(s => s.label === 'ME region');
    assert.deepEqual([me.offset, me.size, me.isa], [0x1000, 0x2000, { unknown: 0 }]);
    assert.ok(p.notes.some(n => n.message.includes(`classified as ${FORMAT_NAMES.intelme}`)), JSON.stringify(p.notes));
    assert.deepEqual(p.candidates, []);
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names PC firmware formats in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const buffer = intelMicrocode();
    const file = { name: 'ucode.bin', buffer, mimeType: 'application/octet-stream' };
    await page.locator('#fileinput').setInputFiles([file]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes(FORMAT_NAMES.intelmicrocode), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.format.format, 'intelmicrocode');
    assert.ok(p.metadata.some(m => m.key?.custom === 'pcfw_microcode_0_revision' && m.value === '0xF0'));
  });
}
