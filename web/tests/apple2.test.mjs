import assert from 'node:assert/strict';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup); after(teardown);

const SECTOR = 256;
const BLOCK = 512;

// A hand-assembled 6502 routine: LDA #$01; STA $0200; LDX #$00; loop: LDA $0300,X; STA $0400,X; INX; BNE loop;
// JSR $FDED; RTS.
const CODE_6502 = [
  0xa9, 0x01, 0x8d, 0x00, 0x02, 0xa2, 0x00, 0xbd, 0x00, 0x03, 0x9d, 0x00, 0x04, 0xe8, 0xd0, 0xf7, 0x20, 0xed, 0xfd,
  0x60,
];

// `size` bytes of the 6502 routine, repeated.
function code(size) {
  const bytes = Buffer.alloc(size);
  for (let at = 0; at < size; at++) {
    bytes[at] = CODE_6502[at % CODE_6502.length];
  }
  return bytes;
}

// Offset of DOS sector `sector` of `track` in a DOS-order image.
const sectorAt = (track, sector) => (track * 16 + sector) * SECTOR;

// A 35-track DOS 3.3 disk in DOS order (Beneath Apple DOS chapter 4): boot code at track 0 sector 0; the VTOC at
// track 17 sector 0 (catalog T17 S15, release 3, volume 254, 122 pairs per list, 35 tracks, 16 sectors, 256 B); the
// catalog chain T17 S15 down to S1; entry 0 `HELLO` (Applesoft, list T18 S12, data T18 S11); entry 1 `PROG` (binary,
// list T18 S15, data T18 S14 and S13: load address 0x6000, length 300, 6502 code).
function dosDisk() {
  const disk = Buffer.alloc(35 * 16 * SECTOR);
  disk[0] = 0x01;
  code(255).copy(disk, 1);
  const vtoc = sectorAt(17, 0);
  disk[vtoc + 0x01] = 17;
  disk[vtoc + 0x02] = 15;
  disk[vtoc + 0x03] = 3;
  disk[vtoc + 0x06] = 254;
  disk[vtoc + 0x27] = 122;
  disk[vtoc + 0x34] = 35;
  disk[vtoc + 0x35] = 16;
  disk.writeUInt16LE(256, vtoc + 0x36);
  for (let sector = 15; sector >= 1; sector--) {
    const catalog = sectorAt(17, sector);
    disk[catalog + 0x01] = sector === 1 ? 0 : 17;
    disk[catalog + 0x02] = sector === 1 ? 0 : sector - 1;
  }
  putEntry(disk, 0, [18, 12], 0x02, 'HELLO');
  putList(disk, [18, 12], [[18, 11]]);
  Buffer.from([0x06, 0x00, 0x07, 0x08, 0x0a, 0x00, 0xba, 0x00]).copy(disk, sectorAt(18, 11));
  putEntry(disk, 1, [18, 15], 0x04, 'PROG');
  putList(disk, [18, 15], [[18, 14], [18, 13]]);
  const binary = Buffer.concat([Buffer.from([0x00, 0x60, 0x2c, 0x01]), code(300)]);
  binary.copy(disk, sectorAt(18, 14), 0, SECTOR);
  binary.copy(disk, sectorAt(18, 13), SECTOR);
  return disk;
}

// Catalog entry `n` of track 17 sector 15: track/sector list, file type, high-bit ASCII name padded with 0xA0, 2
// sectors.
function putEntry(disk, n, list, fileType, name) {
  const entry = sectorAt(17, 15) + 0x0b + 35 * n;
  disk[entry] = list[0];
  disk[entry + 1] = list[1];
  disk[entry + 2] = fileType;
  disk.fill(0xa0, entry + 3, entry + 33);
  for (let i = 0; i < name.length; i++) {
    disk[entry + 3 + i] = name.charCodeAt(i) | 0x80;
  }
  disk.writeUInt16LE(2, entry + 0x21);
}

// A track/sector list with no next list, sector offset 0 and the given data pairs from 0x0C.
function putList(disk, list, pairs) {
  const at = sectorAt(list[0], list[1]);
  pairs.forEach(([track, sector], i) => {
    disk[at + 0x0c + 2 * i] = track;
    disk[at + 0x0d + 2 * i] = sector;
  });
}

// A 16-block ProDOS volume `ZRAX` (ProDOS 8 TRM Appendix B): 6502 loader code in block 0; the volume directory in
// block 2 (header with entry length 0x27, 13 entries per block, 2 files, bitmap block 6, 16 blocks); `PRODOS` (SYS
// seedling, block 7, 100 B of code) and `README` (TXT seedling, block 8, 20 B).
function prodosVolume() {
  const volume = Buffer.alloc(16 * BLOCK);
  code(BLOCK).copy(volume, 0);
  const header = 2 * BLOCK + 4;
  volume[header] = 0xf0 | 4;
  volume.write('ZRAX', header + 1, 'latin1');
  volume[header + 0x1f] = 0x27;
  volume[header + 0x20] = 0x0d;
  volume.writeUInt16LE(2, header + 0x21);
  volume.writeUInt16LE(6, header + 0x23);
  volume.writeUInt16LE(16, header + 0x25);
  putFile(volume, 2, 'PRODOS', 0xff, 7, 100);
  code(100).copy(volume, 7 * BLOCK);
  putFile(volume, 3, 'README', 0x04, 8, 20);
  volume.write('ZRAX PRODOS FIXTURE\r', 8 * BLOCK, 'latin1');
  return volume;
}

// Seedling entry in slot `slot` of block 2: storage type 1, name, file type, key block, 1 block used, EOF, header
// pointer 2.
function putFile(volume, slot, name, fileType, key, eof) {
  const entry = 2 * BLOCK + 4 + (slot - 1) * 0x27;
  volume[entry] = 0x10 | name.length;
  volume.write(name, entry + 1, 'latin1');
  volume[entry + 0x10] = fileType;
  volume.writeUInt16LE(key, entry + 0x11);
  volume.writeUInt16LE(1, entry + 0x13);
  volume.writeUIntLE(eof, entry + 0x15, 3);
  volume.writeUInt16LE(2, entry + 0x25);
}

// A 2IMG file (magnet.ch "Disk Images"): `2IMG`, creator `CPII`, header length 64, version 1, ProDOS order, the block
// count, data at 64.
function twoImg(volume) {
  const header = Buffer.alloc(64);
  header.write('2IMG', 0, 'latin1');
  header.write('CPII', 4, 'latin1');
  header.writeUInt16LE(64, 8);
  header.writeUInt16LE(1, 10);
  header.writeUInt32LE(1, 12);
  header.writeUInt32LE(volume.length / BLOCK, 20);
  header.writeUInt32LE(64, 24);
  header.writeUInt32LE(volume.length, 28);
  return Buffer.concat([header, volume]);
}

const FIXTURES = [
  ['dos', dosDisk(), 'apple2dos'],
  ['prodos', prodosVolume(), 'prodos'],
  ['twoimg', twoImg(prodosVolume()), 'twoimg'],
];

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`Apple II disk images list their files and report 6502 code through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const fixtures = FIXTURES.map(([name, bytes]) => ({ name, bytes: [...bytes] }));
    const payloads = await page.evaluate(async ({ module, fixtures }) => {
      const wasm = await import(module);
      await wasm.default();
      const classify = f => [f.name, JSON.parse(wasm.classify(new Uint8Array(f.bytes)))];
      return Object.fromEntries(fixtures.map(classify));
    }, { module, fixtures });
    for (const [name, , format] of FIXTURES) {
      const p = payloads[name];
      assert.ok(!p.error, `${name}: ${p.error}`);
      assert.equal(p.format.format, format, name);
      assert.equal(p.primary.isa, 'mcs6502', name);
      assert.ok(Object.hasOwn(FORMAT_NAMES, format), `${format} has a display name`);
    }
    const dos = payloads.dos;
    assert.deepEqual(dos.slices.map(s => s.label), ['HELLO', 'PROG', 'Boot code (track 0 sector 0)']);
    const prog = dos.slices.find(s => s.label === 'PROG');
    assert.deepEqual([prog.isa, prog.offset, prog.size], ['mcs6502', sectorAt(18, 14) + 4, SECTOR - 4]);
    assert.equal(prog.decoded.size, 300);
    assert.deepEqual(dos.slices.find(s => s.label === 'HELLO').isa, { unknown: 0 });
    const load = dos.metadata.find(m => m.key?.custom === 'apple2_load_address_1');
    assert.equal(load.value, '0x6000 (B file, 300 B)');
    const labels = ['/ZRAX/PRODOS', '/ZRAX/README', 'Boot code (blocks 0 and 1)'];
    assert.deepEqual(payloads.prodos.slices.map(s => s.label), labels);
    const system = payloads.twoimg.slices.find(s => s.label === '/ZRAX/PRODOS');
    assert.deepEqual([system.isa, system.offset, system.size], ['mcs6502', 64 + 7 * BLOCK, 100]);
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names 2IMG images and reports the creator in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const file = { name: 'disk.2mg', buffer: twoImg(prodosVolume()), mimeType: 'application/octet-stream' };
    await page.locator('#fileinput').setInputFiles([file]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes('2IMG disk image'), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.format.format, 'twoimg');
    assert.equal(p.primary.isa, 'mcs6502');
    assert.ok(p.metadata.some(m => m.key?.custom === 'apple2_twoimg_creator' && m.value === 'CPII'));
  });
}
