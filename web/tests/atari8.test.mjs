import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup);
after(teardown);

// The cc65-linked binary load file (tests/fixtures/atari8/README.md): an init segment at 0x0600, INITAD, the
// program at 0x2E00 and RUNAD.
const program = () => readFile(new URL('../../tests/fixtures/atari8/program.xex', import.meta.url));

// ATR header ("ATR File Format Description"; atari800 afile.h): magic 96 02, image size in 16-byte paragraphs
// (bits 0-15 at 2, bits 16-23 at 6), sector size at 4.
const ATR_HEADER = 16;
const SECTOR = 128;
const SECTORS = 720;
// DOS 2.x ("Inside Atari DOS" chapter 2): VTOC at 360, directory at 361, data sectors of 125 bytes and a
// 3-byte trailer; directory flags 0x42 (in use, written by DOS 2).
const VTOC = 360;
const DIRECTORY = 361;
const DOS2_FILE = 0x42;
const DATA_BYTES = SECTOR - 3;
// Boot record: flags 0, 3 sectors, load address 0x0700, init address 0x0708; `CLC` (18) `RTS` (60) at 0x0706
// and `RTS` (60) at 0x0708.
const BOOT_RECORD = [0x00, 0x03, 0x00, 0x07, 0x08, 0x07, 0x18, 0x60, 0x60];

const sectorOffset = number => ATR_HEADER + (number - 1) * SECTOR;

// A 720-sector single-density DOS 2.x disk: the VTOC (code 2, 707 usable sectors, a bitmap of sectors 0-719 with
// a set bit for each free sector), PROGRAM.XEX in sector 4, README.TXT in sectors 5 and 6, and the boot record.
function atrImage(xex) {
  const image = Buffer.alloc(ATR_HEADER + SECTORS * SECTOR);
  image.set([0x96, 0x02]);
  const paragraphs = (SECTORS * SECTOR) / 16;
  image.writeUInt16LE(paragraphs & 0xffff, 2);
  image.writeUInt16LE(SECTOR, 4);
  image[6] = paragraphs >> 16;
  image.set(BOOT_RECORD, sectorOffset(1));
  const vtoc = sectorOffset(VTOC);
  image[vtoc] = 2;
  image.writeUInt16LE(707, vtoc + 1);
  let free = 707;
  const bitmap = (sector, isFree) => {
    const at = vtoc + 10 + (sector >> 3);
    const mask = 0x80 >> (sector & 7);
    image[at] = isFree ? image[at] | mask : image[at] & ~mask;
  };
  for (let sector = 4; sector < 720; sector++) {
    if (sector < 360 || sector > 368) bitmap(sector, true);
  }
  // File `number`: data sectors with the trailer (file number << 2 | link bits 9-8, link bits 7-0, bytes used),
  // then the directory entry (flags, sector count, first sector, name and extension).
  const writeFile = (number, name, contents, sectors) => {
    sectors.forEach((sector, i) => {
      const chunk = contents.subarray(i * DATA_BYTES, (i + 1) * DATA_BYTES);
      const next = sectors[i + 1] ?? 0;
      const at = sectorOffset(sector);
      image.set(chunk, at);
      image[at + SECTOR - 3] = (number << 2) | (next >> 8);
      image[at + SECTOR - 2] = next & 0xff;
      image[at + SECTOR - 1] = chunk.length;
      bitmap(sector, false);
      free -= 1;
    });
    const entry = sectorOffset(DIRECTORY) + number * 16;
    image[entry] = DOS2_FILE;
    image.writeUInt16LE(sectors.length, entry + 1);
    image.writeUInt16LE(sectors[0], entry + 3);
    image.write(name, entry + 5, 'latin1');
  };
  writeFile(0, 'PROGRAM XEX', xex, [4]);
  writeFile(1, 'README  TXT', Buffer.alloc(200, 'A'), [5, 6]);
  image.writeUInt16LE(free, vtoc + 3);
  return image;
}

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`Atari binary load files and ATR disks classify through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const xex = await program();
    const atr = atrImage(xex);
    const [binary, disk] = await page.evaluate(async ({ module, files }) => {
      const wasm = await import(module);
      await wasm.default();
      return files.map(bytes => JSON.parse(wasm.classify(new Uint8Array(bytes))));
    }, { module, files: [[...xex], [...atr]] });

    assert.ok(!binary.error, binary.error);
    assert.equal(binary.format.format, 'atarixex');
    assert.ok(Object.hasOwn(FORMAT_NAMES, 'atarixex'), 'atarixex has a display name');
    const { isa, bitwidth, endianness } = binary.primary;
    assert.deepEqual([isa, bitwidth, endianness], ['mcs6502', 8, 'little']);
    assert.ok(binary.notes.some(n => n.message === 'Run address (RUNAD) 0x2E00'));
    assert.ok(binary.metadata.some(m => m.key?.custom === 'atarixex_initad' && m.value === '0x0600'));

    assert.ok(!disk.error, disk.error);
    assert.equal(disk.format.format, 'atr');
    assert.ok(Object.hasOwn(FORMAT_NAMES, 'atr'), 'atr has a display name');
    assert.equal(disk.primary.isa, 'mcs6502');
    assert.deepEqual(disk.slices.map(s => s.label), ['PROGRAM.XEX', 'README.TXT', 'Boot sectors 1-3']);
    const file = disk.slices.find(s => s.label === 'PROGRAM.XEX');
    assert.deepEqual([file.isa, file.offset, file.size], ['mcs6502', sectorOffset(4), xex.length]);
    const readme = disk.slices.find(s => s.label === 'README.TXT');
    assert.deepEqual([readme.isa, readme.offset, readme.size], [{ unknown: 0 }, sectorOffset(5), DATA_BYTES]);
    assert.deepEqual(readme.decoded, { transform: 'DOS 2 sector chain', offset: 0, size: 200 });
    const boot = disk.slices.find(s => s.label === 'Boot sectors 1-3');
    assert.deepEqual([boot.isa, boot.offset, boot.size], ['mcs6502', ATR_HEADER, 3 * SECTOR]);
    assert.ok(disk.metadata.some(m => m.key?.custom === 'atr_dos_files' && m.value === 2));
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names ATR disk images in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const atr = atrImage(await program());
    const upload = { name: 'DISK.ATR', buffer: atr, mimeType: 'application/octet-stream' };
    await page.locator('#fileinput').setInputFiles([upload]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes(FORMAT_NAMES.atr), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.primary.isa, 'mcs6502');
    assert.ok(p.metadata.some(m => m.key?.custom === 'atr_image_size' && m.value === atr.length));
  });
}
